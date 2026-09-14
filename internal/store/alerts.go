package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

// Alerts are derived from the audit trail and from connector state by a fixed rule set.
// Every audit insert queues its id through a trigger, so the row and its evaluation
// obligation commit together; the evaluator writes alerts and drains the queue in one
// transaction, so a crash can only repeat work, never skip it. Bursts fold into one
// open alert per rule and key. Mail goes to configured recipients, who must be able to
// read alerts both when configured and again when each message is sent.

var (
	ErrAlertMissing   = errors.New("alert not found")
	ErrAlertNotOpen   = errors.New("alert is not open")
	ErrAlertRecipient = errors.New("recipient may not read alerts")
	ErrAlertSettings  = errors.New("invalid alert settings")
)

const (
	alertSettingsKey      = "alert_settings"
	alertDeliveryAttempts = 8
	alertBatch            = 500
	alertMaxBatches       = 10
	// loginAlertCeiling bounds live login-failure alerts: past it, further sources
	// fold into one alert rather than each minting an alert and its mail.
	loginAlertCeiling = 10
	// loginAlertCooldown bounds login-failure mail: once a login alert has been
	// mailed, further login alerts within this long open without mail, so neither
	// quiet-then-burst cycles nor rotating addresses can re-mail recipients.
	loginAlertCooldown = 4 * time.Hour
)

type Alert struct {
	ID             string        `json:"id"`
	Rule           string        `json:"rule"`
	Key            string        `json:"key"`
	Severity       string        `json:"severity"`
	Title          string        `json:"title"`
	Summary        string        `json:"summary"`
	Status         string        `json:"status"`
	Count          int           `json:"count"`
	FirstSeen      time.Time     `json:"firstSeen"`
	LastSeen       time.Time     `json:"lastSeen"`
	AcknowledgedAt *time.Time    `json:"acknowledgedAt,omitempty"`
	AcknowledgedBy string        `json:"acknowledgedBy,omitempty"`
	ResolvedAt     *time.Time    `json:"resolvedAt,omitempty"`
	Delivery       AlertDelivery `json:"delivery"`
}

// AlertDelivery summarises the mail queued for one alert; LastError is the latest send
// failure (or, failing that, skip reason) so a broken relay stays visible on the inbox.
type AlertDelivery struct {
	Pending   int    `json:"pending"`
	Delivered int    `json:"delivered"`
	Failed    int    `json:"failed"`
	Skipped   int    `json:"skipped"`
	LastError string `json:"lastError"`
}

type AlertSettings struct {
	LoginFailureThreshold     int      `json:"loginFailureThreshold"`
	LoginFailureWindowSeconds int      `json:"loginFailureWindowSeconds"`
	Recipients                []string `json:"recipients"`
}

func (s *Store) migrateAlerts() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS alerts (
 id TEXT PRIMARY KEY, rule TEXT NOT NULL, key TEXT NOT NULL,
 severity TEXT NOT NULL CHECK (severity IN ('critical','warning')),
 title TEXT NOT NULL, summary TEXT NOT NULL,
 status TEXT NOT NULL CHECK (status IN ('open','acknowledged','resolved')),
 count INTEGER NOT NULL DEFAULT 1,
 first_seen DATETIME NOT NULL, last_seen DATETIME NOT NULL,
 acknowledged_at DATETIME, acknowledged_by TEXT, resolved_at DATETIME);
 CREATE UNIQUE INDEX IF NOT EXISTS alerts_live ON alerts(rule, key) WHERE status<>'resolved';
 CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, last_seen DESC, id DESC);
 CREATE TABLE IF NOT EXISTS alert_queue (
 event_id TEXT PRIMARY KEY REFERENCES audit_events(id) ON DELETE CASCADE,
 created_at DATETIME NOT NULL);
 CREATE INDEX IF NOT EXISTS idx_alert_queue_order ON alert_queue(created_at, event_id);
 CREATE TRIGGER IF NOT EXISTS audit_events_alert_queue AFTER INSERT ON audit_events
 BEGIN INSERT INTO alert_queue(event_id, created_at) VALUES (NEW.id, NEW.created_at); END;
 CREATE TABLE IF NOT EXISTS alert_deliveries (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 alert_id TEXT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL, kind TEXT NOT NULL CHECK (kind IN ('opened','resolved')),
 status TEXT NOT NULL CHECK (status IN ('pending','delivered','failed','skipped')),
 attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at DATETIME NOT NULL,
 last_error TEXT NOT NULL DEFAULT '', delivered_at DATETIME,
 created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL);
 CREATE INDEX IF NOT EXISTS idx_alert_deliveries_due ON alert_deliveries(status, next_attempt_at)`)
	return err
}

func (s *Store) AlertSettings() (AlertSettings, error) {
	out := AlertSettings{LoginFailureThreshold: 10, LoginFailureWindowSeconds: 600, Recipients: []string{}}
	raw, err := s.GetSetting(alertSettingsKey)
	if errors.Is(err, ErrNotFound) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return out, err
	}
	if out.Recipients == nil {
		out.Recipients = []string{}
	}
	return out, nil
}

// alertReaderSQL is true for an account that may read alerts right now: an active,
// unended administrator or auditor.
const alertReaderSQL = `status='active' AND (ends_at IS NULL OR ends_at>unixepoch()) AND (role='admin' OR EXISTS (SELECT 1 FROM admin_delegations d WHERE d.user_id=users.id AND d.kind='auditor'))`

func alertReaderTx(tx *sql.Tx, userID string) (email string, ok bool, err error) {
	err = tx.QueryRow(`SELECT email, `+alertReaderSQL+` FROM users WHERE id=?`, userID).Scan(&email, &ok)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return email, ok && email != "", err
}

func (s *Store) SetAlertSettings(a AlertSettings, audit *AuditEvent) error {
	if a.LoginFailureThreshold < 1 || a.LoginFailureThreshold > 1000 || a.LoginFailureWindowSeconds < 60 || a.LoginFailureWindowSeconds > 86400 {
		return ErrAlertSettings
	}
	seen, recipients := map[string]bool{}, []string{}
	for _, id := range a.Recipients {
		if !seen[id] {
			seen[id], recipients = true, append(recipients, id)
		}
	}
	a.Recipients = recipients
	return s.auditedTx(audit, func(tx *sql.Tx) error {
		for _, id := range a.Recipients {
			if _, ok, err := alertReaderTx(tx, id); err != nil {
				return err
			} else if !ok {
				return ErrAlertRecipient
			}
		}
		raw, err := json.Marshal(a)
		if err != nil {
			return err
		}
		_, err = tx.Exec(`INSERT INTO system_settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
 ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP`, alertSettingsKey, string(raw))
		return err
	})
}

// alertText makes untrusted names safe as display and header text: control characters
// out, length bounded.
func alertText(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > 120 {
		s = string(r[:120])
	}
	return s
}

type queuedEvent struct {
	id, actor, action, target, targetType, ip, outcome string
	created                                            time.Time
	details                                            map[string]any
}

func (e queuedEvent) detail(key string) string {
	switch v := e.details[key].(type) {
	case string:
		return v
	case bool:
		if v {
			return "true"
		}
	}
	return ""
}

type alertSpec struct {
	rule, key, severity, title, summary string
	count                               int
}

// EvaluateAlerts applies the rules to the audit events queued since the last pass (a
// bounded number of batches; the rest wait for the next pass) and to the connectors'
// current state. Safe to run at any cadence.
func (s *Store) EvaluateAlerts(now time.Time) error {
	settings, err := s.AlertSettings()
	if err != nil {
		return err
	}
	if err := s.resolveQuietLoginAlerts(now, settings); err != nil {
		return err
	}
	for i := 0; i < alertMaxBatches; i++ {
		n, err := s.evaluateBatch(now, settings)
		if err != nil {
			return err
		}
		if n < alertBatch {
			break
		}
	}
	return s.evaluateOutages(now, settings)
}

// resolveQuietLoginAlerts closes login alerts whose source has recorded no failure for
// a whole window, so retention can reclaim them and a later burst opens a fresh alert.
// Resolution is not mailed: a quiet attacker is not news.
func (s *Store) resolveQuietLoginAlerts(now time.Time, settings AlertSettings) error {
	since := now.Add(-time.Duration(settings.LoginFailureWindowSeconds) * time.Second)
	_, err := s.db.Exec(`UPDATE alerts SET status='resolved', resolved_at=?, last_seen=? WHERE rule='login_failures' AND status<>'resolved'
 AND NOT EXISTS (SELECT 1 FROM audit_events e WHERE e.action='auth.login' AND e.outcome<>'success' AND e.created_at>?
 AND (alerts.key='many-sources' OR e.target_id=alerts.key OR e.ip_address=alerts.key))`, now, now, since)
	return err
}

func (s *Store) evaluateBatch(now time.Time, settings AlertSettings) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT e.id, e.actor_username, e.action, COALESCE(e.target_id,''), COALESCE(e.target_type,''), e.ip_address, e.outcome, COALESCE(e.details_json,''), e.created_at
 FROM alert_queue q JOIN audit_events e ON e.id=q.event_id ORDER BY q.created_at, q.event_id LIMIT ?`, alertBatch)
	if err != nil {
		return 0, err
	}
	var events []queuedEvent
	for rows.Next() {
		var e queuedEvent
		var actor, details sql.NullString
		if err := rows.Scan(&e.id, &actor, &e.action, &e.target, &e.targetType, &e.ip, &e.outcome, &details, &e.created); err != nil {
			rows.Close()
			return 0, err
		}
		e.actor = actor.String
		if details.String != "" {
			_ = json.Unmarshal([]byte(details.String), &e.details)
		}
		events = append(events, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, e := range events {
		spec, err := classifyTx(tx, e, settings, now)
		if err != nil {
			return 0, err
		}
		if spec.rule != "" {
			if err := raiseAlertTx(tx, now, spec, settings.Recipients); err != nil {
				return 0, err
			}
		}
		if _, err := tx.Exec(`DELETE FROM alert_queue WHERE event_id=?`, e.id); err != nil {
			return 0, err
		}
	}
	// Queue rows whose event was trimmed by retention have nothing left to evaluate.
	if _, err := tx.Exec(`DELETE FROM alert_queue WHERE event_id NOT IN (SELECT id FROM audit_events)`); err != nil {
		return 0, err
	}
	return len(events), tx.Commit()
}

func nameTx(tx *sql.Tx, table, id string) string {
	col := "name"
	if table == "users" {
		col = "username"
	} else if table == "oauth_clients" {
		col = "client_name"
	}
	var name string
	if err := tx.QueryRow(`SELECT `+col+` FROM `+table+` WHERE id=?`, id).Scan(&name); err != nil || name == "" {
		return id
	}
	return name
}

func classifyTx(tx *sql.Tx, e queuedEvent, settings AlertSettings, now time.Time) (alertSpec, error) {
	success := e.outcome == "success"
	user := func() string {
		if e.target != "" {
			return alertText(nameTx(tx, "users", e.target))
		}
		return alertText(e.detail("username"))
	}
	switch e.action {
	case "admin.user_created":
		if success && e.detail("role") == "admin" {
			return alertSpec{"privilege_change", e.target, "critical", "Privileges changed for " + user(), alertText(e.actor) + " created " + user() + " as an administrator.", 1}, nil
		}
	case "admin.user_updated":
		if success && e.detail("roleChanged") == "true" {
			return alertSpec{"privilege_change", e.target, "critical", "Privileges changed for " + user(), alertText(e.actor) + " changed the role of " + user() + " to " + alertText(e.detail("role")) + ".", 1}, nil
		}
	case "admin.delegations_updated":
		if success {
			return alertSpec{"privilege_change", e.target, "critical", "Privileges changed for " + user(), alertText(e.actor) + " changed the delegated administration of " + user() + ".", 1}, nil
		}
	case "auth.mfa_recovery_consumed":
		if success {
			return alertSpec{"recovery_use", e.target, "warning", "Recovery used for " + user(), "A recovery code was used to sign in as " + user() + ".", 1}, nil
		}
	case "admin.user_mfa_reset":
		if success {
			return alertSpec{"recovery_use", e.target, "warning", "Recovery used for " + user(), alertText(e.actor) + " reset the second factor of " + user() + ".", 1}, nil
		}
	case "auth.password_reset":
		if success {
			return alertSpec{"recovery_use", e.target, "warning", "Recovery used for " + user(), "A password reset link was redeemed for " + user() + ".", 1}, nil
		}
	case "admin.scim_token_issued", "admin.scim_token_revoked":
		if success {
			name := alertText(nameTx(tx, "scim_connectors", e.target))
			return alertSpec{"connector_credentials", e.target, "critical", "Connector credentials changed: " + name, alertText(e.actor) + " changed the inbound SCIM credentials of " + name + ".", 1}, nil
		}
	case "admin.system_created", "admin.system_configured":
		if success && (e.action == "admin.system_created" || e.detail("credentialRotated") == "true") {
			name := alertText(nameTx(tx, "paired_systems", e.target))
			return alertSpec{"connector_credentials", e.target, "critical", "Connector credentials changed: " + name, alertText(e.actor) + " changed the outbound credentials of " + name + ".", 1}, nil
		}
	case "admin.mail_configured":
		if success {
			return alertSpec{"connector_credentials", "mail", "critical", "Connector credentials changed: mail relay", alertText(e.actor) + " changed the mail relay settings.", 1}, nil
		}
	case "auth.login":
		if success {
			return alertSpec{}, nil
		}
		// The key is never the submitted name: a known account keys by its id, anything
		// else by source address, so an attacker cannot mint alerts by cycling names.
		by, val, key, subject := "target_id", e.target, e.target, "for "+user()
		if e.target == "" {
			by, val, key = "ip_address", e.ip, alertText(e.ip)
			if key == "" {
				key = "unknown-source"
			}
			subject = "from " + key
		}
		var n int
		since := now.Add(-time.Duration(settings.LoginFailureWindowSeconds) * time.Second)
		// Only failures up to this one count, so a batch evaluated together opens the
		// alert once at the threshold and folds the rest in one at a time.
		if err := tx.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action='auth.login' AND outcome<>'success' AND `+by+`=? AND created_at>? AND (created_at<? OR (created_at=? AND id<=?))`, val, since, e.created, e.created, e.id).Scan(&n); err != nil {
			return alertSpec{}, err
		}
		if n < settings.LoginFailureThreshold {
			return alertSpec{}, nil
		}
		spec := alertSpec{"login_failures", key, "warning", "Repeated login failures " + subject, fmt.Sprintf("%d failed sign-ins %s within %d minutes.", n, subject, settings.LoginFailureWindowSeconds/60), n}
		// Past the ceiling of live login alerts, a source without one of its own folds
		// into one shared alert instead of opening its own and mailing everyone again.
		var live, total int
		if err := tx.QueryRow(`SELECT (SELECT COUNT(*) FROM alerts WHERE rule='login_failures' AND key=? AND status<>'resolved'), (SELECT COUNT(*) FROM alerts WHERE rule='login_failures' AND key<>'many-sources' AND status<>'resolved')`, key).Scan(&live, &total); err != nil {
			return alertSpec{}, err
		}
		if live == 0 && total >= loginAlertCeiling {
			spec = alertSpec{"login_failures", "many-sources", "warning", "Repeated login failures from many sources", fmt.Sprintf("Failed sign-ins are arriving from more than %d accounts or addresses within %d minutes; sources past that share this alert.", loginAlertCeiling, settings.LoginFailureWindowSeconds/60), 1}
		}
		return spec, nil
	case "account.end_failed", "group.membership_expiry_failed", "app.assignment_expiry_failed", "access.expiry_reconcile_failed":
		key := e.target
		if key == "" {
			key = "directory"
		}
		table := map[string]string{"user": "users", "group": "groups", "application": "app_registry"}[e.targetType]
		what := "the directory"
		if table != "" {
			what = e.targetType + " " + alertText(nameTx(tx, table, e.target))
		}
		return alertSpec{"access_removal_failed", key, "critical", "Scheduled access removal failed", "Removing expired access for " + what + " failed; the access may still be live.", 1}, nil
	case "account.end_refused":
		return alertSpec{"access_removal_failed", e.target, "critical", "Account end refused for " + user(), "The scheduled end of " + user() + " was refused because it is the last active administrator.", 1}, nil
	}
	return alertSpec{}, nil
}

// raiseAlertTx folds the occurrence into the live alert for its rule and key, or opens
// one. An acknowledged alert reopens and is mailed again; an open one only counts.
func raiseAlertTx(tx *sql.Tx, now time.Time, spec alertSpec, recipients []string) error {
	var id, status string
	err := tx.QueryRow(`SELECT id, status FROM alerts WHERE rule=? AND key=? AND status<>'resolved'`, spec.rule, spec.key).Scan(&id, &status)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		id = uuid.NewString()
		if _, err := tx.Exec(`INSERT INTO alerts(id,rule,key,severity,title,summary,status,count,first_seen,last_seen) VALUES(?,?,?,?,?,?,'open',?,?,?)`,
			id, spec.rule, spec.key, spec.severity, spec.title, spec.summary, spec.count, now, now); err != nil {
			return err
		}
		// Login failures are the one rule an unauthenticated client drives, so their
		// mail is capped per rule, not per key: one mailing per cooldown, the rest of
		// the alerts open on the page only.
		if spec.rule == "login_failures" {
			var recent int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM alert_deliveries d JOIN alerts a ON a.id=d.alert_id WHERE a.rule=? AND d.created_at>?`, spec.rule, now.Add(-loginAlertCooldown)).Scan(&recent); err != nil {
				return err
			}
			if recent > 0 {
				return nil
			}
		}
		return queueDeliveriesTx(tx, now, id, "opened", recipients)
	case err != nil:
		return err
	}
	if _, err := tx.Exec(`UPDATE alerts SET count=count+1, last_seen=?, summary=?, status='open', acknowledged_at=NULL, acknowledged_by=NULL WHERE id=?`, now, spec.summary, id); err != nil {
		return err
	}
	if status == "acknowledged" {
		return queueDeliveriesTx(tx, now, id, "opened", recipients)
	}
	return nil
}

func queueDeliveriesTx(tx *sql.Tx, now time.Time, alertID, kind string, recipients []string) error {
	for _, r := range recipients {
		if _, err := tx.Exec(`INSERT INTO alert_deliveries(alert_id,user_id,kind,status,next_attempt_at,created_at,updated_at) VALUES(?,?,?,'pending',?,?,?)`, alertID, r, kind, now, now, now); err != nil {
			return err
		}
	}
	return nil
}

// evaluateOutages keeps one alert per connector that is failing right now, resolves it
// when the connector delivers again, and opens a fresh one if it fails later, so an
// acknowledged outage never hides a new one.
func (s *Store) evaluateOutages(now time.Time, settings AlertSettings) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	type outage struct{ rule, key, title, summary string }
	var live []outage
	rows, err := tx.Query(`SELECT id, name FROM paired_systems s WHERE status<>'disabled' AND (status='failing' OR EXISTS (SELECT 1 FROM account_sync_events e WHERE e.system_id=s.id AND e.status='failed'))`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			rows.Close()
			return err
		}
		name = alertText(name)
		live = append(live, outage{"provisioning_outage", id, "Provisioning failing: " + name, "Deliveries to " + name + " are failing or have been given up; accounts there may be out of date."})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	rows, err = tx.Query(`SELECT DISTINCT c.id, c.client_name FROM logout_deliveries d JOIN oauth_clients c ON c.id=d.client_id WHERE d.status='failed'`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			rows.Close()
			return err
		}
		name = alertText(name)
		live = append(live, outage{"logout_outage", id, "Logout delivery failing: " + name, "Back-channel logouts to " + name + " have been given up; sessions there may outlive the sign-out."})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, o := range live {
		keep[o.rule+"/"+o.key] = true
		var id string
		err := tx.QueryRow(`SELECT id FROM alerts WHERE rule=? AND key=? AND status<>'resolved'`, o.rule, o.key).Scan(&id)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			id = uuid.NewString()
			if _, err := tx.Exec(`INSERT INTO alerts(id,rule,key,severity,title,summary,status,count,first_seen,last_seen) VALUES(?,?,?,'critical',?,?,'open',1,?,?)`, id, o.rule, o.key, o.title, o.summary, now, now); err != nil {
				return err
			}
			if err := queueDeliveriesTx(tx, now, id, "opened", settings.Recipients); err != nil {
				return err
			}
		case err != nil:
			return err
		default:
			if _, err := tx.Exec(`UPDATE alerts SET last_seen=? WHERE id=?`, now, id); err != nil {
				return err
			}
		}
	}
	rows, err = tx.Query(`SELECT id, rule, key FROM alerts WHERE rule IN ('provisioning_outage','logout_outage') AND status<>'resolved'`)
	if err != nil {
		return err
	}
	var resolved []string
	for rows.Next() {
		var id, rule, key string
		if err := rows.Scan(&id, &rule, &key); err != nil {
			rows.Close()
			return err
		}
		if !keep[rule+"/"+key] {
			resolved = append(resolved, id)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range resolved {
		if _, err := tx.Exec(`UPDATE alerts SET status='resolved', resolved_at=?, last_seen=? WHERE id=?`, now, now, id); err != nil {
			return err
		}
		if err := queueDeliveriesTx(tx, now, id, "resolved", settings.Recipients); err != nil {
			return err
		}
	}
	return tx.Commit()
}

const alertSelect = `SELECT a.id, a.rule, a.key, a.severity, a.title, a.summary, a.status, a.count, a.first_seen, a.last_seen, a.acknowledged_at, COALESCE(a.acknowledged_by,''), a.resolved_at,
 (SELECT COUNT(*) FROM alert_deliveries d WHERE d.alert_id=a.id AND d.status='pending'),
 (SELECT COUNT(*) FROM alert_deliveries d WHERE d.alert_id=a.id AND d.status='delivered'),
 (SELECT COUNT(*) FROM alert_deliveries d WHERE d.alert_id=a.id AND d.status='failed'),
 (SELECT COUNT(*) FROM alert_deliveries d WHERE d.alert_id=a.id AND d.status='skipped'),
 COALESCE((SELECT last_error FROM alert_deliveries d WHERE d.alert_id=a.id AND d.last_error<>'' ORDER BY (d.status='skipped'), d.updated_at DESC, d.id DESC LIMIT 1),'')
 FROM alerts a`

func scanAlert(rows *sql.Rows) (Alert, error) {
	var a Alert
	var ack, res sql.NullTime
	err := rows.Scan(&a.ID, &a.Rule, &a.Key, &a.Severity, &a.Title, &a.Summary, &a.Status, &a.Count, &a.FirstSeen, &a.LastSeen, &ack, &a.AcknowledgedBy, &res,
		&a.Delivery.Pending, &a.Delivery.Delivered, &a.Delivery.Failed, &a.Delivery.Skipped, &a.Delivery.LastError)
	if ack.Valid {
		t := ack.Time
		a.AcknowledgedAt = &t
	}
	if res.Valid {
		t := res.Time
		a.ResolvedAt = &t
	}
	return a, err
}

// ListAlerts pages alerts newest first; status is open, acknowledged, resolved or all.
func (s *Store) ListAlerts(status string, limit, offset int) ([]Alert, int, error) {
	where, args := ` WHERE 1=1`, []any{}
	if status != "all" {
		where, args = ` WHERE a.status=?`, []any{status}
	}
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM alerts a`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(alertSelect+where+` ORDER BY a.last_seen DESC, a.id DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Alert{}
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}

func (s *Store) AcknowledgeAlert(id, actorID string, audit *AuditEvent) error {
	return s.auditedTx(audit, func(tx *sql.Tx) error {
		var status string
		if err := tx.QueryRow(`SELECT status FROM alerts WHERE id=?`, id).Scan(&status); errors.Is(err, sql.ErrNoRows) {
			return ErrAlertMissing
		} else if err != nil {
			return err
		}
		if status != "open" {
			return ErrAlertNotOpen
		}
		_, err := tx.Exec(`UPDATE alerts SET status='acknowledged', acknowledged_at=?, acknowledged_by=? WHERE id=?`, time.Now().UTC(), nameTx(tx, "users", actorID), id)
		return err
	})
}

func alertBackoff(attempts int) time.Duration {
	d := time.Minute
	for i := 1; i < attempts && d < 6*time.Hour; i++ {
		d *= 4
	}
	return min(d, 6*time.Hour)
}

// DeliverAlerts sends every due message through send, one attempt each, until ctx
// ends, and returns how many were attempted. A recipient who can no longer read alerts is skipped, a
// failed send is retried with growing delay, and a message that keeps failing is
// marked failed rather than retried forever. The message names the alert, never the
// audit details behind it.
func (s *Store) DeliverAlerts(ctx context.Context, now time.Time, send func(to, subject, body string) error) (int, error) {
	type due struct {
		id                                       int64
		userID, kind, title, summary, sev, state string
		attempts, count                          int
		first, last                              time.Time
	}
	rows, err := s.db.Query(`SELECT d.id, d.user_id, d.kind, d.attempts, a.title, a.summary, a.severity, a.status, a.count, a.first_seen, a.last_seen
 FROM alert_deliveries d JOIN alerts a ON a.id=d.alert_id WHERE d.status='pending' AND d.next_attempt_at<=? ORDER BY d.id LIMIT 50`, now)
	if err != nil {
		return 0, err
	}
	var batch []due
	for rows.Next() {
		var d due
		if err := rows.Scan(&d.id, &d.userID, &d.kind, &d.attempts, &d.title, &d.summary, &d.sev, &d.state, &d.count, &d.first, &d.last); err != nil {
			rows.Close()
			return 0, err
		}
		batch = append(batch, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	sent := 0
	for _, d := range batch {
		tx, err := s.db.Begin()
		if err != nil {
			return sent, err
		}
		email, ok, err := alertReaderTx(tx, d.userID)
		if err != nil {
			tx.Rollback()
			return sent, err
		}
		if !ok {
			_, err = tx.Exec(`UPDATE alert_deliveries SET status='skipped', last_error='recipient may no longer read alerts', updated_at=? WHERE id=?`, now, d.id)
			if err == nil {
				err = tx.Commit()
			}
			tx.Rollback()
			if err != nil {
				return sent, err
			}
			continue
		}
		tx.Rollback()
		if ctx.Err() != nil {
			// Out of budget for this pass; the rest stay pending for the next one.
			return sent, nil
		}
		subject := "KySignOn alert: " + d.title
		if d.kind == "resolved" {
			subject = "KySignOn alert resolved: " + d.title
		}
		body := fmt.Sprintf("%s\r\n\r\nSeverity: %s\r\nStatus: %s\r\nOccurrences: %d (first %s, last %s)\r\n\r\nReview it on the Alerts page of the KySignOn console. This message carries no further detail by design.\r\n",
			d.summary, d.sev, d.state, d.count, d.first.UTC().Format(time.RFC3339), d.last.UTC().Format(time.RFC3339))
		sent++
		sendErr := send(email, subject, body)
		attempts := d.attempts + 1
		switch {
		case sendErr == nil:
			_, err = s.db.Exec(`UPDATE alert_deliveries SET status='delivered', attempts=?, last_error='', delivered_at=?, updated_at=? WHERE id=?`, attempts, now, now, d.id)
		case attempts >= alertDeliveryAttempts:
			_, err = s.db.Exec(`UPDATE alert_deliveries SET status='failed', attempts=?, last_error=?, updated_at=? WHERE id=?`, attempts, alertText(sendErr.Error()), now, d.id)
		default:
			_, err = s.db.Exec(`UPDATE alert_deliveries SET attempts=?, last_error=?, next_attempt_at=?, updated_at=? WHERE id=?`, attempts, alertText(sendErr.Error()), now.Add(alertBackoff(attempts)), now, d.id)
		}
		if err != nil {
			return sent, err
		}
	}
	return sent, nil
}

// DeleteAlertsOlderThan trims resolved alerts (their deliveries cascade) and finished
// deliveries of live alerts past the cutoff. Live alerts are kept whatever their age.
func (s *Store) DeleteAlertsOlderThan(cutoff time.Time) error {
	if _, err := s.db.Exec(`DELETE FROM alerts WHERE status='resolved' AND resolved_at<?`, cutoff); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM alert_deliveries WHERE status<>'pending' AND updated_at<?`, cutoff)
	return err
}
