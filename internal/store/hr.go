package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

var ErrHRConflict = errors.New("HR source version, ownership or configuration conflict")

type HRConnection struct {
	ConnectorID     string `json:"connectorId"`
	SystemID        string `json:"systemId"`
	Domain          string `json:"domain"`
	WritebackURL    string `json:"writebackUrl"`
	WritebackSecret string `json:"-"`
	Held            bool   `json:"held"`
}

// HRInput contains only source-owned facts. Email and application roles are
// deliberately absent. SourceVersion must increase for every employee change.
type HRInput struct {
	SourceUID     string `json:"sourceUid"`
	PreferredName string `json:"preferredName"`
	DisplayName   string `json:"displayName"`
	Active        bool   `json:"active"`
	SourceVersion int64  `json:"sourceVersion"`
}

type HRWorker struct {
	HRInput
	ID          string `json:"userId"`
	ConnectorID string `json:"connectorId"`
	Email       string `json:"email"`
	State       string `json:"state"`
	Attempts    int    `json:"attempts"`
	LastError   string `json:"lastError,omitempty"`
	Lease       string `json:"-"`
}

const hrSchemaSQL = `CREATE TABLE IF NOT EXISTS hr_connections (
 connector_id TEXT PRIMARY KEY REFERENCES scim_connectors(id) ON DELETE CASCADE,
 system_id TEXT NOT NULL REFERENCES paired_systems(id), domain TEXT NOT NULL,
 writeback_url TEXT NOT NULL, writeback_secret TEXT NOT NULL,
 held BOOLEAN NOT NULL DEFAULT FALSE);
 CREATE TABLE IF NOT EXISTS hr_workers (
 id TEXT PRIMARY KEY, connector_id TEXT NOT NULL REFERENCES hr_connections(connector_id) ON DELETE CASCADE,
 source_uid TEXT NOT NULL, preferred_name TEXT NOT NULL, display_name TEXT NOT NULL,
 source_active BOOLEAN NOT NULL, source_version %[1]s NOT NULL,
 email TEXT NOT NULL DEFAULT '', state TEXT NOT NULL CHECK(state IN ('mailbox_pending','writeback_pending','complete','inactive')),
 attempts %[1]s NOT NULL DEFAULT 0, last_error TEXT NOT NULL DEFAULT '',
 next_attempt %[2]s NOT NULL, lease TEXT NOT NULL DEFAULT '', lease_until %[2]s,
 UNIQUE(connector_id,source_uid));
 CREATE INDEX IF NOT EXISTS hr_workers_due ON hr_workers(next_attempt) WHERE state IN ('mailbox_pending','writeback_pending')`

func migrateHR(tx *sql.Tx) error {
	_, err := tx.Exec(fmt.Sprintf(hrSchemaSQL, "INTEGER", "DATETIME"))
	return err
}
func migrateHRPostgres(tx *sql.Tx) error {
	_, err := tx.Exec(fmt.Sprintf(hrSchemaSQL, "BIGINT", "TIMESTAMPTZ"))
	return err
}

func (s *Store) HRConnection(id string) (*HRConnection, error) {
	c := &HRConnection{ConnectorID: id}
	err := s.db.QueryRow(`SELECT system_id,domain,writeback_url,writeback_secret,held FROM hr_connections WHERE connector_id=?`, id).Scan(&c.SystemID, &c.Domain, &c.WritebackURL, &c.WritebackSecret, &c.Held)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

// Another org's connector is ErrHRConflict, like a missing one.
func (o *OrgStore) ConfigureHR(c HRConnection, audit *AuditEvent) error {
	return o.auditedTx(audit, func(tx *sql.Tx) error {
		var valid bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM scim_connectors c,paired_systems p WHERE c.org_id=? AND c.id=? AND p.id=? AND p.system_type='kypost' AND p.status<>'disabled' AND NOT p.provisioning_hold)`, o.org, c.ConnectorID, c.SystemID).Scan(&valid); err != nil {
			return err
		}
		if !valid {
			return ErrHRConflict
		}
		var foreignUsers bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM users u WHERE u.source_connector_id=? AND NOT EXISTS(SELECT 1 FROM hr_workers w WHERE w.id=u.id AND w.connector_id=u.source_connector_id))`, c.ConnectorID).Scan(&foreignUsers); err != nil {
			return err
		}
		if foreignUsers {
			return ErrHRConflict
		}
		var foreignGroups bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM directory_groups WHERE source_connector_id=?)`, c.ConnectorID).Scan(&foreignGroups); err != nil {
			return err
		}
		if foreignGroups {
			return ErrHRConflict
		}
		// Once workers exist, destination identity and domain are immutable.
		// Credential rotation and writeback endpoint changes require quiescence.
		var busy bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM hr_workers w JOIN hr_connections h ON h.connector_id=w.connector_id WHERE w.connector_id=? AND ((h.system_id<>? OR h.domain<>?) OR (w.lease<>'' AND w.lease_until>?)))`, c.ConnectorID, c.SystemID, c.Domain, time.Now().UTC()).Scan(&busy); err != nil {
			return err
		}
		if busy {
			return ErrHRConflict
		}
		_, err := tx.Exec(`INSERT INTO hr_connections(connector_id,system_id,domain,writeback_url,writeback_secret) VALUES(?,?,?,?,?) ON CONFLICT(connector_id) DO UPDATE SET system_id=excluded.system_id,domain=excluded.domain,writeback_url=excluded.writeback_url,writeback_secret=excluded.writeback_secret,held=FALSE`, c.ConnectorID, c.SystemID, c.Domain, c.WritebackURL, c.WritebackSecret)
		return err
	})
}

const hrWorkerColumns = `id,connector_id,source_uid,preferred_name,display_name,source_active,source_version,email,state,attempts,last_error,lease`

func scanHR(row interface{ Scan(...any) error }) (*HRWorker, error) {
	w := &HRWorker{}
	err := row.Scan(&w.ID, &w.ConnectorID, &w.SourceUID, &w.PreferredName, &w.DisplayName, &w.Active, &w.SourceVersion, &w.Email, &w.State, &w.Attempts, &w.LastError, &w.Lease)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return w, err
}

func (s *Store) HRWorker(connectorID, sourceUID string) (*HRWorker, error) {
	return scanHR(s.db.QueryRow(`SELECT `+hrWorkerColumns+` FROM hr_workers WHERE connector_id=? AND source_uid=?`, connectorID, sourceUID))
}

func ValidateHRInput(in HRInput) error {
	if in.SourceUID == "" || len(in.SourceUID) > 256 || strings.TrimSpace(in.SourceUID) != in.SourceUID || in.SourceVersion < 1 || in.SourceVersion > 1<<53-1 || len(in.DisplayName) > 256 || in.PreferredName == "" || len(in.PreferredName) > 48 || strings.Trim(in.PreferredName, ".") != in.PreferredName || strings.Contains(in.PreferredName, "..") {
		return ErrHRConflict
	}
	for _, r := range in.SourceUID + in.DisplayName {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ErrHRConflict
		}
	}
	for _, r := range in.PreferredName {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return ErrHRConflict
		}
	}
	return nil
}

// ImportHR stages the worker before allocating mail. Missing employees are never
// interpreted as departures; deactivation requires an explicit newer source fact.
func (s *Store) ImportHR(connectorID string, in HRInput, audit *AuditEvent) (*HRWorker, error) {
	if err := ValidateHRInput(in); err != nil {
		return nil, err
	}
	var w *HRWorker
	err := s.auditedTx(audit, func(tx *sql.Tx) error {
		var allowed bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM hr_connections h JOIN scim_connectors c ON c.id=h.connector_id WHERE c.id=? AND c.status='active' AND NOT h.held)`, connectorID).Scan(&allowed); err != nil {
			return err
		}
		if !allowed {
			return ErrHRConflict
		}
		old, err := scanHR(tx.QueryRow(`SELECT `+hrWorkerColumns+` FROM hr_workers WHERE connector_id=? AND source_uid=?`, connectorID, in.SourceUID))
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		now := time.Now().UTC()
		if old != nil {
			if in.SourceVersion < old.SourceVersion || in.SourceVersion == old.SourceVersion && in != old.HRInput || in.PreferredName != old.PreferredName {
				return ErrHRConflict
			}
			if in.SourceVersion == old.SourceVersion {
				w = old
				if audit != nil {
					audit.TargetID = w.ID
				}
				return nil
			}
			w = old
			w.HRInput = in
			if old.Email != "" {
				if err := updateHRUserTx(tx, w); err != nil {
					return err
				}
			}
		} else {
			w = &HRWorker{HRInput: in, ID: uuid.NewString(), ConnectorID: connectorID}
		}
		w.State = "mailbox_pending"
		if w.Email != "" {
			w.State = "writeback_pending"
		}
		if !in.Active {
			w.State = "inactive"
		}
		if audit != nil {
			audit.TargetID = w.ID
		}
		_, err = tx.Exec(`INSERT INTO hr_workers(id,connector_id,source_uid,preferred_name,display_name,source_active,source_version,state,next_attempt) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(connector_id,source_uid) DO UPDATE SET display_name=excluded.display_name,source_active=excluded.source_active,source_version=excluded.source_version,state=excluded.state,attempts=0,last_error='',next_attempt=excluded.next_attempt`, w.ID, connectorID, in.SourceUID, in.PreferredName, in.DisplayName, in.Active, in.SourceVersion, w.State, now)
		return err
	})
	return w, err
}

func updateHRUserTx(tx *sql.Tx, w *HRWorker) error {
	org, err := connectorOrgTx(tx, w.ConnectorID)
	if err != nil {
		return err
	}
	_, err = updateUserTx(tx, org, w.ID, nil, func(_ *sql.Tx, u *User) (bool, error) {
		if u.SourceConnectorID != w.ConnectorID || u.ExternalID != w.SourceUID || u.Email != w.Email {
			return false, ErrHRConflict
		}
		u.DisplayName = w.DisplayName
		u.SourceActive = w.Active
		return false, nil
	})
	return err
}

// ClaimHR owns one durable job for a bounded network pass. Receiver operations
// are idempotent assignments, so recovery from a lost response never creates twice.
func (s *Store) ClaimHR() (*HRWorker, error) {
	now := time.Now().UTC()
	return scanHR(s.db.QueryRow(`UPDATE hr_workers SET lease=?,lease_until=? WHERE id=(SELECT w.id FROM hr_workers w JOIN hr_connections h ON h.connector_id=w.connector_id JOIN scim_connectors c ON c.id=w.connector_id JOIN paired_systems p ON p.id=h.system_id WHERE w.state IN ('mailbox_pending','writeback_pending') AND w.next_attempt<=? AND (w.lease='' OR w.lease_until<=?) AND c.status='active' AND NOT h.held AND p.status<>'disabled' AND NOT p.provisioning_hold ORDER BY w.next_attempt,w.id LIMIT 1) RETURNING `+hrWorkerColumns, uuid.NewString(), now.Add(time.Minute), now, now))
}

func hrAudit(w *HRWorker, action, outcome string) *AuditEvent {
	return &AuditEvent{ID: uuid.NewString(), ActorID: w.ConnectorID, ActorUsername: "hr-connector", Action: action, TargetID: w.ID, TargetType: "user", Outcome: outcome, DetailsJSON: `{}`, CreatedAt: time.Now().UTC()}
}

// FinishHR saves the exact claimed stage only while its source version remains
// current. It creates the identity after KyPost confirmed the assigned address.
func (s *Store) FinishHR(w *HRWorker, email, safeError string) error {
	return s.auditedTx(nil, func(tx *sql.Tx) error {
		current, err := scanHR(tx.QueryRow(`SELECT `+hrWorkerColumns+` FROM hr_workers WHERE id=? AND lease=?`, w.ID, w.Lease))
		if err != nil {
			return err
		}
		if current.SourceVersion != w.SourceVersion {
			_, err = tx.Exec(`UPDATE hr_workers SET lease='',lease_until=NULL WHERE id=? AND lease=?`, w.ID, w.Lease)
			return err
		}
		var live bool
		if err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM hr_connections h JOIN scim_connectors c ON c.id=h.connector_id JOIN paired_systems p ON p.id=h.system_id WHERE c.id=? AND c.status='active' AND NOT h.held AND p.status<>'disabled' AND NOT p.provisioning_hold)`, w.ConnectorID).Scan(&live); err != nil {
			return err
		}
		if !live {
			return ErrHRConflict
		}
		now := time.Now().UTC()
		next := now
		state := w.State
		attempts := 0
		if safeError != "" {
			attempts = w.Attempts + 1
			next = now.Add(time.Duration(1<<min(attempts, 10)) * time.Second)
		} else if w.State == "mailbox_pending" {
			if email == "" {
				return ErrHRConflict
			}
			if err = rejectCrossIdentityTx(tx, w.ID, email, email); err != nil {
				return err
			}
			var org string
			if org, err = connectorOrgTx(tx, w.ConnectorID); err != nil {
				return err
			}
			_, err = tx.Exec(`INSERT INTO users(org_id,id,username,display_name,email,password_hash,role,status,pending,source_connector_id,external_id,source_active,locally_disabled,created_at,updated_at) VALUES(?,?,?,?,?,'','user','disabled',TRUE,?,?,?,FALSE,?,?)`, org, w.ID, email, w.DisplayName, email, w.ConnectorID, w.SourceUID, w.Active, now, now)
			if err != nil {
				return err
			}
			state = "writeback_pending"
		} else {
			state = "complete"
			email = w.Email
		}
		if safeError != "" {
			email = w.Email
		}
		_, err = tx.Exec(`UPDATE hr_workers SET email=?,state=?,attempts=?,last_error=?,next_attempt=?,lease='',lease_until=NULL WHERE id=? AND lease=?`, email, state, attempts, safeError, next, w.ID, w.Lease)
		if err != nil {
			return err
		}
		action := "hr." + w.State
		outcome := "success"
		if safeError != "" {
			outcome = "failure"
		}
		return recordAuditTx(tx, hrAudit(w, action, outcome))
	})
}

func (s *Store) ListHRWorkers(id string, offset int) ([]HRWorker, error) {
	rows, err := s.db.Query(`SELECT `+hrWorkerColumns+` FROM hr_workers WHERE connector_id=? ORDER BY id LIMIT 100 OFFSET ?`, id, max(offset, 0))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []HRWorker{}
	for rows.Next() {
		w, err := scanHR(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, *w)
	}
	return list, rows.Err()
}

// Keep HR-owned fields out of the SCIM write path; only versioned HR imports
// can change them. Connector tokens may still read resources for reconciliation.
func (s *Store) IsHRConnector(id string) (bool, error) {
	var exists bool
	err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM hr_connections WHERE connector_id=?)`, id).Scan(&exists)
	return exists, err
}

// Authorization can precede an administrator converting an empty connector to
// HR. Enforce source ownership under the mutation writer lock as well.
func requireSCIMSourceTx(tx *sql.Tx, id string) error {
	var hr bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM hr_connections WHERE connector_id=?)`, id).Scan(&hr); err != nil {
		return err
	}
	if hr {
		return ErrHRConflict
	}
	return nil
}
