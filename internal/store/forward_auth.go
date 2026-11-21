package store

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Forward-auth (docs/FORWARD-AUTH.md): a proxy app is a launcher card plus a proxy_apps
// row. Codes and forward sessions are stored only as SHA-256 hashes; times are unix seconds.

const forwardAuthSQL = `CREATE TABLE IF NOT EXISTS proxy_apps (
 application_id TEXT PRIMARY KEY REFERENCES applications(id) ON DELETE CASCADE,
 host TEXT NOT NULL UNIQUE, secret_hash TEXT NOT NULL, login_header TEXT NOT NULL,
 bypass_json TEXT NOT NULL DEFAULT '[]', session_seconds %[1]s NOT NULL, created_at %[1]s NOT NULL);
CREATE TABLE IF NOT EXISTS forward_codes (
 hash TEXT PRIMARY KEY,
 application_id TEXT NOT NULL REFERENCES proxy_apps(application_id) ON DELETE CASCADE,
 host TEXT NOT NULL, session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 nonce_hash TEXT NOT NULL, path TEXT NOT NULL, expires_at %[1]s NOT NULL);
CREATE TABLE IF NOT EXISTS forward_sessions (
 hash TEXT PRIMARY KEY,
 application_id TEXT NOT NULL REFERENCES proxy_apps(application_id) ON DELETE CASCADE,
 host TEXT NOT NULL, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 session_id TEXT NOT NULL, primary_at %[1]s, factor_at %[1]s, factor_method TEXT NOT NULL DEFAULT '',
 created_at %[1]s NOT NULL, expires_at %[1]s NOT NULL);
CREATE INDEX IF NOT EXISTS forward_codes_session ON forward_codes(session_id);
CREATE INDEX IF NOT EXISTS forward_codes_user ON forward_codes(user_id);
CREATE INDEX IF NOT EXISTS forward_sessions_session ON forward_sessions(session_id);
CREATE INDEX IF NOT EXISTS forward_sessions_user ON forward_sessions(user_id);
CREATE INDEX IF NOT EXISTS forward_sessions_app ON forward_sessions(application_id)`

func migrateForwardAuth(tx *sql.Tx) error {
	_, err := tx.Exec(fmt.Sprintf(forwardAuthSQL, "INTEGER"))
	return err
}

func migrateForwardAuthPostgres(tx *sql.Tx) error {
	_, err := tx.Exec(fmt.Sprintf(forwardAuthSQL, "BIGINT"))
	return err
}

const (
	ForwardCodeTTL        = 60 * time.Second
	DefaultForwardSession = 12 * 60 * 60
	MinForwardSession     = 5 * 60
	MaxForwardSession     = 7 * 24 * 60 * 60
)

var (
	ErrForwardCode   = errors.New("forward code invalid, spent, expired or not bound to this browser")
	ErrForwardDenied = errors.New("forward sign-in not permitted")
	ErrProxyHostUsed = InputError("another proxy app already uses this host")
)

type ProxyApp struct {
	ID             string   `json:"id"` // the launcher card (applications.id)
	AppID          string   `json:"appId"`
	Name           string   `json:"name"`
	Host           string   `json:"host"`
	LoginHeader    string   `json:"loginHeader"`
	Bypass         []string `json:"bypass"`
	SessionSeconds int64    `json:"sessionSeconds"`
	SecretHash     string   `json:"-"`
}

const proxyAppSelect = `SELECT p.application_id,a.id,l.name,p.host,p.login_header,p.bypass_json,p.session_seconds,p.secret_hash
 FROM proxy_apps p JOIN applications l ON l.id=p.application_id JOIN app_registry a ON a.launcher_id=p.application_id`

func scanProxyApp(row interface{ Scan(...any) error }) (*ProxyApp, error) {
	p := &ProxyApp{}
	var bypass string
	if err := row.Scan(&p.ID, &p.AppID, &p.Name, &p.Host, &p.LoginHeader, &bypass, &p.SessionSeconds, &p.SecretHash); err != nil {
		return nil, err
	}
	return p, json.Unmarshal([]byte(bypass), &p.Bypass)
}

// ProxyAppByHost returns the proxy app for an exact host, or nil.
func (s *Store) ProxyAppByHost(host string) (*ProxyApp, error) {
	p, err := scanProxyApp(s.db.QueryRow(proxyAppSelect+` WHERE p.host=?`, host))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return p, err
}

func (s *Store) ListProxyApps() ([]ProxyApp, error) {
	rows, err := s.db.Query(proxyAppSelect + ` ORDER BY p.host`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ProxyApp{}
	for rows.Next() {
		p, err := scanProxyApp(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

func hostTaken(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unique")
}

// CreateProxyApp adds the launcher card and its proxy row. The app requires MFA by default.
func (s *Store) CreateProxyApp(card *Application, p *ProxyApp, audit *AuditEvent) error {
	return s.auditedTx(audit, func(tx *sql.Tx) error { return createProxyAppTx(tx, card, p) })
}

func createProxyAppTx(tx *sql.Tx, card *Application, p *ProxyApp) error {
	bypass, err := json.Marshal(p.Bypass)
	if err != nil {
		return err
	}
	card.CreatedAt = time.Now().UTC()
	if _, err := tx.Exec(`INSERT INTO applications (id, name, url, icon_name, description, sort_order, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		card.ID, card.Name, card.URL, card.IconName, card.Description, card.SortOrder, card.Enabled, card.CreatedAt); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO proxy_apps(application_id,host,secret_hash,login_header,bypass_json,session_seconds,created_at) VALUES(?,?,?,?,?,?,?)`,
		card.ID, p.Host, p.SecretHash, p.LoginHeader, string(bypass), p.SessionSeconds, card.CreatedAt.Unix()); err != nil {
		if hostTaken(err) {
			return ErrProxyHostUsed
		}
		return err
	}
	_, err = tx.Exec(`UPDATE app_registry SET auth_factor='mfa' WHERE launcher_id=?`, card.ID)
	return err
}

// UpdateProxyApp edits the edge settings. A host change ends the app's forward sessions;
// a shorter session length shortens live ones.
func (s *Store) UpdateProxyApp(p *ProxyApp, audit *AuditEvent) error {
	return s.auditedTx(audit, func(tx *sql.Tx) error { return updateProxyAppTx(tx, p) })
}

func updateProxyAppTx(tx *sql.Tx, p *ProxyApp) error {
	bypass, err := json.Marshal(p.Bypass)
	if err != nil {
		return err
	}
	var oldHost string
	if err := tx.QueryRow(`SELECT host FROM proxy_apps WHERE application_id=?`, p.ID).Scan(&oldHost); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrAppRecordMissing
		}
		return err
	}
	if _, err := tx.Exec(`UPDATE proxy_apps SET host=?,login_header=?,bypass_json=?,session_seconds=? WHERE application_id=?`,
		p.Host, p.LoginHeader, string(bypass), p.SessionSeconds, p.ID); err != nil {
		if hostTaken(err) {
			return ErrProxyHostUsed
		}
		return err
	}
	if oldHost != p.Host {
		return endForwardSessionsTx(tx, p.ID)
	}
	_, err = tx.Exec(`UPDATE forward_sessions SET expires_at=CASE WHEN expires_at>created_at+? THEN created_at+? ELSE expires_at END WHERE application_id=?`,
		p.SessionSeconds, p.SessionSeconds, p.ID)
	return err
}

// ErrProxyAppForeign refuses an installer write to a proxy app it does not own.
var ErrProxyAppForeign = errors.New("proxy app for this host is not owned by this installer")

// EnsureInstallerProxyApp makes the installer-owned proxy app for p.Host match p. It
// creates the app, with secretHash, only when none exists, and replaces the secret only
// when rotate is set; a rerun otherwise keeps the one secret. It reports "created",
// "updated" or "unchanged", the card ID, and whether secretHash was stored.
func (s *Store) EnsureInstallerProxyApp(owner, name string, p *ProxyApp, secretHash string, rotate bool, audit *AuditEvent) (string, string, bool, error) {
	setupID := "proxy-app:" + owner
	status, id, stored := "", "", false
	err := s.inTx(func(tx *sql.Tx) error {
		var ownedBy, ownedID string
		err := tx.QueryRow(`SELECT setup_id,object_id FROM installer_setup_resources WHERE kind='proxy_app' AND name=?`, p.Host).Scan(&ownedBy, &ownedID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if ownedBy != "" && ownedBy != setupID {
			return ErrProxyAppForeign
		}
		current, err := scanProxyApp(tx.QueryRow(proxyAppSelect+` WHERE p.host=?`, p.Host))
		if errors.Is(err, sql.ErrNoRows) {
			card := &Application{ID: uuid.NewString(), Name: name, URL: "https://" + p.Host + "/", IconName: "favicon", Enabled: true}
			p.ID, p.SecretHash = card.ID, secretHash
			if err := createProxyAppTx(tx, card, p); err != nil {
				return err
			}
			if _, err := tx.Exec(`DELETE FROM installer_setup_resources WHERE kind='proxy_app' AND name=?`, p.Host); err != nil {
				return err
			}
			if _, err := tx.Exec(`INSERT INTO installer_setup_resources(kind,name,setup_id,object_id,contract) VALUES('proxy_app',?,?,?,'')`, p.Host, setupID, card.ID); err != nil {
				return err
			}
			status, id, stored = "created", card.ID, true
			return installerProxyAuditTx(tx, audit, p.Host, id, status, stored)
		}
		if err != nil {
			return err
		}
		if ownedID != current.ID {
			return ErrProxyAppForeign
		}
		p.ID, id, status = current.ID, current.ID, "unchanged"
		if current.LoginHeader != p.LoginHeader || current.SessionSeconds != p.SessionSeconds || !slices.Equal(current.Bypass, p.Bypass) {
			if err := updateProxyAppTx(tx, p); err != nil {
				return err
			}
			status = "updated"
		}
		if rotate {
			if _, err := tx.Exec(`UPDATE proxy_apps SET secret_hash=? WHERE application_id=?`, secretHash, current.ID); err != nil {
				return err
			}
			status, stored = "updated", true
		}
		if status == "unchanged" {
			return nil
		}
		return installerProxyAuditTx(tx, audit, p.Host, id, status, stored)
	})
	return status, id, stored, err
}

func installerProxyAuditTx(tx *sql.Tx, audit *AuditEvent, host, id, status string, secret bool) error {
	if audit == nil {
		return nil
	}
	details, err := json.Marshal(map[string]any{"host": host, "status": status, "secretIssued": secret})
	if err != nil {
		return err
	}
	audit.TargetID, audit.DetailsJSON = id, string(details)
	return recordAuditTx(tx, audit)
}

// RotateProxySecret replaces the edge secret hash.
func (s *Store) RotateProxySecret(id, secretHash string, audit *AuditEvent) error {
	return s.auditedTx(audit, func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE proxy_apps SET secret_hash=? WHERE application_id=?`, secretHash, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrAppRecordMissing
		}
		return nil
	})
}

func endForwardSessionsTx(tx *sql.Tx, appID string) error {
	if _, err := tx.Exec(`DELETE FROM forward_codes WHERE application_id=?`, appID); err != nil {
		return err
	}
	_, err := tx.Exec(`DELETE FROM forward_sessions WHERE application_id=?`, appID)
	return err
}

// ForwardCode is minted by /forward/start for one host, login session and browser nonce.
type ForwardCode struct {
	Hash, AppID, Host, SessionID, UserID, NonceHash, Path string
}

func (s *Store) CreateForwardCode(c *ForwardCode, audit *AuditEvent) error {
	return s.auditedTx(audit, func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO forward_codes(hash,application_id,host,session_id,user_id,nonce_hash,path,expires_at) VALUES(?,?,?,?,?,?,?,?)`,
			c.Hash, c.AppID, c.Host, c.SessionID, c.UserID, c.NonceHash, c.Path, time.Now().UTC().Add(ForwardCodeTTL).Unix())
		return err
	})
}

// ForwardAccess is what the check needs about a user and a proxy app.
type ForwardAccess struct {
	Active     bool // account active, not ended, no forced password change
	Allowed    bool // assigned (effective_app_access)
	Policy     AppAuthenticationPolicy
	Enrollment forwardEnrollment
}

// forwardEnrollment is the user's MFA enrollment requirement (enrollment_requirements)
// and the factor bits they hold (enrolled_factors).
type forwardEnrollment struct {
	Required          bool
	Allowed, Enrolled int
	Due               int64
}

// permits mirrors the mfa_session_access view for evidence that may outlive its login row.
func (r forwardEnrollment) permits(e AuthenticationEvidence, now time.Time) bool {
	if !r.Required {
		return true
	}
	if r.Enrolled&r.Allowed == 0 {
		return e.FactorMethod != "recovery" && r.Due > now.Unix()
	}
	bit := factorBit(e.FactorMethod)
	return e.PrimaryAuthenticatedAt != nil && e.FactorAuthenticatedAt != nil && bit&r.Allowed != 0 && bit&r.Enrolled != 0
}

// Permits applies the app policy and the enrollment requirement to evidence. Fresh mode
// needs a per-request interaction the edge cannot have, so it is refused.
func (a ForwardAccess) Permits(e AuthenticationEvidence, now time.Time) bool {
	return a.Active && a.Allowed && a.Policy.Valid() && a.Policy.Mode != "fresh" && a.Policy.EvidenceReason(e, now) == "" &&
		a.Enrollment.permits(e, now)
}

func forwardAccess(q interface {
	QueryRow(string, ...any) *sql.Row
}, appID, userID string) (ForwardAccess, error) {
	var a ForwardAccess
	err := q.QueryRow(`SELECT (u.status='active' AND NOT u.password_change_required AND (u.ends_at IS NULL OR u.ends_at>unixepoch())
 AND EXISTS(SELECT 1 FROM orgs o WHERE o.id=u.org_id AND o.status='active')),
 EXISTS(SELECT 1 FROM effective_app_access e WHERE e.app_id=r.id AND e.user_id=u.id),
 r.auth_mode,r.auth_primary_max_age,r.auth_factor,r.auth_factor_max_age,
 er.required,er.allowed_mask,er.due_at,COALESCE((SELECT SUM(f.bit) FROM enrolled_factors f WHERE f.user_id=u.id),0)
 FROM users u JOIN enrollment_requirements er ON er.user_id=u.id CROSS JOIN app_registry r WHERE u.id=? AND r.launcher_id=?`, userID, appID).Scan(&a.Active, &a.Allowed,
		&a.Policy.Mode, &a.Policy.PrimaryMaxAge, &a.Policy.Factor, &a.Policy.FactorMaxAge,
		&a.Enrollment.Required, &a.Enrollment.Allowed, &a.Enrollment.Due, &a.Enrollment.Enrolled)
	return a, err
}

// ForwardAccessFor is the start route's view of a user and a proxy app.
func (s *Store) ForwardAccessFor(appID, userID string) (ForwardAccess, error) {
	return forwardAccess(s.db, appID, userID)
}

// RedeemForwardCode spends a code whatever the outcome, then creates the forward session
// when the code matches host and nonce and the login, user and access still hold.
// It returns the path to send the browser to.
func (s *Store) RedeemForwardCode(codeHash, host, nonceHash, sessionHash string, audit *AuditEvent) (string, *ProxyApp, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return "", nil, err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	var c ForwardCode
	var expires int64
	err = tx.QueryRow(`DELETE FROM forward_codes WHERE hash=? RETURNING application_id,host,session_id,user_id,nonce_hash,path,expires_at`, codeHash).
		Scan(&c.AppID, &c.Host, &c.SessionID, &c.UserID, &c.NonceHash, &c.Path, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, ErrForwardCode
	}
	if err != nil {
		return "", nil, err
	}
	if c.Host != host || expires <= now.Unix() || subtle.ConstantTimeCompare([]byte(c.NonceHash), []byte(nonceHash)) != 1 {
		return "", nil, errors.Join(ErrForwardCode, tx.Commit())
	}
	app, err := scanProxyApp(tx.QueryRow(proxyAppSelect+` WHERE p.application_id=? AND p.host=?`, c.AppID, host))
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, errors.Join(ErrForwardCode, tx.Commit())
	}
	if err != nil {
		return "", nil, err
	}
	var e AuthenticationEvidence
	err = tx.QueryRow(`SELECT primary_authenticated_at,factor_authenticated_at,COALESCE(factor_method,'') FROM sessions WHERE id=? AND user_id=? AND expires_at>? AND NOT enrollment_only`, c.SessionID, c.UserID, now).
		Scan(&e.PrimaryAuthenticatedAt, &e.FactorAuthenticatedAt, &e.FactorMethod)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, errors.Join(ErrForwardDenied, tx.Commit())
	}
	if err != nil {
		return "", nil, err
	}
	access, err := forwardAccess(tx, c.AppID, c.UserID)
	if err != nil {
		return "", nil, err
	}
	if !access.Permits(e, now) {
		return "", nil, errors.Join(ErrForwardDenied, tx.Commit())
	}
	if _, err = tx.Exec(`INSERT INTO forward_sessions(hash,application_id,host,user_id,session_id,primary_at,factor_at,factor_method,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		sessionHash, c.AppID, host, c.UserID, c.SessionID, unixOrNil(e.PrimaryAuthenticatedAt), unixOrNil(e.FactorAuthenticatedAt), e.FactorMethod,
		now.Unix(), now.Unix()+app.SessionSeconds); err != nil {
		return "", nil, err
	}
	if audit != nil {
		audit.ActorID, audit.TargetID = c.UserID, c.AppID
	}
	if err = recordAuditTx(tx, audit); err != nil {
		return "", nil, err
	}
	return c.Path, app, tx.Commit()
}

// ForwardSession is a live forward session with its user's identity.
type ForwardSession struct {
	AppID, UserID, Username, Email string
	ExpiresAt                      time.Time
	Evidence                       AuthenticationEvidence
	Access                         ForwardAccess
	Groups                         []string
}

// ForwardSessionFor reads the session for a cookie hash on host, or nil when there is no
// live one bound to that host. Groups are the user's live groups assigned to the app.
func (s *Store) ForwardSessionFor(hash, host string) (*ForwardSession, error) {
	fs := &ForwardSession{}
	var primary, factor sql.NullInt64
	var expires int64
	err := s.db.QueryRow(`SELECT f.application_id,f.user_id,u.username,u.email,f.expires_at,f.primary_at,f.factor_at,f.factor_method
 FROM forward_sessions f JOIN proxy_apps p ON p.application_id=f.application_id JOIN users u ON u.id=f.user_id
 WHERE f.hash=? AND f.host=? AND p.host=? AND f.expires_at>?`, hash, host, host, time.Now().UTC().Unix()).
		Scan(&fs.AppID, &fs.UserID, &fs.Username, &fs.Email, &expires, &primary, &factor, &fs.Evidence.FactorMethod)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	fs.ExpiresAt = time.Unix(expires, 0).UTC()
	fs.Evidence.PrimaryAuthenticatedAt, fs.Evidence.FactorAuthenticatedAt = timeFromUnix(primary), timeFromUnix(factor)
	if fs.Access, err = forwardAccess(s.db, fs.AppID, fs.UserID); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT g.name FROM app_registry r JOIN app_group_assignments ag ON ag.app_id=r.id
 JOIN live_group_memberships m ON m.group_id=ag.group_id JOIN directory_groups g ON g.id=ag.group_id
 WHERE r.launcher_id=? AND m.user_id=? ORDER BY g.name`, fs.AppID, fs.UserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		fs.Groups = append(fs.Groups, name)
	}
	return fs, rows.Err()
}

// EndForwardSession deletes the session for a cookie hash on host. It reports the user
// and app, empty when there was none.
func (s *Store) EndForwardSession(hash, host string, audit *AuditEvent) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var userID, appID string
	err = tx.QueryRow(`DELETE FROM forward_sessions WHERE hash=? AND host=? RETURNING user_id,application_id`, hash, host).Scan(&userID, &appID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if audit != nil {
		audit.ActorID, audit.TargetID = userID, appID
	}
	if err = recordAuditTx(tx, audit); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// DeleteExpiredForwardRows is housekeeping for codes and sessions past their end.
func (s *Store) DeleteExpiredForwardRows() error {
	now := time.Now().UTC().Unix()
	if _, err := s.db.Exec(`DELETE FROM forward_codes WHERE expires_at<=?`, now); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM forward_sessions WHERE expires_at<=?`, now)
	return err
}
