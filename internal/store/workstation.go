package store

import (
	"database/sql"
	"errors"
	"time"
)

// Workstation login (design: docs/superpowers/specs/2026-11-19-workstation-login-design.md).
// A workstation app is a public oauth_clients row plus a workstation_apps row. Its
// sessions are sessions rows with workstation_client_id set: every existing revocation
// path reaches them, and no browser cookie can name one.

const (
	DeviceCodeTTLMin       = 120
	DeviceCodeTTLMax       = 900
	DeviceCodeTTLDefault   = 300
	OfflineWindowMax       = 30 * 24 * 3600
	OfflineWindowDefault   = 7 * 24 * 3600
	DeviceCodeInterval     = 5
	maxPendingDeviceCodes  = 1000
	deviceCodeSweepRetain  = time.Hour
	deviceCodeStatusWait   = "pending"
	deviceCodeStatusOK     = "approved"
	deviceCodeStatusDenied = "denied"
)

var (
	// ErrDeviceGrantUnavailable: unknown client, not a workstation app, disabled, or grant off.
	ErrDeviceGrantUnavailable = errors.New("device grant is not available for this client")
	// ErrDeviceCodeCapacity: the app already has maxPendingDeviceCodes live codes.
	ErrDeviceCodeCapacity = errors.New("too many pending device codes")
)

type WorkstationApp struct {
	ClientID           string `json:"clientId"`
	ClientName         string `json:"clientName"`
	Enabled            bool   `json:"enabled"`
	DeviceGrantEnabled bool   `json:"deviceGrantEnabled"`
	DeviceCodeTTL      int    `json:"deviceCodeTtl"`
	OfflineWindow      int    `json:"offlineWindow"`
	// RequirePassword refuses a sign-in for the app unless a password was typed in it.
	RequirePassword bool `json:"requirePassword"`
	// MacSignIn: the app's only redirect URI is XCredsRedirectURI.
	MacSignIn bool   `json:"macSignIn"`
	AppID     string `json:"appId"`
	// Groups are the names of the directory groups assigned to the app.
	Groups []string `json:"groups"`
}

// XCredsRedirectURI is the loopback redirect XCreds' web view intercepts; nothing listens there.
const XCredsRedirectURI = "http://127.0.0.1/xcreds"

const xcredsRedirectsJSON = `["` + XCredsRedirectURI + `"]`

// WorkstationSettings are the admin-set values of a workstation app.
type WorkstationSettings struct {
	DeviceGrant     bool
	DeviceCodeTTL   int
	OfflineWindow   int
	RequirePassword bool
	MacSignIn       bool
}

// ValidWorkstationSettings reports whether the admin-set values are in range.
func ValidWorkstationSettings(ttl, window int) bool {
	return ttl >= DeviceCodeTTLMin && ttl <= DeviceCodeTTLMax && window >= 0 && window <= OfflineWindowMax
}

func migrateWorkstationLogin(tx *sql.Tx) error {
	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM pragma_table_info('sessions') WHERE name='workstation_client_id'`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := tx.Exec(`ALTER TABLE sessions ADD COLUMN workstation_client_id TEXT`); err != nil {
			return err
		}
	}
	_, err := tx.Exec(workstationTablesSQL(`DATETIME`, `INTEGER`))
	return err
}

func migrateWorkstationLoginPostgres(tx *sql.Tx) error {
	if _, err := tx.Exec(`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS workstation_client_id TEXT`); err != nil {
		return err
	}
	_, err := tx.Exec(workstationTablesSQL(`TIMESTAMPTZ`, `BIGINT`))
	return err
}

// migrateWorkstationPassword adds the require-password rule and the interaction's
// record of its password step (design: 2026-11-19-workstation-macos-design.md).
func migrateWorkstationPassword(tx *sql.Tx) error {
	for _, c := range []struct{ table, column, ddl string }{
		{"workstation_apps", "require_password", `ALTER TABLE workstation_apps ADD COLUMN require_password BOOLEAN NOT NULL DEFAULT FALSE`},
		{"authorization_interactions", "password_at", `ALTER TABLE authorization_interactions ADD COLUMN password_at DATETIME`},
	} {
		var n int
		if err := tx.QueryRow(`SELECT count(*) FROM pragma_table_info(?) WHERE name=?`, c.table, c.column).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			if _, err := tx.Exec(c.ddl); err != nil {
				return err
			}
		}
	}
	return nil
}

func migrateWorkstationPasswordPostgres(tx *sql.Tx) error {
	_, err := tx.Exec(`ALTER TABLE workstation_apps ADD COLUMN IF NOT EXISTS require_password BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE authorization_interactions ADD COLUMN IF NOT EXISTS password_at TIMESTAMPTZ`)
	return err
}

func workstationTablesSQL(ts, num string) string {
	return `CREATE TABLE IF NOT EXISTS workstation_apps (
	client_id TEXT PRIMARY KEY REFERENCES oauth_clients(id) ON DELETE CASCADE,
	device_grant_enabled BOOLEAN NOT NULL DEFAULT FALSE,
	device_code_ttl ` + num + ` NOT NULL DEFAULT 300 CHECK(device_code_ttl BETWEEN 120 AND 900),
	offline_window ` + num + ` NOT NULL DEFAULT 604800 CHECK(offline_window BETWEEN 0 AND 2592000)
);
CREATE TABLE IF NOT EXISTS device_codes (
	id TEXT PRIMARY KEY,
	client_id TEXT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
	device_code_hash TEXT NOT NULL UNIQUE,
	user_code_hash TEXT NOT NULL UNIQUE,
	scope TEXT NOT NULL,
	ip_address TEXT NOT NULL,
	user_agent TEXT NOT NULL,
	interval_seconds ` + num + ` NOT NULL,
	status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','denied')),
	user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
	approved_session_id TEXT,
	primary_authenticated_at ` + ts + `,
	factor_authenticated_at ` + ts + `,
	factor_method TEXT NOT NULL DEFAULT '',
	auth_app_id TEXT NOT NULL DEFAULT '',
	auth_revision ` + num + ` NOT NULL DEFAULT 0,
	role_revision ` + num + ` NOT NULL DEFAULT 0,
	session_id TEXT,
	last_polled_at ` + ts + `,
	expires_at ` + ts + ` NOT NULL,
	created_at ` + ts + ` NOT NULL,
	redeemed_at ` + ts + `
);
CREATE INDEX IF NOT EXISTS idx_device_codes_client ON device_codes(client_id, status);`
}

const workstationAppSelect = `SELECT c.id,c.client_name,c.enabled,w.device_grant_enabled,w.device_code_ttl,w.offline_window,w.require_password,c.redirect_uris_json='` + xcredsRedirectsJSON + `',COALESCE(a.id,'') FROM workstation_apps w JOIN oauth_clients c ON c.id=w.client_id LEFT JOIN app_registry a ON a.client_id=c.id`

func scanWorkstationApp(sc interface{ Scan(...any) error }) (*WorkstationApp, error) {
	w := &WorkstationApp{Groups: []string{}}
	err := sc.Scan(&w.ClientID, &w.ClientName, &w.Enabled, &w.DeviceGrantEnabled, &w.DeviceCodeTTL, &w.OfflineWindow, &w.RequirePassword, &w.MacSignIn, &w.AppID)
	return w, err
}

// GetWorkstationApp returns the client's workstation settings, or nil when it is not one.
func (s *Store) GetWorkstationApp(clientID string) (*WorkstationApp, error) {
	w, err := scanWorkstationApp(s.db.QueryRow(workstationAppSelect+` WHERE w.client_id=?`, clientID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return w, s.workstationGroups(w)
}

func (s *Store) ListWorkstationApps() ([]WorkstationApp, error) {
	rows, err := s.db.Query(workstationAppSelect + ` ORDER BY c.client_name`)
	if err != nil {
		return nil, err
	}
	out := []WorkstationApp{}
	for rows.Next() {
		w, err := scanWorkstationApp(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, *w)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if err := s.workstationGroups(&out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Store) workstationGroups(w *WorkstationApp) error {
	rows, err := s.db.Query(`SELECT g.name FROM app_group_assignments x JOIN directory_groups g ON g.id=x.group_id WHERE x.app_id=? ORDER BY g.name`, w.AppID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		w.Groups = append(w.Groups, name)
	}
	return rows.Err()
}

// CreateWorkstationApp registers a public client with no redirect URIs, the groups claim
// on and assigned-only access, plus its workstation settings, with the audit row.
func (s *Store) CreateWorkstationApp(c *OAuthClient, audit *AuditEvent) error {
	c.ClientType, c.ClientSecretHash, c.RedirectURIsJSON, c.PostLogoutRedirectURIsJSON = "public", "", "[]", "[]"
	c.AllowedScopesJSON, c.Enabled, c.CreatedAt = `["openid","profile","email"]`, true, time.Now().UTC()
	return s.auditedTx(audit, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO oauth_clients (id, client_name, client_type, client_secret_hash, redirect_uris_json, allowed_scopes_json, enabled, created_at, post_logout_redirect_uris_json, backchannel_logout_uri, description, icon_name) VALUES (?,?,?,?,?,?,?,?,?,'','','')`,
			c.ID, c.ClientName, c.ClientType, c.ClientSecretHash, c.RedirectURIsJSON, c.AllowedScopesJSON, c.Enabled, c.CreatedAt, c.PostLogoutRedirectURIsJSON); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE app_registry SET groups_claim=TRUE, access_mode='assigned_only' WHERE client_id=?`, c.ID); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO workstation_apps(client_id) VALUES(?)`, c.ID)
		return err
	})
}

// UpdateWorkstationApp changes the settings. A shorter offline window clamps the app's
// live workstation sessions and refresh tokens now; 0 ends them. Mac sign-in sets the
// client's redirect URIs to exactly the XCreds one, or none.
func (s *Store) UpdateWorkstationApp(clientID string, set WorkstationSettings, audit *AuditEvent) error {
	grant, ttl, window := set.DeviceGrant, set.DeviceCodeTTL, set.OfflineWindow
	if !ValidWorkstationSettings(ttl, window) {
		return InputError("device code lifetime or offline window out of range")
	}
	redirects := "[]"
	if set.MacSignIn {
		redirects = xcredsRedirectsJSON
	}
	return s.auditedTx(audit, func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE workstation_apps SET device_grant_enabled=?, device_code_ttl=?, offline_window=?, require_password=? WHERE client_id=?`, grant, ttl, window, set.RequirePassword, clientID)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return ErrNotFound
		}
		if _, err = tx.Exec(`UPDATE oauth_clients SET redirect_uris_json=? WHERE id=?`, redirects, clientID); err != nil {
			return err
		}
		now := time.Now().UTC()
		if !grant {
			// Turning the grant off ends every code in flight; turning it on again revives none.
			if _, err = tx.Exec(`UPDATE device_codes SET status='denied' WHERE client_id=? AND status IN ('pending','approved') AND redeemed_at IS NULL`, clientID); err != nil {
				return err
			}
		}
		if window == 0 {
			_, err = revokeSessionsTx(tx, now, `workstation_client_id=?`, clientID)
			return err
		}
		end := now.Add(time.Duration(window) * time.Second)
		if _, err = tx.Exec(`UPDATE sessions SET expires_at=? WHERE workstation_client_id=? AND expires_at>?`, end, clientID, end); err != nil {
			return err
		}
		live := `SELECT id FROM sessions WHERE workstation_client_id=?`
		if _, err = tx.Exec(`UPDATE issued_tokens SET expires_at=? WHERE expires_at>? AND session_id IN (`+live+`)`, end, end, clientID); err != nil {
			return err
		}
		_, err = tx.Exec(`UPDATE refresh_tokens SET expires_at=? WHERE expires_at>? AND family_jti IN (SELECT jti FROM issued_tokens WHERE session_id IN (`+live+`))`, end, end, clientID)
		return err
	})
}

// DeviceCode is one RFC 8628 grant. Only hashes of the codes are stored.
type DeviceCode struct {
	AuthenticationEvidence
	ID                string
	ClientID          string
	ClientName        string
	DeviceCodeHash    string
	UserCodeHash      string
	Scope             string
	IPAddress         string
	UserAgent         string
	Interval          int
	Status            string
	UserID            string
	ApprovedSessionID string
	Policy            AppPolicyBinding
	SessionID         string
	LastPolledAt      *time.Time
	ExpiresAt         time.Time
	CreatedAt         time.Time
	RedeemedAt        *time.Time
}

// CreateDeviceCode stores a new pending code while the client is an enabled workstation
// app with the grant on and fewer than maxPendingDeviceCodes live codes.
func (s *Store) CreateDeviceCode(d *DeviceCode) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	var ok bool
	var pending int
	err = tx.QueryRow(`SELECT c.enabled AND w.device_grant_enabled, (SELECT COUNT(*) FROM device_codes d WHERE d.client_id=c.id AND d.status='pending' AND d.expires_at>?) FROM workstation_apps w JOIN oauth_clients c ON c.id=w.client_id WHERE c.id=?`, now, d.ClientID).Scan(&ok, &pending)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !ok) {
		return ErrDeviceGrantUnavailable
	}
	if err != nil {
		return err
	}
	if pending >= maxPendingDeviceCodes {
		return ErrDeviceCodeCapacity
	}
	d.CreatedAt, d.Status = now, deviceCodeStatusWait
	if _, err = tx.Exec(`INSERT INTO device_codes(id,client_id,device_code_hash,user_code_hash,scope,ip_address,user_agent,interval_seconds,status,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		d.ID, d.ClientID, d.DeviceCodeHash, d.UserCodeHash, d.Scope, d.IPAddress, d.UserAgent, d.Interval, d.Status, d.ExpiresAt, now); err != nil {
		return err
	}
	return tx.Commit()
}

const deviceCodeSelect = `SELECT d.id,d.client_id,c.client_name,d.scope,d.ip_address,d.user_agent,d.interval_seconds,d.status,COALESCE(d.user_id,''),COALESCE(d.approved_session_id,''),d.primary_authenticated_at,d.factor_authenticated_at,d.factor_method,d.auth_app_id,d.auth_revision,d.role_revision,COALESCE(d.session_id,''),d.last_polled_at,d.expires_at,d.created_at,d.redeemed_at FROM device_codes d JOIN oauth_clients c ON c.id=d.client_id`

func scanDeviceCode(row *sql.Row) (*DeviceCode, error) {
	d := &DeviceCode{}
	err := row.Scan(&d.ID, &d.ClientID, &d.ClientName, &d.Scope, &d.IPAddress, &d.UserAgent, &d.Interval, &d.Status, &d.UserID, &d.ApprovedSessionID, &d.PrimaryAuthenticatedAt, &d.FactorAuthenticatedAt, &d.FactorMethod, &d.Policy.AppID, &d.Policy.AuthRevision, &d.Policy.RoleRevision, &d.SessionID, &d.LastPolledAt, &d.ExpiresAt, &d.CreatedAt, &d.RedeemedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return d, err
}

// PendingDeviceCode returns the live, undecided code with this user-code hash, or nil.
func (s *Store) PendingDeviceCode(userCodeHash string) (*DeviceCode, error) {
	return scanDeviceCode(s.db.QueryRow(deviceCodeSelect+` WHERE d.user_code_hash=? AND d.status='pending' AND d.expires_at>?`, userCodeHash, time.Now().UTC()))
}

// DecideDeviceCode records the signed-in user's approval or denial of a live pending
// code. Approval snapshots the session's evidence and the policy binding it was checked
// against. ErrNotFound when the code is no longer pending.
func (s *Store) DecideDeviceCode(id string, approve bool, sess *Session, binding AppPolicyBinding, audit *AuditEvent) error {
	status := deviceCodeStatusDenied
	if approve {
		status = deviceCodeStatusOK
	}
	return s.auditedTx(audit, func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE device_codes SET status=?,user_id=?,approved_session_id=?,primary_authenticated_at=?,factor_authenticated_at=?,factor_method=?,auth_app_id=?,auth_revision=?,role_revision=? WHERE id=? AND status='pending' AND expires_at>?`,
			status, sess.UserID, sess.ID, sess.PrimaryAuthenticatedAt, sess.FactorAuthenticatedAt, sess.FactorMethod, binding.AppID, binding.AuthRevision, binding.RoleRevision, id, time.Now().UTC())
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return ErrNotFound
		}
		return nil
	})
}

// PollDeviceCode records a poll and returns the code (nil when unknown), whether this
// poll came sooner than its interval allows, and the time of the previous poll.
func (s *Store) PollDeviceCode(deviceCodeHash string) (*DeviceCode, bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	d, err := scanDeviceCode(tx.QueryRow(deviceCodeSelect+` WHERE d.device_code_hash=?`, deviceCodeHash))
	if err != nil || d == nil {
		return nil, false, err
	}
	now := time.Now().UTC()
	// One second of slack: a client sleeping exactly the interval may arrive a little early.
	tooFast := d.LastPolledAt != nil && now.Sub(*d.LastPolledAt) < time.Duration(d.Interval-1)*time.Second
	if _, err = tx.Exec(`UPDATE device_codes SET last_polled_at=? WHERE id=?`, now, d.ID); err != nil {
		return nil, false, err
	}
	return d, tooFast, tx.Commit()
}

// EndReplayedDeviceCode ends the workstation session a redeemed code created, because
// its device code was presented again.
func (s *Store) EndReplayedDeviceCode(d *DeviceCode, audit *AuditEvent) error {
	return s.auditedTx(audit, func(tx *sql.Tx) error {
		_, err := revokeSessionsTx(tx, time.Now().UTC(), `id=? AND workstation_client_id=?`, d.SessionID, d.ClientID)
		return err
	})
}

// RedeemDeviceCode spends an approved code once and, in one transaction, creates the
// workstation session, registers the access token and, when family is set, the refresh
// family and its first token. The approving browser session must still exist, so every
// path that ends sessions also stops an approved code that is not yet redeemed.
func (s *Store) RedeemDeviceCode(d *DeviceCode, sess *Session, access *IssuedToken, family *RefreshFamily, refreshHash string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	res, err := tx.Exec(`UPDATE device_codes SET redeemed_at=?, session_id=? WHERE id=? AND status='approved' AND redeemed_at IS NULL AND expires_at>? AND EXISTS(SELECT 1 FROM sessions WHERE id=device_codes.approved_session_id AND user_id=device_codes.user_id AND expires_at>? AND workstation_client_id IS NULL)`, now, sess.ID, d.ID, now, now)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return ErrAppAccessDenied
	}
	if err = startWorkstationSessionTx(tx, sess, d.UserID, d.ClientID, d.AuthenticationEvidence, d.Policy, access, family, refreshHash, now); err != nil {
		return err
	}
	return tx.Commit()
}

// startWorkstationSessionTx creates a workstation session for an active user and
// registers its access token and, when family is set, the refresh family and first token.
func startWorkstationSessionTx(tx *sql.Tx, sess *Session, userID, clientID string, ev AuthenticationEvidence, policy AppPolicyBinding, access *IssuedToken, family *RefreshFamily, refreshHash string, now time.Time) error {
	res, err := tx.Exec(`INSERT INTO sessions (id,user_id,session_token_hash,ip_address,user_agent,expires_at,created_at,last_active_at,primary_authenticated_at,factor_authenticated_at,factor_method,workstation_client_id) SELECT ?,?,?,?,?,?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM users WHERE id=? AND status='active')`,
		sess.ID, userID, sess.SessionTokenHash, sess.IPAddress, sess.UserAgent, sess.ExpiresAt, now, now, ev.PrimaryAuthenticatedAt, ev.FactorAuthenticatedAt, ev.FactorMethod, clientID, userID)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return ErrAppAccessDenied
	}
	if _, err = tx.Exec(`UPDATE sessions SET enrollment_only=NOT (SELECT allowed FROM mfa_session_access WHERE id=?) WHERE id=?`, sess.ID, sess.ID); err != nil {
		return err
	}
	access.SessionID, access.Policy = sess.ID, policy
	if err = recordIssuedTokenTx(tx, access); err != nil {
		return err
	}
	if family == nil {
		return nil
	}
	family.SessionID = sess.ID
	if err = recordIssuedTokenTx(tx, &IssuedToken{JTI: family.JTI, UserID: family.UserID, ClientID: family.ClientID, SessionID: sess.ID, ExpiresAt: family.ExpiresAt, Policy: policy}); err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO refresh_families(jti,scope,primary_authenticated_at,factor_authenticated_at,factor_method,auth_app_id,auth_revision,role_revision,idle_seconds) VALUES(?,?,?,?,?,?,?,?,?)`,
		family.JTI, family.Scope, family.PrimaryAuthenticatedAt, family.FactorAuthenticatedAt, family.FactorMethod, family.Policy.AppID, family.Policy.AuthRevision, family.Policy.RoleRevision, int64(family.Idle/time.Second)); err != nil {
		return err
	}
	return insertRefreshTokenTx(tx, family, refreshHash, now)
}

// StartCodeWorkstationSession is the authorization-code counterpart of RedeemDeviceCode,
// for a code ExchangeAuthorizationCode has just spent. The code's browser session must
// still be live and its policy binding current.
func (s *Store) StartCodeWorkstationSession(code *AuthorizationCode, sess *Session, access *IssuedToken, family *RefreshFamily, refreshHash string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	var ok bool
	if err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM authorization_codes ac
 JOIN app_registry policy ON policy.client_id=ac.client_id AND policy.id=ac.auth_app_id AND policy.auth_revision=ac.auth_policy_revision AND policy.role_revision=ac.role_revision
 JOIN sessions b ON b.id=ac.session_id AND b.user_id=ac.user_id AND b.expires_at>? AND b.workstation_client_id IS NULL
 WHERE ac.id=? AND ac.client_id=? AND ac.used_at IS NOT NULL AND ac.expires_at>? AND (ac.authentication_expires_at IS NULL OR ac.authentication_expires_at>=?))`,
		now, code.ID, code.ClientID, now, now).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return ErrAppAccessDenied
	}
	policy := AppPolicyBinding{AppID: code.AuthenticationAppID, AuthRevision: code.AuthenticationPolicyRevision, RoleRevision: code.RoleRevision}
	if err = startWorkstationSessionTx(tx, sess, code.UserID, code.ClientID, code.AuthenticationEvidence, policy, access, family, refreshHash, now); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteExpiredDeviceCodes sweeps codes an hour past their expiry.
func (s *Store) DeleteExpiredDeviceCodes() error {
	_, err := s.db.Exec(`DELETE FROM device_codes WHERE expires_at<?`, time.Now().UTC().Add(-deviceCodeSweepRetain))
	return err
}

// denyApprovedDeviceCodesTx withdraws approvals not yet redeemed, for revocations that keep
// the approving browser session alive (a password change keeps the proving one). An empty
// clientID means every app.
func denyApprovedDeviceCodesTx(tx *sql.Tx, userID, clientID string) error {
	_, err := tx.Exec(`UPDATE device_codes SET status='denied' WHERE user_id=? AND (?='' OR client_id=?) AND status='approved' AND redeemed_at IS NULL`, userID, clientID, clientID)
	return err
}
