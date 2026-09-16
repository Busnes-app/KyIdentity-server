package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var ErrAppAccessDenied = errors.New("application access denied")

// This predicate is shared by live access and admin previews. Administrators have
// no implicit bypass. Lifecycle expiry can extend f.active when it is introduced.
func appAllowedSQL(mode, enabled string) string {
	return `f.active AND f.client_enabled AND ` + enabled + ` AND (` + mode + `='all_active_users' OR f.direct OR f.group_assigned)`
}
func (s *Store) migrateAppAccess() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('app_registry') WHERE name='access_mode'`).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		if _, err = tx.Exec(`ALTER TABLE app_registry ADD COLUMN access_mode TEXT NOT NULL DEFAULT 'assigned_only' CHECK(access_mode IN ('assigned_only','all_active_users'));
 ALTER TABLE app_registry ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT 1;
 UPDATE app_registry SET access_mode='all_active_users';`); err != nil {
			return err
		}
	}
	_, err = tx.Exec(`CREATE TABLE IF NOT EXISTS app_user_assignments (
 app_id TEXT NOT NULL REFERENCES app_registry(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY(app_id,user_id));
 CREATE TABLE IF NOT EXISTS app_group_assignments (
 app_id TEXT NOT NULL REFERENCES app_registry(id) ON DELETE CASCADE,
 group_id TEXT NOT NULL REFERENCES directory_groups(id) ON DELETE CASCADE, PRIMARY KEY(app_id,group_id));
 CREATE INDEX IF NOT EXISTS app_assignments_user ON app_user_assignments(user_id,app_id);
 CREATE INDEX IF NOT EXISTS app_assignments_group ON app_group_assignments(group_id,app_id)`)
	if err != nil {
		return err
	}
	// Expiry instants (unix seconds, NULL = never) on direct assignments, memberships and
	// accounts. The views read them on every decision, so they hold with no worker.
	for _, col := range []struct{ table, column string }{{"app_user_assignments", "expires_at"}, {"group_memberships", "expires_at"}, {"users", "ends_at"}} {
		if err = tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name=?`, col.table, col.column).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			if _, err = tx.Exec(`ALTER TABLE ` + col.table + ` ADD COLUMN ` + col.column + ` INTEGER`); err != nil {
				return err
			}
		}
	}
	_, err = tx.Exec(`DROP VIEW IF EXISTS effective_app_access; DROP VIEW IF EXISTS app_access_facts; DROP VIEW IF EXISTS live_group_memberships;
 CREATE VIEW live_group_memberships AS SELECT group_id,user_id FROM group_memberships WHERE expires_at IS NULL OR expires_at>unixepoch();
 CREATE VIEW app_access_facts AS SELECT a.id app_id,u.id user_id,
 (u.status='active' AND (u.ends_at IS NULL OR u.ends_at>unixepoch())) active,a.access_mode,a.enabled,
 (a.client_id IS NULL OR EXISTS(SELECT 1 FROM oauth_clients c WHERE c.id=a.client_id AND c.enabled)) client_enabled,
 EXISTS(SELECT 1 FROM app_user_assignments d WHERE d.app_id=a.id AND d.user_id=u.id AND (d.expires_at IS NULL OR d.expires_at>unixepoch())) direct,
 EXISTS(SELECT 1 FROM app_group_assignments g JOIN live_group_memberships m ON m.group_id=g.group_id WHERE g.app_id=a.id AND m.user_id=u.id) group_assigned
 FROM app_registry a CROSS JOIN users u;
 CREATE VIEW effective_app_access AS SELECT f.app_id,f.user_id FROM app_access_facts f WHERE ` + appAllowedSQL("f.access_mode", "f.enabled"))
	if err != nil {
		return err
	}
	return tx.Commit()
}

// Must run under the mutation's writer lock. Deleting even spent codes prevents an
// in-flight exchange from reviving them if access is removed and then re-granted.
// ponytail: scan live tokens/codes on access edits; scope to affected apps/users if this grows slow.
func revokeLostAppAccessTx(tx *sql.Tx) error {
	now := time.Now().UTC()
	lost := `NOT EXISTS(SELECT 1 FROM effective_app_access e JOIN app_registry a ON a.id=e.app_id WHERE e.user_id=t.user_id AND a.client_id=t.client_id)`
	if _, err := tx.Exec(`UPDATE issued_tokens AS t SET revoked_at=? WHERE revoked_at IS NULL AND `+lost, now); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM authorization_codes AS t WHERE ` + lost); err != nil {
		return err
	}
	// A client that saw a login for access that no longer exists is told to log out,
	// and the sid mapping goes with the access so the delivery happens once.
	lostSession := `NOT EXISTS(SELECT 1 FROM effective_app_access e JOIN app_registry a ON a.id=e.app_id WHERE e.user_id=cs.user_id AND a.client_id=cs.client_id)`
	if err := enqueueLogoutTx(tx, now, lostSession); err != nil {
		return err
	}
	_, err := tx.Exec(`DELETE FROM oidc_client_sessions AS cs WHERE ` + lostSession)
	return err
}
func (s *Store) ClientAccessAllowed(userID, clientID string) (bool, error) {
	var allowed bool
	err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM effective_app_access e JOIN app_registry a ON a.id=e.app_id JOIN oauth_clients c ON c.id=a.client_id WHERE e.user_id=? AND c.id=? AND c.enabled)`, userID, clientID).Scan(&allowed)
	return allowed, err
}
func (s *Store) LauncherAppAccess(userID string) (map[string]bool, error) {
	rows, err := s.db.Query(`SELECT COALESCE(a.client_id,''),COALESCE(a.launcher_id,'') FROM effective_app_access e JOIN app_registry a ON a.id=e.app_id WHERE e.user_id=?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	allowed := map[string]bool{}
	for rows.Next() {
		var c, l string
		if err := rows.Scan(&c, &l); err != nil {
			return nil, err
		}
		if c != "" {
			allowed["client:"+c] = true
		}
		if l != "" {
			allowed["custom:"+l] = true
		}
	}
	return allowed, rows.Err()
}
func (s *Store) SetAppPolicy(id, mode string, enabled bool, revision int, audit *AuditEvent) error {
	if mode != "assigned_only" && mode != "all_active_users" {
		return ErrAppLinkConflict
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	before, err := lockAppRecord(tx, id, revision)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE app_registry SET access_mode=?,enabled=?,revision=revision+1 WHERE id=?`, mode, enabled, id); err != nil {
		return err
	}
	if err = revokeLostAppAccessTx(tx); err != nil {
		return err
	}
	if err = reconcileProvisioningTx(tx, time.Now().UTC()); err != nil {
		return err
	}
	if err = appRegistryAudit(audit, map[string]any{"before": before, "accessMode": mode, "enabled": enabled}); err != nil {
		return err
	}
	if err = recordAuditTx(tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) SetAppAssignment(id, kind, principal string, assigned bool, audit *AuditEvent) error {
	return s.setAppAssignment(id, kind, principal, assigned, nil, audit)
}

// SetAppAssignmentUntil grants until an instant (nil = no bound); repeating it moves the
// instant. Only direct user grants carry one.
func (s *Store) SetAppAssignmentUntil(id, kind, principal string, expiresAt *time.Time, audit *AuditEvent) error {
	if kind != "users" && expiresAt != nil {
		return ErrAppLinkConflict
	}
	if err := checkExpiry(expiresAt, time.Now().UTC()); err != nil {
		return err
	}
	return s.setAppAssignment(id, kind, principal, true, expiresAt, audit)
}

func (s *Store) setAppAssignment(id, kind, principal string, assigned bool, expiresAt *time.Time, audit *AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	principalName, err := applyAppAssignmentTx(tx, id, kind, principal, assigned, expiresAt)
	if err != nil {
		return err
	}
	app, err := scanAppRecord(tx.QueryRow(appRecordSelect+appRecordFrom+` WHERE a.id=?`, id))
	if err != nil {
		return err
	}
	if err = appRegistryAudit(audit, map[string]any{"app": app, "kind": kind, "principalId": principal, "principalName": principalName, "assigned": assigned}); err != nil {
		return err
	}
	if err = recordAuditTx(tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

type AppAccessUser struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	DisplayName   string `json:"displayName"`
	Status        string `json:"status"`
	Direct        bool   `json:"direct"`
	GroupAssigned bool   `json:"groupAssigned"`
	Effective     bool   `json:"effective"`
	Preview       bool   `json:"preview"`
	Reason        string `json:"reason"`
	// DirectExpiresAt bounds the direct grant; nil means it does not expire.
	DirectExpiresAt *time.Time `json:"directExpiresAt,omitempty"`
}
type AppAccessUsers struct {
	Users        []AppAccessUser `json:"users"`
	Total        int             `json:"total"`
	Limit        int             `json:"limit"`
	Offset       int             `json:"offset"`
	LosingAccess int             `json:"losingAccess"`
	// GainingAccess counts active users the proposed policy would newly admit; with a
	// linked provisioning system these become downstream account changes.
	GainingAccess int       `json:"gainingAccess"`
	App           AppRecord `json:"app"`
}

func (s *Store) ListAppAccessUsers(id, query, previewMode string, previewEnabled *bool, limit, offset int) (*AppAccessUsers, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	app, err := scanAppRecord(tx.QueryRow(appRecordSelect+appRecordFrom+` WHERE a.id=?`, id))
	if err != nil {
		return nil, err
	}
	mode, enabled := app.AccessMode, app.Enabled
	if previewMode != "" {
		mode = previewMode
	}
	if previewEnabled != nil {
		enabled = *previewEnabled
	}
	if mode != "all_active_users" && mode != "assigned_only" {
		return nil, ErrAppLinkConflict
	}
	p := &AppAccessUsers{Users: []AppAccessUser{}, Limit: limit, Offset: offset, App: app}
	current, proposed := appAllowedSQL("f.access_mode", "f.enabled"), appAllowedSQL("?", "?")
	// Predicate placeholders appear in enabled, mode order.
	if err = tx.QueryRow(`SELECT COUNT(*) FROM app_access_facts f WHERE f.app_id=? AND (`+current+`) AND NOT (`+proposed+`)`, id, enabled, mode).Scan(&p.LosingAccess); err != nil {
		return nil, err
	}
	if err = tx.QueryRow(`SELECT COUNT(*) FROM app_access_facts f WHERE f.app_id=? AND NOT (`+current+`) AND (`+proposed+`)`, id, enabled, mode).Scan(&p.GainingAccess); err != nil {
		return nil, err
	}
	from := ` FROM users u JOIN app_access_facts f ON f.user_id=u.id WHERE f.app_id=? AND (instr(lower(u.username),lower(?))>0 OR instr(lower(u.display_name),lower(?))>0)`
	if err = tx.QueryRow(`SELECT COUNT(*)`+from, id, query, query).Scan(&p.Total); err != nil {
		return nil, err
	}
	rows, err := tx.Query(`SELECT u.id,u.username,u.display_name,u.status,f.direct,f.group_assigned,(`+current+`),(`+proposed+`),`+accessReasonSQL+`,
 (SELECT d.expires_at FROM app_user_assignments d WHERE d.app_id=f.app_id AND d.user_id=u.id)`+from+` ORDER BY u.username COLLATE NOCASE,u.id LIMIT ? OFFSET ?`, enabled, mode, id, query, query, limit, offset)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var u AppAccessUser
		var expires sql.NullInt64
		if err = rows.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Status, &u.Direct, &u.GroupAssigned, &u.Effective, &u.Preview, &u.Reason, &expires); err != nil {
			rows.Close()
			return nil, err
		}
		u.DirectExpiresAt = timeFromUnix(expires)
		p.Users = append(p.Users, u)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	return p, tx.Commit()
}

type AppAccessGroup struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Assigned bool   `json:"assigned"`
}

func (s *Store) ListAppAccessGroups(id, query string, limit, offset int) ([]AppAccessGroup, int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	var exists bool
	if err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM app_registry WHERE id=?)`, id).Scan(&exists); err != nil {
		return nil, 0, err
	}
	if !exists {
		return nil, 0, ErrAppRecordMissing
	}
	var total int
	where := ` WHERE instr(lower(g.name),lower(?))>0`
	if err = tx.QueryRow(`SELECT COUNT(*) FROM directory_groups g`+where, query).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := tx.Query(`SELECT g.id,g.name,EXISTS(SELECT 1 FROM app_group_assignments x WHERE x.app_id=? AND x.group_id=g.id) FROM directory_groups g`+where+` ORDER BY g.name COLLATE NOCASE,g.id LIMIT ? OFFSET ?`, id, query, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	result := []AppAccessGroup{}
	for rows.Next() {
		var g AppAccessGroup
		if err = rows.Scan(&g.ID, &g.Name, &g.Assigned); err != nil {
			rows.Close()
			return nil, 0, err
		}
		result = append(result, g)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, 0, err
	}
	return result, total, tx.Commit()
}

func ensureAppLinkPoliciesTx(tx *sql.Tx, target, source AppRecord) error {
	if target.AccessMode != source.AccessMode || target.Enabled != source.Enabled || target.Authentication != source.Authentication {
		return fmt.Errorf("%w: access settings differ", ErrAppLinkConflict)
	}
	var count int
	if err := tx.QueryRow(`SELECT (SELECT COUNT(*) FROM app_user_assignments WHERE app_id IN (?,?))+(SELECT COUNT(*) FROM app_group_assignments WHERE app_id IN (?,?))`, target.ID, source.ID, target.ID, source.ID).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return fmt.Errorf("%w: remove assignments before linking", ErrAppLinkConflict)
	}
	if err := tx.QueryRow(`SELECT COUNT(*) FROM app_roles WHERE app_id IN (?,?)`, target.ID, source.ID).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return fmt.Errorf("%w: remove app roles before linking", ErrAppLinkConflict)
	}
	if target.LegacyRoleClaim != source.LegacyRoleClaim || target.GroupsClaim != source.GroupsClaim {
		return fmt.Errorf("%w: claim settings differ", ErrAppLinkConflict)
	}
	return nil
}

// applyAppAssignmentTx is the one way a grant row is written: it bumps the app's
// revision, writes or removes the row, and runs the grant and provisioning follow-up.
// Manual grants and approved access requests both come through here.
func applyAppAssignmentTx(tx *sql.Tx, id, kind, principal string, assigned bool, expiresAt *time.Time) (string, error) {
	table, column, source, name := "", "", "", ""
	switch kind {
	case "users":
		table, column, source, name = "app_user_assignments", "user_id", "users", "username"
	case "groups":
		table, column, source, name = "app_group_assignments", "group_id", "directory_groups", "name"
	default:
		return "", ErrAppLinkConflict
	}
	result, err := tx.Exec(`UPDATE app_registry SET revision=revision+1 WHERE id=?`, id)
	if err != nil {
		return "", err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return "", ErrAppRecordMissing
	}
	var principalName string
	if err = tx.QueryRow(`SELECT `+name+` FROM `+source+` WHERE id=?`, principal).Scan(&principalName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrAppRecordMissing
		}
		return "", err
	}
	if assigned && kind == "users" {
		_, err = tx.Exec(`INSERT INTO app_user_assignments(app_id,user_id,expires_at) VALUES(?,?,?) ON CONFLICT(app_id,user_id) DO UPDATE SET expires_at=excluded.expires_at`, id, principal, unixOrNil(expiresAt))
	} else if assigned {
		_, err = tx.Exec(`INSERT INTO `+table+`(app_id,`+column+`) VALUES(?,?) ON CONFLICT DO NOTHING`, id, principal)
	} else {
		_, err = tx.Exec(`DELETE FROM `+table+` WHERE app_id=? AND `+column+`=?`, id, principal)
	}
	if err != nil {
		return "", err
	}
	if err = revokeLostAppAccessTx(tx); err != nil {
		return "", err
	}
	return principalName, reconcileProvisioningTx(tx, time.Now().UTC())
}
