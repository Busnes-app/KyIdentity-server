package store

import (
	"database/sql"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Busness-app/ky-primitives/scim"
	"github.com/google/uuid"
)

// App roles: fixed role names an app understands, mapped explicitly from groups or
// users. A token carries only the roles of the app it is for, under the fixed claim
// name `roles`; the global directory role reaches an app only while its legacy claim
// stays on. Any role or claim-shape change revokes the affected grants and bumps the
// app's role revision, so a code issued before the change cannot be exchanged after it.

var (
	ErrAppRoleExists  = errors.New("role name already exists for this app")
	ErrAppRoleInvalid = errors.New("role name must be 1-64 characters of letters, digits, '_', '.', ':' or '-'")
)

var roleName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)

// MaxIdentityClaimBytes bounds the serialized identity claims of one token; a mapping
// set that does not fit is an actionable configuration error, never a truncation.
const MaxIdentityClaimBytes = 4096

type AppRolePrincipal struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type AppRole struct {
	ID          string             `json:"id"`
	AppID       string             `json:"appId"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	CreatedAt   time.Time          `json:"createdAt"`
	Users       []AppRolePrincipal `json:"users"`
	Groups      []AppRolePrincipal `json:"groups"`
}

func (s *Store) migrateAppRoles() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('app_registry') WHERE name='role_revision'`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		// Existing apps keep the global role claim they were built against; new apps start
		// on app roles only.
		if _, err = tx.Exec(`ALTER TABLE app_registry ADD COLUMN role_revision INTEGER NOT NULL DEFAULT 0;
 ALTER TABLE app_registry ADD COLUMN legacy_role_claim BOOLEAN NOT NULL DEFAULT 0;
 ALTER TABLE app_registry ADD COLUMN groups_claim BOOLEAN NOT NULL DEFAULT 0;
 UPDATE app_registry SET legacy_role_claim=1;`); err != nil {
			return err
		}
	}
	if err = tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('authorization_codes') WHERE name='role_revision'`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err = tx.Exec(`ALTER TABLE authorization_codes ADD COLUMN role_revision INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS app_roles (
 id TEXT PRIMARY KEY, app_id TEXT NOT NULL REFERENCES app_registry(id) ON DELETE CASCADE,
 name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', created_at DATETIME NOT NULL);
 CREATE UNIQUE INDEX IF NOT EXISTS app_roles_name ON app_roles(app_id, lower(name));
 CREATE TABLE IF NOT EXISTS app_role_user_assignments (
 role_id TEXT NOT NULL REFERENCES app_roles(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY(role_id,user_id));
 CREATE TABLE IF NOT EXISTS app_role_group_assignments (
 role_id TEXT NOT NULL REFERENCES app_roles(id) ON DELETE CASCADE,
 group_id TEXT NOT NULL REFERENCES directory_groups(id) ON DELETE CASCADE, PRIMARY KEY(role_id,group_id));
 CREATE INDEX IF NOT EXISTS app_role_assignments_user ON app_role_user_assignments(user_id);
 CREATE INDEX IF NOT EXISTS app_role_assignments_group ON app_role_group_assignments(group_id)`); err != nil {
		return err
	}
	return tx.Commit()
}

func scanAppRole(row interface{ Scan(...any) error }) (*AppRole, error) {
	r := &AppRole{Users: []AppRolePrincipal{}, Groups: []AppRolePrincipal{}}
	err := row.Scan(&r.ID, &r.AppID, &r.Name, &r.Description, &r.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAppRecordMissing
	}
	return r, err
}

func principalsTx(tx *sql.Tx, query, roleID string) ([]AppRolePrincipal, error) {
	rows, err := tx.Query(query, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AppRolePrincipal{}
	for rows.Next() {
		var p AppRolePrincipal
		if err := rows.Scan(&p.ID, &p.Name); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

const roleUsersSQL = `SELECT u.id,u.username FROM app_role_user_assignments a JOIN users u ON u.id=a.user_id WHERE a.role_id=? ORDER BY u.username COLLATE NOCASE`
const roleGroupsSQL = `SELECT g.id,g.name FROM app_role_group_assignments a JOIN directory_groups g ON g.id=a.group_id WHERE a.role_id=? ORDER BY g.name COLLATE NOCASE`

// ListAppRoles returns an app's roles with their explicit mappings.
func (s *Store) ListAppRoles(appID string) ([]AppRole, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var exists bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM app_registry WHERE id=?)`, appID).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrAppRecordMissing
	}
	rows, err := tx.Query(`SELECT id,app_id,name,description,created_at FROM app_roles WHERE app_id=? ORDER BY name COLLATE NOCASE`, appID)
	if err != nil {
		return nil, err
	}
	var roles []AppRole
	for rows.Next() {
		r, err := scanAppRole(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		roles = append(roles, *r)
	}
	rows.Close()
	out := make([]AppRole, 0, len(roles))
	for _, r := range roles {
		if r.Users, err = principalsTx(tx, roleUsersSQL, r.ID); err != nil {
			return nil, err
		}
		if r.Groups, err = principalsTx(tx, roleGroupsSQL, r.ID); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, tx.Commit()
}

// roleChangeTx is the follow-up to any role or mapping change: bump the app's role
// revision (which blocks exchange of every code issued before it), revoke the affected
// users' live tokens and pending codes for the app's client, and push their new desired
// state to the app's provisioning connection.
func roleChangeTx(tx *sql.Tx, app AppRecord, users []string, now time.Time) error {
	if _, err := tx.Exec(`UPDATE app_registry SET role_revision=role_revision+1,revision=revision+1 WHERE id=?`, app.ID); err != nil {
		return err
	}
	for _, uid := range users {
		if app.ClientID != "" {
			if _, err := tx.Exec(`UPDATE issued_tokens SET revoked_at=? WHERE client_id=? AND user_id=? AND revoked_at IS NULL`, now, app.ClientID, uid); err != nil {
				return err
			}
			if _, err := tx.Exec(`DELETE FROM authorization_codes WHERE client_id=? AND user_id=?`, app.ClientID, uid); err != nil {
				return err
			}
		}
		if app.SystemID != "" {
			var desired bool
			if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM sync_resource_state st JOIN paired_systems s ON s.id=st.system_id WHERE st.system_id=? AND st.resource_id=? AND st.kind='user' AND st.active AND s.status<>'disabled')
 AND EXISTS(SELECT 1 FROM effective_app_access e WHERE e.app_id=? AND e.user_id=?)`, app.SystemID, uid, app.ID, uid).Scan(&desired); err != nil {
				return err
			}
			if !desired {
				continue
			}
			u, err := scanUser(tx.QueryRow(`SELECT `+userColumns+` FROM users WHERE id=?`, uid))
			if err != nil || u == nil {
				return err
			}
			payload, err := scimUserPayloadTx(tx, u, true, app.SystemID)
			if err != nil {
				return err
			}
			if err := queueDesiredStateTx(tx, desiredState{systemID: app.SystemID, resourceID: uid, kind: "user", active: true, payload: payload}, now); err != nil {
				return err
			}
		}
	}
	return nil
}

// GetAppRecord reads one app record with its connections and settings.
func (s *Store) GetAppRecord(id string) (AppRecord, error) {
	return scanAppRecord(s.db.QueryRow(appRecordSelect+appRecordFrom+` WHERE a.id=?`, id))
}

func lockAppForRoles(tx *sql.Tx, appID string) (AppRecord, error) {
	if _, err := tx.Exec(`UPDATE app_registry SET revision=revision WHERE id=?`, appID); err != nil {
		return AppRecord{}, err
	}
	return scanAppRecord(tx.QueryRow(appRecordSelect+appRecordFrom+` WHERE a.id=?`, appID))
}

func (s *Store) CreateAppRole(appID, name, description string, audit *AuditEvent) (*AppRole, error) {
	name, description = strings.TrimSpace(name), strings.TrimSpace(description)
	if !roleName.MatchString(name) || len(description) > 512 {
		return nil, ErrAppRoleInvalid
	}
	role := &AppRole{ID: uuid.NewString(), AppID: appID, Name: name, Description: description, CreatedAt: time.Now().UTC(), Users: []AppRolePrincipal{}, Groups: []AppRolePrincipal{}}
	err := s.auditedTx(audit, func(tx *sql.Tx) error {
		app, err := lockAppForRoles(tx, appID)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO app_roles(id,app_id,name,description,created_at) VALUES(?,?,?,?,?)`, role.ID, appID, name, description, role.CreatedAt); err != nil {
			if isUniqueViolation(err) {
				return ErrAppRoleExists
			}
			return err
		}
		// The first role switches the connection from the global role to app roles:
		// everyone provisioned there is re-sent with their (empty) app roles.
		if err := appRoleShapeChangeTx(tx, app, 1, role.CreatedAt); err != nil {
			return err
		}
		return appRegistryAudit(audit, map[string]any{"app": app.ID, "roleId": role.ID, "name": name})
	})
	if err != nil {
		return nil, err
	}
	return role, nil
}

// appRoleShapeChangeTx runs the role follow-up for every user with access to the app
// when its role count has just become boundary: the payload shape changed for all of
// them, not only for role holders.
func appRoleShapeChangeTx(tx *sql.Tx, app AppRecord, boundary int, now time.Time) error {
	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM app_roles WHERE app_id=?`, app.ID).Scan(&count); err != nil {
		return err
	}
	if count != boundary {
		if _, err := tx.Exec(`UPDATE app_registry SET revision=revision+1 WHERE id=?`, app.ID); err != nil {
			return err
		}
		return nil
	}
	users, err := scanStrings(tx.Query(`SELECT DISTINCT user_id FROM effective_app_access WHERE app_id=?`, app.ID))
	if err != nil {
		return err
	}
	return roleChangeTx(tx, app, users, now)
}

// roleHoldersTx lists every user who holds the role directly or through a group.
func roleHoldersTx(tx *sql.Tx, roleID string) ([]string, error) {
	return scanStrings(tx.Query(`SELECT user_id FROM app_role_user_assignments WHERE role_id=?
 UNION SELECT m.user_id FROM app_role_group_assignments a JOIN group_memberships m ON m.group_id=a.group_id WHERE a.role_id=?`, roleID, roleID))
}

func (s *Store) DeleteAppRole(appID, roleID string, audit *AuditEvent) error {
	now := time.Now().UTC()
	return s.auditedTx(audit, func(tx *sql.Tx) error {
		app, err := lockAppForRoles(tx, appID)
		if err != nil {
			return err
		}
		holders, err := roleHoldersTx(tx, roleID)
		if err != nil {
			return err
		}
		var name string
		if err := tx.QueryRow(`DELETE FROM app_roles WHERE id=? AND app_id=? RETURNING name`, roleID, appID).Scan(&name); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrAppRecordMissing
			}
			return err
		}
		if err := roleChangeTx(tx, app, holders, now); err != nil {
			return err
		}
		// The last role going returns the connection to the global role for everyone.
		if err := appRoleShapeChangeTx(tx, app, 0, now); err != nil {
			return err
		}
		return appRegistryAudit(audit, map[string]any{"app": app.ID, "roleId": roleID, "name": name, "affectedUsers": len(holders)})
	})
}

// SetAppRoleAssignment maps a user or a group to a role, or unmaps it. The users whose
// effective roles change lose their live grants for the app.
func (s *Store) SetAppRoleAssignment(appID, roleID, kind, principal string, assigned bool, audit *AuditEvent) error {
	table, column, source, name := "", "", "", ""
	switch kind {
	case "users":
		table, column, source, name = "app_role_user_assignments", "user_id", "users", "username"
	case "groups":
		table, column, source, name = "app_role_group_assignments", "group_id", "directory_groups", "name"
	default:
		return ErrAppLinkConflict
	}
	now := time.Now().UTC()
	return s.auditedTx(audit, func(tx *sql.Tx) error {
		app, err := lockAppForRoles(tx, appID)
		if err != nil {
			return err
		}
		var roleLabel, principalName string
		if err := tx.QueryRow(`SELECT name FROM app_roles WHERE id=? AND app_id=?`, roleID, appID).Scan(&roleLabel); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrAppRecordMissing
			}
			return err
		}
		if err := tx.QueryRow(`SELECT `+name+` FROM `+source+` WHERE id=?`, principal).Scan(&principalName); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrAppRecordMissing
			}
			return err
		}
		var res sql.Result
		if assigned {
			res, err = tx.Exec(`INSERT INTO `+table+`(role_id,`+column+`) VALUES(?,?) ON CONFLICT DO NOTHING`, roleID, principal)
		} else {
			res, err = tx.Exec(`DELETE FROM `+table+` WHERE role_id=? AND `+column+`=?`, roleID, principal)
		}
		if err != nil {
			return err
		}
		affected := []string{principal}
		if kind == "groups" {
			if affected, err = scanStrings(tx.Query(`SELECT user_id FROM group_memberships WHERE group_id=?`, principal)); err != nil {
				return err
			}
		}
		if changed, _ := res.RowsAffected(); changed > 0 {
			if err := roleChangeTx(tx, app, affected, now); err != nil {
				return err
			}
		}
		return appRegistryAudit(audit, map[string]any{"app": app.ID, "roleId": roleID, "role": roleLabel, "kind": kind, "principalId": principal, "principalName": principalName, "assigned": assigned})
	})
}

// SetAppClaimSettings decides which claims the app's tokens carry beyond its roles: the
// legacy global role, and the names of its assigned groups the user belongs to. A
// change alters the token shape, so every live grant for the app is revoked.
func (s *Store) SetAppClaimSettings(appID string, legacyRole, groupsClaim bool, revision int, audit *AuditEvent) error {
	now := time.Now().UTC()
	return s.auditedTx(audit, func(tx *sql.Tx) error {
		app, err := lockAppRecord(tx, appID, revision)
		if err != nil {
			return err
		}
		if app.LegacyRoleClaim == legacyRole && app.GroupsClaim == groupsClaim {
			return appRegistryAudit(audit, map[string]any{"app": app.ID, "unchanged": true})
		}
		if _, err := tx.Exec(`UPDATE app_registry SET legacy_role_claim=?,groups_claim=?,role_revision=role_revision+1,revision=revision+1 WHERE id=?`, legacyRole, groupsClaim, appID); err != nil {
			return err
		}
		if app.ClientID != "" {
			if _, err := tx.Exec(`DELETE FROM authorization_codes WHERE client_id=?`, app.ClientID); err != nil {
				return err
			}
			if _, err := tx.Exec(`UPDATE issued_tokens SET revoked_at=? WHERE client_id=? AND revoked_at IS NULL`, now, app.ClientID); err != nil {
				return err
			}
		}
		return appRegistryAudit(audit, map[string]any{"app": app.ID, "legacyRoleClaim": legacyRole, "groupsClaim": groupsClaim})
	})
}

// AppClaims is what one app's token may say about a user beyond identity: the app's
// roles the user holds, and, when the app asks for it, the assigned groups they are in.
type AppClaims struct {
	Roles       []string
	Groups      []string
	LegacyRole  bool
	GroupsClaim bool
}

func appClaimsTx(tx *sql.Tx, userID, appID string) (AppClaims, error) {
	var c AppClaims
	if err := tx.QueryRow(`SELECT legacy_role_claim, groups_claim FROM app_registry WHERE id=?`, appID).Scan(&c.LegacyRole, &c.GroupsClaim); err != nil {
		return c, err
	}
	roles, err := scanStrings(tx.Query(`SELECT DISTINCT r.name FROM app_roles r WHERE r.app_id=? AND (
 EXISTS(SELECT 1 FROM app_role_user_assignments a WHERE a.role_id=r.id AND a.user_id=?)
 OR EXISTS(SELECT 1 FROM app_role_group_assignments a JOIN group_memberships m ON m.group_id=a.group_id WHERE a.role_id=r.id AND m.user_id=?))`, appID, userID, userID))
	if err != nil {
		return c, err
	}
	sort.Strings(roles)
	c.Roles = roles
	if c.GroupsClaim {
		// The app's allowed groups are the ones assigned to it or mapped to one of its
		// roles; the user's other groups are none of the app's business.
		groups, err := scanStrings(tx.Query(`SELECT DISTINCT g.name FROM directory_groups g JOIN group_memberships m ON m.group_id=g.id WHERE m.user_id=? AND (
 EXISTS(SELECT 1 FROM app_group_assignments a WHERE a.app_id=? AND a.group_id=g.id)
 OR EXISTS(SELECT 1 FROM app_role_group_assignments ra JOIN app_roles r ON r.id=ra.role_id WHERE r.app_id=? AND ra.group_id=g.id))`, userID, appID, appID))
		if err != nil {
			return c, err
		}
		sort.Strings(groups)
		c.Groups = groups
	}
	return c, nil
}

// UserAppClaims resolves the claims a token for clientID may carry about userID. A
// client with no app record yields nothing but the legacy role.
func (s *Store) UserAppClaims(userID, clientID string) (AppClaims, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return AppClaims{}, err
	}
	defer tx.Rollback()
	var appID string
	err = tx.QueryRow(`SELECT id FROM app_registry WHERE client_id=?`, clientID).Scan(&appID)
	if errors.Is(err, sql.ErrNoRows) {
		return AppClaims{LegacyRole: true}, tx.Commit()
	}
	if err != nil {
		return AppClaims{}, err
	}
	c, err := appClaimsTx(tx, userID, appID)
	if err != nil {
		return AppClaims{}, err
	}
	return c, tx.Commit()
}

// scimUserPayloadTx builds the SCIM profile for one provisioning connection. When the
// app behind that connection defines roles, the payload carries the user's roles for
// that app; otherwise the global role, as before roles existed.
func scimUserPayloadTx(tx *sql.Tx, u *User, active bool, systemID string) ([]byte, error) {
	var appID string
	err := tx.QueryRow(`SELECT id FROM app_registry WHERE system_id=? AND EXISTS(SELECT 1 FROM app_roles r WHERE r.app_id=app_registry.id)`, systemID).Scan(&appID)
	if errors.Is(err, sql.ErrNoRows) {
		return scimUserPayload(u, active)
	}
	if err != nil {
		return nil, err
	}
	claims, err := appClaimsTx(tx, u.ID, appID)
	if err != nil {
		return nil, err
	}
	roles := make([]scim.MultiValue, 0, len(claims.Roles))
	for i, r := range claims.Roles {
		roles = append(roles, scim.MultiValue{Value: r, Primary: i == 0})
	}
	return scimUserPayloadWithRoles(u, active, roles)
}
