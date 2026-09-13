package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"modernc.org/sqlite"
)

var ErrGroupNameExists = errors.New("group name already exists")
var ErrGroupSourceOwned = errors.New("group name is managed by its SCIM connector")
var ErrGroupTargetMissing = errors.New("group or user not found")

type Group struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	// SourceConnectorID names the inbound SCIM connector that owns the group's name and
	// member set; empty for local groups. ExternalID is the upstream's key, when it sent one.
	SourceConnectorID string    `json:"sourceConnectorId,omitempty"`
	ExternalID        string    `json:"externalId,omitempty"`
	MemberCount       int       `json:"memberCount"`
	Member            bool      `json:"member"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

type GroupUser struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
	Status      string `json:"status"`
	Member      bool   `json:"member"`
}

func groupWriteError(err error) error {
	var sqliteErr *sqlite.Error
	if errors.As(err, &sqliteErr) {
		switch sqliteErr.Code() {
		case 2067:
			return ErrGroupNameExists // SQLITE_CONSTRAINT_UNIQUE
		case 787:
			return ErrGroupTargetMissing // SQLITE_CONSTRAINT_FOREIGNKEY
		}
	}
	return err
}

func (s *Store) CreateGroup(g *Group, audit *AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	g.CreatedAt = time.Now().UTC()
	g.UpdatedAt = g.CreatedAt
	if _, err = tx.Exec(`INSERT INTO directory_groups(id,name,description,created_at,updated_at) VALUES (?,?,?,?,?)`, g.ID, g.Name, g.Description, g.CreatedAt, g.UpdatedAt); err != nil {
		return groupWriteError(err)
	}
	if err = recordAuditTx(tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) UpdateGroup(g *Group, audit *AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	g.UpdatedAt = time.Now().UTC()
	var sourceOwned bool
	if err = tx.QueryRow(`SELECT source_connector_id IS NOT NULL AND name<>? FROM directory_groups WHERE id=?`, g.Name, g.ID).Scan(&sourceOwned); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if sourceOwned {
		return ErrGroupSourceOwned
	}
	result, err := tx.Exec(`UPDATE directory_groups SET name=?,description=?,updated_at=? WHERE id=?`, g.Name, g.Description, g.UpdatedAt, g.ID)
	if err != nil {
		return groupWriteError(err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrGroupTargetMissing
	}
	if err = reconcileProvisioningTx(tx, g.UpdatedAt); err != nil {
		return err
	}
	if err = recordAuditTx(tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteGroup(id string, audit *AuditEvent) error {
	return s.DeleteGroupForSession(id, "", audit)
}

func (s *Store) DeleteGroupForSession(id, sessionID string, audit *AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	name, err := deleteGroupTx(tx, id, sessionID)
	if err != nil {
		return err
	}
	setGroupAuditDetails(audit, map[string]string{"name": name})
	if err = recordAuditTx(tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

// deleteGroupTx removes a group with its memberships and policy, revoking what those
// memberships granted. Users are never touched. It returns the deleted group's name.
func deleteGroupTx(tx *sql.Tx, id, sessionID string) (string, error) {
	var err error
	// Revoke while memberships and policy still exist; cascades remove both below.
	for _, query := range []string{
		`DELETE FROM authorization_codes WHERE user_id IN (SELECT m.user_id FROM group_memberships m JOIN enrollment_policies p ON p.group_id=m.group_id AND p.required WHERE m.group_id=?)`,
		`DELETE FROM authorization_interactions WHERE user_id IN (SELECT m.user_id FROM group_memberships m JOIN enrollment_policies p ON p.group_id=m.group_id AND p.required WHERE m.group_id=?)`,
	} {
		if _, err = tx.Exec(query, id); err != nil {
			return "", err
		}
	}
	if _, err = tx.Exec(`UPDATE issued_tokens SET revoked_at=? WHERE revoked_at IS NULL AND user_id IN (SELECT m.user_id FROM group_memberships m JOIN enrollment_policies p ON p.group_id=m.group_id AND p.required WHERE m.group_id=?)`, time.Now().UTC(), id); err != nil {
		return "", err
	}

	// The preceding grant writes hold the writer lock. Check login evidence before
	// cascading away the policy; step-up alone cannot authorize this relaxation.
	var required bool
	if err = tx.QueryRow(`SELECT required FROM enrollment_policies WHERE group_id=?`, id).Scan(&required); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrGroupTargetMissing
		}
		return "", err
	}
	if required {
		preview, err := previewEnrollmentTx(tx, sessionID, "")
		if err != nil {
			return "", err
		}
		if !preview.CanActivate {
			return "", ErrEmergencyAdministrator
		}
	}
	// Deleting the group ends every role its members held through it; the follow-up runs
	// once the cascade has removed the memberships and mappings it must not see.
	apps, err := mappedRoleApps(tx, id)
	if err != nil {
		return "", err
	}
	members, err := scanStrings(tx.Query(`SELECT user_id FROM group_memberships WHERE group_id=?`, id))
	if err != nil {
		return "", err
	}
	var name string
	if err = tx.QueryRow(`DELETE FROM directory_groups WHERE id=? RETURNING name`, id).Scan(&name); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrGroupTargetMissing
		}
		return "", err
	}
	if err = roleChangeForAppsTx(tx, apps, members); err != nil {
		return "", err
	}
	if err = revokeLostAppAccessTx(tx); err != nil {
		return "", err
	}
	if err = reconcileProvisioningTx(tx, time.Now().UTC()); err != nil {
		return "", err
	}
	return name, nil
}

// Individual membership writes cannot overwrite another administrator's edits.
// Repeating either desired state is idempotent; each accepted request is audited.
func (s *Store) SetGroupMembership(groupID, userID string, member bool, audit *AuditEvent) error {
	return s.SetGroupMembershipForSession(groupID, userID, member, "", audit)
}

func (s *Store) SetGroupMembershipForSession(groupID, userID string, member bool, sessionID string, audit *AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	groupName, username, err := setGroupMembershipTx(tx, groupID, userID, member, sessionID)
	if err != nil {
		return err
	}
	setGroupAuditDetails(audit, map[string]string{"userId": userID, "username": username, "groupName": groupName})
	if err = recordAuditTx(tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

// setGroupMembershipTx applies one membership change with its policy checks and the
// grant/provisioning follow-up, returning the names for the audit row.
func setGroupMembershipTx(tx *sql.Tx, groupID, userID string, member bool, sessionID string) (groupName, username string, err error) {
	if groupName, username, err = applyGroupMembershipTx(tx, groupID, userID, member, sessionID); err != nil {
		return "", "", err
	}
	return groupName, username, reconcileAccessTx(tx)
}

// reconcileAccessTx is the whole-directory follow-up to any membership change: revoke
// grants that no longer have a source and converge downstream desired state. It is
// set-based, so one run after a batch of changes yields the same state as one per change.
func reconcileAccessTx(tx *sql.Tx) error {
	if err := revokeLostAppAccessTx(tx); err != nil {
		return err
	}
	return reconcileProvisioningTx(tx, time.Now().UTC())
}

// applyGroupMembershipTx writes one membership row with its policy checks and nothing
// else; the caller owes a reconcileAccessTx before committing.
func applyGroupMembershipTx(tx *sql.Tx, groupID, userID string, member bool, sessionID string) (groupName, username string, err error) {
	var result sql.Result
	if member {
		result, err = tx.Exec(`INSERT INTO group_memberships(group_id,user_id) VALUES (?,?) ON CONFLICT(group_id,user_id) DO NOTHING`, groupID, userID)
	} else {
		result, err = tx.Exec(`DELETE FROM group_memberships WHERE group_id=? AND user_id=?`, groupID, userID)
	}
	if err != nil {
		return "", "", groupWriteError(err)
	}
	// The preceding write acquires the writer lock before checking either parent.
	if err = tx.QueryRow(`SELECT g.name,u.username FROM directory_groups g CROSS JOIN users u WHERE g.id=? AND u.id=?`, groupID, userID).Scan(&groupName, &username); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", ErrGroupTargetMissing
		}
		return "", "", err
	}
	var required bool
	if err = tx.QueryRow(`SELECT required FROM enrollment_policies WHERE group_id=?`, groupID).Scan(&required); err != nil {
		return "", "", err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return "", "", err
	}
	if required && changed > 0 {
		var compatible bool
		if err = tx.QueryRow(`SELECT allowed_mask<>0 FROM enrollment_requirements WHERE user_id=?`, userID).Scan(&compatible); err != nil {
			return "", "", err
		}
		if !compatible {
			return "", "", ErrEnrollmentPolicy
		}
		preview, err := previewEnrollmentTx(tx, sessionID, "")
		if err != nil {
			return "", "", err
		}
		if !preview.CanActivate {
			return "", "", ErrEmergencyAdministrator
		}
		if err = invalidateUserEnrollmentTx(tx, userID); err != nil {
			return "", "", err
		}
	}
	if changed > 0 {
		if err = groupRoleChangeTx(tx, groupID, []string{userID}); err != nil {
			return "", "", err
		}
	}
	return groupName, username, nil
}

// mappedRoleApps lists the apps with a role mapped to the group.
func mappedRoleApps(tx *sql.Tx, groupID string) ([]AppRecord, error) {
	ids, err := scanStrings(tx.Query(`SELECT DISTINCT r.app_id FROM app_role_group_assignments a JOIN app_roles r ON r.id=a.role_id WHERE a.group_id=?`, groupID))
	if err != nil {
		return nil, err
	}
	apps := make([]AppRecord, 0, len(ids))
	for _, id := range ids {
		app, err := scanAppRecord(tx.QueryRow(appRecordSelect+appRecordFrom+` WHERE a.id=?`, id))
		if err != nil {
			return nil, err
		}
		apps = append(apps, app)
	}
	return apps, nil
}

// groupRoleChangeTx runs the role follow-up for every app that maps the group to one
// of its roles: joining or leaving such a group changes those users' roles there.
func groupRoleChangeTx(tx *sql.Tx, groupID string, users []string) error {
	apps, err := mappedRoleApps(tx, groupID)
	if err != nil {
		return err
	}
	return roleChangeForAppsTx(tx, apps, users)
}

func roleChangeForAppsTx(tx *sql.Tx, apps []AppRecord, users []string) error {
	if len(users) == 0 {
		return nil
	}
	now := time.Now().UTC()
	for _, app := range apps {
		if err := roleChangeTx(tx, app, users, now); err != nil {
			return err
		}
	}
	return nil
}

// Count and page share a read snapshot. userID optionally annotates membership for
// the user-management view without downloading the entire directory.
// ponytail: substring searches scan names; add FTS if large-directory searches become slow.
func (s *Store) ListGroups(query, userID string, limit, offset int) ([]Group, int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	if userID != "" {
		var exists bool
		if err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM users WHERE id=?)`, userID).Scan(&exists); err != nil {
			return nil, 0, err
		}
		if !exists {
			return nil, 0, ErrGroupTargetMissing
		}
	}
	where := ` WHERE instr(lower(g.name),lower(?))>0`
	var total int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM directory_groups g`+where, query).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := tx.Query(`SELECT g.id,g.name,g.description,g.source_connector_id,g.external_id,g.created_at,g.updated_at,
 (SELECT COUNT(*) FROM group_memberships m WHERE m.group_id=g.id),
 EXISTS(SELECT 1 FROM group_memberships m WHERE m.group_id=g.id AND m.user_id=?)
 FROM directory_groups g`+where+` ORDER BY g.name COLLATE NOCASE,g.id LIMIT ? OFFSET ?`, userID, query, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	groups := []Group{}
	for rows.Next() {
		var g Group
		var source, external sql.NullString
		if err = rows.Scan(&g.ID, &g.Name, &g.Description, &source, &external, &g.CreatedAt, &g.UpdatedAt, &g.MemberCount, &g.Member); err != nil {
			rows.Close()
			return nil, 0, err
		}
		g.SourceConnectorID, g.ExternalID = source.String, external.String
		groups = append(groups, g)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, 0, err
	}
	return groups, total, tx.Commit()
}

func (s *Store) ListGroupUsers(groupID, query string, includeNonMembers bool, limit, offset int) ([]GroupUser, int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	var exists bool
	if err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM directory_groups WHERE id=?)`, groupID).Scan(&exists); err != nil {
		return nil, 0, err
	}
	if !exists {
		return nil, 0, ErrGroupTargetMissing
	}
	from := ` FROM users u LEFT JOIN group_memberships m ON m.user_id=u.id AND m.group_id=?
 WHERE (? OR m.user_id IS NOT NULL) AND (instr(lower(u.username),lower(?))>0 OR instr(lower(u.display_name),lower(?))>0 OR instr(lower(u.email),lower(?))>0)`
	args := []any{groupID, includeNonMembers, query, query, query}
	var total int
	if err = tx.QueryRow(`SELECT COUNT(*)`+from, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := tx.Query(`SELECT u.id,u.username,u.display_name,u.email,u.status,m.user_id IS NOT NULL`+from+` ORDER BY u.username COLLATE NOCASE,u.id LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	users := []GroupUser{}
	for rows.Next() {
		var u GroupUser
		if err = rows.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Email, &u.Status, &u.Member); err != nil {
			rows.Close()
			return nil, 0, err
		}
		users = append(users, u)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, 0, err
	}
	return users, total, tx.Commit()
}

// Capture readable identifiers while holding the mutation's writer lock, so renames
// and deletion cannot leave the audit referring to a different version of the target.
func setGroupAuditDetails(audit *AuditEvent, details map[string]string) {
	if audit != nil {
		encoded, _ := json.Marshal(details) // String maps cannot fail JSON encoding.
		audit.DetailsJSON = string(encoded)
	}
}
