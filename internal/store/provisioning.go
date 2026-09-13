package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Busness-app/ky-primitives/scim"
	"github.com/google/uuid"
)

const scimGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"

// sync_resource_state holds the desired downstream state per connector/resource and the
// revision every event for that resource carries. provisioned records that the receiver
// acknowledged a create or update, so a loss before then drops the create instead of
// disabling an account that never existed. Existing pairs are backfilled as provisioned
// because delivery covered the whole directory before this table existed.
func (s *Store) migrateProvisioning() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, c := range []struct{ probe, ddl string }{
		{`SELECT COUNT(*) FROM pragma_table_info('paired_systems') WHERE name='groups_enabled'`, `ALTER TABLE paired_systems ADD COLUMN groups_enabled BOOLEAN NOT NULL DEFAULT 0`},
		{`SELECT COUNT(*) FROM pragma_table_info('account_sync_events') WHERE name='revision'`, `ALTER TABLE account_sync_events ADD COLUMN revision INTEGER NOT NULL DEFAULT 0`},
		{`SELECT COUNT(*) FROM pragma_table_info('scim_user_links') WHERE name='kind'`, `ALTER TABLE scim_user_links ADD COLUMN kind TEXT NOT NULL DEFAULT 'user';
 DROP INDEX IF EXISTS scim_remote_user;
 CREATE UNIQUE INDEX scim_remote_resource ON scim_user_links(system_id,kind,remote_id) WHERE remote_id<>''`},
		{`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='sync_resource_state'`, `CREATE TABLE sync_resource_state (
 system_id TEXT NOT NULL REFERENCES paired_systems(id) ON DELETE CASCADE,
 resource_id TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'user',
 active BOOLEAN NOT NULL, provisioned BOOLEAN NOT NULL DEFAULT 0,
 revision INTEGER NOT NULL DEFAULT 0, members TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(system_id,resource_id));
 INSERT INTO sync_resource_state(system_id,resource_id,active,provisioned,revision)
 SELECT a.system_id,e.user_id,1,1,1 FROM effective_app_access e JOIN app_registry a ON a.id=e.app_id WHERE a.system_id IS NOT NULL`},
		// offboarded_at is the durable acknowledgement of a deactivation or deletion; the
		// outbox row that carried it is pruned, this is not.
		{`SELECT COUNT(*) FROM pragma_table_info('sync_resource_state') WHERE name='offboarded_at'`, `ALTER TABLE sync_resource_state ADD COLUMN offboarded_at DATETIME`},
	} {
		var n int
		if err = tx.QueryRow(c.probe).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			if _, err = tx.Exec(c.ddl); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func scimUserPayload(u *User, active bool) ([]byte, error) {
	res := scim.User{
		Schemas: []string{scim.UserSchema}, ID: u.ID, ExternalID: u.ID, UserName: u.Username,
		DisplayName: u.DisplayName, Name: &scim.Name{Formatted: u.DisplayName}, Active: active,
		Meta: &scim.Meta{ResourceType: "User", Created: &u.CreatedAt, LastModified: &u.UpdatedAt},
	}
	if u.Email != "" {
		res.Emails = []scim.MultiValue{{Value: u.Email, Type: "work", Primary: true}}
	}
	if u.Role != "" {
		res.Roles = []scim.MultiValue{{Value: u.Role, Primary: true}}
	}
	return json.Marshal(res)
}

// A deleted or unknown user still needs a body the receiver can act on.
func scimInactivePayload(userID string) []byte {
	b, _ := json.Marshal(scim.User{Schemas: []string{scim.UserSchema}, ID: userID, ExternalID: userID, Active: false})
	return b
}

func scimGroupPayload(groupID string) []byte {
	b, _ := json.Marshal(map[string]any{"schemas": []string{scimGroupSchema}, "id": groupID, "externalId": groupID})
	return b
}

const userColumns = `id, username, display_name, email, password_hash, role, status, pending, email_verified_at, created_at, updated_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	u := &User{}
	var verified sql.NullTime
	err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Email, &u.PasswordHash, &u.Role, &u.Status, &u.Pending, &verified, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if verified.Valid {
		at := verified.Time
		u.EmailVerifiedAt = &at
	}
	return u, err
}

type desiredState struct {
	systemID, resourceID, kind string
	active                     bool
	payload                    []byte
	members                    string
	// force sends even when the receiver already holds this state (resync); for users
	// it sends user.created so a missing suite account is recreated.
	force bool
	// deleted announces removal from the directory instead of an inactive profile.
	deleted bool
}

// queueDesiredStateTx records the new desired state and the outbox work that delivers it.
// Unfenced desired-state work for the resource is superseded; a fenced attempt keeps its
// place and the new event queues behind it.
func queueDesiredStateTx(tx *sql.Tx, d desiredState, now time.Time) error {
	var provisioned, fenced bool
	if err := tx.QueryRow(`SELECT COALESCE((SELECT provisioned FROM sync_resource_state WHERE system_id=? AND resource_id=?),0),
 EXISTS(SELECT 1 FROM sync_delivery_attempts WHERE system_id=? AND user_id=?)`, d.systemID, d.resourceID, d.systemID, d.resourceID).Scan(&provisioned, &fenced); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM account_sync_events WHERE system_id=? AND user_id=? AND status IN ('pending','failed')
 AND event_type IN ('user.created','user.updated','group.updated','group.deleted')
 AND NOT EXISTS(SELECT 1 FROM sync_delivery_attempts a WHERE a.event_id=account_sync_events.id)`, d.systemID, d.resourceID); err != nil {
		return err
	}
	if !d.active && !provisioned && !fenced {
		// Nothing downstream has heard of this resource; forget it rather than disable a ghost.
		_, err := tx.Exec(`DELETE FROM sync_resource_state WHERE system_id=? AND resource_id=?`, d.systemID, d.resourceID)
		return err
	}
	var revision int
	if err := tx.QueryRow(`INSERT INTO sync_resource_state(system_id,resource_id,kind,active,revision,members) VALUES(?,?,?,?,1,?)
 ON CONFLICT(system_id,resource_id) DO UPDATE SET active=excluded.active,revision=revision+1,members=excluded.members,offboarded_at=NULL RETURNING revision`,
		d.systemID, d.resourceID, d.kind, d.active, d.members).Scan(&revision); err != nil {
		return err
	}
	eventType := "user.updated"
	switch {
	case d.deleted:
		eventType = "user.deleted"
	case d.kind == "group" && d.active:
		eventType = "group.updated"
	case d.kind == "group":
		eventType = "group.deleted"
	case d.active && (!provisioned || d.force):
		eventType = "user.created"
	}
	return insertResourceEventTx(tx, d.systemID, d.resourceID, eventType, d.payload, revision, now)
}

func insertResourceEventTx(tx *sql.Tx, systemID, resourceID, eventType string, payload []byte, revision int, now time.Time) error {
	_, err := tx.Exec(`INSERT INTO account_sync_events (id, user_id, system_id, event_type, payload_json, attempts, status, created_at, updated_at, revision) VALUES (?, ?, ?, ?, ?, 0, 'pending', ?, ?, ?)`,
		uuid.New().String(), resourceID, systemID, eventType, string(payload), now, now, revision)
	return err
}

// queueUserNotificationTx sends an event that carries no desired state (MFA reset) to
// every connector that currently holds the account. It neither supersedes nor is superseded.
func queueUserNotificationTx(tx *sql.Tx, u *User, eventType string, now time.Time) error {
	payload, err := scimUserPayload(u, u.Status == "active")
	if err != nil {
		return err
	}
	rows, err := tx.Query(`SELECT st.system_id,st.revision FROM sync_resource_state st JOIN paired_systems s ON s.id=st.system_id
 WHERE st.resource_id=? AND st.kind='user' AND st.active AND s.status<>'disabled'`, u.ID)
	if err != nil {
		return err
	}
	type target struct {
		id  string
		rev int
	}
	var targets []target
	for rows.Next() {
		var t target
		if err := rows.Scan(&t.id, &t.rev); err != nil {
			rows.Close()
			return err
		}
		targets = append(targets, t)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, t := range targets {
		if err := insertResourceEventTx(tx, t.id, u.ID, eventType, payload, t.rev, now); err != nil {
			return err
		}
	}
	return nil
}

// queueUserUpdateTx delivers a profile change to every connector where the account is
// desired and stays desired. Scope transitions are reconcileProvisioningTx's job.
func queueUserUpdateTx(tx *sql.Tx, u *User, now time.Time) error {
	systems, err := scanStrings(tx.Query(`SELECT st.system_id FROM sync_resource_state st JOIN paired_systems s ON s.id=st.system_id
 WHERE st.resource_id=? AND st.kind='user' AND st.active AND s.status<>'disabled'
 AND EXISTS(SELECT 1 FROM effective_app_access e JOIN app_registry a ON a.id=e.app_id WHERE a.system_id=st.system_id AND e.user_id=st.resource_id)`, u.ID))
	if err != nil {
		return err
	}
	payload, err := scimUserPayload(u, true)
	if err != nil {
		return err
	}
	for _, sys := range systems {
		if err := queueDesiredStateTx(tx, desiredState{systemID: sys, resourceID: u.ID, kind: "user", active: true, payload: payload}, now); err != nil {
			return err
		}
	}
	return nil
}

func scanStrings(rows *sql.Rows, err error) ([]string, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

type resourcePair struct{ systemID, resourceID string }

func scanPairs(rows *sql.Rows, err error) ([]resourcePair, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []resourcePair
	for rows.Next() {
		var p resourcePair
		if err := rows.Scan(&p.systemID, &p.resourceID); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// reconcileProvisioningTx queues the work that moves every connector from its recorded
// desired state to the state effective access now implies. It runs inside each access
// mutation and periodically from the worker, so cascades that bypass a mutation path
// (client deletion, foreign-key cascades) still converge.
func reconcileProvisioningTx(tx *sql.Tx, now time.Time) error {
	gains, err := scanPairs(tx.Query(`SELECT s.id,u.id FROM paired_systems s JOIN app_registry a ON a.system_id=s.id
 JOIN effective_app_access e ON e.app_id=a.id JOIN users u ON u.id=e.user_id
 LEFT JOIN sync_resource_state st ON st.system_id=s.id AND st.resource_id=u.id
 WHERE s.status<>'disabled' AND (st.resource_id IS NULL OR NOT st.active) ORDER BY s.id,u.id`))
	if err != nil {
		return err
	}
	losses, err := scanPairs(tx.Query(`SELECT st.system_id,st.resource_id FROM sync_resource_state st JOIN paired_systems s ON s.id=st.system_id
 WHERE st.kind='user' AND st.active AND s.status<>'disabled'
 AND NOT EXISTS(SELECT 1 FROM effective_app_access e JOIN app_registry a ON a.id=e.app_id WHERE a.system_id=st.system_id AND e.user_id=st.resource_id)
 ORDER BY st.system_id,st.resource_id`))
	if err != nil {
		return err
	}
	for _, p := range gains {
		u, err := scanUser(tx.QueryRow(`SELECT `+userColumns+` FROM users WHERE id=?`, p.resourceID))
		if err != nil || u == nil {
			return err
		}
		payload, err := scimUserPayload(u, true)
		if err != nil {
			return err
		}
		if err := queueDesiredStateTx(tx, desiredState{systemID: p.systemID, resourceID: p.resourceID, kind: "user", active: true, payload: payload}, now); err != nil {
			return err
		}
	}
	for _, p := range losses {
		u, err := scanUser(tx.QueryRow(`SELECT `+userColumns+` FROM users WHERE id=?`, p.resourceID))
		if err != nil {
			return err
		}
		payload := scimInactivePayload(p.resourceID)
		if u != nil {
			if payload, err = scimUserPayload(u, false); err != nil {
				return err
			}
		}
		if err := queueDesiredStateTx(tx, desiredState{systemID: p.systemID, resourceID: p.resourceID, kind: "user", active: false, payload: payload}, now); err != nil {
			return err
		}
	}
	if err := reconcileGroupsTx(tx, now, false); err != nil {
		return err
	}
	// Exhausted work that still describes current desired state re-enters backoff: desired
	// state does not lapse because a connector was down. Exhausted work a newer state has
	// overtaken (it survived supersession only because it was fenced) is discarded, exactly
	// as supersession would have done; reviving it would replay an old create after a
	// later disable. Deletion and MFA reset carry no desired state and always retry.
	current := `(SELECT st.revision FROM sync_resource_state st WHERE st.system_id=account_sync_events.system_id AND st.resource_id=account_sync_events.user_id)`
	unfenced := `status='failed' AND NOT EXISTS(SELECT 1 FROM sync_delivery_attempts a WHERE a.event_id=account_sync_events.id)`
	stateless := `event_type IN ('user.deleted','user.mfa_reset')`
	if _, err = tx.Exec(`DELETE FROM account_sync_events WHERE ` + unfenced + ` AND NOT ` + stateless + ` AND revision<>COALESCE(` + current + `,-1)`); err != nil {
		return err
	}
	_, err = tx.Exec(`UPDATE account_sync_events SET status='pending',attempts=0,next_attempt_at=?,updated_at=? WHERE `+unfenced+` AND (`+stateless+` OR revision=`+current+`)`, now.Add(30*time.Minute), now)
	return err
}

type desiredGroup struct{ systemID, groupID, name string }

func desiredGroupsTx(tx *sql.Tx, systemID string) ([]desiredGroup, error) {
	rows, err := tx.Query(`SELECT s.id,g.id,g.name FROM paired_systems s JOIN app_registry a ON a.system_id=s.id
 JOIN app_group_assignments ga ON ga.app_id=a.id JOIN directory_groups g ON g.id=ga.group_id
 WHERE s.groups_enabled AND s.system_type='scim' AND s.status<>'disabled' AND (?='' OR s.id=?) ORDER BY s.id,g.id`, systemID, systemID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []desiredGroup
	for rows.Next() {
		var g desiredGroup
		if err := rows.Scan(&g.systemID, &g.groupID, &g.name); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// The hash covers the name and the in-scope member set, so any change re-queues the
// group once. Delivery reads the live membership again, so a stale snapshot is harmless.
func groupMembersHashTx(tx *sql.Tx, g desiredGroup) (string, error) {
	ids, err := scanStrings(tx.Query(`SELECT m.user_id FROM group_memberships m WHERE m.group_id=?
 AND EXISTS(SELECT 1 FROM effective_app_access e JOIN app_registry a ON a.id=e.app_id WHERE a.system_id=? AND e.user_id=m.user_id) ORDER BY m.user_id`, g.groupID, g.systemID))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(g.name + "\n" + strings.Join(ids, "\n")))
	return hex.EncodeToString(sum[:]), nil
}

// Group delivery is limited to generic SCIM connectors that opted in. Turning the flag
// off leaves remote groups alone; only unassignment or deletion removes one.
func reconcileGroupsTx(tx *sql.Tx, now time.Time, force bool) error {
	desired, err := desiredGroupsTx(tx, "")
	if err != nil {
		return err
	}
	for _, g := range desired {
		hash, err := groupMembersHashTx(tx, g)
		if err != nil {
			return err
		}
		var active bool
		var members string
		err = tx.QueryRow(`SELECT active,members FROM sync_resource_state WHERE system_id=? AND resource_id=?`, g.systemID, g.groupID).Scan(&active, &members)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if force || err != nil || !active || members != hash {
			if err := queueDesiredStateTx(tx, desiredState{systemID: g.systemID, resourceID: g.groupID, kind: "group", active: true, payload: scimGroupPayload(g.groupID), members: hash, force: force}, now); err != nil {
				return err
			}
		}
	}
	lost, err := scanPairs(tx.Query(`SELECT st.system_id,st.resource_id FROM sync_resource_state st JOIN paired_systems s ON s.id=st.system_id
 WHERE st.kind='group' AND st.active AND s.groups_enabled AND s.status<>'disabled'
 AND NOT EXISTS(SELECT 1 FROM app_registry a JOIN app_group_assignments ga ON ga.app_id=a.id WHERE a.system_id=st.system_id AND ga.group_id=st.resource_id)`))
	if err != nil {
		return err
	}
	for _, p := range lost {
		if err := queueDesiredStateTx(tx, desiredState{systemID: p.systemID, resourceID: p.resourceID, kind: "group", active: false, payload: scimGroupPayload(p.resourceID)}, now); err != nil {
			return err
		}
	}
	return nil
}

// ReconcileProvisioning is the worker's safety net for changes that reached effective
// access without passing through a provisioning-aware mutation.
func (s *Store) ReconcileProvisioning() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := reconcileProvisioningTx(tx, time.Now().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

// ResyncSystem re-sends the desired state of everything in scope for one connector.
// It never provisions a user outside the connector's effective access.
func (s *Store) ResyncSystem(systemID string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM paired_systems WHERE id=?)`, systemID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return errors.New("paired system not found")
	}
	now := time.Now().UTC()
	if err := reconcileProvisioningTx(tx, now); err != nil {
		return err
	}
	rows, err := tx.Query(`SELECT `+userColumns+` FROM users WHERE id IN (SELECT resource_id FROM sync_resource_state WHERE system_id=? AND kind='user' AND active) ORDER BY id`, systemID)
	if err != nil {
		return err
	}
	var users []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			rows.Close()
			return err
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, u := range users {
		payload, err := scimUserPayload(u, true)
		if err != nil {
			return err
		}
		if err := queueDesiredStateTx(tx, desiredState{systemID: systemID, resourceID: u.ID, kind: "user", active: true, payload: payload, force: true}, now); err != nil {
			return err
		}
	}
	groups, err := desiredGroupsTx(tx, systemID)
	if err != nil {
		return err
	}
	for _, g := range groups {
		hash, err := groupMembersHashTx(tx, g)
		if err != nil {
			return err
		}
		if err := queueDesiredStateTx(tx, desiredState{systemID: g.systemID, resourceID: g.groupID, kind: "group", active: true, payload: scimGroupPayload(g.groupID), members: hash, force: true}, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SCIMGroupMembers returns what a remote group should hold right now: the group's name and
// the remote IDs of in-scope members that already exist at the target. exists is false
// once the group has been deleted locally; the queued group.deleted follows.
func (s *Store) SCIMGroupMembers(systemID, groupID string) (name string, exists bool, remoteIDs []string, err error) {
	err = s.db.QueryRow(`SELECT name FROM directory_groups WHERE id=?`, groupID).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil, nil
	}
	if err != nil {
		return "", false, nil, err
	}
	remoteIDs, err = scanStrings(s.db.Query(`SELECT l.remote_id FROM group_memberships m
 JOIN scim_user_links l ON l.system_id=? AND l.kind='user' AND l.local_id=m.user_id AND l.remote_id<>''
 WHERE m.group_id=? AND EXISTS(SELECT 1 FROM effective_app_access e JOIN app_registry a ON a.id=e.app_id WHERE a.system_id=? AND e.user_id=m.user_id)
 ORDER BY l.remote_id`, systemID, groupID, systemID))
	if remoteIDs == nil {
		remoteIDs = []string{}
	}
	return name, true, remoteIDs, err
}

// A confirmed first delivery establishes the remote link, so groups holding this user
// are re-queued to pick the member up.
func provisionedTx(tx *sql.Tx, ev AccountSyncEvent, now time.Time) error {
	if ev.EventType == "user.deleted" || ev.EventType == "user.updated" {
		// A delivered inactive state for the current revision is the acknowledgement the
		// offboarding view reads; a newer desired state clears it.
		if _, err := tx.Exec(`UPDATE sync_resource_state SET offboarded_at=? WHERE system_id=? AND resource_id=? AND kind='user' AND NOT active AND revision=?`, now, ev.SystemID, ev.UserID, ev.Revision); err != nil {
			return err
		}
	}
	switch ev.EventType {
	case "user.created", "user.updated", "group.updated":
	case "group.deleted":
		_, err := tx.Exec(`DELETE FROM sync_resource_state WHERE system_id=? AND resource_id=? AND kind='group' AND NOT active`, ev.SystemID, ev.UserID)
		return err
	default:
		return nil
	}
	r, err := tx.Exec(`UPDATE sync_resource_state SET provisioned=1 WHERE system_id=? AND resource_id=? AND NOT provisioned`, ev.SystemID, ev.UserID)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n != 1 || ev.EventType == "group.updated" {
		return nil
	}
	groups, err := desiredGroupsTx(tx, ev.SystemID)
	if err != nil {
		return err
	}
	for _, g := range groups {
		var member bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM group_memberships WHERE group_id=? AND user_id=?)`, g.groupID, ev.UserID).Scan(&member); err != nil {
			return err
		}
		if !member {
			continue
		}
		hash, err := groupMembersHashTx(tx, g)
		if err != nil {
			return err
		}
		if err := queueDesiredStateTx(tx, desiredState{systemID: g.systemID, resourceID: g.groupID, kind: "group", active: true, payload: scimGroupPayload(g.groupID), members: hash, force: true}, now); err != nil {
			return err
		}
	}
	return nil
}
