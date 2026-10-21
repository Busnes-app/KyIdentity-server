package store

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// PasswordChangeMigrationSetting marks that existing accounts were checked once for a
// bootstrap password that was never replaced. Later starts never re-evaluate them.
const PasswordChangeMigrationSetting = "password_change_required_migrated"

// bootstrapPasswordUnchangedSQL selects the bootstrap administrator still on the password
// it was created with. Identity: an admin.user_created row by the "bootstrap" actor, or,
// once retention has pruned every creation row for the account, an administrator whose row
// was never modified. Unchanged: no later success row that could have set a password
// (user.password_changed, auth.password_reset, or an admin.user_updated that revoked access
// or predates that detail); for the pruned case, updated_at still equals created_at.
// Retention deletes oldest first, so a surviving creation row means every later row
// survives too. Setup-owned and upstream-owned accounts are never selected.
const bootstrapPasswordUnchangedSQL = `SELECT u.id, u.username FROM users u
 WHERE u.role='admin' AND NOT u.pending AND NOT u.password_change_required AND u.password_hash<>''
 AND u.source_connector_id IS NULL
 AND NOT EXISTS(SELECT 1 FROM installer_setup_resources r WHERE r.kind='user' AND r.object_id=u.id)
 AND ((EXISTS(SELECT 1 FROM audit_events a WHERE a.action='admin.user_created' AND a.outcome='success' AND a.actor_username='bootstrap' AND a.target_id=u.id)
   AND NOT EXISTS(SELECT 1 FROM audit_events a WHERE a.target_id=u.id AND a.outcome='success' AND (a.action IN ('user.password_changed','auth.password_reset')
    OR (a.action='admin.user_updated' AND COALESCE(CASE WHEN json_valid(a.details_json) THEN json_extract(a.details_json,'$.accessRevoked') END,1)))))
  OR (NOT EXISTS(SELECT 1 FROM audit_events a WHERE a.action='admin.user_created' AND a.target_id=u.id) AND u.updated_at=u.created_at))`

// migratePasswordChangeRequired adds the flag and, once per database, flags a bootstrap
// administrator who never replaced the first-run password. Flagging only restricts the
// account's sessions to choosing a new password; the password itself still signs in.
func (s *Store) migratePasswordChangeRequired() error {
	if err := s.addColumnIfMissing("users", "password_change_required", `ALTER TABLE users ADD COLUMN password_change_required BOOLEAN NOT NULL DEFAULT 0`); err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var done bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM system_settings WHERE key=?)`, PasswordChangeMigrationSetting).Scan(&done); err != nil || done {
		return err
	}
	rows, err := tx.Query(bootstrapPasswordUnchangedSQL)
	if err != nil {
		return err
	}
	type account struct{ id, username string }
	var flagged []account
	for rows.Next() {
		var a account
		if err := rows.Scan(&a.id, &a.username); err != nil {
			rows.Close()
			return err
		}
		flagged = append(flagged, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, a := range flagged {
		details, _ := json.Marshal(map[string]string{"reason": "bootstrap_password_unchanged", "username": a.username})
		if _, err := tx.Exec(`UPDATE users SET password_change_required=1 WHERE id=?`, a.id); err != nil {
			return err
		}
		if err := recordAuditTx(tx, &AuditEvent{ID: uuid.NewString(), ActorUsername: "kyidentity-migration", Action: "system.password_change_required",
			TargetID: a.id, TargetType: "user", Outcome: "success", DetailsJSON: string(details), CreatedAt: now}); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT INTO system_settings (key, value, updated_at) VALUES (?, '1', CURRENT_TIMESTAMP)`, PasswordChangeMigrationSetting); err != nil {
		return err
	}
	return tx.Commit()
}
