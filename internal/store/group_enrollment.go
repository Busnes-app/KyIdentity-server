package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Deadlines belong to a stable policy, not to a membership. Removing/re-adding
// membership and policy reactivation therefore cannot start another grace period.
func (s *Store) migrateEnrollmentPolicy() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name='enrollment_only'`).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		if _, err = tx.Exec(`ALTER TABLE sessions ADD COLUMN enrollment_only BOOLEAN NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	// Views and their dependent triggers are replaced in the same transaction as the schema.
	if _, err = tx.Exec(`DROP VIEW IF EXISTS mfa_session_access; DROP VIEW IF EXISTS enrollment_requirements; DROP VIEW IF EXISTS applicable_enrollment_policies;
 DROP TRIGGER IF EXISTS enrollment_new_user; DROP TRIGGER IF EXISTS enrollment_user_role; DROP TRIGGER IF EXISTS enrollment_new_group; DROP TRIGGER IF EXISTS enrollment_new_member; DROP TRIGGER IF EXISTS enrollment_role_compatibility; DROP TRIGGER IF EXISTS enrollment_new_delegation;`); err != nil {
		return err
	}
	if err = tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('enrollment_policies')`).Scan(&exists); err != nil {
		return err
	}
	if exists > 0 {
		var hasGroup int
		if err = tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('enrollment_policies') WHERE name='group_id'`).Scan(&hasGroup); err != nil {
			return err
		}
		if hasGroup == 0 {
			if _, err = tx.Exec(`CREATE TEMP TABLE saved_enrollment_policies AS SELECT * FROM enrollment_policies;
 CREATE TEMP TABLE saved_enrollment_deadlines AS SELECT * FROM enrollment_deadlines;
 DROP TABLE enrollment_deadlines; DROP TABLE enrollment_policies;`); err != nil {
				return err
			}
		} else {
			exists = 0
		}
	}
	if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS enrollment_policies (
 scope TEXT PRIMARY KEY,group_id TEXT UNIQUE REFERENCES directory_groups(id) ON DELETE CASCADE,
 required BOOLEAN NOT NULL DEFAULT 0,allowed_mask INTEGER NOT NULL DEFAULT 7 CHECK(allowed_mask BETWEEN 1 AND 7),
 grace_seconds INTEGER NOT NULL DEFAULT 0 CHECK(grace_seconds BETWEEN 0 AND 7776000),revision INTEGER NOT NULL DEFAULT 1,
 CHECK((group_id IS NULL AND scope IN ('organization','administrators')) OR (group_id IS NOT NULL AND scope='group:'||group_id)));
 CREATE TABLE IF NOT EXISTS enrollment_deadlines (user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 scope TEXT NOT NULL REFERENCES enrollment_policies(scope) ON DELETE CASCADE,due_at INTEGER NOT NULL,PRIMARY KEY(user_id,scope));`); err != nil {
		return err
	}
	if exists > 0 {
		if _, err = tx.Exec(`INSERT INTO enrollment_policies(scope,required,allowed_mask,grace_seconds,revision) SELECT scope,required,allowed_mask,grace_seconds,revision FROM saved_enrollment_policies;
 INSERT INTO enrollment_deadlines SELECT * FROM saved_enrollment_deadlines;
 DROP TABLE saved_enrollment_policies; DROP TABLE saved_enrollment_deadlines;`); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(`INSERT OR IGNORE INTO enrollment_policies(scope) VALUES('organization'),('administrators');
 INSERT OR IGNORE INTO enrollment_policies(scope,group_id) SELECT 'group:'||id,id FROM directory_groups;
 CREATE VIEW applicable_enrollment_policies AS
 SELECT u.id user_id,p.scope,p.allowed_mask,p.grace_seconds FROM users u JOIN enrollment_policies p ON p.required AND p.scope='organization'
 UNION ALL SELECT u.id,p.scope,p.allowed_mask,p.grace_seconds FROM users u JOIN enrollment_policies p ON p.required AND p.scope='administrators' WHERE (u.role='admin' OR EXISTS(SELECT 1 FROM admin_delegations d WHERE d.user_id=u.id))
 UNION ALL SELECT m.user_id,p.scope,p.allowed_mask,p.grace_seconds FROM group_memberships m JOIN enrollment_policies p ON p.group_id=m.group_id AND p.required;
 CREATE VIEW enrollment_requirements AS
 SELECT u.id user_id,
 EXISTS(SELECT 1 FROM enrollment_policies p WHERE p.required AND p.scope IN (SELECT 'organization' UNION ALL SELECT 'administrators' WHERE (u.role='admin' OR EXISTS(SELECT 1 FROM admin_delegations d WHERE d.user_id=u.id)) UNION ALL SELECT 'group:'||m.group_id FROM group_memberships m WHERE m.user_id=u.id)) required,
 COALESCE((SELECT MIN(p.allowed_mask&1)+MIN(p.allowed_mask&2)+MIN(p.allowed_mask&4) FROM enrollment_policies p WHERE p.required AND p.scope IN (SELECT 'organization' UNION ALL SELECT 'administrators' WHERE (u.role='admin' OR EXISTS(SELECT 1 FROM admin_delegations d WHERE d.user_id=u.id)) UNION ALL SELECT 'group:'||m.group_id FROM group_memberships m WHERE m.user_id=u.id)),7) allowed_mask,
 COALESCE((SELECT MIN(COALESCE(d.due_at,0)) FROM enrollment_policies p LEFT JOIN enrollment_deadlines d ON d.user_id=u.id AND d.scope=p.scope WHERE p.required AND p.scope IN (SELECT 'organization' UNION ALL SELECT 'administrators' WHERE (u.role='admin' OR EXISTS(SELECT 1 FROM admin_delegations d WHERE d.user_id=u.id)) UNION ALL SELECT 'group:'||m.group_id FROM group_memberships m WHERE m.user_id=u.id)),0) due_at
 FROM users u;
 CREATE VIEW IF NOT EXISTS enrolled_factors AS
 SELECT user_id,1 bit FROM mfa_methods WHERE method_type='totp'
 UNION SELECT user_id,2 FROM native_devices WHERE is_mfa_approver AND public_key IS NOT NULL AND public_key<>''
 UNION SELECT user_id,4 FROM webauthn_credentials;` + enrollmentSessionViewSQL + `
 CREATE TRIGGER enrollment_new_user AFTER INSERT ON users BEGIN
 INSERT OR IGNORE INTO enrollment_deadlines SELECT p.user_id,p.scope,unixepoch()+p.grace_seconds FROM applicable_enrollment_policies p WHERE p.user_id=NEW.id; END;
 CREATE TRIGGER enrollment_user_role AFTER UPDATE OF role ON users BEGIN
 INSERT OR IGNORE INTO enrollment_deadlines SELECT p.user_id,p.scope,unixepoch()+p.grace_seconds FROM applicable_enrollment_policies p WHERE p.user_id=NEW.id; END;
 CREATE TRIGGER enrollment_new_group AFTER INSERT ON directory_groups BEGIN
 INSERT INTO enrollment_policies(scope,group_id) VALUES('group:'||NEW.id,NEW.id); END;
 CREATE TRIGGER enrollment_new_member AFTER INSERT ON group_memberships BEGIN
 INSERT OR IGNORE INTO enrollment_deadlines SELECT p.user_id,p.scope,unixepoch()+p.grace_seconds FROM applicable_enrollment_policies p WHERE p.user_id=NEW.user_id AND p.scope='group:'||NEW.group_id; END;
 CREATE TRIGGER enrollment_role_compatibility AFTER UPDATE OF role ON users BEGIN
 SELECT CASE WHEN EXISTS(SELECT 1 FROM enrollment_requirements WHERE user_id=NEW.id AND allowed_mask=0) THEN RAISE(ABORT,'conflicting enrollment policies') END; END;
 CREATE TRIGGER enrollment_new_delegation AFTER INSERT ON admin_delegations BEGIN
 SELECT CASE WHEN EXISTS(SELECT 1 FROM enrollment_requirements WHERE user_id=NEW.user_id AND allowed_mask=0) THEN RAISE(ABORT,'conflicting enrollment policies') END;
 INSERT OR IGNORE INTO enrollment_deadlines SELECT p.user_id,p.scope,unixepoch()+p.grace_seconds FROM applicable_enrollment_policies p WHERE p.user_id=NEW.user_id AND p.scope='administrators'; END;`); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) GroupEnrollmentPolicy(groupID string) (EnrollmentPolicy, error) {
	var p EnrollmentPolicy
	var mask int
	err := s.db.QueryRow(`SELECT scope,required,allowed_mask,grace_seconds,revision FROM enrollment_policies WHERE group_id=?`, groupID).Scan(&p.Scope, &p.Required, &mask, &p.GraceSeconds, &p.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrGroupTargetMissing
	}
	p.AllowedMethods = factorNames(mask)
	return p, err
}

// Policy membership changes invalidate old grants even on relaxation. Otherwise a
// remove/re-add could revive an old code or online token before it expires.
func invalidateUserEnrollmentTx(tx *sql.Tx, userID string) error {
	for _, query := range []string{`DELETE FROM authorization_codes WHERE user_id=?`, `DELETE FROM authorization_interactions WHERE user_id=?`} {
		if _, err := tx.Exec(query, userID); err != nil {
			return err
		}
	}
	_, err := tx.Exec(`UPDATE issued_tokens SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`, time.Now().UTC(), userID)
	return err
}

func enrollmentMutationError(err error) error {
	if err != nil && strings.Contains(err.Error(), "conflicting enrollment policies") {
		return ErrEnrollmentPolicy
	}
	return err
}
