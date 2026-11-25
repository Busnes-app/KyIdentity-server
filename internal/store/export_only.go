package store

import (
	"database/sql"
	"errors"
)

// The org gate and the export-only session (tenancy design, Views and the Delete
// everything amendment). A session is created only for a user whose org is active, or, in
// a deletion_scheduled org, for the one export-only exception; every code, token and token
// check re-reads it. A single-tenant install's default org is always active, so none of
// this changes what it does.

// ErrOrgSuspended: every credential passed, but the user's org is not active and this is
// not an export-only exception.
var ErrOrgSuspended = errors.New("store: the organisation is not active")

// orgActiveSQL is org_active (tenancy design, Views): the users row u is in an active org.
// The account flows outside sign-in add it to their own user rule: link issuance and
// redemption, forgot-password and step-up.
func orgActiveSQL(u string) string {
	return `EXISTS(SELECT 1 FROM orgs o WHERE o.id=` + u + `.org_id AND o.status='active')`
}

// exportOnlySQL: user u of org o may hold an export-only session. The holder when billing
// scheduled the deletion; every other activated member when the holder asked (Delete
// everything); never the holder who asked.
func exportOnlySQL(u, o string) string {
	asked := `EXISTS(SELECT 1 FROM org_erasures e WHERE e.org_id=` + o + `.id)`
	return `(` + o + `.status='deletion_scheduled' AND NOT ` + u + `.pending AND (NOT ` + asked + ` AND ` + o + `.account_holder_user_id=` + u + `.id
 OR EXISTS(SELECT 1 FROM org_erasures e WHERE e.org_id=` + o + `.id AND e.holder_user_id<>` + u + `.id)))`
}

// sessionOrgSQL: session s may still be granted access through its org. Its user's org is
// active, or the session is export-only and still allowed one.
func sessionOrgSQL(s string) string {
	return `EXISTS(SELECT 1 FROM users ou JOIN orgs oo ON oo.id=ou.org_id WHERE ou.id=` + s + `.user_id AND ou.org_id=oo.id
 AND (oo.status='active' OR ` + s + `.export_only AND ` + exportOnlySQL("ou", "oo") + `))`
}

// exportOnlyNowSQL: session s is export-only now. The stored flag holds only while its
// user's org is still not active, so a resumed org's sessions are whole again.
func exportOnlyNowSQL(s string) string {
	return `(` + s + `.export_only AND EXISTS(SELECT 1 FROM users eu JOIN orgs eo ON eo.id=eu.org_id WHERE eu.id=` + s + `.user_id AND eo.status<>'active'))`
}

func migrateExportOnly(tx *sql.Tx) error {
	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM pragma_table_info('sessions') WHERE name='export_only'`).Scan(&n); err != nil || n == 1 {
		return err
	}
	_, err := tx.Exec(`ALTER TABLE sessions ADD COLUMN export_only BOOLEAN NOT NULL DEFAULT FALSE`)
	return err
}

func migrateExportOnlyPostgres(tx *sql.Tx) error {
	_, err := tx.Exec(`ALTER TABLE sessions ADD COLUMN export_only BOOLEAN NOT NULL DEFAULT FALSE`)
	return err
}

// orgRefusedTx tells a session refused for its org from one refused for its user. A user
// the export-only exception admits was refused for another reason (a changed password).
func orgRefusedTx(tx *sql.Tx, userID string) (bool, error) {
	var refused bool
	err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM users u JOIN orgs o ON o.id=u.org_id WHERE u.id=? AND u.status='active' AND o.status<>'active'
 AND NOT `+exportOnlySQL("u", "o")+`)`, userID).Scan(&refused)
	return refused, err
}

// SessionExportOnly reports whether the session is export-only now.
func (s *Store) SessionExportOnly(sessionID string) (bool, error) {
	var on bool
	err := s.db.QueryRow(`SELECT `+exportOnlyNowSQL("sessions")+` FROM sessions WHERE id=?`, sessionID).Scan(&on)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return on, err
}
