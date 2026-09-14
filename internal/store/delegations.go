package store

import (
	"database/sql"
	"errors"
	"sort"
	"time"
)

// Delegated administration: a global administrator hands fixed, narrow permissions to
// ordinary users. Helpdesk recovers ordinary accounts, auditors read everything, and
// app owners manage grants and role mappings of the apps named here. The rows are
// read on every request, so removing one takes effect on the next call, and the
// global `admin` role stays the only thing the last-administrator invariant counts.
// Anyone holding a delegation falls under the `administrators` MFA enrollment scope:
// the powers are administrative even when the role is not.

var ErrUserMissing = errors.New("user not found")

type Delegations struct {
	Helpdesk bool     `json:"helpdesk"`
	Auditor  bool     `json:"auditor"`
	AppOwner []string `json:"appOwner"`
}

func (s *Store) migrateDelegations() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS admin_delegations (
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 kind TEXT NOT NULL CHECK (kind IN ('helpdesk','auditor','app_owner')),
 app_id TEXT REFERENCES app_registry(id) ON DELETE CASCADE,
 created_at DATETIME NOT NULL,
 CHECK ((kind='app_owner') = (app_id IS NOT NULL)));
 CREATE UNIQUE INDEX IF NOT EXISTS admin_delegations_key ON admin_delegations(user_id, kind, COALESCE(app_id,''))`)
	return err
}

// Delegations reads one user's delegated permissions.
func (s *Store) Delegations(userID string) (Delegations, error) {
	d := Delegations{AppOwner: []string{}}
	rows, err := s.db.Query(`SELECT kind, COALESCE(app_id,'') FROM admin_delegations WHERE user_id=? ORDER BY kind, app_id`, userID)
	if err != nil {
		return d, err
	}
	defer rows.Close()
	for rows.Next() {
		var kind, appID string
		if err := rows.Scan(&kind, &appID); err != nil {
			return d, err
		}
		switch kind {
		case "helpdesk":
			d.Helpdesk = true
		case "auditor":
			d.Auditor = true
		case "app_owner":
			d.AppOwner = append(d.AppOwner, appID)
		}
	}
	return d, rows.Err()
}

// SetDelegations replaces a user's delegations with exactly the set given.
func (s *Store) SetDelegations(userID string, d Delegations, audit *AuditEvent) error {
	apps := append([]string(nil), d.AppOwner...)
	sort.Strings(apps)
	now := time.Now().UTC()
	return s.auditedTx(audit, func(tx *sql.Tx) error {
		var exists bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM users WHERE id=?)`, userID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrUserMissing
		}
		if _, err := tx.Exec(`DELETE FROM admin_delegations WHERE user_id=?`, userID); err != nil {
			return err
		}
		for kind, on := range map[string]bool{"helpdesk": d.Helpdesk, "auditor": d.Auditor} {
			if !on {
				continue
			}
			if _, err := tx.Exec(`INSERT INTO admin_delegations(user_id,kind,created_at) VALUES(?,?,?)`, userID, kind, now); err != nil {
				return enrollmentMutationError(err)
			}
		}
		for i, appID := range apps {
			if i > 0 && apps[i-1] == appID {
				continue
			}
			if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM app_registry WHERE id=?)`, appID).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return ErrAppRecordMissing
			}
			if _, err := tx.Exec(`INSERT INTO admin_delegations(user_id,kind,app_id,created_at) VALUES(?,'app_owner',?,?)`, userID, appID, now); err != nil {
				return enrollmentMutationError(err)
			}
		}
		// A changed requirement set invalidates outstanding grants, as membership does.
		if err := invalidateUserEnrollmentTx(tx, userID); err != nil {
			return err
		}
		return appRegistryAudit(audit, map[string]any{"user": userID, "helpdesk": d.Helpdesk, "auditor": d.Auditor, "appOwner": apps})
	})
}

// ListAppRecordsOwnedBy pages the app records the user owns through a delegation.
func (s *Store) ListAppRecordsOwnedBy(userID, query string, limit, offset int) ([]AppRecord, int, error) {
	return s.listAppRecords(` AND a.id IN (SELECT app_id FROM admin_delegations WHERE user_id=? AND kind='app_owner')`, []any{userID}, query, limit, offset)
}
