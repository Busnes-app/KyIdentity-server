package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Expiring access. Direct app assignments and group memberships carry an optional UTC
// instant after which they no longer grant anything, and an account carries an optional
// end date after which it is disabled. The instants are read by the access views on
// every decision (authorize, exchange, provisioning selection), so expiry holds with no
// worker running. RunDueExpiries is the follow-up: it removes what has passed, revokes
// what depended on it, ends accounts and re-sends downstream state. The rows themselves
// are the persisted due work; a restart simply runs the follow-up again.

var ErrExpiryInPast = errors.New("expiry must be in the future")

// activeAdminSQL is the one definition of an administrator who can still act: the role,
// an active row, and an end date that has not passed. Every last-administrator count
// uses it, so an ended administrator the follow-up has not yet processed never counts.
const activeAdminSQL = `role='admin' AND status='active' AND (ends_at IS NULL OR ends_at>unixepoch())`

// ExpiryRun counts what one follow-up pass removed.
type ExpiryRun struct {
	Accounts, Memberships, Assignments int
}

func unixOrNil(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Unix()
}

func timeFromUnix(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := time.Unix(v.Int64, 0).UTC()
	return &t
}

func checkExpiry(expiresAt *time.Time, now time.Time) error {
	if expiresAt != nil && !expiresAt.After(now) {
		return ErrExpiryInPast
	}
	return nil
}

func expiryAudit(tx *sql.Tx, now time.Time, action, targetID, targetType, outcome string, details map[string]any) error {
	b, _ := json.Marshal(details)
	return recordAuditTx(tx, &AuditEvent{ID: uuid.NewString(), ActorUsername: "expiry", Action: action, TargetID: targetID, TargetType: targetType, Outcome: outcome, DetailsJSON: string(b), CreatedAt: now})
}

type idPair struct{ a, b string }

func scanIDPairs(rows *sql.Rows, err error) ([]idPair, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []idPair
	for rows.Next() {
		var p idPair
		if err := rows.Scan(&p.a, &p.b); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// RunDueExpiries applies every expiry whose instant has passed. Each item commits on
// its own, so one row that cannot be processed neither blocks the rest nor hides: its
// failure is audited and returned, and the next pass retries it. The pass only ever
// removes; an instant extended before the run is not due and is untouched.
func (s *Store) RunDueExpiries(now time.Time) (ExpiryRun, error) {
	var run ExpiryRun
	var errs []error
	unix := now.Unix()
	fail := func(action, targetID, targetType string, err error) {
		errs = append(errs, fmt.Errorf("%s %s: %w", action, targetID, err))
		_ = s.auditedTx(nil, func(tx *sql.Tx) error {
			return expiryAudit(tx, now, action, targetID, targetType, "failure", map[string]any{"error": err.Error()})
		})
	}

	// Accounts past their end date are disabled and offboarded. The last administrator
	// is kept and the refusal audited; the invariant outranks the schedule.
	ended, err := scanUsers(s.db.Query(`SELECT `+userColumns+` FROM users WHERE ends_at IS NOT NULL AND ends_at<=? AND status='active'`, unix))
	if err != nil {
		return run, err
	}
	for _, u := range ended {
		var endedNow bool
		err := s.auditedTx(nil, func(tx *sql.Tx) error {
			if u.Role == "admin" {
				var others int
				if err := tx.QueryRow(`SELECT COUNT(*) FROM users WHERE `+activeAdminSQL+` AND id<>?`, u.ID).Scan(&others); err != nil {
					return err
				}
				if others == 0 {
					if _, err := tx.Exec(`UPDATE users SET ends_at=NULL, updated_at=? WHERE id=?`, now, u.ID); err != nil {
						return err
					}
					return expiryAudit(tx, now, "account.end_refused", u.ID, "user", "denied", map[string]any{"username": u.Username, "reason": "last_active_admin"})
				}
			}
			if _, err := tx.Exec(`UPDATE users SET status='disabled', locally_disabled=1, updated_at=? WHERE id=?`, now, u.ID); err != nil {
				return err
			}
			u.Status, u.LocallyDisabled = "disabled", true
			if err := offboardUserTx(tx, u, false, now); err != nil {
				return err
			}
			if err := queueUserUpdateTx(tx, u, now); err != nil {
				return err
			}
			endedNow = true
			return expiryAudit(tx, now, "account.ended", u.ID, "user", "success", map[string]any{"username": u.Username})
		})
		if err != nil {
			fail("account.end_failed", u.ID, "user", err)
			continue
		}
		if endedNow {
			run.Accounts++
		}
	}

	// Expired memberships leave the group the way a removal does: roles mapped through
	// the group end, and a required MFA policy no longer applies. The administrator who
	// scheduled the instant already spent step-up; no live session is needed now.
	members, err := scanIDPairs(s.db.Query(`SELECT group_id,user_id FROM group_memberships WHERE expires_at IS NOT NULL AND expires_at<=?`, unix))
	if err != nil {
		return run, errors.Join(append(errs, err)...)
	}
	for _, m := range members {
		err := s.auditedTx(nil, func(tx *sql.Tx) error {
			if _, err := tx.Exec(`DELETE FROM group_memberships WHERE group_id=? AND user_id=?`, m.a, m.b); err != nil {
				return err
			}
			if err := groupRoleChangeTx(tx, m.a, []string{m.b}); err != nil {
				return err
			}
			var required bool
			if err := tx.QueryRow(`SELECT COALESCE((SELECT required FROM enrollment_policies WHERE group_id=?),0)`, m.a).Scan(&required); err != nil {
				return err
			}
			if required {
				if err := invalidateUserEnrollmentTx(tx, m.b); err != nil {
					return err
				}
			}
			return expiryAudit(tx, now, "group.membership_expired", m.a, "group", "success", map[string]any{"userId": m.b})
		})
		if err != nil {
			fail("group.membership_expiry_failed", m.a, "group", err)
			continue
		}
		run.Memberships++
	}

	assignments, err := scanIDPairs(s.db.Query(`SELECT app_id,user_id FROM app_user_assignments WHERE expires_at IS NOT NULL AND expires_at<=?`, unix))
	if err != nil {
		return run, errors.Join(append(errs, err)...)
	}
	for _, d := range assignments {
		err := s.auditedTx(nil, func(tx *sql.Tx) error {
			if _, err := tx.Exec(`DELETE FROM app_user_assignments WHERE app_id=? AND user_id=?`, d.a, d.b); err != nil {
				return err
			}
			if _, err := tx.Exec(`UPDATE app_registry SET revision=revision+1 WHERE id=?`, d.a); err != nil {
				return err
			}
			return expiryAudit(tx, now, "app.assignment_expired", d.a, "application", "success", map[string]any{"userId": d.b})
		})
		if err != nil {
			fail("app.assignment_expiry_failed", d.a, "application", err)
			continue
		}
		run.Assignments++
	}

	// The shared follow-up is set-based: it converges grants and downstream state for
	// everything the views now deny, whichever items above succeeded.
	if err := s.auditedTx(nil, func(tx *sql.Tx) error {
		if err := revokeLostAppAccessTx(tx); err != nil {
			return err
		}
		return reconcileProvisioningTx(tx, now)
	}); err != nil {
		fail("access.expiry_reconcile_failed", "", "directory", err)
	}
	return run, errors.Join(errs...)
}

func scanUsers(rows *sql.Rows, err error) ([]*User, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// AccessEndsAt is the instant the user's effective access to the client's app ends,
// or nil when nothing bounds it: the latest live grant wins, since access is a union,
// and the account end date caps the result. Tokens are bounded to it at issue.
func (s *Store) AccessEndsAt(userID, clientID string) (*time.Time, error) {
	var appID, mode string
	var endsAt sql.NullInt64
	err := s.db.QueryRow(`SELECT a.id,a.access_mode,u.ends_at FROM app_registry a JOIN users u ON u.id=? WHERE a.client_id=?`, userID, clientID).Scan(&appID, &mode, &endsAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	end := timeFromUnix(endsAt)
	if mode == "all_active_users" {
		return end, nil
	}
	rows, err := s.db.Query(`SELECT d.expires_at FROM app_user_assignments d WHERE d.app_id=? AND d.user_id=? AND (d.expires_at IS NULL OR d.expires_at>unixepoch())
 UNION ALL SELECT m.expires_at FROM app_group_assignments g JOIN group_memberships m ON m.group_id=g.group_id WHERE g.app_id=? AND m.user_id=? AND (m.expires_at IS NULL OR m.expires_at>unixepoch())`, appID, userID, appID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var latest *time.Time
	for rows.Next() {
		var v sql.NullInt64
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		if !v.Valid {
			return end, rows.Err() // one unbounded grant: only the account bounds access
		}
		if t := timeFromUnix(v); latest == nil || t.After(*latest) {
			latest = t
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if end == nil || (latest != nil && latest.Before(*end)) {
		return latest, nil
	}
	return end, nil
}
