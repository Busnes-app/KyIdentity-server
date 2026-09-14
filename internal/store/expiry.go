package store

import (
	"database/sql"
	"encoding/json"
	"errors"
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

// RunDueExpiries applies every expiry whose instant has passed. It is idempotent and
// only ever removes: an instant extended before the run is not due and is untouched.
func (s *Store) RunDueExpiries(now time.Time) (ExpiryRun, error) {
	var run ExpiryRun
	tx, err := s.db.Begin()
	if err != nil {
		return run, err
	}
	defer tx.Rollback()
	unix := now.Unix()

	// Accounts past their end date are disabled and offboarded. The last administrator
	// is kept and the refusal audited; the invariant outranks the schedule.
	ended, err := scanUsers(tx.Query(`SELECT `+userColumns+` FROM users WHERE ends_at IS NOT NULL AND ends_at<=? AND status='active'`, unix))
	if err != nil {
		return run, err
	}
	for _, u := range ended {
		if u.Role == "admin" {
			var others int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM users WHERE role='admin' AND status='active' AND id<>? AND (ends_at IS NULL OR ends_at>?)`, u.ID, unix).Scan(&others); err != nil {
				return run, err
			}
			if others == 0 {
				if _, err := tx.Exec(`UPDATE users SET ends_at=NULL, updated_at=? WHERE id=?`, now, u.ID); err != nil {
					return run, err
				}
				if err := expiryAudit(tx, now, "account.end_refused", u.ID, "user", "denied", map[string]any{"username": u.Username, "reason": "last_active_admin"}); err != nil {
					return run, err
				}
				continue
			}
		}
		if _, err := tx.Exec(`UPDATE users SET status='disabled', locally_disabled=1, updated_at=? WHERE id=?`, now, u.ID); err != nil {
			return run, err
		}
		u.Status, u.LocallyDisabled = "disabled", true
		if err := offboardUserTx(tx, u, false, now); err != nil {
			return run, err
		}
		if err := queueUserUpdateTx(tx, u, now); err != nil {
			return run, err
		}
		if err := expiryAudit(tx, now, "account.ended", u.ID, "user", "success", map[string]any{"username": u.Username}); err != nil {
			return run, err
		}
		run.Accounts++
	}

	// Expired memberships leave the group the way a removal does: roles mapped through
	// the group end, and a required MFA policy no longer applies. The administrator who
	// scheduled the instant already spent step-up; no live session is needed now.
	type pair struct{ a, b string }
	var expiredMembers []pair
	rows, err := tx.Query(`SELECT group_id,user_id FROM group_memberships WHERE expires_at IS NOT NULL AND expires_at<=?`, unix)
	if err != nil {
		return run, err
	}
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.a, &p.b); err != nil {
			rows.Close()
			return run, err
		}
		expiredMembers = append(expiredMembers, p)
	}
	rows.Close()
	for _, m := range expiredMembers {
		if _, err := tx.Exec(`DELETE FROM group_memberships WHERE group_id=? AND user_id=?`, m.a, m.b); err != nil {
			return run, err
		}
		if err := groupRoleChangeTx(tx, m.a, []string{m.b}); err != nil {
			return run, err
		}
		var required bool
		if err := tx.QueryRow(`SELECT COALESCE((SELECT required FROM enrollment_policies WHERE group_id=?),0)`, m.a).Scan(&required); err != nil {
			return run, err
		}
		if required {
			if err := invalidateUserEnrollmentTx(tx, m.b); err != nil {
				return run, err
			}
		}
		if err := expiryAudit(tx, now, "group.membership_expired", m.a, "group", "success", map[string]any{"userId": m.b}); err != nil {
			return run, err
		}
		run.Memberships++
	}

	var expiredAssignments []pair
	rows, err = tx.Query(`SELECT app_id,user_id FROM app_user_assignments WHERE expires_at IS NOT NULL AND expires_at<=?`, unix)
	if err != nil {
		return run, err
	}
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.a, &p.b); err != nil {
			rows.Close()
			return run, err
		}
		expiredAssignments = append(expiredAssignments, p)
	}
	rows.Close()
	for _, d := range expiredAssignments {
		if _, err := tx.Exec(`DELETE FROM app_user_assignments WHERE app_id=? AND user_id=?`, d.a, d.b); err != nil {
			return run, err
		}
		if _, err := tx.Exec(`UPDATE app_registry SET revision=revision+1 WHERE id=?`, d.a); err != nil {
			return run, err
		}
		if err := expiryAudit(tx, now, "app.assignment_expired", d.a, "application", "success", map[string]any{"userId": d.b}); err != nil {
			return run, err
		}
		run.Assignments++
	}

	if err := revokeLostAppAccessTx(tx); err != nil {
		return run, err
	}
	if err := reconcileProvisioningTx(tx, now); err != nil {
		return run, err
	}
	return run, tx.Commit()
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
