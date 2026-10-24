package store

import (
	"strings"
	"testing"
	"time"
)

func expiryOutcomes(t *testing.T, s *Store, action, outcome string) int {
	t.Helper()
	return count(t, s, `SELECT COUNT(*) FROM audit_events WHERE action=? AND outcome=? AND actor_username='expiry'`, action, outcome)
}

// Guards per-item failure isolation in RunDueExpiries: an account whose end cannot be
// applied stays as it was, gets a failure audit row and is reported, while the other
// due account in the same pass still ends.
func TestRunDueExpiriesIsolatesAccountFailures(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	stuck, due := createTestUser(t, s), createTestUser(t, s)
	past := time.Now().Add(-time.Minute).Unix()
	mustExec(t, s, `UPDATE users SET ends_at=? WHERE id IN (?,?)`, past, stuck.ID, due.ID)
	mustExec(t, s, `CREATE TRIGGER block_end BEFORE UPDATE OF status ON users WHEN NEW.id='`+stuck.ID+`' AND NEW.status='disabled' BEGIN SELECT RAISE(ABORT,'blocked'); END`)
	run, err := s.RunDueExpiries(time.Now().UTC())
	if err == nil || !strings.Contains(err.Error(), "account.end_failed "+stuck.ID) {
		t.Fatalf("failure not reported: %v", err)
	}
	if run.Accounts != 1 {
		t.Fatalf("accounts ended = %d, want 1", run.Accounts)
	}
	// The account already reads as disabled past its end date; the stored row is untouched.
	if count(t, s, `SELECT COUNT(*) FROM users WHERE id=? AND status='active' AND NOT locally_disabled`, stuck.ID) != 1 {
		t.Fatal("failed end changed the stored account")
	}
	if got, _ := s.GetUserByID(stuck.ID); got.Status != "disabled" {
		t.Fatal("account past its end date reads as active")
	}
	if got, _ := s.GetUserByID(due.ID); got.Status != "disabled" || !got.LocallyDisabled {
		t.Fatalf("due account not ended: %+v", got)
	}
	if expiryOutcomes(t, s, "account.end_failed", "failure") != 1 || expiryOutcomes(t, s, "account.ended", "success") != 1 {
		t.Fatal("expiry audit rows wrong")
	}
}

// Guards membership expiry under a required MFA policy: the lapsed membership is removed
// and the user's grants are invalidated (the policy no longer applies, so evidence must be
// re-proved), with an expiry audit row. A failed removal is audited and kept.
func TestRunDueExpiriesMembershipUnderRequiredPolicy(t *testing.T) {
	s, u, a := appAccessFixture(t)
	if err := s.SetAppAssignment(a.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	for _, g := range []string{"required", "plain"} {
		if err := s.CreateGroup(&Group{ID: g, Name: g}, nil); err != nil {
			t.Fatal(err)
		}
		if err := s.SetGroupMembership(g, u.ID, true, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.RecordIssuedToken(accessToken(u, "tok", "")); err != nil {
		t.Fatal(err)
	}
	mustExec(t, s, `UPDATE enrollment_policies SET required=1, grace_seconds=3600 WHERE group_id='required'`)
	mustExec(t, s, `UPDATE group_memberships SET expires_at=? WHERE user_id=?`, time.Now().Add(-time.Minute).Unix(), u.ID)
	mustExec(t, s, `CREATE TRIGGER block_plain BEFORE DELETE ON group_memberships WHEN OLD.group_id='plain' BEGIN SELECT RAISE(ABORT,'blocked'); END`)
	run, err := s.RunDueExpiries(time.Now().UTC())
	if err == nil || !strings.Contains(err.Error(), "group.membership_expiry_failed plain") {
		t.Fatalf("membership failure not reported: %v", err)
	}
	if run.Memberships != 1 {
		t.Fatalf("memberships expired = %d, want 1", run.Memberships)
	}
	if count(t, s, `SELECT COUNT(*) FROM group_memberships WHERE group_id='required'`) != 0 || count(t, s, `SELECT COUNT(*) FROM group_memberships WHERE group_id='plain'`) != 1 {
		t.Fatal("wrong memberships removed")
	}
	assertRevoked(t, s, "tok", true)
	if expiryOutcomes(t, s, "group.membership_expired", "success") != 1 || expiryOutcomes(t, s, "group.membership_expiry_failed", "failure") != 1 {
		t.Fatal("membership expiry audit rows wrong")
	}
}

// Guards assignment expiry failure: a direct grant that cannot be removed is audited as a
// failure and reported, not silently skipped.
func TestRunDueExpiriesAssignmentFailureAudited(t *testing.T) {
	s, u, a := appAccessFixture(t)
	if err := s.SetAppAssignmentUntil(a.ID, "users", u.ID, future(time.Hour), nil); err != nil {
		t.Fatal(err)
	}
	mustExec(t, s, `UPDATE app_user_assignments SET expires_at=? WHERE user_id=?`, time.Now().Add(-time.Minute).Unix(), u.ID)
	mustExec(t, s, `CREATE TRIGGER block_assignment BEFORE DELETE ON app_user_assignments BEGIN SELECT RAISE(ABORT,'blocked'); END`)
	run, err := s.RunDueExpiries(time.Now().UTC())
	if err == nil || run.Assignments != 0 {
		t.Fatalf("run = %+v, %v", run, err)
	}
	if expiryOutcomes(t, s, "app.assignment_expiry_failed", "failure") != 1 {
		t.Fatal("assignment failure not audited")
	}
	// The view already denies the lapsed grant even though its row stays.
	if allowed, _ := s.ClientAccessAllowed(u.ID, "client"); allowed {
		t.Fatal("lapsed assignment still grants access")
	}
}
