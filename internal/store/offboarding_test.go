package store

import (
	"testing"
	"time"
)

// provisionedUser seeds a SCIM connector with an assigned, delivered account for u.
func provisionedUser(t *testing.T, s *Store, u *User, systemID string) {
	t.Helper()
	app := provisioningFixture(t, s, systemID)
	if err := s.SetAppAssignment(app, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if events := deliverAll(t, s); len(events) != 1 || events[0].EventType != "user.created" {
		t.Fatalf("seed delivery: %+v", events)
	}
}

// Disabling deactivates the account on every connector that holds it, including one that
// only knows the user through a remote mapping and never had a grant.
func TestDisablingDeactivatesEveryConnectorHoldingTheAccount(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	provisionedUser(t, s, u, "assigned")
	if err := s.CreatePairedSystem(&PairedSystem{ID: "legacy", Name: "legacy", SystemType: "scim", CallbackURL: "https://legacy.example/scim", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveSCIMUserLink("legacy", u.ID, "remote-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePairedSystem(&PairedSystem{ID: "stranger", Name: "stranger", SystemType: "scim", CallbackURL: "https://stranger.example/scim", Status: "active"}); err != nil {
		t.Fatal(err)
	}

	u.Status = "disabled"
	if err := s.UpdateUserWithSyncEvents(u, true, nil); err != nil {
		t.Fatal(err)
	}
	if got := pendingFor(t, s, "assigned", u.ID); len(got) != 1 || got[0] != (queued{"user.updated", 2, false}) {
		t.Fatalf("assigned connector: %+v", got)
	}
	if got := pendingFor(t, s, "legacy", u.ID); len(got) != 1 || got[0] != (queued{"user.updated", 1, false}) {
		t.Fatalf("legacy connector with a mapping but no grant: %+v", got)
	}
	if got := pendingFor(t, s, "stranger", u.ID); len(got) != 0 {
		t.Fatalf("a connector that never held the account was told: %+v", got)
	}
	var active, provisioned bool
	if err := s.db.QueryRow(`SELECT active,provisioned FROM sync_resource_state WHERE system_id='legacy' AND resource_id=?`, u.ID).Scan(&active, &provisioned); err != nil || active || !provisioned {
		t.Fatalf("legacy state row = active %v provisioned %v (%v)", active, provisioned, err)
	}
}

// Deletion is disablement plus removal: sessions end with their logout tokens queued,
// tokens die, every holder is told, and the completion state and remote mappings outlive
// the directory row so the operator can watch the work finish.
func TestDeletingRevokesAccessQueuesLogoutAndKeepsCompletionState(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	provisionedUser(t, s, u, "assigned")
	if err := s.SaveSCIMUserLink("assigned", u.ID, "remote-9"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	sess := seedSession(t, s, u.ID, now.Add(time.Hour), now)
	seedLogoutClient(t, s, "app", "https://app.example/bc")
	if _, err := s.EnsureClientSession("app", sess, u.ID); err != nil {
		t.Fatal(err)
	}
	jti, _, _ := seedGrants(t, s, u.ID, sess, "tok")

	if err := s.DeleteUserWithSyncEvents(u.ID, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetUserByID(u.ID); got != nil {
		t.Fatal("user row survived")
	}
	if n := countDeliveries(t, s, `user_id=? AND status='queued'`, u.ID); n != 1 {
		t.Fatalf("logout deliveries = %d, want 1", n)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM issued_tokens WHERE jti=? AND revoked_at IS NULL`, jti); n != 0 {
		t.Fatal("token outlived the account")
	}
	if got := pendingFor(t, s, "assigned", u.ID); len(got) != 1 || got[0] != (queued{"user.deleted", 2, false}) {
		t.Fatalf("deletion event: %+v", got)
	}
	if remote, _, err := s.SCIMUserLink("assigned", u.ID); err != nil || remote != "remote-9" {
		t.Fatalf("remote mapping lost: %q %v", remote, err)
	}

	off, err := s.UserOffboarding(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !off.Deleted || len(off.Targets) != 1 || len(off.Logouts) != 1 || off.Acknowledged || off.Verified {
		t.Fatalf("offboarding before delivery: %+v", off)
	}
	tgt := off.Targets[0]
	if tgt.SystemID != "assigned" || tgt.SystemName != "assigned" || !tgt.Recorded || tgt.Acknowledged || tgt.Verified || tgt.LastEvent == nil || tgt.LastEvent.Type != "user.deleted" || tgt.LastEvent.Status != "pending" {
		t.Fatalf("target before delivery: %+v", tgt)
	}

	deliverAll(t, s)
	d, err := s.ClaimLogoutDelivery(time.Minute)
	if err != nil || d == nil {
		t.Fatalf("claim: %v", err)
	}
	if err := s.FinishLogoutDelivery(d, nil); err != nil {
		t.Fatal(err)
	}
	off, _ = s.UserOffboarding(u.ID)
	if !off.Acknowledged || off.Verified || !off.Targets[0].Acknowledged || off.Targets[0].Observed != "" {
		t.Fatalf("offboarding after acknowledgement: %+v", off)
	}

	// A listing that saw the account gone, taken after the delivery, verifies the target.
	if _, err := s.db.Exec(`UPDATE sync_resource_state SET observed='absent',observed_at=? WHERE resource_id=?`, time.Now().UTC().Add(time.Second), u.ID); err != nil {
		t.Fatal(err)
	}
	off, _ = s.UserOffboarding(u.ID)
	if !off.Verified || !off.Targets[0].Verified {
		t.Fatalf("offboarding after listing: %+v", off)
	}
	if _, err := s.db.Exec(`UPDATE sync_resource_state SET observed='unsupported' WHERE resource_id=?`, u.ID); err != nil {
		t.Fatal(err)
	}
	off, _ = s.UserOffboarding(u.ID)
	if off.Verified || off.Targets[0].Verified || !off.Acknowledged {
		t.Fatalf("unsupported verification counted as verified: %+v", off)
	}
}

func TestDeletionRollsBackWhenTheAuditRowCannotBeWritten(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	now := time.Now().UTC()
	sess := seedSession(t, s, u.ID, now.Add(time.Hour), now)
	seedLogoutClient(t, s, "app", "https://app.example/bc")
	if _, err := s.EnsureClientSession("app", sess, u.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUserWithSyncEvents(u.ID, poisonedAudit(t, s, "admin.user_deleted", u.ID)); err == nil {
		t.Fatal("deletion succeeded without its audit row")
	}
	if got, _ := s.GetUserByID(u.ID); got == nil {
		t.Fatal("user deleted despite rollback")
	}
	if n := countDeliveries(t, s, `1=1`); n != 0 {
		t.Fatal("logout queued despite rollback")
	}
	if left, _ := s.ListUserSessions(u.ID, time.Hour); len(left) != 1 {
		t.Fatal("session lost despite rollback")
	}
}

// Re-enabling starts a new desired-state generation: the old deactivation cannot land
// after the reactivation, and the user has no session left to resume.
func TestReenablingStartsANewGenerationAndRequiresANewLogin(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	provisionedUser(t, s, u, "assigned")
	now := time.Now().UTC()
	seedSession(t, s, u.ID, now.Add(time.Hour), now)

	u.Status = "disabled"
	if err := s.UpdateUserWithSyncEvents(u, true, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE account_sync_events SET status='failed' WHERE user_id=? AND status='pending'`, u.ID); err != nil {
		t.Fatal(err)
	}
	u.Status = "active"
	if err := s.UpdateUserWithSyncEvents(u, false, nil); err != nil {
		t.Fatal(err)
	}
	if got := pendingFor(t, s, "assigned", u.ID); len(got) != 1 || got[0] != (queued{"user.updated", 3, true}) {
		t.Fatalf("after re-enable: %+v", got)
	}
	if left, _ := s.ListUserSessions(u.ID, time.Hour); len(left) != 0 {
		t.Fatal("a session survived disable and re-enable")
	}
	off, err := s.UserOffboarding(u.ID)
	if err != nil || off.Deleted || !off.Active || off.Acknowledged || off.Verified || len(off.Targets) != 1 || off.Targets[0].Recorded {
		t.Fatalf("offboarding view after re-enable: %+v %v", off, err)
	}
}
