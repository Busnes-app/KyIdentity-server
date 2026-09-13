package store

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
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

// Completion is decided over every delivery, not the page the UI shows.
func TestLogoutCompletionCountsEveryDelivery(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	seedLogoutClient(t, s, "app", "https://app.example/bc")
	u.Status = "disabled"
	if err := s.UpdateUserWithSyncEvents(u, true, nil); err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Add(-time.Hour)
	for i := 0; i < 51; i++ {
		status := "delivered"
		if i == 0 {
			status = "queued"
		}
		if _, err := s.db.Exec(`INSERT INTO logout_deliveries (id,client_id,user_id,sid,status,attempts,next_attempt_at,created_at,updated_at) VALUES (?,'app',?,?,?,1,?,?,?)`,
			uuid.NewString(), u.ID, "sid-"+uuid.NewString(), status, base, base.Add(time.Duration(i)*time.Second), base); err != nil {
			t.Fatal(err)
		}
	}
	off, err := s.UserOffboarding(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(off.Logouts) != 50 {
		t.Fatalf("display page = %d rows", len(off.Logouts))
	}
	if off.Acknowledged || off.Verified {
		t.Fatalf("a queued delivery outside the display page was rounded up: %+v", off)
	}
}

// A connector with no recorded account still gets a bare deletion in case it holds one
// from whole-directory delivery; that deletion must be a visible target, not hidden work.
func TestUntrackedHolderKeepsDeletionOutOfComplete(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	provisionedUser(t, s, u, "tracked")
	if err := s.CreatePairedSystem(&PairedSystem{ID: "untracked", Name: "untracked", SystemType: "scim", CallbackURL: "https://untracked.example/scim", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUserWithSyncEvents(u.ID, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE account_sync_events SET status='delivered' WHERE user_id=? AND system_id='tracked'`, u.ID); err != nil {
		t.Fatal(err)
	}
	off, err := s.UserOffboarding(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(off.Targets) != 2 {
		t.Fatalf("targets = %+v, want both connectors", off.Targets)
	}
	if off.Acknowledged || off.Verified {
		t.Fatalf("pending deletion on the untracked connector was rounded up: %+v", off)
	}
	for _, tgt := range off.Targets {
		if tgt.SystemID == "untracked" && (tgt.Acknowledged || tgt.Verified || tgt.LastEvent == nil || tgt.LastEvent.Type != "user.deleted" || tgt.LastEvent.Status != "pending") {
			t.Fatalf("untracked target: %+v", tgt)
		}
	}
}

// A sign-out that exhausted its attempts must keep holding the view back, even after
// housekeeping has run past the retention window.
func TestExhaustedLogoutOutlivesPruningAndKeepsCompletionFalse(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	now := time.Now().UTC()
	sess := seedSession(t, s, u.ID, now.Add(time.Hour), now)
	seedLogoutClient(t, s, "app", "https://app.example/bc")
	if _, err := s.EnsureClientSession("app", sess, u.ID); err != nil {
		t.Fatal(err)
	}
	u.Status = "disabled"
	if err := s.UpdateUserWithSyncEvents(u, true, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE logout_deliveries SET attempts=4, next_attempt_at=? WHERE user_id=?`, now.Add(-time.Second), u.ID); err != nil {
		t.Fatal(err)
	}
	d, err := s.ClaimLogoutDelivery(time.Minute)
	if err != nil || d == nil {
		t.Fatalf("claim: %v", err)
	}
	if err := s.FinishLogoutDelivery(d, errors.New("receiver down")); err != nil {
		t.Fatal(err)
	}
	if n := countDeliveries(t, s, `user_id=? AND status='failed'`, u.ID); n != 1 {
		t.Fatalf("failed rows = %d", n)
	}
	if _, err := s.db.Exec(`UPDATE logout_deliveries SET updated_at=? WHERE user_id=?`, now.Add(-8*24*time.Hour), u.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteLogoutDeliveriesOlderThan(now.Add(-7 * 24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	off, err := s.UserOffboarding(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if off.Acknowledged || off.Verified || len(off.Logouts) != 1 || off.Logouts[0].Status != "failed" {
		t.Fatalf("a pruned failure was read as success: %+v", off)
	}
}

// A connector that answered 200 but still lists the account as active has not removed
// it; the acknowledgement is contradicted, not merely unverified.
func TestListingThatStillSeesTheAccountActiveContradictsTheAcknowledgement(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	provisionedUser(t, s, u, "assigned")
	u.Status = "disabled"
	if err := s.UpdateUserWithSyncEvents(u, true, nil); err != nil {
		t.Fatal(err)
	}
	deliverAll(t, s)
	off, err := s.UserOffboarding(u.ID)
	if err != nil || !off.Acknowledged || !off.Targets[0].Acknowledged {
		t.Fatalf("before the listing: %+v %v", off, err)
	}
	if _, err := s.db.Exec(`UPDATE sync_resource_state SET observed='present_active',observed_at=? WHERE resource_id=?`, off.Targets[0].LastEvent.UpdatedAt.Add(time.Second), u.ID); err != nil {
		t.Fatal(err)
	}
	off, _ = s.UserOffboarding(u.ID)
	tgt := off.Targets[0]
	if off.Acknowledged || off.Verified || tgt.Acknowledged || tgt.Verified || !tgt.Contradicted {
		t.Fatalf("a contradicting listing was rounded up: %+v", off)
	}
	// A listing taken before the delivery says nothing about it.
	if _, err := s.db.Exec(`UPDATE sync_resource_state SET observed_at=? WHERE resource_id=?`, tgt.LastEvent.UpdatedAt.Add(-time.Second), u.ID); err != nil {
		t.Fatal(err)
	}
	off, _ = s.UserOffboarding(u.ID)
	if !off.Acknowledged || off.Targets[0].Contradicted {
		t.Fatalf("a stale listing contradicted a later delivery: %+v", off)
	}
}
