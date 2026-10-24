package store

import (
	"errors"
	"testing"
	"time"
)

// Guards the resync removal replay: an account a connector knows only through a remote
// mapping, with no access, is re-sent as inactive (never deleted), so a target restored
// from backup cannot readmit it. A mapped account that no longer exists locally gets a
// bare inactive payload. Unknown systems are ErrNotFound; an audit failure rolls back.
func TestResyncSystemReplaysRemovals(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	provisioningFixture(t, s, "target")
	former := createTestUser(t, s)
	if err := s.SaveSCIMUserLink("target", former.ID, "remote-former"); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveSCIMUserLink("target", "gone-user", "remote-gone"); err != nil {
		t.Fatal(err)
	}
	if err := s.ResyncSystem("missing", nil); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown system", err)
	}
	if err := s.ResyncSystem("target", poisonedAudit(t, s, "admin.system_resynced", "target")); err == nil {
		t.Fatal("resync ignored audit failure")
	}
	if got := pendingFor(t, s, "target", former.ID); len(got) != 0 {
		t.Fatal("failed resync queued events", got)
	}
	if err := s.ResyncSystem("target", &AuditEvent{ID: "resync", Action: "admin.system_resynced", Outcome: "success", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	got := pendingFor(t, s, "target", former.ID)
	if len(got) != 1 || got[0].Type != "user.updated" || got[0].Active {
		t.Fatalf("mapped account without access not replayed inactive: %+v", got)
	}
	if gone := pendingFor(t, s, "target", "gone-user"); len(gone) != 1 || gone[0].Active || gone[0].Type == "user.deleted" {
		t.Fatalf("missing mapped account not replayed inactive: %+v", gone)
	}
	if count(t, s, `SELECT COUNT(*) FROM sync_resource_state WHERE system_id='target' AND resource_id=? AND NOT active AND provisioned`, former.ID) != 1 {
		t.Fatal("replayed removal not recorded as provisioned")
	}
}

// Guards the MFA-reset notification: connectors that hold the active account are told,
// disabled connectors are not.
func TestResetUserMFANotifiesHoldingConnectors(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	provisionedUser(t, s, u, "target")
	provisionedUser(t, s, u, "paused")
	mustExec(t, s, `UPDATE paired_systems SET status='disabled' WHERE id='paused'`)
	if err := s.ResetUserMFA(u.ID, nil); err != nil {
		t.Fatal(err)
	}
	got := pendingFor(t, s, "target", u.ID)
	if len(got) != 1 || got[0].Type != "user.mfa_reset" || !got[0].Active {
		t.Fatalf("holding connector not notified: %+v", got)
	}
	if paused := pendingFor(t, s, "paused", u.ID); len(paused) != 0 {
		t.Fatalf("disabled connector notified: %+v", paused)
	}
}
