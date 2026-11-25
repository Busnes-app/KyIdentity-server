package store

import (
	"database/sql"
	"errors"
	"testing"
	"time"
)

// A pending holder past its invite's expiry stays, and org.holder_invite_expired is
// queued once; a live newer invite, or an org that is not active, queues nothing.
func TestHolderInviteExpiredQueuedOnce(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	platformTestTokenRow(t, s)
	org, holder := platformOrg(t, s, "inv")
	other, otherHolder := platformOrg(t, s, "inv2")
	expired := func(user string) {
		if _, err := s.db.Exec(`UPDATE account_tokens SET expires_at=? WHERE user_id=?`, time.Now().UTC().Add(-time.Minute), user); err != nil {
			t.Fatal(err)
		}
	}
	expired(holder.ID)
	expired(otherHolder.ID)
	if _, err := s.db.Exec(`UPDATE orgs SET status='suspended' WHERE id=?`, other.ID); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.DeleteExpiredAccountTokens(); err != nil {
			t.Fatal(err)
		}
	}
	events := func(id string) int {
		return count(t, s, `SELECT COUNT(*) FROM platform_events WHERE org_id=? AND type='org.holder_invite_expired'`, id)
	}
	if n := events(org.ID); n != 1 {
		t.Fatalf("holder_invite_expired: %d, want 1", n)
	}
	if n := events(other.ID); n != 0 {
		t.Fatalf("a suspended org's expiry queued %d", n)
	}
	if u, _ := s.PrincipalByID(holder.ID); u == nil || !u.Pending {
		t.Fatal("the pending holder was removed")
	}
	// A resent invite supersedes the old one: its expiry by the resend queues nothing.
	org3, h3 := platformOrg(t, s, "inv3")
	if _, err := lifecycle(s, "resend", func(tx *sql.Tx, now time.Time) (*PlatformOrg, error) {
		_, _, _, err := s.Platform().ResendInvite(tx, now, testCaller, org3.ID, h3.ID)
		return nil, err
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteExpiredAccountTokens(); err != nil {
		t.Fatal(err)
	}
	if n := events(org3.ID); n != 0 {
		t.Fatalf("a superseded invite queued %d", n)
	}
}

// The account holder cannot be disabled by disable-user either; the pointer stays live.
func TestHolderSurvivesDisableUser(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	platformTestTokenRow(t, s)
	org, holder := platformOrg(t, s, "du")
	if _, err := s.db.Exec(`UPDATE users SET pending=FALSE, status='active' WHERE id=?`, holder.ID); err != nil {
		t.Fatal(err)
	}
	guard := &User{ID: "guard", Username: "guard-admin", Email: "guard@example.test", Role: "admin", Status: "active"}
	if err := s.DefaultOrg().CreateUser(guard); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DisableUserByName(holder.Username, "guard-admin", nil); !errors.Is(erasureError(err), ErrAccountHolder) {
		t.Fatalf("disable-user on the holder: %v", err)
	}
	if _, err := s.db.Exec(`UPDATE users SET ends_at=? WHERE id=?`, time.Now().Add(time.Hour).Unix(), holder.ID); err == nil {
		t.Fatal("the holder was given an end date")
	}
	if o, _ := s.Platform().PlatformOrg(org.ID); o.AccountHolderUserID != holder.ID || !o.HolderActivated {
		t.Fatalf("holder pointer: %+v", o)
	}
	if err := s.Org(holder.Org()).DeleteUserWithSyncEvents(holder.ID, nil); !errors.Is(erasureError(err), ErrAccountHolder) {
		t.Fatalf("delete of the holder: %v", err)
	}
}

// A member whose email changed but whose username kept the old address is not the member
// at that old address: the add is email_in_use and the member is untouched.
func TestAddMemberMatchesByEmailOnly(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	platformTestTokenRow(t, s)
	org, holder := platformOrg(t, s, "um")
	if _, err := s.db.Exec(`UPDATE users SET email='renamed@example.test' WHERE id=?`, holder.ID); err != nil {
		t.Fatal(err)
	}
	_, _, err := s.Platform().PlatformWrite("tok", "add", "h", func(tx *sql.Tx, now time.Time) (int, any, error) {
		status, res, _, _, err := s.Platform().AddMember(tx, now, testCaller, org.ID, holder.Username, "Other", "")
		return status, res, err
	})
	if !errors.Is(err, ErrEmailInUse) {
		t.Fatalf("add at the old address: %v", err)
	}
}
