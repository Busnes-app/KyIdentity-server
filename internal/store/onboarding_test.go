package store

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func pendingUser(t *testing.T, s *Store) *User {
	t.Helper()
	u := &User{ID: uuid.NewString(), Username: "p" + uuid.NewString()[:8], DisplayName: "Pending", Email: uuid.NewString()[:8] + "@x.test", Role: "user", Status: "disabled", Pending: true}
	if err := s.CreateUserWithSyncEvents(u, nil); err != nil {
		t.Fatal(err)
	}
	return u
}

// An invited account cannot sign in until its single-use link sets a password; a newer
// link retires the old one, and a used, expired or mismatched link does nothing.
func TestPendingUserActivatesThroughASingleUseLink(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := pendingUser(t, s)
	first, err := s.IssueAccountToken(u.ID, "activation", "manual", 24*time.Hour, nil)
	if err != nil || first == "" {
		t.Fatalf("issue: %q %v", first, err)
	}
	second, err := s.IssueAccountToken(u.ID, "activation", "manual", 24*time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RedeemAccountToken(first, "activation", "hash-1", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("superseded link redeemed: %v", err)
	}
	if _, err := s.RedeemAccountToken(second, "reset", "hash-1", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("activation link accepted as a reset: %v", err)
	}
	if _, err := s.IssueAccountToken(u.ID, "reset", "manual", time.Hour, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("reset link issued for a pending account: %v", err)
	}
	got, err := s.RedeemAccountToken(second, "activation", "hash-1", nil)
	if err != nil || got == nil || got.ID != u.ID {
		t.Fatalf("redeem: %+v %v", got, err)
	}
	stored, _ := s.GetUserByID(u.ID)
	if stored.Pending || stored.Status != "active" || stored.PasswordHash != "hash-1" || stored.EmailVerifiedAt != nil {
		t.Fatalf("after activation: %+v", stored)
	}
	if _, err := s.RedeemAccountToken(second, "activation", "hash-2", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("link replayed: %v", err)
	}
	if _, err := s.IssueAccountToken(u.ID, "activation", "manual", time.Hour, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("activation link issued for an active account: %v", err)
	}
	expired, err := s.IssueAccountToken(u.ID, "reset", "manual", -time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RedeemAccountToken(expired, "reset", "hash-3", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired link redeemed: %v", err)
	}
	if _, err := s.RedeemAccountToken("not-a-token", "reset", "hash-3", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown link redeemed: %v", err)
	}
}

// Only a link that reached the address proves the address.
func TestEmailDeliveredActivationVerifiesTheAddress(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := pendingUser(t, s)
	raw, err := s.IssueAccountToken(u.ID, "activation", "email", time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RedeemAccountToken(raw, "activation", "hash", nil); err != nil {
		t.Fatal(err)
	}
	stored, _ := s.GetUserByID(u.ID)
	if stored.EmailVerifiedAt == nil {
		t.Fatal("email delivered activation did not verify the address")
	}
}

// Pending accounts are invisible to provisioning until they activate, then they gain
// access like any other active account.
func TestPendingUsersAreNotProvisionedUntilActivation(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	app := provisioningFixture(t, s, "target")
	u := pendingUser(t, s)
	if err := s.SetAppAssignment(app, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if got := pendingFor(t, s, "target", u.ID); len(got) != 0 {
		t.Fatalf("pending account provisioned: %+v", got)
	}
	raw, _ := s.IssueAccountToken(u.ID, "activation", "manual", time.Hour, nil)
	if _, err := s.RedeemAccountToken(raw, "activation", "hash", nil); err != nil {
		t.Fatal(err)
	}
	if got := pendingFor(t, s, "target", u.ID); len(got) != 1 || got[0].Type != "user.created" {
		t.Fatalf("activation did not provision: %+v", got)
	}
}

// A reset link replaces the password and ends every session and grant, and clears the
// lockout counter so the owner can sign in with the new password at once.
func TestResetLinkReplacesPasswordAndRevokesEverything(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	now := time.Now().UTC()
	sess := seedSession(t, s, u.ID, now.Add(time.Hour), now)
	jti, _, _ := seedGrants(t, s, u.ID, sess, "app")
	for range 3 {
		if _, err := s.RecordFailedLogin(u.ID); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := s.IssueAccountToken(u.ID, "reset", "email", 30*time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RedeemAccountToken(raw, "reset", "new-hash", nil); err != nil {
		t.Fatal(err)
	}
	stored, _ := s.GetUserByID(u.ID)
	if stored.PasswordHash != "new-hash" || stored.Status != "active" {
		t.Fatalf("after reset: %+v", stored)
	}
	if left, _ := s.ListUserSessions(u.ID, time.Hour); len(left) != 0 {
		t.Fatal("session survived a password reset")
	}
	if n := count(t, s, `SELECT COUNT(*) FROM issued_tokens WHERE jti=? AND revoked_at IS NULL`, jti); n != 0 {
		t.Fatal("token survived a password reset")
	}
	if n := count(t, s, `SELECT COUNT(*) FROM login_failures WHERE user_id=?`, u.ID); n != 0 {
		t.Fatal("lockout counter survived a password reset")
	}
	u.Status = "disabled"
	if err := s.UpdateUserWithSyncEvents(u, true, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.IssueAccountToken(u.ID, "reset", "manual", time.Hour, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("reset link issued for a disabled account: %v", err)
	}
}

// Changing the password keeps the session that proved itself and ends everything else,
// including any reset link still in flight.
func TestChangePasswordKeepsTheCurrentSessionAndRevokesTheRest(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	now := time.Now().UTC()
	keep := seedSession(t, s, u.ID, now.Add(time.Hour), now)
	other := seedSession(t, s, u.ID, now.Add(time.Hour), now)
	jti, _, _ := seedGrants(t, s, u.ID, other, "app")
	raw, _ := s.IssueAccountToken(u.ID, "reset", "manual", time.Hour, nil)

	if err := s.ChangePassword(u.ID, keep, "changed", nil); err != nil {
		t.Fatal(err)
	}
	left, _ := s.ListUserSessions(u.ID, time.Hour)
	if len(left) != 1 || left[0].ID != keep {
		t.Fatalf("sessions after change: %+v", left)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM issued_tokens WHERE jti=? AND revoked_at IS NULL`, jti); n != 0 {
		t.Fatal("token survived a password change")
	}
	if _, err := s.RedeemAccountToken(raw, "reset", "x", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("reset link survived a password change: %v", err)
	}
	stored, _ := s.GetUserByID(u.ID)
	if stored.PasswordHash != "changed" {
		t.Fatal("password not changed")
	}
	if err := s.ChangePassword(uuid.NewString(), keep, "x", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
}

// A new address is unproven: verification and every outstanding link go with the old one.
func TestEmailChangeClearsVerificationAndOutstandingLinks(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := pendingUser(t, s)
	raw, _ := s.IssueAccountToken(u.ID, "activation", "email", time.Hour, nil)
	if _, err := s.RedeemAccountToken(raw, "activation", "hash", nil); err != nil {
		t.Fatal(err)
	}
	reset, _ := s.IssueAccountToken(u.ID, "reset", "email", time.Hour, nil)
	stored, _ := s.GetUserByID(u.ID)
	stored.Email = "new-" + stored.Email
	if err := s.UpdateUserWithSyncEvents(stored, false, nil); err != nil {
		t.Fatal(err)
	}
	after, _ := s.GetUserByID(u.ID)
	if after.EmailVerifiedAt != nil {
		t.Fatal("verification survived an address change")
	}
	if _, err := s.RedeemAccountToken(reset, "reset", "x", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("reset link survived an address change: %v", err)
	}
	// An unrelated profile edit keeps both.
	again, _ := s.IssueAccountToken(u.ID, "reset", "email", time.Hour, nil)
	after.DisplayName = "Renamed"
	if err := s.UpdateUserWithSyncEvents(after, false, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RedeemAccountToken(again, "reset", "y", nil); err != nil {
		t.Fatalf("reset link lost on a profile edit: %v", err)
	}
}

func TestRedeemRollsBackWhenTheAuditRowCannotBeWritten(t *testing.T) {
	s, _ := newStoreWithUser(t, "user")
	u := pendingUser(t, s)
	raw, _ := s.IssueAccountToken(u.ID, "activation", "manual", time.Hour, nil)
	if _, err := s.RedeemAccountToken(raw, "activation", "hash", poisonedAudit(t, s, "auth.account_activated", u.ID)); err == nil {
		t.Fatal("activation succeeded without its audit row")
	}
	stored, _ := s.GetUserByID(u.ID)
	if !stored.Pending || stored.PasswordHash != "" {
		t.Fatalf("activation applied despite rollback: %+v", stored)
	}
	if _, err := s.RedeemAccountToken(raw, "activation", "hash", nil); err != nil {
		t.Fatalf("link consumed despite rollback: %v", err)
	}
}

func TestExpiredAccountTokensArePruned(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := pendingUser(t, s)
	if _, err := s.IssueAccountToken(u.ID, "activation", "manual", -time.Second, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteExpiredAccountTokens(); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM account_tokens`); n != 0 {
		t.Fatalf("expired tokens left: %d", n)
	}
}
