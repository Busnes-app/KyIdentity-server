package store

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// A redemption queued behind a revocation must not pass the expiry that revocation set:
// its clock is read under the write lock, not while it waits for it.
func TestRedemptionQueuedBehindRevocationFails(t *testing.T) {
	s, close := setupTestStore(t)
	defer close()
	u := &User{ID: uuid.NewString(), Username: "invited", DisplayName: "invited", Email: "invited@example.test", Role: "user", Status: "disabled", Pending: true}
	if err := s.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	link, err := s.IssueAccountToken(u.ID, "activation", "manual", time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Hold the write lock as a disable would.
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	done := make(chan error, 1)
	go func() {
		_, err := s.RedeemAccountToken(link, "activation", "new-hash", nil)
		done <- err
	}()
	// Let the redemption start and queue on the lock (busy_timeout is 5s). A slow
	// scheduler can only make this pass vacuously, never fail correct code.
	time.Sleep(200 * time.Millisecond)
	if err := revokeUserAccessTx(tx, u.ID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrNotFound) {
		t.Fatalf("queued redemption: %v", err)
	}
	got, err := s.GetUserByID(u.ID)
	if err != nil || got.Status != "disabled" || !got.Pending {
		t.Fatalf("account after revocation: %+v %v", got, err)
	}
}
