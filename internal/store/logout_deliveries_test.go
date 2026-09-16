package store

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func seedLogoutClient(t *testing.T, s *Store, id, backchannel string) {
	t.Helper()
	c := &OAuthClient{ID: id, ClientName: "App " + id, ClientType: "public", RedirectURIsJSON: `["https://app/cb"]`, AllowedScopesJSON: `["openid"]`, BackchannelLogoutURI: backchannel, Enabled: true}
	if err := s.CreateOAuthClient(c); err != nil {
		t.Fatal(err)
	}
}

func countDeliveries(t *testing.T, s *Store, where string, args ...any) int {
	t.Helper()
	return count(t, s, `SELECT COUNT(*) FROM logout_deliveries WHERE `+where, args...)
}

func TestOAuthClientPersistsBackchannelLogoutURI(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	seedLogoutClient(t, s, "app", "https://app.example/backchannel")
	got, err := s.GetOAuthClientByID("app")
	if err != nil || got == nil || got.BackchannelLogoutURI != "https://app.example/backchannel" {
		t.Fatalf("get: %+v %v", got, err)
	}
	got.BackchannelLogoutURI = ""
	if err := s.UpdateOAuthClient(got); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListOAuthClients()
	if err != nil || len(list) != 1 || list[0].BackchannelLogoutURI != "" {
		t.Fatalf("list: %+v %v", list, err)
	}
}

// Ending a session queues one logout per client that saw it and registered a receiver;
// clients without a receiver get nothing, and other sessions are untouched.
func TestRevokingASessionQueuesLogoutForItsReceivers(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	now := time.Now().UTC()
	a := seedSession(t, s, u.ID, now.Add(time.Hour), now)
	b := seedSession(t, s, u.ID, now.Add(time.Hour), now)
	seedLogoutClient(t, s, "with", "https://with.example/bc")
	seedLogoutClient(t, s, "without", "")
	sidA, _ := s.EnsureClientSession("with", a, u.ID)
	if _, err := s.EnsureClientSession("without", a, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnsureClientSession("with", b, u.ID); err != nil {
		t.Fatal(err)
	}

	if err := s.RevokeSession(u.ID, a, nil); err != nil {
		t.Fatal(err)
	}
	if n := countDeliveries(t, s, `1=1`); n != 1 {
		t.Fatalf("deliveries = %d, want 1", n)
	}
	if n := countDeliveries(t, s, `client_id='with' AND user_id=? AND sid=? AND status='queued'`, u.ID, sidA); n != 1 {
		t.Fatal("delivery is not for the revoked session's receiver")
	}
	if err := s.RevokeOtherSessions(u.ID, uuid.NewString(), nil); err != nil {
		t.Fatal(err)
	}
	if n := countDeliveries(t, s, `1=1`); n != 2 {
		t.Fatalf("revoke-others should queue session B: %d", n)
	}
}

func TestDisablingAUserQueuesLogoutForEverySession(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	now := time.Now().UTC()
	seedLogoutClient(t, s, "app", "https://app.example/bc")
	for range 2 {
		sid := seedSession(t, s, u.ID, now.Add(time.Hour), now)
		if _, err := s.EnsureClientSession("app", sid, u.ID); err != nil {
			t.Fatal(err)
		}
	}
	u.Status = "disabled"
	if err := s.UpdateUserWithSyncEvents(u, true, nil); err != nil {
		t.Fatal(err)
	}
	if n := countDeliveries(t, s, `user_id=? AND status='queued'`, u.ID); n != 2 {
		t.Fatalf("deliveries = %d, want 2", n)
	}
}

func TestRevokingOneClientQueuesLogoutOnlyForThatClient(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	now := time.Now().UTC()
	sess := seedSession(t, s, u.ID, now.Add(time.Hour), now)
	seedLogoutClient(t, s, "x", "https://x.example/bc")
	seedLogoutClient(t, s, "y", "https://y.example/bc")
	for _, c := range []string{"x", "y"} {
		if _, err := s.EnsureClientSession(c, sess, u.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.RevokeUserClientAccess(u.ID, "x", nil); err != nil {
		t.Fatal(err)
	}
	if n := countDeliveries(t, s, `client_id='x'`); n != 1 {
		t.Fatal("no delivery queued for x")
	}
	if n := countDeliveries(t, s, `client_id='y'`); n != 0 {
		t.Fatal("delivery queued for an untouched client")
	}
	if n := count(t, s, `SELECT COUNT(*) FROM sessions WHERE id=?`, sess); n != 1 {
		t.Fatal("browser session must survive a per-client revocation")
	}
}

func TestLogoutDeliveryClaimRetryAndTerminalFailure(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	now := time.Now().UTC()
	sess := seedSession(t, s, u.ID, now.Add(time.Hour), now)
	seedLogoutClient(t, s, "app", "https://app.example/bc")
	if _, err := s.EnsureClientSession("app", sess, u.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeSession(u.ID, sess, nil); err != nil {
		t.Fatal(err)
	}

	d, err := s.ClaimLogoutDelivery(time.Minute)
	if err != nil || d == nil || d.ClientID != "app" || d.UserID != u.ID || d.SID == "" || d.Attempts != 1 {
		t.Fatalf("claim: %+v %v", d, err)
	}
	if d.BackchannelLogoutURI != "https://app.example/bc" {
		t.Fatalf("claimed delivery lacks its target: %+v", d)
	}
	if again, err := s.ClaimLogoutDelivery(time.Minute); err != nil || again != nil {
		t.Fatalf("a leased delivery was claimed twice: %+v %v", again, err)
	}

	// A stale claim token cannot finish the job.
	stale := *d
	stale.ClaimToken = "stale"
	if err := s.FinishLogoutDelivery(&stale, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale claim finished the delivery: %v", err)
	}

	if err := s.FinishLogoutDelivery(d, errors.New("503")); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListLogoutDeliveries(u.ID, 10)
	if err != nil || len(rows) != 1 || rows[0].Status != "queued" || rows[0].LastError != "503" || !rows[0].NextAttemptAt.After(now) {
		t.Fatalf("after failure: %+v %v", rows, err)
	}
	if d, err := s.ClaimLogoutDelivery(time.Minute); err != nil || d != nil {
		t.Fatalf("a delivery waiting for its backoff was claimed: %+v %v", d, err)
	}

	// Exhaust the attempts: the job ends failed and is never claimed again.
	if _, err := s.db.Exec(`UPDATE logout_deliveries SET next_attempt_at=?, attempts=4`, now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	d, err = s.ClaimLogoutDelivery(time.Minute)
	if err != nil || d == nil || d.Attempts != 5 {
		t.Fatalf("fifth claim: %+v %v", d, err)
	}
	if err := s.FinishLogoutDelivery(d, errors.New("still down")); err != nil {
		t.Fatal(err)
	}
	rows, _ = s.ListLogoutDeliveries(u.ID, 10)
	if rows[0].Status != "failed" {
		t.Fatalf("status = %q, want failed", rows[0].Status)
	}
	if d, _ := s.ClaimLogoutDelivery(time.Minute); d != nil {
		t.Fatal("a failed delivery was claimed")
	}
}

func TestLogoutDeliverySuccessAndExpiredLeaseReclaim(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	now := time.Now().UTC()
	sess := seedSession(t, s, u.ID, now.Add(time.Hour), now)
	seedLogoutClient(t, s, "app", "https://app.example/bc")
	if _, err := s.EnsureClientSession("app", sess, u.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeSession(u.ID, sess, nil); err != nil {
		t.Fatal(err)
	}
	first, err := s.ClaimLogoutDelivery(-time.Second)
	if err != nil || first == nil {
		t.Fatalf("claim: %v", err)
	}
	second, err := s.ClaimLogoutDelivery(time.Minute)
	if err != nil || second == nil || second.ID != first.ID || second.Attempts != 2 {
		t.Fatalf("expired lease not reclaimed: %+v %v", second, err)
	}
	if err := s.FinishLogoutDelivery(first, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the lapsed worker finished the job: %v", err)
	}
	if err := s.FinishLogoutDelivery(second, nil); err != nil {
		t.Fatal(err)
	}
	rows, _ := s.ListLogoutDeliveries(u.ID, 10)
	if len(rows) != 1 || rows[0].Status != "delivered" || rows[0].ClientName != "App app" {
		t.Fatalf("rows = %+v", rows)
	}
}

// A client whose delivery is mid-flight is skipped, so one slow receiver holds at most
// one worker; a lapsed lease does not count.
func TestClaimSkipsClientsWithAnActiveLease(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	now := time.Now().UTC()
	a := seedSession(t, s, u.ID, now.Add(time.Hour), now)
	b := seedSession(t, s, u.ID, now.Add(time.Hour), now)
	seedLogoutClient(t, s, "slow", "https://slow.example/bc")
	seedLogoutClient(t, s, "fast", "https://fast.example/bc")
	for _, sess := range []string{a, b} {
		if _, err := s.EnsureClientSession("slow", sess, u.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.EnsureClientSession("fast", b, u.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeSession(u.ID, a, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeSession(u.ID, b, nil); err != nil {
		t.Fatal(err)
	}

	first, err := s.ClaimLogoutDelivery(time.Minute)
	if err != nil || first == nil || first.ClientID != "slow" {
		t.Fatalf("first claim: %+v %v", first, err)
	}
	second, err := s.ClaimLogoutDelivery(time.Minute)
	if err != nil || second == nil || second.ClientID != "fast" {
		t.Fatalf("second claim should skip the leased client: %+v %v", second, err)
	}
	if third, err := s.ClaimLogoutDelivery(time.Minute); err != nil || third != nil {
		t.Fatalf("slow's second row was claimed while its first is in flight: %+v %v", third, err)
	}
	if err := s.FinishLogoutDelivery(first, nil); err != nil {
		t.Fatal(err)
	}
	if next, err := s.ClaimLogoutDelivery(time.Minute); err != nil || next == nil || next.ClientID != "slow" {
		t.Fatalf("slow's second row after the first finished: %+v %v", next, err)
	}
}

func TestPruningRemovesOnlyDeliveredOldRows(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	now := time.Now().UTC()
	sess := seedSession(t, s, u.ID, now.Add(time.Hour), now)
	seedLogoutClient(t, s, "a", "https://a.example/bc")
	seedLogoutClient(t, s, "b", "https://b.example/bc")
	seedLogoutClient(t, s, "c", "https://c.example/bc")
	for _, c := range []string{"a", "b", "c"} {
		if _, err := s.EnsureClientSession(c, sess, u.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.RevokeSession(u.ID, sess, nil); err != nil {
		t.Fatal(err)
	}
	old := now.Add(-8 * 24 * time.Hour)
	if _, err := s.db.Exec(`UPDATE logout_deliveries SET status='delivered', updated_at=? WHERE client_id='a'`, old); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE logout_deliveries SET status='failed', updated_at=? WHERE client_id='b'`, old); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE logout_deliveries SET updated_at=? WHERE client_id='c'`, old); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteLogoutDeliveriesOlderThan(now.Add(-7 * 24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n := countDeliveries(t, s, `1=1`); n != 2 {
		t.Fatalf("deliveries after prune = %d, want the failed and queued ones", n)
	}
	if n := countDeliveries(t, s, `client_id='a'`); n != 0 {
		t.Fatal("the old delivered row survived the prune")
	}
	if n := countDeliveries(t, s, `client_id='b' AND status='failed'`); n != 1 {
		t.Fatal("the failed delivery was pruned: its absence would read as success")
	}
	if n := countDeliveries(t, s, `client_id='c' AND status='queued'`); n != 1 {
		t.Fatal("the queued delivery was pruned")
	}
}
