package store

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// replicas opens n stores on one database file: separate processes in everything the
// store can see, since each has its own connection pool.
func replicas(t *testing.T, n int) []*Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "shared.db")
	out := make([]*Store, n)
	for i := range out {
		s, err := New(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		out[i] = s
	}
	return out
}

// together runs fn once per replica, all released at the same instant.
func together(t *testing.T, stores []*Store, fn func(i int, s *Store) error) {
	t.Helper()
	start := make(chan struct{})
	errs := make([]error, len(stores))
	var wg sync.WaitGroup
	for i, s := range stores {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = fn(i, s)
		}()
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("replica %d: %v", i, err)
		}
	}
}

func TestLeaseHasOneHolder(t *testing.T) {
	stores := replicas(t, 8)
	for round := range 20 {
		var held atomic.Int32
		releases := make([]func(), len(stores))
		together(t, stores, func(i int, s *Store) error {
			release, ok, err := s.AcquireLease("job", time.Minute)
			if ok {
				held.Add(1)
				releases[i] = release
			}
			return err
		})
		if held.Load() != 1 {
			t.Fatalf("round %d: %d replicas hold the lease, want 1", round, held.Load())
		}
		for _, release := range releases {
			if release != nil {
				release()
			}
		}
	}
}

func TestLeaseExpiresAndReleaseIsTheHoldersOnly(t *testing.T) {
	stores := replicas(t, 2)
	a, b := stores[0], stores[1]
	stale, ok, err := a.AcquireLease("job", 30*time.Millisecond)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	if _, ok, _ := b.AcquireLease("job", time.Minute); ok {
		t.Fatal("a live lease was taken over")
	}
	if _, ok, _ := a.AcquireLease("job", time.Minute); ok {
		t.Fatal("the holder's own process took the lease twice")
	}
	if _, ok, _ := b.AcquireLease("other", time.Minute); !ok {
		t.Fatal("leases with different names blocked each other")
	}
	time.Sleep(60 * time.Millisecond)
	if _, ok, err := b.AcquireLease("job", time.Minute); err != nil || !ok {
		t.Fatal("an expired lease was not taken over:", ok, err)
	}
	// The first holder finishing late must not free the lease its successor now holds.
	stale()
	if _, ok, _ := a.AcquireLease("job", time.Minute); ok {
		t.Fatal("a stale release freed the successor's lease")
	}
}

// N replicas spending from one bucket get the bucket's allowance once, not N times.
func TestSharedRateLimitHoldsAcrossReplicas(t *testing.T) {
	stores := replicas(t, 6)
	now := time.Now()
	const burst = 10
	var allowed atomic.Int32
	together(t, stores, func(_ int, s *Store) error {
		for range burst {
			ok, err := s.AllowRate("login_push:user-1", burst, burst/3600.0, now, true)
			if err != nil {
				return err
			}
			if ok {
				allowed.Add(1)
			}
		}
		return nil
	})
	if allowed.Load() != burst {
		t.Fatalf("%d replicas were allowed %d requests in all, want %d", len(stores), allowed.Load(), burst)
	}
	if ok, _ := stores[0].AllowRate("login_push:user-2", burst, burst/3600.0, now, true); !ok {
		t.Fatal("one key's exhaustion refused another key")
	}
}

// The database bucket refills exactly as the in-memory token bucket does.
func TestSharedRateLimitRefills(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	t0 := time.Now()
	spend := func(at time.Time) bool {
		t.Helper()
		ok, err := s.AllowRate("k", 3, 0.5, at, true) // 3 burst, one more every 2 s
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	for i, want := range []bool{true, true, true, false} {
		if got := spend(t0); got != want {
			t.Fatalf("request %d at t0: allowed=%v want %v", i, got, want)
		}
	}
	if spend(t0.Add(1900 * time.Millisecond)) {
		t.Fatal("allowed before one request's worth had refilled")
	}
	if !spend(t0.Add(2 * time.Second)) {
		t.Fatal("refused after one request's worth had refilled")
	}
	if spend(t0.Add(2 * time.Second)) {
		t.Fatal("a refill of one allowed two")
	}
	// A long idle period refills to the burst and no further.
	later := t0.Add(time.Hour)
	for i, want := range []bool{true, true, true, false} {
		if got := spend(later); got != want {
			t.Fatalf("request %d after idling: allowed=%v want %v", i, got, want)
		}
	}
	// A limit that never refills stays spent.
	for i, want := range []bool{true, false} {
		if ok, _ := s.AllowRate("never", 1, 0, later.Add(time.Duration(i)*1000*time.Hour), true); ok != want {
			t.Fatalf("zero-rate request %d: allowed=%v want %v", i, ok, want)
		}
	}
}

func TestSharedRateLimitSweepKeepsLiveBuckets(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	now := time.Now()
	for i := range 5 {
		if ok, _ := s.AllowRate(fmt.Sprintf("fast:%d", i), 10, 1, now, true); !ok {
			t.Fatal("first request refused")
		}
	}
	for range 3 {
		_, _ = s.AllowRate("slow", 3, 1.0/3600, now, true)
	}
	// A minute on, the one-per-second buckets are full again; the hourly one is still owed.
	n, err := s.SweepRateLimits(now.Add(time.Minute))
	if err != nil || n != 1 {
		t.Fatalf("buckets left = %d (%v), want only the one still owed tokens", n, err)
	}
	if ok, _ := s.AllowRate("slow", 3, 1.0/3600, now.Add(time.Minute), true); ok {
		t.Fatal("the sweep handed a spent bucket a fresh allowance")
	}
	// At the cap an existing bucket still spends; a new key is refused, not admitted.
	if ok, _ := s.AllowRate("fast:0", 10, 1, now.Add(time.Minute), false); ok {
		t.Fatal("a swept bucket was re-created at the cap")
	}
	if ok, _ := s.AllowRate("slow", 3, 1.0/3600, now.Add(2*time.Hour), false); !ok {
		t.Fatal("an existing bucket was refused at the cap after refilling")
	}
}

// Two servers starting on one fresh database, or one being upgraded, must both come up.
func TestConcurrentFirstStartMigratesOnce(t *testing.T) {
	for name, path := range map[string]string{
		"fresh":   filepath.Join(t.TempDir(), "fresh.db"),
		"upgrade": legacyDatabase(t),
	} {
		t.Run(name, func(t *testing.T) {
			const n = 6
			stores := make([]*Store, n)
			errs := make([]error, n)
			start := make(chan struct{})
			var wg sync.WaitGroup
			for i := range n {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					stores[i], errs[i] = New(path)
				}()
			}
			close(start)
			wg.Wait()
			for i, err := range errs {
				if err != nil {
					t.Fatalf("start %d: %v", i, err)
				}
				defer stores[i].Close()
			}
			refPath := filepath.Join(t.TempDir(), "reference.db")
			ref, err := New(refPath)
			if err != nil {
				t.Fatal(err)
			}
			ref.Close()
			if got, want := fmt.Sprint(schemaFingerprint(t, path)), fmt.Sprint(schemaFingerprint(t, refPath)); got != want {
				t.Fatalf("schema after concurrent starts differs from a fresh install:\n got %s\nwant %s", got, want)
			}
			var leases int
			if err := stores[0].db.QueryRow(`SELECT COUNT(*) FROM leases WHERE name='migrate'`).Scan(&leases); err != nil || leases != 0 {
				t.Fatalf("migration lease left behind: %d %v", leases, err)
			}
		})
	}
}

// Each queued alert mail is sent by exactly one replica.
func TestAlertDeliveriesAreClaimedOnce(t *testing.T) {
	stores := replicas(t, 4)
	s := stores[0]
	var ids []string
	for i := range 12 {
		ids = append(ids, alertAdmin(t, s, fmt.Sprintf("root%d", i)).ID)
	}
	if err := s.SetAlertSettings(AlertSettings{LoginFailureThreshold: 10, LoginFailureWindowSeconds: 600, Recipients: ids}, nil); err != nil {
		t.Fatal(err)
	}
	audited(t, s, "admin.scim_token_issued", "root0", "c1", "scim_connector", "success", "")
	evaluate(t, s)

	var mu sync.Mutex
	sent := map[string]int{}
	send := func(to, _, _ string) error {
		mu.Lock()
		sent[to]++
		mu.Unlock()
		time.Sleep(5 * time.Millisecond) // long enough for every replica to be mid-pass
		return nil
	}
	now := time.Now().UTC()
	for range 3 {
		together(t, stores, func(_ int, r *Store) error {
			_, err := r.DeliverAlerts(context.Background(), now, send)
			return err
		})
	}
	if len(sent) != len(ids) {
		t.Fatalf("%d recipients mailed, want %d", len(sent), len(ids))
	}
	for to, n := range sent {
		if n != 1 {
			t.Fatalf("%s was mailed %d times", to, n)
		}
	}
}

// A replica that dies holding a claim does not strand the mail: the claim expires.
func TestAbandonedAlertClaimIsRetried(t *testing.T) {
	stores := replicas(t, 2)
	s := stores[0]
	admin := alertAdmin(t, s, "root")
	if err := s.SetAlertSettings(AlertSettings{LoginFailureThreshold: 10, LoginFailureWindowSeconds: 600, Recipients: []string{admin.ID}}, nil); err != nil {
		t.Fatal(err)
	}
	audited(t, s, "admin.scim_token_issued", "root", "c1", "scim_connector", "success", "")
	evaluate(t, s)
	now := time.Now().UTC()
	// The dying replica: claimed, then gone before recording anything.
	if _, err := s.db.Exec(`UPDATE alert_deliveries SET lease_until_ms=?`, now.Add(alertDeliveryLease).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	count := func(at time.Time) int {
		t.Helper()
		n, err := stores[1].DeliverAlerts(context.Background(), at, func(string, string, string) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(now.Add(alertDeliveryLease - time.Second)); n != 0 {
		t.Fatal("a live claim was taken over")
	}
	if n := count(now.Add(alertDeliveryLease + time.Second)); n != 1 {
		t.Fatal("an expired claim was never retried")
	}
}

// Limits changed on one replica reach the others within the refresh interval, and the
// change is measured against what is stored, not against the changing replica's cache.
func TestSessionLimitsReachOtherReplicas(t *testing.T) {
	old := sessionLimitsRefresh
	sessionLimitsRefresh = 20 * time.Millisecond
	t.Cleanup(func() { sessionLimitsRefresh = old })
	stores := replicas(t, 2)
	a, b := stores[0], stores[1]
	seed := SessionLimits{Absolute: 24 * 3600, Idle: 8 * 3600}
	for _, s := range stores {
		if err := s.LoadSessionLimits(seed); err != nil {
			t.Fatal(err)
		}
	}
	tight := SessionLimits{Absolute: 2 * 3600, Idle: 600}
	if _, err := a.SetSessionLimits(tight, nil); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for b.SessionLimits() != tight {
		if time.Now().After(deadline) {
			t.Fatalf("replica b still applies %+v", b.SessionLimits())
		}
		time.Sleep(5 * time.Millisecond)
	}

	// b relaxes the limits straight away. A session past the tight limits must still end,
	// even where b's cache had not caught up with a's change.
	u := createTestUser(t, a)
	now := time.Now().UTC()
	if err := a.CreateSession(&Session{ID: "idle", UserID: u.ID, SessionTokenHash: "idle", ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.Exec(`UPDATE sessions SET last_active_at=? WHERE id='idle'`, now.Add(-20*time.Minute)); err != nil {
		t.Fatal(err)
	}
	b.limits.Store(&seed) // the stale cache
	ended, err := b.SetSessionLimits(seed, nil)
	if err != nil || ended != 1 {
		t.Fatalf("relaxing from a stale cache ended %d sessions (%v), want the one past the stored limits", ended, err)
	}
}

// Every capsule is snapshotted while its server holds the backup lease. A restore must
// not inherit it, or the restored server refuses to back up until the lease runs out.
func TestRestoreDropsTheCapsulesLeases(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	if _, ok, err := s.AcquireLease("backup", time.Hour); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if ok, err := s.AllowRate("reset:u", 1, 0, time.Now(), true); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if _, err := s.ApplyRestoredState(time.Now().UTC(), nil); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.AcquireLease("backup", time.Hour); err != nil || !ok {
		t.Fatal("the restored server inherited the capsule's backup lease:", ok, err)
	}
	if ok, _ := s.AllowRate("reset:u", 1, 0, time.Now(), true); !ok {
		t.Fatal("the restored server inherited the capsule's rate-limit buckets")
	}
}
