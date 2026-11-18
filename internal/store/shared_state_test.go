package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
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
	stale, ok, err := a.AcquireLease("job", time.Minute)
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
	// The holder dies and its minute passes (set directly: a short real ttl races a loaded machine).
	if _, err := a.db.Exec(`UPDATE leases SET until_ms=? WHERE name='job'`, time.Now().UnixMilli()-1); err != nil {
		t.Fatal(err)
	}
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
	for i, want := range []bool{true, true, true, false, false} {
		if ok, _ := s.AllowRate("never", 3, 0, later.Add(time.Duration(i)*1000*time.Hour), true); ok != want {
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
			if name == "upgrade" {
				SkipOnPostgres(t, "upgrades a legacy SQLite file")
			}
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

// Lease time is the database's: a row the database says is live is refused, and one it says
// has expired is taken, whatever the asking replica's own clock reads.
func TestLeaseUsesTheDatabaseClock(t *testing.T) {
	stores := replicas(t, 2)
	a, b := stores[0], stores[1]
	var dbNow int64
	if err := a.db.QueryRow(`SELECT ` + a.leaseNow()).Scan(&dbNow); err != nil {
		t.Fatal(err)
	}
	if skew := time.Now().UnixMilli() - dbNow; skew > 5000 || skew < -5000 {
		t.Fatalf("database clock read %d ms away from this process", skew)
	}
	// Live by database time though an hour stale by any replica clock an hour fast.
	if _, err := a.db.Exec(`INSERT INTO leases(name, token, until_ms) VALUES('job','someone',` + a.leaseNow() + `+60000)`); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := b.AcquireLease("job", time.Minute); err != nil || ok {
		t.Fatal("a lease the database holds live was taken:", ok, err)
	}
	if _, err := a.db.Exec(`UPDATE leases SET until_ms=` + a.leaseNow() + `-1 WHERE name='job'`); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := b.AcquireLease("job", time.Minute); err != nil || !ok {
		t.Fatal("a lease the database holds expired was refused:", ok, err)
	}
}

// A live holder keeps its lease through work far longer than the ttl.
func TestHeldLeaseOutlivesItsTTL(t *testing.T) {
	stores := replicas(t, 2)
	ttl := 400 * time.Millisecond
	ctx, release, ok, err := stores[0].HoldLease(context.Background(), "backup", ttl)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	deadline := time.Now().Add(4 * ttl)
	for time.Now().Before(deadline) {
		if _, ok, _ := stores[1].AcquireLease("backup", ttl); ok {
			t.Fatal("another replica took a lease its holder was renewing")
		}
		if ctx.Err() != nil {
			t.Fatal("the holder lost a lease nobody took:", context.Cause(ctx))
		}
		time.Sleep(ttl / 8)
	}
	release()
	if ctx.Err() == nil {
		t.Fatal("release left the hold's context running")
	}
	if _, ok, err := stores[1].AcquireLease("backup", ttl); err != nil || !ok {
		t.Fatal("release did not give the lease back:", ok, err)
	}
}

// Deleting or stealing the row ends the holder's context within one renewal interval, and
// the holder's release then leaves the new holder alone.
func TestALostLeaseEndsTheHold(t *testing.T) {
	for _, how := range []string{"deleted", "stolen"} {
		t.Run(how, func(t *testing.T) {
			stores := replicas(t, 2)
			ttl := 800 * time.Millisecond
			ctx, release, ok, err := stores[0].HoldLease(context.Background(), "backup", ttl)
			if err != nil || !ok {
				t.Fatal(ok, err)
			}
			defer release()
			q := `DELETE FROM leases WHERE name='backup'`
			if how == "stolen" {
				q = `UPDATE leases SET token='thief' WHERE name='backup'`
			}
			if _, err := stores[1].db.Exec(q); err != nil {
				t.Fatal(err)
			}
			lost := time.Now()
			select {
			case <-ctx.Done():
			case <-time.After(ttl/4 + time.Second):
				t.Fatal("the holder kept working after its lease was gone")
			}
			if !errors.Is(context.Cause(ctx), ErrLeaseLost) {
				t.Fatalf("cause %v", context.Cause(ctx))
			}
			t.Logf("lost after %v (interval %v)", time.Since(lost), ttl/4)
			release()
			if how == "stolen" {
				var token string
				if err := stores[1].db.QueryRow(`SELECT token FROM leases WHERE name='backup'`).Scan(&token); err != nil || token != "thief" {
					t.Fatalf("the old holder's release freed the new holder's lease: %q %v", token, err)
				}
			}
		})
	}
}

// One failed renewal while plenty of the lease is left is retried, not treated as a loss;
// failures that run the lease down below one interval end the hold.
func TestRenewalErrorsEndTheHoldOnlyNearExpiry(t *testing.T) {
	ttl := 400 * time.Millisecond
	run := func(renew func() (bool, error)) error {
		ctx, cancel := context.WithCancelCause(context.Background())
		defer cancel(nil)
		stop := make(chan struct{})
		done := make(chan struct{})
		go func() {
			defer close(done)
			keepLease(ctx, stop, cancel, ttl, time.Now().Add(ttl), func(context.Context) (bool, error) { return renew() })
		}()
		select {
		case <-done:
			return context.Cause(ctx)
		case <-time.After(3 * ttl):
			close(stop)
			<-done
			return nil
		}
	}
	var calls atomic.Int32
	if err := run(func() (bool, error) {
		if calls.Add(1) == 1 {
			return false, errors.New("lock timeout")
		}
		return true, nil
	}); err != nil {
		t.Fatalf("one transient failure ended the hold: %v", err)
	}
	if calls.Load() < 3 {
		t.Fatalf("renewal stopped after the failure: %d calls", calls.Load())
	}
	if err := run(func() (bool, error) { return false, errors.New("database unreachable") }); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("failures past the margin: %v", err)
	}
}

// A renewal that never answers (a one-sided partition, a stalled proxy: the statement is sent
// and nothing comes back) ends the hold before the lease expires on the database, so the
// work stops before another replica can take it; and a release while the renewal is stuck
// returns at once instead of waiting for the database.
func TestABlockedRenewalEndsTheHoldBeforeExpiry(t *testing.T) {
	ttl := 800 * time.Millisecond
	every := ttl / 4
	blocked := func(rctx context.Context) (bool, error) {
		<-rctx.Done() // what a driver does with a statement the network swallowed
		return false, rctx.Err()
	}
	t.Run("ends with ErrLeaseLost before the ttl", func(t *testing.T) {
		ctx, cancel := context.WithCancelCause(context.Background())
		defer cancel(nil)
		begun := time.Now()
		done := make(chan struct{})
		go func() { defer close(done); keepLease(ctx, make(chan struct{}), cancel, ttl, begun.Add(ttl), blocked) }()
		select {
		case <-done:
		case <-time.After(2 * ttl):
			t.Fatal("a renewal that never answered kept the hold past the lease's expiry")
		}
		took := time.Since(begun)
		if !errors.Is(context.Cause(ctx), ErrLeaseLost) {
			t.Fatalf("cause %v", context.Cause(ctx))
		}
		// The first renewal starts at one interval and may run until one interval before
		// expiry: the hold ends there, a full interval before the lease could be taken.
		if took < ttl-every-50*time.Millisecond || took >= ttl {
			t.Fatalf("the hold ended after %v, want about %v and before %v", took, ttl-every, ttl)
		}
	})
	t.Run("a slow take does not restart the expiry clock", func(t *testing.T) {
		ctx, cancel := context.WithCancelCause(context.Background())
		defer cancel(nil)
		// Half the lease elapsed before its successful take response arrived.
		remaining := ttl / 2
		expires := time.Now().Add(remaining)
		done := make(chan struct{})
		go func() { defer close(done); keepLease(ctx, make(chan struct{}), cancel, ttl, expires, blocked) }()
		select {
		case <-done:
		case <-time.After(remaining):
			t.Fatal("a delayed take response extended ownership past its original expiry")
		}
		if !errors.Is(context.Cause(ctx), ErrLeaseLost) {
			t.Fatalf("cause %v", context.Cause(ctx))
		}
	})
	t.Run("a release during the stuck renewal returns at once", func(t *testing.T) {
		ctx, cancel := context.WithCancelCause(context.Background())
		stop, done := make(chan struct{}), make(chan struct{})
		entered := make(chan struct{})
		go func() {
			defer close(done)
			keepLease(ctx, stop, cancel, ttl, time.Now().Add(ttl), func(rctx context.Context) (bool, error) {
				close(entered)
				return blocked(rctx)
			})
		}()
		<-entered
		released := time.Now()
		cancel(context.Canceled) // HoldLease's release: cancel, then stop and wait
		close(stop)
		select {
		case <-done:
		case <-time.After(every):
			t.Fatal("release waited on a renewal stuck on the database")
		}
		if took := time.Since(released); took > 100*time.Millisecond {
			t.Fatalf("release took %v", took)
		}
		if !errors.Is(context.Cause(ctx), context.Canceled) {
			t.Fatalf("a release is not a lost lease: %v", context.Cause(ctx))
		}
	})
}

// shiftedClock opens a second handle on the store at path whose sessions see the database
// clock moved by shift: a schema-local clock_timestamp() ahead of pg_catalog on the search
// path. It stands in for a database whose clock differs from the caller's.
func shiftedClock(t *testing.T, path string, shift string) *Store {
	t.Helper()
	schema, _, err := testSchema(path)
	if err != nil {
		t.Fatal(err)
	}
	var b [6]byte
	_, _ = rand.Read(b[:])
	clock := "kt_clock_" + hex.EncodeToString(b[:])
	admin, err := sql.Open("kypg", testDatabaseURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(`DROP SCHEMA ` + clock + ` CASCADE`); _ = admin.Close() })
	for _, q := range []string{`CREATE SCHEMA ` + clock,
		`CREATE FUNCTION ` + clock + `.clock_timestamp() RETURNS timestamptz LANGUAGE sql AS $$ SELECT pg_catalog.clock_timestamp() + interval '` + shift + `' $$`} {
		if _, err := admin.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	s, err := openPostgres(testDatabaseURL(), schema+","+clock+",pg_catalog,public", false, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// The lease is decided by the database's clock, never the caller's: with the database an hour
// ahead of every caller, a row expired by the database is taken although every caller's clock
// says it is live; with it an hour behind, a row live by the database is refused although
// every caller's clock says it has expired. A lease computed on the caller's clock fails both.
func TestLeaseFollowsTheDatabaseClockNotTheCallers(t *testing.T) {
	requirePostgres(t)
	path := filepath.Join(t.TempDir(), "clock.db")
	plain, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	set := func(untilFromNow time.Duration) {
		t.Helper()
		if _, err := plain.db.Exec(`DELETE FROM leases WHERE name='job'`); err != nil {
			t.Fatal(err)
		}
		// The true time in ms, written as a literal so the shifted handles' clocks do not apply.
		if _, err := plain.db.Exec(`INSERT INTO leases(name, token, until_ms) VALUES('job','someone',?)`, time.Now().Add(untilFromNow).UnixMilli()); err != nil {
			t.Fatal(err)
		}
	}
	ahead, behind := shiftedClock(t, path, "1 hour"), shiftedClock(t, path, "-1 hour")
	var dbNow int64
	if err := ahead.db.QueryRow(`SELECT ` + ahead.leaseNow()).Scan(&dbNow); err != nil || dbNow-time.Now().UnixMilli() < 50*60*1000 {
		t.Fatalf("the shifted handle does not see a shifted database clock: %d %v", dbNow-time.Now().UnixMilli(), err)
	}

	set(30 * time.Minute) // live to every caller, expired to a database an hour ahead
	if _, ok, err := ahead.AcquireLease("job", time.Minute); err != nil || !ok {
		t.Fatal("a lease the database holds expired was refused by the caller's clock:", ok, err)
	}
	set(-30 * time.Minute) // expired to every caller, live to a database an hour behind
	if _, ok, err := behind.AcquireLease("job", time.Minute); err != nil || ok {
		t.Fatal("a lease the database holds live was taken by the caller's clock:", ok, err)
	}
}
