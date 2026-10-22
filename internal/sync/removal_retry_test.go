package sync

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	stdsync "sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// The worker reads time.Now, so these tests advance the clock by making every backoff
// and recovery deadline due, after recording how long the worker asked to wait.

type outboxRow struct {
	eventType, status string
	attempts          int
	wait              time.Duration
}

func outbox(t *testing.T, s *store.Store, systemID, userID string) []outboxRow {
	t.Helper()
	db, err := sql.Open("sqlite", syncTestDBs[s]+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT event_type,status,attempts,next_attempt_at FROM account_sync_events WHERE system_id=? AND user_id=? AND status<>'delivered' ORDER BY rowid`, systemID, userID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []outboxRow
	for rows.Next() {
		var r outboxRow
		var next sql.NullTime
		if err := rows.Scan(&r.eventType, &r.status, &r.attempts, &next); err != nil {
			t.Fatal(err)
		}
		if next.Valid {
			r.wait = time.Until(next.Time)
		}
		out = append(out, r)
	}
	return out
}

func elapse(t *testing.T, s *store.Store) {
	t.Helper()
	past := time.Now().UTC().Add(-time.Second)
	execRaw(t, s, `UPDATE account_sync_events SET next_attempt_at=? WHERE next_attempt_at IS NOT NULL`, past)
	execRaw(t, s, `UPDATE sync_delivery_attempts SET recover_after=?`, past)
}

func dispatch(t *testing.T, e *Engine) {
	t.Helper()
	if err := e.DispatchPendingEvents(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func outageOpen(t *testing.T, s *store.Store, systemID string) bool {
	t.Helper()
	if err := s.EvaluateAlerts(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	alerts, _, err := s.ListAlerts("all", 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range alerts {
		if a.Rule == "provisioning_outage" && a.Key == systemID && a.Status != "resolved" {
			return true
		}
	}
	return false
}

type hit struct {
	event  string
	active bool
}

// flakyReceiver is a suite receiver that answers 503 while down, or the queued statuses
// first. It records every request it saw. With fence set it refuses, as suite receivers
// do, a meta.version older than one it applied.
type flakyReceiver struct {
	down   atomic.Bool
	mu     stdsync.Mutex
	script []int
	hits   []hit
	fence  bool
	last   int
}

func (f *flakyReceiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body SCIMUserResource
	_ = json.NewDecoder(r.Body).Decode(&body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hits = append(f.hits, hit{r.Header.Get("X-KySignOn-Event-Type"), body.Active})
	var version int
	if body.Meta != nil {
		_, _ = fmt.Sscanf(body.Meta.Version, `W/"%d"`, &version)
	}
	switch {
	case f.down.Load():
		w.WriteHeader(503)
	case f.fence && version < f.last:
		w.WriteHeader(409)
	case len(f.script) > 0:
		w.WriteHeader(f.script[0])
		f.script = f.script[1:]
	default:
		f.last = max(f.last, version)
		w.WriteHeader(200)
	}
}

func (f *flakyReceiver) seen() []hit {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]hit(nil), f.hits...)
}

func suiteFixture(t *testing.T) (*Engine, *store.Store, *store.User, *store.PairedSystem, *flakyReceiver) {
	t.Helper()
	e, s, _, cleanup := setupTestSyncEngine(t)
	t.Cleanup(cleanup)
	recv := &flakyReceiver{}
	srv := httptest.NewServer(recv)
	t.Cleanup(srv.Close)
	sys, _, err := e.CreateSystem(&CreateSystemRequest{Name: "directory", SystemType: "suite_webhook", CallbackURL: srv.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	u := member(t, s)
	if err := s.SetAppAssignment(appRecordFor(t, s, sys.ID).ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	return e, s, u, sys, recv
}

// A receiver down for well over 30 minutes still gets the removal once it is back, with
// no administrator step, for suite webhooks and generic SCIM alike. The removal outlives
// the attempt budget, waits at most 30 minutes between tries, and alerts while it retries.
func TestRemovalRetriesUntilReceiverReturns(t *testing.T) {
	for _, kind := range []string{"suite_webhook", "scim"} {
		t.Run(kind, func(t *testing.T) {
			e, s, _, cleanup := setupTestSyncEngine(t)
			defer cleanup()
			var down atomic.Bool
			remote := newFakeSCIM()
			flaky := &flakyReceiver{}
			var handler http.Handler = flaky
			req := &CreateSystemRequest{Name: "target", SystemType: kind}
			if kind == "scim" {
				handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if down.Load() {
						w.WriteHeader(503)
						return
					}
					remote.ServeHTTP(w, r)
				})
				req.BearerToken = "target-token"
			}
			srv := httptest.NewTLSServer(handler)
			defer srv.Close()
			e.httpClient = srv.Client()
			req.CallbackURL = srv.URL
			if kind == "scim" {
				req.CallbackURL += "/scim/v2"
			}
			sys, _, err := e.CreateSystem(req, nil)
			if err != nil {
				t.Fatal(err)
			}
			u := member(t, s)
			if err := s.SetAppAssignment(appRecordFor(t, s, sys.ID).ID, "users", u.ID, true, nil); err != nil {
				t.Fatal(err)
			}
			dispatch(t, e)
			if got := outbox(t, s, sys.ID, u.ID); len(got) != 0 {
				t.Fatalf("create not delivered: %+v", got)
			}

			down.Store(true)
			flaky.down.Store(true)
			setStatus(t, s, u, "disabled")
			var downFor time.Duration
			for i := 1; i <= 12; i++ {
				dispatch(t, e)
				got := outbox(t, s, sys.ID, u.ID)
				if len(got) != 1 || got[0].status != "pending" || got[0].attempts != i || got[0].eventType != "user.updated" {
					t.Fatalf("attempt %d: removal %+v", i, got)
				}
				if got[0].wait > 30*time.Minute || got[0].wait < retryDelay(i-1)-time.Minute {
					t.Fatalf("attempt %d waits %s", i, got[0].wait)
				}
				downFor += got[0].wait
				if i == store.SyncAttemptBudget {
					// As if other users' deliveries had succeeded meanwhile.
					execRaw(t, s, `UPDATE paired_systems SET status='active' WHERE id=?`, sys.ID)
					if !outageOpen(t, s, sys.ID) {
						t.Fatal("a removal retrying past the budget raised no alert")
					}
					failing, err := s.ListFailingSyncEvents(sys.ID)
					if err != nil || len(failing) != 1 || failing[0].Status != "pending" || failing[0].EventType != "user.updated" {
						t.Fatalf("deliveries view %+v %v", failing, err)
					}
				}
				elapse(t, s)
			}
			if downFor < 3*time.Hour {
				t.Fatalf("simulated outage only %s", downFor)
			}

			down.Store(false)
			flaky.down.Store(false)
			dispatch(t, e)
			if got := outbox(t, s, sys.ID, u.ID); len(got) != 0 {
				t.Fatalf("removal not delivered after the outage: %+v", got)
			}
			if kind == "scim" {
				if ru, ok := remote.userByExternal(u.ID); !ok || ru.Active {
					t.Fatalf("SCIM account still active: %+v", ru)
				}
			} else if h := flaky.seen(); h[len(h)-1] != (hit{"user.updated", false}) {
				t.Fatalf("last delivery %+v", h)
			}
			if outageOpen(t, s, sys.ID) {
				t.Fatal("alert still open after delivery")
			}
		})
	}
}

// A non-removal still gives up at the budget (unchanged), alerts, and the reconcile pass
// re-sends it from current desired state for a suite webhook, as for SCIM.
func TestExhaustedWebhookCreateIsRevived(t *testing.T) {
	e, s, u, sys, recv := suiteFixture(t)
	recv.down.Store(true)
	for i := 0; i < store.SyncAttemptBudget; i++ {
		dispatch(t, e)
		elapse(t, s)
	}
	if got := outbox(t, s, sys.ID, u.ID); len(got) != 1 || got[0].status != "failed" || got[0].eventType != "user.created" {
		t.Fatalf("create after budget: %+v", got)
	}
	if !outageOpen(t, s, sys.ID) {
		t.Fatal("exhausted create raised no alert")
	}
	if failing, err := s.ListFailingSyncEvents(sys.ID); err != nil || len(failing) != 1 || failing[0].Status != "failed" {
		t.Fatalf("deliveries view %+v %v", failing, err)
	}
	recv.down.Store(false)
	if err := s.ReconcileProvisioning(); err != nil {
		t.Fatal(err)
	}
	if got := outbox(t, s, sys.ID, u.ID); len(got) != 1 || got[0].status != "pending" || got[0].attempts != 0 || got[0].wait > 30*time.Minute {
		t.Fatalf("create after reconcile: %+v", got)
	}
	elapse(t, s)
	dispatch(t, e)
	if got := outbox(t, s, sys.ID, u.ID); len(got) != 0 {
		t.Fatalf("revived create not delivered: %+v", got)
	}
	if outageOpen(t, s, sys.ID) {
		t.Fatal("alert still open after delivery")
	}
}

// A removal whose answer was lost after its request was written is resent, not held.
func TestUncertainRemovalIsResent(t *testing.T) {
	e, s, u, sys, recv := suiteFixture(t)
	dispatch(t, e)
	recv.mu.Lock()
	recv.script = []int{500}
	recv.mu.Unlock()
	setStatus(t, s, u, "disabled")
	dispatch(t, e)
	if held, err := s.ListSyncDeliveryAttempts(sys.ID); err != nil || len(held) != 0 {
		t.Fatalf("removal held as uncertain: %+v %v", held, err)
	}
	elapse(t, s)
	dispatch(t, e)
	want := []hit{{"user.created", true}, {"user.updated", false}, {"user.updated", false}}
	if got := recv.seen(); len(got) != len(want) || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("receiver saw %+v", got)
	}
	if got := outbox(t, s, sys.ID, u.ID); len(got) != 0 {
		t.Fatalf("removal not delivered: %+v", got)
	}
}

// An uncertain write stays held past its recovery time, and a removal queued behind it
// waits with it: an expired deadline does not prove the write cannot still land, and a
// late active update would restore access after the removal. Generic SCIM updates carry
// no revision a receiver could use to refuse one. The alert stays open meanwhile.
func TestHeldWriteHoldsRemoval(t *testing.T) {
	for _, kind := range []string{"suite_webhook", "scim"} {
		t.Run(kind, func(t *testing.T) {
			e, s, _, cleanup := setupTestSyncEngine(t)
			defer cleanup()
			remote := newFakeSCIM()
			flaky := &flakyReceiver{}
			var handler http.Handler = flaky
			req := &CreateSystemRequest{Name: "target", SystemType: kind}
			if kind == "scim" {
				handler, req.BearerToken = remote, "target-token"
			}
			srv := httptest.NewTLSServer(handler)
			defer srv.Close()
			e.httpClient = srv.Client()
			req.CallbackURL = srv.URL
			if kind == "scim" {
				req.CallbackURL += "/scim/v2"
			}
			sys, _, err := e.CreateSystem(req, nil)
			if err != nil {
				t.Fatal(err)
			}
			u := member(t, s)
			if err := s.SetAppAssignment(appRecordFor(t, s, sys.ID).ID, "users", u.ID, true, nil); err != nil {
				t.Fatal(err)
			}
			dispatch(t, e)

			// The receiver stays unable to answer, so every write it is sent is uncertain.
			remote.mu.Lock()
			remote.putStatus = 500
			remote.mu.Unlock()
			flaky.mu.Lock()
			flaky.script = []int{500, 500, 500, 500}
			flaky.mu.Unlock()
			if _, err := s.EditUser(u.ID, nil, func(next *store.User) (bool, error) { next.DisplayName = "Pat Renamed"; return true, nil }); err != nil {
				t.Fatal(err)
			}
			dispatch(t, e)
			held, err := s.ListSyncDeliveryAttempts(sys.ID)
			if err != nil || len(held) != 1 || held[0].EventType != "user.updated" {
				t.Fatalf("active update not held: %+v %v", held, err)
			}

			setStatus(t, s, u, "disabled")
			for i := 0; i < 3; i++ {
				elapse(t, s)
				dispatch(t, e)
			}
			got := outbox(t, s, sys.ID, u.ID)
			if len(got) != 2 || got[1].eventType != "user.updated" || got[1].attempts != 0 {
				t.Fatalf("removal sent ahead of the held update: %+v", got)
			}
			if held, err := s.ListSyncDeliveryAttempts(sys.ID); err != nil || len(held) != 1 {
				t.Fatalf("held update released without an operator: %+v %v", held, err)
			}
			for _, h := range flaky.seen() {
				if !h.active {
					t.Fatalf("receiver saw the removal: %+v", flaky.seen())
				}
			}
			execRaw(t, s, `UPDATE paired_systems SET status='active' WHERE id=?`, sys.ID)
			if !outageOpen(t, s, sys.ID) {
				t.Fatal("held update raised no alert")
			}
		})
	}
}

// A removal is never held in order behind an MFA reset that cannot be delivered, and
// never drops it: the reset follows the removal at a revision the receiver accepts, and
// a re-grant before either is delivered still sends the reset ahead of reactivation.
func TestRemovalGoesAheadOfUndeliveredMFAReset(t *testing.T) {
	e, s, u, sys, recv := suiteFixture(t)
	recv.fence = true
	dispatch(t, e)
	recv.down.Store(true)
	if err := e.ResetUserMFAAndRevoke(u.ID, nil); err != nil {
		t.Fatal(err)
	}
	dispatch(t, e)
	setStatus(t, s, u, "disabled")
	if got := outbox(t, s, sys.ID, u.ID); len(got) != 2 || got[0].eventType != "user.updated" || got[1].eventType != "user.mfa_reset" {
		t.Fatalf("outbox after removal %+v", got)
	}
	setStatus(t, s, u, "active")
	if got := outbox(t, s, sys.ID, u.ID); len(got) != 2 || got[0].eventType != "user.mfa_reset" || got[1].eventType != "user.updated" {
		t.Fatalf("outbox after re-grant %+v", got)
	}
	setStatus(t, s, u, "disabled")
	recv.down.Store(false)
	elapse(t, s)
	dispatch(t, e)
	dispatch(t, e)
	got := recv.seen()
	if len(got) < 2 || got[len(got)-2] != (hit{"user.updated", false}) || got[len(got)-1].event != "user.mfa_reset" {
		t.Fatalf("receiver saw %+v", got)
	}
	if left := outbox(t, s, sys.ID, u.ID); len(left) != 0 {
		t.Fatalf("reset refused as stale: %+v", left)
	}
	setStatus(t, s, u, "active")
	dispatch(t, e)
	if got := recv.seen(); got[len(got)-1] != (hit{"user.updated", true}) {
		t.Fatalf("receiver saw %+v", got)
	}
}

// Per-person order holds while a removal retries past the budget: a re-grant supersedes
// it, and the receiver ends on the re-grant, never on a stale removal.
func TestRegrantSupersedesRetryingRemoval(t *testing.T) {
	e, s, u, sys, recv := suiteFixture(t)
	dispatch(t, e)
	recv.down.Store(true)
	setStatus(t, s, u, "disabled")
	for i := 0; i < store.SyncAttemptBudget+2; i++ {
		dispatch(t, e)
		elapse(t, s)
	}
	setStatus(t, s, u, "active")
	if got := outbox(t, s, sys.ID, u.ID); len(got) != 1 || got[0].eventType != "user.updated" || got[0].attempts != 0 {
		t.Fatalf("outbox after re-grant %+v", got)
	}
	recv.down.Store(false)
	dispatch(t, e)
	got := recv.seen()
	if got[len(got)-1] != (hit{"user.updated", true}) || got[len(got)-2] != (hit{"user.updated", false}) {
		t.Fatalf("receiver saw %+v", got)
	}
}

func TestRetryDelayIsCapped(t *testing.T) {
	for _, n := range []int{6, 40, 64, 1000} {
		if d := retryDelay(n); d != 30*time.Minute {
			t.Fatalf("retryDelay(%d) = %s", n, d)
		}
	}
	if retryDelay(0) != 30*time.Second || retryDelay(4) != 8*time.Minute {
		t.Fatal("early backoff changed")
	}
}
