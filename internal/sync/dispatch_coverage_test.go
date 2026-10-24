package sync

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	stdsync "sync"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// covOutboxRow is the persisted state of one outbox event.
type covOutboxRow struct {
	status, lastError string
	attempts          int
	next              sql.NullTime
	claimed           bool
}

func covEventState(t *testing.T, s *store.Store, id string) covOutboxRow {
	t.Helper()
	db, err := sql.Open("sqlite", syncTestDBs[s]+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var r covOutboxRow
	var lastError sql.NullString
	var token string
	if err := db.QueryRow(`SELECT status,last_error,attempts,next_attempt_at,claim_token FROM account_sync_events WHERE id=?`, id).Scan(&r.status, &lastError, &r.attempts, &r.next, &token); err != nil {
		t.Fatal(err)
	}
	r.lastError, r.claimed = lastError.String, token != ""
	return r
}

// covHits counts requests to a suite receiver.
type covHits struct {
	mu   stdsync.Mutex
	n    int
	last *http.Request
	code int
}

func (h *covHits) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.n++
	h.last = r
	if h.code != 0 {
		w.WriteHeader(h.code)
	}
}

func (h *covHits) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.n
}

// covSuiteEvent pairs a suite webhook receiver and queues one user.created event for it.
func covSuiteEvent(t *testing.T) (*Engine, *store.Store, *store.PairedSystem, *covHits, string) {
	t.Helper()
	e, s, u, cleanup := setupTestSyncEngine(t)
	t.Cleanup(cleanup)
	hits := &covHits{}
	srv := httptest.NewServer(hits)
	t.Cleanup(srv.Close)
	sys, _, err := e.CreateSystem(&CreateSystemRequest{Name: "suite", SystemType: "suite_webhook", CallbackURL: srv.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(UserToSCIMResource(u))
	id := uuid.NewString()
	insertSyncEvent(t, s, store.AccountSyncEvent{ID: id, UserID: u.ID, SystemID: sys.ID, EventType: "user.created", PayloadJSON: string(body), Status: "pending", Revision: 1})
	return e, s, sys, hits, id
}

func covClaim(t *testing.T, s *store.Store) []store.AccountSyncEvent {
	t.Helper()
	events, err := s.ClaimDueSyncEvents(50, deliveryLease)
	if err != nil || len(events) != 1 {
		t.Fatal("claim", events, err)
	}
	return events
}

func covFences(t *testing.T, s *store.Store, systemID string) int {
	t.Helper()
	attempts, err := s.ListSyncDeliveryAttempts(systemID)
	if err != nil {
		t.Fatal(err)
	}
	return len(attempts)
}

// A connector disabled, or reverted to an unreviewed custom protocol, between claim
// and delivery must not receive the event; it stays pending with no attempt spent and
// no fence left behind, so it goes out once the connector is usable again.
func TestDispatchSystemHoldsEventsForConnectorPausedAfterClaim(t *testing.T) {
	for _, change := range []string{`status='disabled'`, `system_type='custom'`} {
		t.Run(change, func(t *testing.T) {
			e, s, sys, hits, id := covSuiteEvent(t)
			events := covClaim(t, s)
			execRaw(t, s, `UPDATE paired_systems SET `+change+` WHERE id=?`, sys.ID)
			if err := e.dispatchSystem(context.Background(), events); err != nil {
				t.Fatal(err)
			}
			if hits.count() != 0 {
				t.Fatal("paused connector received the event")
			}
			got := covEventState(t, s, id)
			if got.status != "pending" || got.attempts != 0 || got.lastError != "" || got.claimed || got.next.Valid {
				t.Fatalf("event %+v", got)
			}
			if covFences(t, s, sys.ID) != 0 {
				t.Fatal("paused connector kept a delivery fence")
			}
		})
	}
}

// A connector deleted after its events were claimed can never receive them: the event
// fails permanently with a fixed reason instead of retrying forever.
func TestDispatchSystemFailsEventsForDeletedConnector(t *testing.T) {
	e, s, sys, hits, id := covSuiteEvent(t)
	events := covClaim(t, s)
	execRaw(t, s, `DELETE FROM paired_systems WHERE id=?`, sys.ID)
	if err := e.dispatchSystem(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	got := covEventState(t, s, id)
	if hits.count() != 0 || got.status != "failed" || got.lastError != "paired system no longer exists" || got.claimed {
		t.Fatalf("hits=%d event %+v", hits.count(), got)
	}
}

// A connector whose credential cannot be opened sends nothing unsigned: the event backs
// off with an attempt spent and the connector is marked failing so an alert can fire.
func TestDispatchSystemBacksOffWhenSecretUnavailable(t *testing.T) {
	e, s, sys, hits, id := covSuiteEvent(t)
	execRaw(t, s, `UPDATE paired_systems SET hmac_secret_encrypted=? WHERE id=?`, mustEncrypt(t, e, uuid.NewString(), "x"), sys.ID)
	before := time.Now()
	if err := e.DispatchPendingEvents(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := covEventState(t, s, id)
	if hits.count() != 0 || got.status != "pending" || got.attempts != 1 || got.lastError != "signing secret unavailable" {
		t.Fatalf("hits=%d event %+v", hits.count(), got)
	}
	if !got.next.Valid || got.next.Time.Before(before.Add(retryDelay(0)-time.Second)) {
		t.Fatalf("no backoff: %+v", got.next)
	}
	if after, _ := s.GetPairedSystemByID(sys.ID); after.Status != "failing" {
		t.Fatal("connector not marked failing", after.Status)
	}
}

// A claim that is no longer ours (taken over after its lease expired) must not be sent:
// only the holder of the current claim token may begin a delivery.
func TestDispatchSystemSkipsStaleClaim(t *testing.T) {
	e, s, sys, hits, id := covSuiteEvent(t)
	events := covClaim(t, s)
	execRaw(t, s, `UPDATE account_sync_events SET claim_token='someone-else' WHERE id=?`, id)
	if err := e.dispatchSystem(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	if hits.count() != 0 || covFences(t, s, sys.ID) != 0 {
		t.Fatal("stale claim was delivered or fenced")
	}
	if got := covEventState(t, s, id); got.status != "pending" || got.attempts != 0 {
		t.Fatalf("event %+v", got)
	}
}

// Shutdown stops a pass before it fences anything: a cancelled context sends nothing
// and leaves no fence, so the unsent claim simply expires with its lease.
func TestDispatchSystemStopsOnCancelledContext(t *testing.T) {
	e, s, sys, hits, id := covSuiteEvent(t)
	events := covClaim(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := e.dispatchSystem(ctx, events); err != nil {
		t.Fatal(err)
	}
	if hits.count() != 0 || covFences(t, s, sys.ID) != 0 {
		t.Fatal("cancelled pass delivered or fenced")
	}
	if got := covEventState(t, s, id); got.attempts != 0 || got.status != "pending" {
		t.Fatalf("event %+v", got)
	}
}

type covRoundTrip func(*http.Request) (*http.Response, error)

func (f covRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Shutdown that interrupts a delivery before its request was written spends no
// attempt and keeps the original schedule; it is not a delivery failure.
func TestDispatchShutdownBeforeWriteSpendsNoAttempt(t *testing.T) {
	e, s, sys, hits, id := covSuiteEvent(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.httpClient = &http.Client{Transport: covRoundTrip(func(r *http.Request) (*http.Response, error) {
		cancel()
		return nil, context.Canceled
	})}
	if err := e.DispatchPendingEvents(ctx); err != nil {
		t.Fatal(err)
	}
	got := covEventState(t, s, id)
	if hits.count() != 0 || got.status != "pending" || got.attempts != 0 || got.lastError != "" || got.claimed || got.next.Valid {
		t.Fatalf("event %+v", got)
	}
	if covFences(t, s, sys.ID) != 0 {
		t.Fatal("interrupted delivery left a fence")
	}
}

// A connector row that cannot be read stops this connector's pass with the error and
// releases the begun fence without spending an attempt.
func TestDispatchSystemUnreadableConnectorReleasesFence(t *testing.T) {
	e, s, sys, hits, id := covSuiteEvent(t)
	events := covClaim(t, s)
	execRaw(t, s, `UPDATE paired_systems SET created_at='not a time' WHERE id=?`, sys.ID)
	if err := e.dispatchSystem(context.Background(), events); err == nil {
		t.Fatal("unreadable connector was not reported")
	}
	got := covEventState(t, s, id)
	if hits.count() != 0 || got.status != "pending" || got.attempts != 0 || got.claimed {
		t.Fatalf("hits=%d event %+v", hits.count(), got)
	}
	if covFences(t, s, sys.ID) != 0 {
		t.Fatal("fence kept after unreadable connector")
	}
}

// If recording a delivery outcome fails, the pass reports the store error and keeps the
// durable fence: the connector is not sent the user's next event until recovery, so a
// write the target may have applied is never overtaken.
func TestDispatchOutcomeWriteFailureKeepsFence(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		// beforeClaim edits the event before it is claimed; afterClaim edits the connector.
		beforeClaim, afterClaim string
	}{
		{name: "delivered", code: 200},
		{name: "retry", code: 400},
		{name: "budget exhausted", code: 400, beforeClaim: `UPDATE account_sync_events SET attempts=4`},
		{name: "uncertain", code: 500},
		{name: "disabled", afterClaim: `UPDATE paired_systems SET status='disabled'`},
		{name: "secret unavailable", afterClaim: `UPDATE paired_systems SET hmac_secret_encrypted='not-sealed'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, s, sys, hits, id := covSuiteEvent(t)
			hits.code = tc.code
			if tc.beforeClaim != "" {
				execRaw(t, s, tc.beforeClaim)
			}
			events := covClaim(t, s)
			if tc.afterClaim != "" {
				execRaw(t, s, tc.afterClaim)
			}
			// Every outcome write either releases the claim or records an error on the
			// claimed row; refuse exactly those updates.
			execRaw(t, s, `CREATE TRIGGER cov_refuse_outcome BEFORE UPDATE ON account_sync_events
 WHEN OLD.claim_token<>'' AND (NEW.claim_token='' OR NEW.last_error IS NOT OLD.last_error)
 BEGIN SELECT RAISE(ABORT,'outcome write refused'); END`)
			err := e.dispatchSystem(context.Background(), events)
			if err == nil || !strings.Contains(err.Error(), "outcome write refused") {
				t.Fatalf("err=%v", err)
			}
			if covFences(t, s, sys.ID) != 1 {
				t.Fatal("failed outcome write released the fence")
			}
			if got := covEventState(t, s, id); got.status != "pending" || !got.claimed {
				t.Fatalf("event %+v", got)
			}
		})
	}
}

// The worker drains the outbox without an external trigger and returns when its
// context ends. Polls against a deadline rather than sleeping a fixed time.
func TestStartWorkerDeliversQueuedEventAndStops(t *testing.T) {
	e, s, _, hits, id := covSuiteEvent(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		e.StartWorker(ctx)
		close(done)
	}()
	deadline := time.Now().Add(20 * time.Second)
	for covEventState(t, s, id).status != "delivered" {
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatal("worker did not deliver the queued event")
		}
		select {
		case <-done:
			t.Fatal("worker exited early")
		case <-time.After(50 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("worker did not stop on cancel")
	}
	hits.mu.Lock()
	defer hits.mu.Unlock()
	if hits.n != 1 || hits.last.Header.Get("Idempotency-Key") != id || hits.last.Method != http.MethodPost {
		t.Fatalf("hits=%d last=%v", hits.n, hits.last)
	}
}

// CreateSystem refuses incomplete or unsafe connector definitions with input errors and
// stores nothing; a SCIM connector never hands back its token, a suite webhook returns
// the signing secret it generated, sealed under the new connector's ID.
func TestCreateSystemValidation(t *testing.T) {
	e, s, _, cleanup := setupTestSyncEngine(t)
	defer cleanup()
	var input store.InputError
	for _, tc := range []struct {
		name string
		req  CreateSystemRequest
	}{
		{"no name or type", CreateSystemRequest{CallbackURL: "https://t.example.test/scim/v2", BearerToken: "tok"}},
		{"bad callback", CreateSystemRequest{Name: "x", SystemType: "scim", CallbackURL: "ftp://t.example.test/", BearerToken: "tok"}},
		{"unknown type", CreateSystemRequest{Name: "x", SystemType: "custom", CallbackURL: "https://t.example.test/hook"}},
		{"scim over http", CreateSystemRequest{Name: "x", SystemType: "scim", CallbackURL: "http://t.example.test/scim/v2", BearerToken: "tok"}},
		{"scim with query", CreateSystemRequest{Name: "x", SystemType: "scim", CallbackURL: "https://t.example.test/scim/v2?x=1", BearerToken: "tok"}},
		{"scim without token", CreateSystemRequest{Name: "x", SystemType: "scim", CallbackURL: "https://t.example.test/scim/v2"}},
		{"scim token too long", CreateSystemRequest{Name: "x", SystemType: "scim", CallbackURL: "https://t.example.test/scim/v2", BearerToken: strings.Repeat("a", 8193)}},
		{"scim token control char", CreateSystemRequest{Name: "x", SystemType: "scim", CallbackURL: "https://t.example.test/scim/v2", BearerToken: "a\nb"}},
		{"suite with chosen secret", CreateSystemRequest{Name: "x", SystemType: "suite_webhook", CallbackURL: "https://t.example.test/hook", BearerToken: "mine"}},
	} {
		req := tc.req
		if _, _, err := e.CreateSystem(&req, nil); !errors.As(err, &input) {
			t.Errorf("%s: err=%v", tc.name, err)
		}
	}
	if systems, _ := s.ListAllPairedSystems(); len(systems) != 0 {
		t.Fatal("refused definitions were stored", systems)
	}

	// Defaults: no type is generic SCIM; no name is the type (kypost below).
	sys, token, err := e.CreateSystem(&CreateSystemRequest{Name: "target", CallbackURL: "https://t.example.test/scim/v2", BearerToken: "tok"}, nil)
	if err != nil || token != "" || sys.SystemType != "scim" || sys.Name != "target" {
		t.Fatalf("sys=%+v token=%q err=%v", sys, token, err)
	}
	if secret, err := e.SigningSecret(sys); err != nil || secret != "tok" {
		t.Fatal(secret, err)
	}
	audited := false
	suite, secret, err := e.CreateSystem(&CreateSystemRequest{SystemType: "kypost", CallbackURL: "https://t.example.test/hook"}, func(ps *store.PairedSystem) *store.AuditEvent {
		audited = true
		return &store.AuditEvent{ID: uuid.NewString(), ActorUsername: "root", Action: "admin.system_paired", TargetID: ps.ID, TargetType: "paired_system", Outcome: "success", CreatedAt: time.Now().UTC()}
	})
	if err != nil || len(secret) != 64 || suite.Name != "kypost" || !audited {
		t.Fatalf("suite=%+v secret=%q err=%v audited=%v", suite, secret, err, audited)
	}
	if opened, err := e.SigningSecret(suite); err != nil || opened != secret {
		t.Fatal("generated secret not recoverable", err)
	}
}

// FormatUserAsSCIM accepts the payload shapes queued events carry and maps status and
// active consistently; an explicit active flag wins over status, and unusable input fails.
func TestFormatUserAsSCIMShapes(t *testing.T) {
	if _, err := FormatUserAsSCIM(nil); err == nil {
		t.Fatal("nil payload accepted")
	}
	if UserToSCIMResource(nil) != nil {
		t.Fatal("nil user produced a resource")
	}
	user := store.User{ID: "u1", Username: "alice", DisplayName: "Alice", Email: "a@example.test", Role: "admin", Status: "disabled"}
	for _, in := range []any{user, &user} {
		got, err := FormatUserAsSCIM(in)
		if err != nil || got.ID != "u1" || got.UserName != "alice" || got.Active || got.Emails[0].Value != "a@example.test" || got.Roles[0].Value != "admin" {
			t.Fatalf("%T: %+v %v", in, got, err)
		}
	}
	res := SCIMUserResource{ID: "r1", UserName: "bob", Active: true}
	if got, err := FormatUserAsSCIM(res); err != nil || got.ID != "r1" || !got.Active {
		t.Fatal(got, err)
	}
	if got, err := FormatUserAsSCIM(&res); err != nil || got != &res {
		t.Fatal("pointer resource not passed through", got, err)
	}
	// A bare map in the legacy shape: username, status, email and role.
	got, err := FormatUserAsSCIM(map[string]any{"id": "m1", "username": "carol", "status": "suspended", "email": "c@example.test", "role": "user", "displayName": "Carol"})
	if err != nil || got.UserName != "carol" || got.Active || got.ExternalID != "m1" || got.Name.Formatted != "Carol" || got.Emails[0].Value != "c@example.test" || got.Roles[0].Value != "user" {
		t.Fatalf("%+v %v", got, err)
	}
	got, err = FormatUserAsSCIM(map[string]any{"id": "m2", "userName": "dave", "status": "disabled", "active": true})
	if err != nil || !got.Active || got.UserName != "dave" || got.Emails != nil || got.Roles != nil {
		t.Fatalf("explicit active ignored: %+v %v", got, err)
	}
	got, err = FormatUserAsSCIM(map[string]any{"id": "m3", "userName": "erin"})
	if err != nil || !got.Active {
		t.Fatalf("no status should default active: %+v %v", got, err)
	}
	// A full SCIM body is decoded as such, keeping its own fields.
	got, err = FormatUserAsSCIM(json.RawMessage(`{"schemas":["` + SCIMUserSchema + `"],"id":"s1","userName":"frank","active":false,"roles":[{"value":"user","primary":true}]}`))
	if err != nil || got.ID != "s1" || got.Active || len(got.Roles) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := FormatUserAsSCIM(json.RawMessage(`"just a string"`)); err == nil {
		t.Fatal("non-object payload accepted")
	}
	if _, err := FormatUserAsSCIM(math.Inf(1)); err == nil {
		t.Fatal("unmarshalable payload accepted")
	}
}

// The handler-facing wrappers queue work atomically with the mutation: a new user in a
// connector's scope gets a create, and a deletion leaves a removal for that connector.
func TestUserMutationWrappersQueueEvents(t *testing.T) {
	e, s, _, cleanup := setupTestSyncEngine(t)
	defer cleanup()
	sys, _, err := e.CreateSystem(&CreateSystemRequest{Name: "suite", SystemType: "suite_webhook", CallbackURL: "https://suite.example.test/hook"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	grantAllUsers(t, s, sys.ID)
	u := &store.User{ID: uuid.NewString(), Username: "newbie", DisplayName: "New", Email: "n@example.test", PasswordHash: "x", Role: "user", Status: "active"}
	if err := e.CreateUserAndQueueSyncEvents(u, nil); err != nil {
		t.Fatal(err)
	}
	if got := outbox(t, s, sys.ID, u.ID); len(got) != 1 || got[0].eventType != "user.created" {
		t.Fatalf("create not queued: %+v", got)
	}
	if err := e.DeleteUserAndQueueSyncEvents(u.ID, nil); err != nil {
		t.Fatal(err)
	}
	got := outbox(t, s, sys.ID, u.ID)
	if len(got) == 0 || got[len(got)-1].eventType != "user.deleted" {
		t.Fatalf("removal not queued: %+v", got)
	}
	if stored, _ := s.GetUserByID(u.ID); stored != nil {
		t.Fatal("user not deleted")
	}
}
