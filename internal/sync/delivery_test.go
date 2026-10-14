package sync

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	stdsync "sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
)

func TestTimedOutWriteBlocksLaterDelivery(t *testing.T) {
	e, s, u, cleanup := setupSync(t)
	defer cleanup()
	entered := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	var calls atomic.Int32
	remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		w.WriteHeader(204)
		close(finished)
	}))
	defer remote.Close()
	defer close(release)
	e.httpClient = remote.Client()
	e.httpClient.Timeout = 50 * time.Millisecond
	target, _, err := e.CreateSystem(&CreateSystemRequest{Name: "target", SystemType: "suite_webhook", CallbackURL: remote.URL})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"old", "new"} {
		if err := s.CreateAccountSyncEvent(&store.AccountSyncEvent{ID: id, UserID: u.ID, SystemID: target.ID, EventType: "user.updated", PayloadJSON: `{}`, Status: "pending"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.DispatchPendingEvents(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	default:
		t.Fatal("request never reached remote")
	}
	if err := e.DispatchPendingEvents(context.Background()); err != nil {
		t.Fatal(err)
	}
	attempts, err := s.ListSyncDeliveryAttempts(target.ID)
	if err != nil || len(attempts) != 1 || calls.Load() != 1 {
		t.Fatal("later write bypassed uncertain request", attempts, calls.Load(), err)
	}
	// Read-back of suite protocols is explicitly unavailable, never an unblock.
	result, err := e.ReadBackSyncResource(context.Background(), target, "user.created", u.ID)
	if err != nil || result["state"] != "unsupported" {
		t.Fatal(result, err)
	}
}

func TestDeliveryOutcomeClassification(t *testing.T) {
	for _, code := range []int{200, 201, 204, 202, 400, 408, 409, 429, 500, 503} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) }))
			defer remote.Close()
			tracker := &deliveryTransport{base: http.DefaultTransport}
			client := &http.Client{Transport: tracker}
			req, _ := http.NewRequest("PUT", remote.URL, nil)
			response, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			want := code == 202 || code == 408 || (code >= 500 && code != 503)
			if tracker.uncertain.Load() != want {
				t.Fatalf("status %d uncertain=%v", code, tracker.uncertain.Load())
			}
			// A later successful read cannot turn an uncertain mutation into an acknowledgment.
			response, err = client.Get(remote.URL)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if tracker.uncertain.Load() != want {
				t.Fatal("read cleared mutation uncertainty")
			}
		})
	}
}

func TestDeliveryDoesNotReplayInsideHTTPTransport(t *testing.T) {
	for _, body := range []string{`{"active":true}`, ""} {
		t.Run(body, func(t *testing.T) {
			var writes atomic.Int32
			remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					w.WriteHeader(204)
					return
				}
				_, _ = io.Copy(io.Discard, r.Body)
				if writes.Add(1) == 1 {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					conn.Close()
					return
				}
				w.WriteHeader(204)
			}))
			defer remote.Close()
			tracker := &deliveryTransport{base: remote.Client().Transport}
			if tracker.base == nil {
				tracker.base = http.DefaultTransport
			}
			client := &http.Client{Transport: tracker}
			// Prime a reused connection: net/http may transparently replay an idempotency-key
			// POST after losing its response, before the dispatcher can observe uncertainty.
			response, err := client.Get(remote.URL)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			req, err := http.NewRequest(http.MethodPost, remote.URL, strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Idempotency-Key", "event")
			response, err = client.Do(req)
			if response != nil {
				response.Body.Close()
			}
			if err == nil || writes.Load() != 1 || !tracker.uncertain.Load() {
				t.Fatalf("hidden retry: writes=%d error=%v uncertain=%v", writes.Load(), err, tracker.uncertain.Load())
			}
		})
	}
}

// A request whose bytes never left, or that the receiver refused before applying,
// backs off without fencing; a lost response after the write still fences.
func TestDeliveryFencesOnlyWrittenRequests(t *testing.T) {
	refused, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refusedURL := "http://" + refused.Addr().String()
	refused.Close()
	unavailable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(503)
	}))
	defer unavailable.Close()
	lost := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
	}))
	defer lost.Close()
	for _, tc := range []struct {
		name, url string
		fenced    bool
	}{{"refused", refusedURL, false}, {"unavailable", unavailable.URL, false}, {"lost", lost.URL, true}} {
		t.Run(tc.name, func(t *testing.T) {
			e, s, u, cleanup := setupSync(t)
			defer cleanup()
			target, _, err := e.CreateSystem(&CreateSystemRequest{Name: tc.name, SystemType: "suite_webhook", CallbackURL: tc.url})
			if err != nil {
				t.Fatal(err)
			}
			if err := s.CreateAccountSyncEvent(&store.AccountSyncEvent{ID: "ev", UserID: u.ID, SystemID: target.ID, EventType: "user.updated", PayloadJSON: `{}`, Status: "pending"}); err != nil {
				t.Fatal(err)
			}
			if err := e.DispatchPendingEvents(context.Background()); err != nil {
				t.Fatal(err)
			}
			attempts, err := s.ListSyncDeliveryAttempts(target.ID)
			if err != nil || (len(attempts) == 1) != tc.fenced {
				t.Fatal("fence", attempts, err)
			}
			if tc.fenced {
				return
			}
			pending, err := s.GetPendingSyncEvents(10)
			if err != nil || len(pending) != 1 || pending[0].Attempts != 1 || pending[0].NextAttempt == nil || !pending[0].NextAttempt.After(time.Now()) {
				t.Fatalf("not backed off: %+v %v", pending, err)
			}
		})
	}
}

// One black-holed connector must not hold up delivery to another, and each
// connector still delivers a user's events in queue order.
func TestSlowConnectorDoesNotDelayOthers(t *testing.T) {
	e, s, u, cleanup := setupSync(t)
	defer cleanup()
	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.WriteHeader(204)
	}))
	defer slow.Close()
	releaseSlow := stdsync.OnceFunc(func() { close(release) })
	defer releaseSlow()
	fastHit := make(chan struct{}, 1)
	var mu stdsync.Mutex
	var order []string
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		order = append(order, r.Header.Get("Idempotency-Key"))
		mu.Unlock()
		select {
		case fastHit <- struct{}{}:
		default:
		}
		w.WriteHeader(204)
	}))
	defer fast.Close()
	slowSys, _, err := e.CreateSystem(&CreateSystemRequest{Name: "slow", SystemType: "suite_webhook", CallbackURL: slow.URL})
	if err != nil {
		t.Fatal(err)
	}
	fastSys, _, err := e.CreateSystem(&CreateSystemRequest{Name: "fast", SystemType: "suite_webhook", CallbackURL: fast.URL})
	if err != nil {
		t.Fatal(err)
	}
	// The slow connector's event is claimed first.
	queue := []string{"slow-1", "fast-1", "fast-2", "fast-3"}
	for _, id := range queue {
		system := fastSys.ID
		if id == "slow-1" {
			system = slowSys.ID
		}
		if err := s.CreateAccountSyncEvent(&store.AccountSyncEvent{ID: id, UserID: u.ID, SystemID: system, EventType: "user.updated", PayloadJSON: `{}`, Status: "pending"}); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan error, 1)
	go func() { done <- e.DispatchPendingEvents(context.Background()) }()
	select {
	case <-fastHit:
	case <-time.After(2 * time.Second):
		t.Fatal("fast connector waited for the slow one")
	}
	releaseSlow()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := e.DispatchPendingEvents(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(order, ",") != "fast-1,fast-2,fast-3" {
		t.Fatal("per-user order broken", order)
	}
}
