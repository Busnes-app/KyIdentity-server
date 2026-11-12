package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/config"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// replicaLimiters is n servers' middleware over one database, as replicas run.
func replicaLimiters(t *testing.T, n int) []*MiddlewareManager {
	t.Helper()
	path := filepath.Join(t.TempDir(), "shared.db")
	out := make([]*MiddlewareManager, n)
	for i := range out {
		s, err := store.New(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		out[i] = NewMiddlewareManager(s, nil, config.DefaultForwardedHeader, testCSRFKey)
		out[i].shared = true
	}
	return out
}

// The per-user cap on push-approval prompts is five an hour however many replicas the
// load balancer spreads the attempts over.
func TestSharedLimitsHoldAcrossReplicas(t *testing.T) {
	limiters := replicaLimiters(t, 4)
	var allowed atomic.Int32
	var wg sync.WaitGroup
	for _, m := range limiters {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 5 {
				if m.allowRateLimit("login_push:u", loginPushesPerHour, loginPushesPerHour/3600.0) {
					allowed.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if allowed.Load() != loginPushesPerHour {
		t.Fatalf("%d replicas sent %d pushes in the hour, want %d", len(limiters), allowed.Load(), loginPushesPerHour)
	}

	// The same holds for an IP bucket in front of a handler.
	hits := 0
	for range 3 {
		for _, m := range limiters {
			h := m.RateLimit("login", 10, 0.2)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
			r := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
			r.RemoteAddr = "198.51.100.7:4000"
			h.ServeHTTP(httptest.NewRecorder(), r)
		}
	}
	if hits != 10 {
		t.Fatalf("12 logins from one address over %d replicas reached the handler %d times, want 10", len(limiters), hits)
	}
}

// Without the replica flag nothing touches the database: the in-memory limiter is unchanged.
func TestUnsharedLimiterNeverUsesTheDatabase(t *testing.T) {
	m := NewMiddlewareManager(nil, nil, config.DefaultForwardedHeader, testCSRFKey)
	for i := range 6 {
		if got := m.allowRateLimit("k", 5, 0); got != (i < 5) {
			t.Fatalf("request %d: allowed=%v", i, got)
		}
	}
}

// A limiter that cannot reach its database refuses; it never waves requests through.
func TestSharedLimiterFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.db")
	s, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	m := NewMiddlewareManager(s, nil, config.DefaultForwardedHeader, testCSRFKey)
	m.shared = true
	if !m.allowRateLimit("reset:u", 3, 1.0/3600) {
		t.Fatal("first request refused")
	}
	_ = s.Close()
	if m.allowRateLimit("reset:u", 3, 1.0/3600) {
		t.Fatal("a request was allowed while the limiter's database was unreachable")
	}
}

// At the cap a new key is refused and a live bucket keeps counting, as in memory; the
// sweep reopens the table once buckets have refilled.
func TestSharedLimiterIsCappedAndSwept(t *testing.T) {
	m := replicaLimiters(t, 1)[0]
	clock := time.Now()
	m.now = func() time.Time { return clock }
	m.maxLimiters = 3
	for _, k := range []string{"a", "b", "c"} {
		if !m.allowRateLimit(k, 2, 1) {
			t.Fatal("refused under the cap")
		}
	}
	m.sweepLimiters()
	if m.allowRateLimit("d", 2, 1) {
		t.Fatal("a new bucket was admitted at the cap")
	}
	if !m.allowRateLimit("a", 2, 1) || m.allowRateLimit("a", 2, 1) {
		t.Fatal("an existing bucket did not keep its count at the cap")
	}
	clock = clock.Add(2 * time.Minute)
	m.sweepLimiters()
	if !m.allowRateLimit("d", 2, 1) {
		t.Fatal("a new bucket was refused after the old ones refilled and were swept")
	}
}
