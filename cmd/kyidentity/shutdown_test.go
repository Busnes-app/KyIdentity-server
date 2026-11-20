package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/api"
	"github.com/Busnes-app/kyidentity-server/internal/audit"
	"github.com/Busnes-app/kyidentity-server/internal/auth"
	"github.com/Busnes-app/kyidentity-server/internal/backup"
	"github.com/Busnes-app/kyidentity-server/internal/config"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/mfa"
	"github.com/Busnes-app/kyidentity-server/internal/oauth"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	kysync "github.com/Busnes-app/kyidentity-server/internal/sync"
	"github.com/google/uuid"
)

func TestShutdownBudgetFitsTheGracePeriods(t *testing.T) {
	const kubernetesAndComposeGrace, dockerDefault = 30 * time.Second, 10 * time.Second
	r := shutdownPlan(true)
	if r.drain != 5*time.Second || r.shutdown != 5*time.Second || r.wait != 10*time.Second {
		t.Fatalf("replicated plan %+v, want 5+5+10", r)
	}
	if total := r.drain + r.shutdown + r.wait; total != 20*time.Second || total > kubernetesAndComposeGrace {
		t.Fatalf("replicated shutdown takes %v, grace is %v", total, kubernetesAndComposeGrace)
	}
	s := shutdownPlan(false)
	if s.drain != 0 || s.shutdown != 5*time.Second || s.wait != 3*time.Second {
		t.Fatalf("single plan %+v, want 0+5+3", s)
	}
	if total := s.drain + s.shutdown + s.wait; total != 8*time.Second || total >= dockerDefault {
		t.Fatalf("single shutdown takes %v, Docker waits %v", total, dockerDefault)
	}
}

// blocker is a deposit or drill that runs until its context ends.
type blocker struct{ entered chan struct{} }

func newBlocker() *blocker { return &blocker{entered: make(chan struct{}, 8)} }

func (b *blocker) block(ctx context.Context) error {
	b.entered <- struct{}{}
	<-ctx.Done()
	return context.Cause(ctx)
}

func (b *blocker) Deposit(ctx context.Context, _, _ string, _ []byte) (backup.Receipt, error) {
	return backup.Receipt{}, b.block(ctx)
}

func (b *blocker) wait(t *testing.T, what string) {
	t.Helper()
	select {
	case <-b.entered:
	case <-time.After(30 * time.Second):
		t.Fatalf("%s never started", what)
	}
}

// liveServer serves srv for cfg on a real loopback listener.
func liveServer(t *testing.T, cfg *config.Config, s *store.Store) (*api.Server, string) {
	t.Helper()
	km, err := crypto.LoadOrCreateRSAKey(cfg.RSAKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	eng := mfa.NewEngine(s, cfg.EncryptionKey)
	origin, err := mfa.IssuerOrigin(cfg.IssuerURL)
	if err != nil {
		t.Fatal(err)
	}
	eng.SetIssuerOrigin(origin)
	srv := api.NewServer(cfg, s, km, kysync.NewEngine(s, cfg.EncryptionKey), eng, oauth.NewEngine(s, km, cfg.IssuerURL), audit.NewLogger(s), nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	return srv, "http://" + ln.Addr().String()
}

// adminClient is a signed-in administrator's browser against base.
type adminClient struct {
	t    *testing.T
	base string
	http *http.Client
	csrf string
}

func newAdminClient(t *testing.T, s *store.Store, base string) *adminClient {
	t.Helper()
	hash, _ := auth.HashPassword("shutdown-test-password")
	u := &store.User{ID: uuid.NewString(), Username: "operator", DisplayName: "Operator", Email: "operator@shutdown.test", PasswordHash: hash, Role: "admin", Status: "active"}
	if err := s.DefaultOrg().CreateUser(u); err != nil {
		t.Fatal(err)
	}
	token, _ := crypto.GenerateRandomHex(32)
	if err := s.CreateSession(&store.Session{ID: uuid.NewString(), UserID: u.ID, SessionTokenHash: crypto.HashSHA256(token), IPAddress: "127.0.0.1", UserAgent: "test", ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	target, _ := url.Parse(base)
	jar.SetCookies(target, []*http.Cookie{{Name: "kyidentity_session", Value: token, Path: "/"}})
	c := &adminClient{t: t, base: base, http: &http.Client{Jar: jar, Timeout: time.Minute}}
	var body struct {
		CSRFToken string `json:"csrfToken"`
	}
	res := c.do("GET", "/api/auth/csrf")
	if err := json.Unmarshal(res.body, &body); err != nil || body.CSRFToken == "" {
		t.Fatalf("no CSRF token: %d %s", res.status, res.body)
	}
	c.csrf = body.CSRFToken
	return c
}

type answer struct {
	status int
	header http.Header
	body   []byte
	err    error
}

// at is the same signed-in browser talking to another server on the same database.
func (c *adminClient) at(base string) *adminClient {
	other := *c
	other.base = base
	return &other
}

func (c *adminClient) do(method, path string) answer {
	req, _ := http.NewRequest(method, c.base+path, nil)
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return answer{err: err}
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	return answer{status: res.StatusCode, header: res.Header, body: raw}
}

func (c *adminClient) start(method, path string) <-chan answer {
	out := make(chan answer, 1)
	go func() { out <- c.do(method, path) }()
	return out
}

// answeredAt receives the one answer from ch and the time it came, from begun.
func answeredAt(ch <-chan answer, begun *time.Time) <-chan struct {
	answer
	at time.Duration
} {
	out := make(chan struct {
		answer
		at time.Duration
	}, 1)
	go func() {
		a := <-ch
		out <- struct {
			answer
			at time.Duration
		}{a, time.Since(*begun)}
	}()
	return out
}

func failures(t *testing.T, s *store.Store, action string) int {
	t.Helper()
	_, n, err := s.SearchAuditEvents(store.AuditFilter{Action: action, Outcome: "failure", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// leaseFree reports whether name can be taken now: with a two-minute ttl, only a deleted
// row is free this soon.
func leaseFree(t *testing.T, s *store.Store, name string) bool {
	t.Helper()
	release, ok, err := s.AcquireLease(name, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		release()
	}
	return ok
}

func checkHealth(t *testing.T, c *adminClient, wantReady int, wantServer string) {
	t.Helper()
	ready := c.do("GET", "/readyz")
	var body struct {
		Checks map[string]string `json:"checks"`
	}
	_ = json.Unmarshal(ready.body, &body)
	if ready.status != wantReady || body.Checks["server"] != wantServer || ready.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("/readyz: %d %s %v", ready.status, ready.body, ready.header)
	}
	if live := c.do("GET", "/livez"); live.status != 200 || live.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("/livez: %d %v", live.status, live.header)
	}
}

// The SIGTERM sequence on a real listener. A replica keeps serving with /readyz at 503 for
// the drain while refusing new deposits and drills; a single server closes its listener at
// once. In both, the backup work still running is cancelled at the wait phase, records its
// failure and gives back its lease before the sequence returns, and in-flight requests get
// their answer.
func TestGracefulStopDrainsCancelsAndWaits(t *testing.T) {
	t.Run("replicated: scheduled run and drill", func(t *testing.T) {
		cfg, _ := commandInstance(t, true)
		s := handles(t, cfg.DBPath, 1)[0]
		if err := backup.StorePairing(s, cfg.EncryptionKey, "https://recovery.example.test", "token"); err != nil {
			t.Fatal(err)
		}
		deposits, drills := newBlocker(), newBlocker()
		t.Cleanup(api.UseBackupFakesForTest(deposits, drills.block))
		srv, base := liveServer(t, cfg, s)
		admin := newAdminClient(t, s, base)
		checkHealth(t, admin, 200, "ok")

		sched, stopSched := context.WithCancel(context.Background())
		work, cancelWork := context.WithCancel(context.Background())
		defer cancelWork()
		loopDone := make(chan struct{})
		go func() {
			defer close(loopDone)
			backupLoop(sched, work, cfg, s, deposits, audit.NewLogger(s), 20*time.Millisecond)
		}()
		deposits.wait(t, "the scheduled deposit")
		var begun time.Time
		drill := answeredAt(admin.start("POST", "/api/admin/backup/drill"), &begun)
		drills.wait(t, "the drill")

		begun = time.Now()
		loopEnded := make(chan time.Duration, 1)
		go func() { <-loopDone; loopEnded <- time.Since(begun) }()
		stopped := make(chan struct{})
		go func() {
			defer close(stopped)
			gracefulStop(shutdownPlan(true), srv, stopSched, cancelWork, map[string]func(context.Context) bool{
				"scheduled backup": func(done context.Context) bool {
					select {
					case <-loopDone:
						return true
					case <-done.Done():
						return false
					}
				},
			})
		}()
		// Inside the five-second drain: out of rotation, still serving, refusing new backup work.
		time.Sleep(500 * time.Millisecond)
		checkHealth(t, admin, 503, "draining")
		if res := admin.do("GET", "/.well-known/openid-configuration"); res.status != 200 {
			t.Fatalf("discovery during the drain: %d", res.status)
		}
		for _, path := range []string{"/api/admin/backup/deposit", "/api/admin/backup/drill"} {
			if res := admin.do("POST", path); res.status != http.StatusServiceUnavailable {
				t.Fatalf("new %s during the drain: %d %s", path, res.status, res.body)
			}
		}
		if time.Since(begun) > 4*time.Second {
			t.Fatal("the drain checks ran too late to be inside the drain")
		}
		select {
		case <-stopped:
		case <-time.After(25 * time.Second):
			t.Fatal("the sequence did not return within its budget")
		}
		took := time.Since(begun)
		if took < readinessDrainDelay || took > 20*time.Second+2*time.Second {
			t.Fatalf("the replicated sequence took %v", took)
		}
		// Cancelled at the wait phase: after the drain and after the listener's full shutdown,
		// which the in-flight drill holds open, never before.
		phase := readinessDrainDelay + httpShutdownTimeout - 200*time.Millisecond
		res := <-drill
		if res.err != nil || res.status != http.StatusInternalServerError || res.at < phase {
			t.Fatalf("the in-flight drill: %d %s %v at %v, want a failure after %v", res.status, res.body, res.err, res.at, phase)
		}
		if ended := <-loopEnded; ended < phase {
			t.Fatalf("the scheduled run ended at %v, before the wait phase at %v", ended, phase)
		}
		if failures(t, s, "admin.backup_run") != 1 || failures(t, s, "admin.backup_drill_run") != 1 {
			t.Fatalf("failures recorded: run %d, drill %d", failures(t, s, "admin.backup_run"), failures(t, s, "admin.backup_drill_run"))
		}
		if !leaseFree(t, s, backup.Lease) || !leaseFree(t, s, backup.DrillLease) {
			t.Fatal("a lease was left behind")
		}
	})

	t.Run("single server: back up now and drill", func(t *testing.T) {
		cfg, _ := commandInstance(t, true)
		s := handles(t, cfg.DBPath, 1)[0]
		if err := backup.StorePairing(s, cfg.EncryptionKey, "https://recovery.example.test", "token"); err != nil {
			t.Fatal(err)
		}
		deposits, drills := newBlocker(), newBlocker()
		t.Cleanup(api.UseBackupFakesForTest(deposits, drills.block))
		srv, base := liveServer(t, cfg, s)
		admin := newAdminClient(t, s, base)
		checkHealth(t, admin, 200, "ok")
		var begun time.Time
		deposit := answeredAt(admin.start("POST", "/api/admin/backup/deposit"), &begun)
		deposits.wait(t, "back up now")
		drill := answeredAt(admin.start("POST", "/api/admin/backup/drill"), &begun)
		drills.wait(t, "the drill")

		begun = time.Now()
		stopped := make(chan struct{})
		go func() {
			defer close(stopped)
			gracefulStop(shutdownPlan(false), srv, func() {}, func() {}, nil)
		}()
		// No drain: the listener closes at once.
		fresh := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: time.Second}
		for {
			if _, err := fresh.Get(base + "/livez"); err != nil {
				break
			}
			if time.Since(begun) > time.Second {
				t.Fatal("a single server kept accepting connections after SIGTERM")
			}
			time.Sleep(20 * time.Millisecond)
		}
		select {
		case <-stopped:
		case <-time.After(15 * time.Second):
			t.Fatal("the sequence did not return within its budget")
		}
		if took := time.Since(begun); took > 8*time.Second+2*time.Second {
			t.Fatalf("the single-server sequence took %v", took)
		}
		for name, ch := range map[string]<-chan struct {
			answer
			at time.Duration
		}{"back up now": deposit, "drill": drill} {
			// No drain: cancelled once the listener's shutdown has waited its full time.
			if res := <-ch; res.err != nil || res.status < 500 || res.at < httpShutdownTimeout-200*time.Millisecond {
				t.Fatalf("the in-flight %s: %d %s %v at %v", name, res.status, res.body, res.err, res.at)
			}
		}
		if failures(t, s, "admin.backup_run") != 1 || failures(t, s, "admin.backup_drill_run") != 1 {
			t.Fatalf("failures recorded: run %d, drill %d", failures(t, s, "admin.backup_run"), failures(t, s, "admin.backup_drill_run"))
		}
		if !leaseFree(t, s, backup.Lease) || !leaseFree(t, s, backup.DrillLease) {
			t.Fatal("a lease was left behind")
		}
		if _, ok, _ := backup.LastDeposit(s); ok {
			t.Fatal("a cancelled deposit recorded a receipt")
		}
	})
}
