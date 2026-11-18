package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/recoverykey"
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

// adminCaller signs an administrator in on srv and returns a function making their requests,
// step-up included when asked.
func adminCaller(t *testing.T, srv *Server, s *store.Store) func(method, path string, body []byte, stepUp bool) *httptest.ResponseRecorder {
	t.Helper()
	hash, _ := auth.HashPassword("AdminPassword123!")
	admin := &store.User{ID: uuid.NewString(), Username: "admin-" + uuid.NewString()[:8], DisplayName: "Admin", Email: uuid.NewString()[:8] + "@replica.test", PasswordHash: hash, Role: "admin", Status: "active"}
	if err := s.CreateUser(admin); err != nil {
		t.Fatal(err)
	}
	token, _ := crypto.GenerateRandomHex(32)
	if err := s.CreateSession(&store.Session{ID: uuid.NewString(), UserID: admin.ID, SessionTokenHash: crypto.HashSHA256(token), IPAddress: "127.0.0.1", UserAgent: "Go-Test", ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	csrf := srv.middleware.IssueCSRFToken(token)
	return func(method, path string, body []byte, stepUp bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.AddCookie(&http.Cookie{Name: "kyidentity_session", Value: token})
		req.AddCookie(&http.Cookie{Name: "kyidentity_csrf", Value: csrf})
		req.Header.Set("X-CSRF-Token", csrf)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if stepUp {
			req.Header.Set(StepUpHeader, mintStepUp(t, srv, token, method+" "+path))
		}
		w := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(w, req)
		return w
	}
}

// serverOn builds a second server on the database at dbPath with its own data directory, as
// another replica is.
func serverOn(t *testing.T, dbPath string, base *config.Config) (*Server, *store.Store) {
	t.Helper()
	s, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	cfg := *base
	cfg.DataDir = t.TempDir()
	km, err := crypto.LoadOrCreateRSAKey(cfg.RSAKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	eng := mfa.NewEngine(s, cfg.EncryptionKey)
	eng.SetIssuerOrigin(testIssuerOrigin)
	return NewServer(&cfg, s, km, kysync.NewEngine(s, cfg.EncryptionKey), eng, oauth.NewEngine(s, km, cfg.IssuerURL), audit.NewLogger(s), nil), s
}

func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("not JSON (%d): %s", w.Code, w.Body.String())
	}
	return out
}

// A handler that has not answered by the deadline is answered with 503 JSON at once; the
// named long routes keep their own budgets.
func TestRequestDeadlineAnswersAStalledRequest(t *testing.T) {
	const d = 300 * time.Millisecond
	release := make(chan struct{})
	defer close(release)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /stalled", func(w http.ResponseWriter, r *http.Request) {
		<-release // a store call with no context: it ignores the deadline
		w.WriteHeader(http.StatusTeapot)
	})
	mux.HandleFunc("GET /fast", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen", "yes")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("made"))
	})
	mux.HandleFunc("POST /api/admin/backup/deposit", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Context().Deadline(); ok {
			t.Error("a long route got the ordinary deadline")
		}
		time.Sleep(2 * d)
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(withDeadline(mux, mux, d))
	defer srv.Close()

	start := time.Now()
	res, err := http.Get(srv.URL + "/stalled")
	if err != nil {
		t.Fatal(err)
	}
	took := time.Since(start)
	var body map[string]string
	_ = json.NewDecoder(res.Body).Decode(&body)
	res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable || body["error"] != "request_timeout" || !strings.HasPrefix(res.Header.Get("Content-Type"), "application/json") {
		t.Fatalf("stalled request: %d %v %s", res.StatusCode, body, res.Header.Get("Content-Type"))
	}
	if took > d+time.Second {
		t.Fatalf("answered after %v, deadline %v", took, d)
	}

	res, err = http.Get(srv.URL + "/fast")
	if err != nil {
		t.Fatal(err)
	}
	raw := new(bytes.Buffer)
	_, _ = raw.ReadFrom(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusCreated || res.Header.Get("X-Seen") != "yes" || raw.String() != "made" {
		t.Fatalf("a request inside the deadline came back as %d %q %v", res.StatusCode, raw, res.Header)
	}

	res, err = http.Post(srv.URL+"/api/admin/backup/deposit", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("a long route was cut at the ordinary deadline: %d", res.StatusCode)
	}
}

// The exemptions are exactly the named long routes, each a route the server serves, and the
// deadline leaves the 503 room before the listener's write timeout.
func TestLongRoutesAreExactlyTheNamedExemptions(t *testing.T) {
	want := []string{
		"GET /api/admin/audit-events/export",
		"GET /api/admin/backup/export-capsule",
		"POST /api/admin/access-requests/{id}/approve",
		"POST /api/admin/access-requests/{id}/deny",
		"POST /api/admin/backup/deposit",
		"POST /api/admin/backup/drill",
		"POST /api/admin/backup/pair-remote",
		"POST /api/admin/mail/test",
		"POST /api/admin/users/{id}/activation-link",
		"POST /api/admin/users/{id}/reset-link",
	}
	var got []string
	for pattern, reason := range longRoutes {
		got = append(got, pattern)
		if reason == "" {
			t.Errorf("%s has no reason", pattern)
		}
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("exemptions\n got %v\nwant %v", got, want)
	}
	srv, _, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	for _, pattern := range want {
		method, path, _ := strings.Cut(pattern, " ")
		req := httptest.NewRequest(method, strings.ReplaceAll(path, "{id}", "x"), nil)
		if _, matched := srv.mux.Handler(req); matched != pattern {
			t.Errorf("%s is not a served route (matched %q)", pattern, matched)
		}
	}
	if requestDeadline >= srv.httpServer.WriteTimeout {
		t.Fatalf("requestDeadline %v is not below WriteTimeout %v", requestDeadline, srv.httpServer.WriteTimeout)
	}
}

// A settings read that fails is reported as unavailable, never as unpaired or unpinned, and
// a deposit or export is refused as a server error rather than "pair first".
func TestBackupReadErrorsAreNotUnpaired(t *testing.T) {
	priv, _ := recoverykey.Generate()
	fake := &fakeRecovery{result: backup.PairingResult{APIToken: "kyrec_live_t", Key: backup.RecoveryKey{Public: priv.Public(), Threshold: 2, TotalShares: 3}}}
	prev := newRecoveryClient
	newRecoveryClient = func(*config.Config) recoveryClient { return fake }
	t.Cleanup(func() { newRecoveryClient = prev })
	srv, s, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	do := adminCaller(t, srv, s)
	body, _ := json.Marshal(map[string]string{"recovery_url": "https://recovery.example.test", "pairing_code": "123456"})
	if w := do("POST", "/api/admin/backup/pair-remote", body, true); w.Code != http.StatusOK {
		t.Fatalf("pair: %d %s", w.Code, w.Body.String())
	}
	if got := decode(t, do("GET", "/api/admin/backup/status", nil, false)); got["paired"] != true || got["key_pinned"] != true {
		t.Fatalf("paired status: %v", got)
	}
	raw, err := store.OpenRawForTest(srv.cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`ALTER TABLE system_settings RENAME TO system_settings_hidden`); err != nil {
		t.Fatal(err)
	}
	w := do("GET", "/api/admin/backup/status", nil, false)
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "paired") || strings.Contains(w.Body.String(), "key_pinned") {
		t.Fatalf("status with unreadable settings: %d %s", w.Code, w.Body.String())
	}
	for _, c := range []struct {
		method, path string
		stepUp       bool
	}{{"POST", "/api/admin/backup/deposit", false}, {"GET", "/api/admin/backup/export-capsule", true}} {
		if w := do(c.method, c.path, nil, c.stepUp); w.Code < 500 {
			t.Errorf("%s with unreadable settings: %d %s", c.path, w.Code, w.Body.String())
		}
	}
	if _, err := raw.Exec(`ALTER TABLE system_settings_hidden RENAME TO system_settings`); err != nil {
		t.Fatal(err)
	}
	if got := decode(t, do("GET", "/api/admin/backup/status", nil, false)); got["paired"] != true {
		t.Fatalf("status once readable again: %v", got)
	}
}

// The pinned key offered again with another k-of-n is refused on pin-key and on pairing,
// changing nothing; with the same k-of-n it is accepted.
func TestPinnedTopologyIsWriteOnceOverHTTP(t *testing.T) {
	priv, _ := recoverykey.Generate()
	fake := &fakeRecovery{}
	prev := newRecoveryClient
	newRecoveryClient = func(*config.Config) recoveryClient { return fake }
	t.Cleanup(func() { newRecoveryClient = prev })
	srv, s, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	do := adminCaller(t, srv, s)
	pin := func(k, n int) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"public_key": base64.StdEncoding.EncodeToString(priv.Public().Bytes()), "threshold": k, "total_shares": n})
		return do("POST", "/api/admin/backup/pin-key", body, true)
	}
	if w := pin(2, 3); w.Code != http.StatusOK {
		t.Fatalf("first pin: %d %s", w.Code, w.Body.String())
	}
	sealed, _ := s.GetSetting("kyrecovery_public_key")
	if w := pin(3, 5); w.Code != http.StatusConflict {
		t.Fatalf("same key, other topology: %d %s", w.Code, w.Body.String())
	}
	fake.result = backup.PairingResult{APIToken: "tok", Key: backup.RecoveryKey{Public: priv.Public(), Threshold: 2, TotalShares: 4}}
	body, _ := json.Marshal(map[string]string{"recovery_url": "https://recovery.example.test", "pairing_code": "123456"})
	if w := do("POST", "/api/admin/backup/pair-remote", body, true); w.Code != http.StatusConflict {
		t.Fatalf("pairing with another topology: %d %s", w.Code, w.Body.String())
	}
	if _, err := s.GetSetting("kyrecovery_token_enc"); err == nil {
		t.Fatal("a refused pairing stored its token")
	}
	got := decode(t, do("GET", "/api/admin/backup/status", nil, false))
	if got["threshold"] != float64(2) || got["total_shares"] != float64(3) {
		t.Fatalf("topology after refusals: %v", got)
	}
	if after, _ := s.GetSetting("kyrecovery_public_key"); after != sealed {
		t.Fatal("a refused pin rewrote the sealed key copy")
	}
	if w := pin(2, 3); w.Code != http.StatusOK {
		t.Fatalf("same key, same topology: %d %s", w.Code, w.Body.String())
	}
}

// Two servers sharing one database pin two different keys at the same moment: one wins.
// The loser's data directory never gains a recovery.pub for its key, and once it names the
// winner's key, as a replica's configuration must, it reports the winner's key and topology.
func TestConcurrentPinsOnTwoServersHaveOneWinner(t *testing.T) {
	prev := newRecoveryClient
	newRecoveryClient = func(*config.Config) recoveryClient { return &fakeRecovery{} }
	t.Cleanup(func() { newRecoveryClient = prev })
	for round := range 5 {
		a, sa, _, _, _, cleanup := setupTestServer(t)
		b, sb := serverOn(t, a.cfg.DBPath, a.cfg)
		doA, doB := adminCaller(t, a, sa), adminCaller(t, b, sb)
		keyA, _ := recoverykey.Generate()
		keyB, _ := recoverykey.Generate()
		pin := func(do func(string, string, []byte, bool) *httptest.ResponseRecorder, k recoverykey.PrivateKey, n int) func() *httptest.ResponseRecorder {
			body, _ := json.Marshal(map[string]any{"public_key": base64.StdEncoding.EncodeToString(k.Public().Bytes()), "threshold": 2, "total_shares": n})
			return func() *httptest.ResponseRecorder { return do("POST", "/api/admin/backup/pin-key", body, true) }
		}
		calls := []func() *httptest.ResponseRecorder{pin(doA, keyA, 3), pin(doB, keyB, 4)}
		replies := make([]*httptest.ResponseRecorder, 2)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i, call := range calls {
			wg.Add(1)
			go func() { defer wg.Done(); <-start; replies[i] = call() }()
		}
		close(start)
		wg.Wait()
		codes := []int{replies[0].Code, replies[1].Code}
		slices.Sort(codes)
		if !slices.Equal(codes, []int{http.StatusOK, http.StatusConflict}) {
			t.Fatalf("round %d: replies %d %s / %d %s", round, replies[0].Code, replies[0].Body, replies[1].Code, replies[1].Body)
		}
		winner, loser, wantID, wantN, loserKey := a, b, keyA.Public().ID(), 3, keyB.Public().ID()
		loserDo := doB
		if replies[1].Code == http.StatusOK {
			winner, loser, wantID, wantN, loserKey = b, a, keyB.Public().ID(), 4, keyA.Public().ID()
			loserDo = doA
		}
		if raw, err := os.ReadFile(backup.RecoveryKeyPath(loser.cfg.DataDir)); err == nil {
			if pk, _ := recoverykey.ParsePublicKey(raw); pk.ID() == loserKey {
				t.Fatalf("round %d: the loser wrote recovery.pub for the key that lost", round)
			}
		}
		loser.cfg.RecoveryKeyID = wantID
		for name, do := range map[string]func(string, string, []byte, bool) *httptest.ResponseRecorder{"winner": map[*Server]func(string, string, []byte, bool) *httptest.ResponseRecorder{a: doA, b: doB}[winner], "loser": loserDo} {
			got := decode(t, do("GET", "/api/admin/backup/status", nil, false))
			if got["recovery_key_id"] != wantID || got["threshold"] != float64(2) || got["total_shares"] != float64(wantN) {
				t.Fatalf("round %d: the %s reports %v, want %s 2-of-%d", round, name, got, wantID, wantN)
			}
		}
		if raw, err := os.ReadFile(filepath.Join(loser.cfg.DataDir, "recovery.pub")); err != nil {
			t.Fatalf("round %d: the loser has no recovery.pub for the winner: %v", round, err)
		} else if pk, _ := recoverykey.ParsePublicKey(raw); pk.ID() != wantID {
			t.Fatalf("round %d: the loser holds key %s", round, pk.ID())
		}
		cleanup()
	}
}

// The status page only reads the backup directory: on a directory every replica shares, a
// rename or prune outside the backup lease would race the replica holding it.
func TestBackupStatusNeverChangesTheBackupDirectory(t *testing.T) {
	srv, s, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	dir := t.TempDir()
	srv.cfg.BackupDir, srv.cfg.BackupKeep = dir, 1
	files := []string{"KySignOn-cap-KySignOn-123456789.kycap", "KySignOn.cap-1.kycap", "KySignOn.cap-2.kycap", "KySignOn.cap-3.kycap"}
	for _, name := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	do := adminCaller(t, srv, s)
	if w := do("GET", "/api/admin/backup/status", nil, false); w.Code != http.StatusOK {
		t.Fatalf("status: %d %s", w.Code, w.Body.String())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	slices.Sort(got)
	want := slices.Clone(files)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("status changed the backup directory: %v -> %v", want, got)
	}
}

// The replica fingerprint is read by the server start and accept-replica-config only: no
// GET the API serves, admin or public, returns it.
func TestReplicaFingerprintIsInNoAPIResponse(t *testing.T) {
	srv, s, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	const marker = "f1ngerpr1nt-value-that-must-never-be-served"
	if err := s.SetSetting(config.ReplicaConfigSetting, `{"KYIDENTITY_ISSUER_URL":"`+marker+`"}`); err != nil {
		t.Fatal(err)
	}
	do := adminCaller(t, srv, s)
	paths := []string{"/readyz", "/livez", "/healthz", "/api/branding", "/.well-known/openid-configuration", "/api/installer/network"}
	for _, rt := range srv.adminRoutes {
		if rt.method == "GET" && !strings.Contains(rt.path, "{") {
			paths = append(paths, rt.path)
		}
	}
	if len(paths) < 20 {
		t.Fatalf("only %d routes probed", len(paths))
	}
	for _, path := range paths {
		w := do("GET", path, nil, true)
		if strings.Contains(w.Body.String(), marker) {
			t.Fatalf("GET %s served the replica fingerprint", path)
		}
	}
}
