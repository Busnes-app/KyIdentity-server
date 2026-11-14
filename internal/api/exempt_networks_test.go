package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/config"
	"github.com/Busnes-app/kyidentity-server/internal/mfa"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

const (
	officeRange = "203.0.113.0/24"
	officeIP    = "203.0.113.5"
	outsideIP   = "198.51.100.9"
)

func withOffice(c *config.Config) { c.RateLimitExemptCIDRs = officeRange }

// loginFrom posts a sign-in from peer, with an optional X-Forwarded-For chain.
func loginFrom(t *testing.T, srv *Server, peer, xff, username, password string) int {
	t.Helper()
	raw, _ := json.Marshal(map[string]string{"username": username, "password": password})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(raw))
	req.RemoteAddr = peer + ":41000"
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	csrf := "test-csrf-" + uuid.New().String()
	req.AddCookie(&http.Cookie{Name: "kyidentity_csrf", Value: csrf})
	req.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)
	return w.Code
}

// throttledWithin reports whether peer meets a 429 on sign-in within n attempts.
func throttledWithin(t *testing.T, srv *Server, peer, xff string, n int) bool {
	t.Helper()
	for range n {
		if loginFrom(t, srv, peer, xff, "nobody", "wrong-password") == http.StatusTooManyRequests {
			return true
		}
	}
	return false
}

func freeze(srv *Server) {
	now := time.Now()
	srv.middleware.now = func() time.Time { return now }
}

// An allowlisted office goes past the per-IP sign-in bucket; everyone else keeps it.
func TestExemptNetworkSkipsThePerIPLoginLimit(t *testing.T) {
	srv, _, _, _, _, cleanup := setupTestServerWith(t, withOffice)
	defer cleanup()
	freeze(srv)
	if throttledWithin(t, srv, officeIP, "", 30) {
		t.Fatal("an office address was throttled by the per-IP sign-in limit")
	}
	if throttledWithin(t, srv, outsideIP, "", 10) {
		t.Fatal("outside address throttled early")
	}
	if code := loginFrom(t, srv, outsideIP, "", "nobody", "wrong-password"); code != http.StatusTooManyRequests {
		t.Fatalf("outside attempt 11 answered %d, want 429", code)
	}
}

// The per-account lockout still bounds password guessing from an office, and it locks only
// the guessed account, not the colleague behind the same address.
func TestExemptNetworkKeepsTheAccountLockout(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServerWith(t, withOffice)
	defer cleanup()
	freeze(srv)
	victim, colleague := newUser(t, db, "user"), newUser(t, db, "user")
	for i := range store.MaxFailedLogins {
		if code := loginFrom(t, srv, officeIP, "", victim.Username, "wrong-password"); code != http.StatusUnauthorized {
			t.Fatalf("wrong password %d answered %d", i+1, code)
		}
	}
	if code := loginFrom(t, srv, officeIP, "", victim.Username, "correct-horse-battery"); code != http.StatusUnauthorized {
		t.Fatalf("locked account signed in from the office: %d", code)
	}
	if code := loginFrom(t, srv, officeIP, "", colleague.Username, "correct-horse-battery"); code != http.StatusOK {
		t.Fatalf("a colleague behind the same address was refused: %d", code)
	}
}

// With no trusted proxy, X-Forwarded-For is the caller's own claim and buys no exemption.
func TestForgedForwardedForCannotClaimAnExemptNetwork(t *testing.T) {
	srv, _, _, _, _, cleanup := setupTestServerWith(t, withOffice)
	defer cleanup()
	freeze(srv)
	if !throttledWithin(t, srv, outsideIP, officeIP, 11) {
		t.Fatal("a forged X-Forwarded-For claimed the office network")
	}
}

// Behind a trusted proxy the client it reports is matched; an office address the client
// prepends to the chain is not.
func TestExemptNetworkMatchesTheClientATrustedProxyReports(t *testing.T) {
	srv, _, _, _, _, cleanup := setupTestServerWith(t, withOffice, func(c *config.Config) {
		c.TrustedProxyCIDRs = []string{"192.0.2.7/32"}
		c.ForwardedHeader = "X-Forwarded-For"
	})
	defer cleanup()
	freeze(srv)
	if throttledWithin(t, srv, "192.0.2.7", officeIP, 30) {
		t.Fatal("office client behind the proxy was throttled")
	}
	if !throttledWithin(t, srv, "192.0.2.7", officeIP+", "+outsideIP, 11) {
		t.Fatal("a prepended office address was believed")
	}
}

// OIDC authorize: the office skips the per-IP allowance, but the per-browser cap on
// pending sign-ins still applies.
func TestExemptNetworkSkipsTheAuthorizeIPLimitOnly(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServerWith(t, withOffice)
	defer cleanup()
	freeze(srv)
	newClient(t, db, "app", []string{"https://app.example/cb"}, []string{"openid"})
	path := "/oauth/authorize?client_id=app&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&response_type=code&scope=openid&code_challenge=challenge&code_challenge_method=S256"
	get := func(peer, query string, cookie *http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path+query, nil)
		req.RemoteAddr = peer + ":41000"
		if cookie != nil {
			req.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(w, req)
		return w
	}
	errorOf := func(w *httptest.ResponseRecorder) string {
		location, _ := url.Parse(w.Header().Get("Location"))
		return location.Query().Get("error")
	}
	for n := range 310 {
		if e := errorOf(get(officeIP, "&prompt=none", nil)); e != "login_required" {
			t.Fatalf("office request %d: %q, want login_required", n+1, e)
		}
	}
	for n := range 301 {
		e := errorOf(get(outsideIP, "&prompt=none", nil))
		if want := map[bool]string{true: "temporarily_unavailable", false: "login_required"}[n == 300]; e != want {
			t.Fatalf("outside request %d: %q, want %q", n+1, e, want)
		}
	}
	first := get(officeIP, "&prompt=login", nil)
	var browser *http.Cookie
	for _, c := range first.Result().Cookies() {
		if c.Name == authorizationBrowserCookie {
			browser = c
		}
	}
	if browser == nil {
		t.Fatal("no browser cookie")
	}
	for range 9 {
		get(officeIP, "&prompt=login", browser)
	}
	if e := errorOf(get(officeIP, "&prompt=login", browser)); e != "temporarily_unavailable" {
		t.Fatalf("eleventh pending sign-in from one office browser: %q, want the per-browser cap", e)
	}
}

func networksOf(t *testing.T, w *httptest.ResponseRecorder) (networks, environment string, exempted float64) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var out struct {
		Networks    string  `json:"networks"`
		Environment string  `json:"environment"`
		Exempted    float64 `json:"exempted"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.Networks, out.Environment, out.Exempted
}

const networksPath = "/api/admin/rate-limit-networks"

// An administrator's list takes effect at once, is stored canonically, audited, counted and
// still there after a restart; the environment's list stays alongside it.
func TestAdminSetsExemptNetworks(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServerWith(t, func(c *config.Config) { c.RateLimitExemptCIDRs = "198.18.7.0/24" })
	defer cleanup()
	freeze(srv)
	admin := newSession(t, db, newUser(t, db, "admin"), time.Now().UTC().Add(time.Hour))

	if n, env, ex := networksOf(t, adminRequest(t, srv, "GET", networksPath, admin, "")); n != "" || env != "198.18.7.0/24" || ex != 0 {
		t.Fatalf("before: %q %q %v", n, env, ex)
	}
	if !throttledWithin(t, srv, officeIP, "", 11) {
		t.Fatal("office exempt before it was listed")
	}
	body := `{"networks":" 203.0.113.77/24 , 2001:db8:1::/48"}`
	if w := adminRequestNoStepUp(t, srv, "PUT", networksPath, admin, body); w.Code != http.StatusForbidden {
		t.Fatalf("PUT without step-up answered %d", w.Code)
	}
	if n, _, _ := networksOf(t, adminRequest(t, srv, "PUT", networksPath, admin, body)); n != "203.0.113.0/24,2001:db8:1::/48" {
		t.Fatalf("stored %q, want the canonical list", n)
	}
	if throttledWithin(t, srv, "203.0.113.6", "", 15) || throttledWithin(t, srv, "198.18.7.50", "", 15) {
		t.Fatal("a listed network was throttled")
	}
	if _, _, ex := networksOf(t, adminRequest(t, srv, "GET", networksPath, admin, "")); ex != 30 {
		t.Fatalf("exempted = %v, want 30", ex)
	}
	rows := auditRows(t, db, "admin.rate_limit_networks_configured")
	if len(rows) != 1 || !strings.Contains(rows[0].DetailsJSON, `"old":""`) || !strings.Contains(rows[0].DetailsJSON, `"new":"203.0.113.0/24,2001:db8:1::/48"`) {
		t.Fatalf("audit: %+v", rows)
	}

	restarted := NewServer(srv.cfg, db, srv.keyManager, srv.syncEngine, srv.mfaEngine, srv.oauthEngine, srv.audit, nil)
	freeze(restarted)
	if throttledWithin(t, restarted, "203.0.113.7", "", 15) {
		t.Fatal("the stored list was not loaded at startup")
	}

	if n, _, _ := networksOf(t, adminRequest(t, srv, "PUT", networksPath, admin, `{"networks":""}`)); n != "" {
		t.Fatalf("cleared list reads %q", n)
	}
	if !throttledWithin(t, srv, "203.0.113.200", "", 11) {
		t.Fatal("a removed network is still exempt")
	}
	if throttledWithin(t, srv, "198.18.7.51", "", 15) {
		t.Fatal("clearing the admin list dropped the environment's network")
	}
}

// A list that would switch the limit off widely is refused with the reason, and nothing changes.
func TestExemptNetworksRefuseBroadOrInvalidLists(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	freeze(srv)
	admin := newSession(t, db, newUser(t, db, "admin"), time.Now().UTC().Add(time.Hour))
	if w := adminRequest(t, srv, "PUT", networksPath, admin, `{"networks":"`+officeRange+`"}`); w.Code != http.StatusOK {
		t.Fatalf("seed: %d %s", w.Code, w.Body.String())
	}
	for bad, reason := range map[string]string{
		"0.0.0.0/0": "too broad", "::/0": "too broad", "10.0.0.0/8": "too broad", "2001:db8::/32": "too broad",
		"office": "not an address", "127.0.0.1": "loopback", "203.0.113.0/24,nope": "not an address",
	} {
		w := adminRequest(t, srv, "PUT", networksPath, admin, `{"networks":"`+bad+`"}`)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), reason) {
			t.Errorf("PUT %q answered %d %s, want 400 naming %q", bad, w.Code, w.Body.String(), reason)
		}
	}
	for _, bad := range []string{`{}`, `{"networks":1}`, `{"networks":"","x":1}`} {
		if w := adminRequest(t, srv, "PUT", networksPath, admin, bad); w.Code != http.StatusBadRequest {
			t.Errorf("PUT %s answered %d", bad, w.Code)
		}
	}
	if n, _, _ := networksOf(t, adminRequest(t, srv, "GET", networksPath, admin, "")); n != officeRange {
		t.Fatalf("a refused list replaced the stored one: %q", n)
	}
	if !throttledWithin(t, srv, "10.9.9.9", "", 11) {
		t.Fatal("an address in a refused range was exempt")
	}
	if rows := auditRows(t, db, "admin.rate_limit_networks_configured"); len(rows) != 1 {
		t.Fatalf("refused saves were audited as changes: %d rows", len(rows))
	}
}

// A stored list that no longer parses is dropped at startup, keeping only the environment's.
func TestUnreadableStoredExemptListFallsBackToTheEnvironment(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServerWith(t, withOffice)
	defer cleanup()
	if err := db.SetSetting(store.RateLimitExemptKey, "10.0.0.0/8"); err != nil {
		t.Fatal(err)
	}
	restarted := NewServer(srv.cfg, db, srv.keyManager, srv.syncEngine, srv.mfaEngine, srv.oauthEngine, srv.audit, nil)
	freeze(restarted)
	if !throttledWithin(t, restarted, "10.1.2.3", "", 11) {
		t.Fatal("a too-broad stored list was applied")
	}
	if throttledWithin(t, restarted, officeIP, "", 15) {
		t.Fatal("the environment's network was dropped too")
	}
}

// Replicas pick up another replica's change on their next re-read.
func TestExemptNetworksReachOtherReplicas(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	other := NewServer(srv.cfg, db, srv.keyManager, srv.syncEngine, srv.mfaEngine, srv.oauthEngine, srv.audit, nil)
	freeze(other)
	admin := newSession(t, db, newUser(t, db, "admin"), time.Now().UTC().Add(time.Hour))
	if w := adminRequest(t, srv, "PUT", networksPath, admin, `{"networks":"`+officeRange+`"}`); w.Code != http.StatusOK {
		t.Fatalf("save: %d", w.Code)
	}
	other.middleware.reloadExemptNetworks(false)
	if throttledWithin(t, other, officeIP, "", 15) {
		t.Fatal("the other replica did not pick up the list")
	}
}

// Only administrators read or change the list; delegated auditors and helpdesk do not.
func TestExemptNetworksAreAdminOnly(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	exp := time.Now().UTC().Add(time.Hour)
	user := newSession(t, db, newUser(t, db, "user"), exp)
	auditor := newUser(t, db, "user")
	if err := db.SetDelegations(auditor.ID, store.Delegations{Auditor: true, Helpdesk: true}, nil); err != nil {
		t.Fatal(err)
	}
	delegated := newSession(t, db, auditor, exp)
	for _, cookie := range []string{"", user, delegated} {
		for _, method := range []string{"GET", "PUT"} {
			call := adminRequest
			if cookie == "" {
				call = adminRequestNoStepUp
			}
			if w := call(t, srv, method, networksPath, cookie, `{"networks":"`+officeRange+`"}`); w.Code != http.StatusForbidden && w.Code != http.StatusUnauthorized {
				t.Errorf("%s by a non-admin answered %d", method, w.Code)
			}
		}
	}
	if n, _ := db.RateLimitExemptNetworks(); n != "" {
		t.Fatalf("a non-admin changed the list: %q", n)
	}
}

// officeExempted is how many requests skipped a per-IP limit on srv's current list.
func officeExempted(srv *Server) uint64 { return srv.middleware.exempt.Load().list.Exempted() }

// A listed network spends one shared budget, then meets the per-IP limit again; a second
// office address still has its own per-IP allowance after the first has spent its own.
func TestOfficeBudgetIsSharedThenFallsBackToThePerIPLimit(t *testing.T) {
	srv, _, _, _, _, cleanup := setupTestServerWith(t, withOffice)
	defer cleanup()
	freeze(srv)
	malformed := func(peer string) int { // the limiter runs before the body is read
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader("{"))
		req.RemoteAddr = peer + ":41000"
		req.AddCookie(&http.Cookie{Name: "kyidentity_csrf", Value: "test-csrf"})
		req.Header.Set("X-CSRF-Token", "test-csrf")
		w := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(w, req)
		if w.Code != http.StatusTooManyRequests && w.Code != http.StatusBadRequest {
			t.Fatalf("malformed sign-in answered %d %s", w.Code, w.Body.String())
		}
		return w.Code
	}
	const first, second = "203.0.113.5", "203.0.113.6"
	for n := range officeBudget {
		peer := first
		if n%2 == 1 {
			peer = second
		}
		if code := malformed(peer); code == http.StatusTooManyRequests {
			t.Fatalf("office request %d was throttled inside the office budget", n+1)
		}
	}
	if got := officeExempted(srv); got != officeBudget {
		t.Fatalf("exempted count %d, want %d", got, officeBudget)
	}
	for n := range 10 {
		if code := malformed(first); code == http.StatusTooManyRequests {
			t.Fatalf("first office address throttled at per-IP attempt %d", n+1)
		}
	}
	if code := malformed(first); code != http.StatusTooManyRequests {
		t.Fatalf("first office address past its budget and per-IP limit answered %d, want 429", code)
	}
	for n := range 10 {
		if code := malformed(second); code == http.StatusTooManyRequests {
			t.Fatalf("second office address throttled by the first one's per-IP window at %d", n+1)
		}
	}
	if code := malformed(second); code != http.StatusTooManyRequests {
		t.Fatalf("second office address answered %d past its per-IP limit, want 429", code)
	}
	if got := officeExempted(srv); got != officeBudget {
		t.Fatalf("requests that met the per-IP limit were counted as exempted: %d", got)
	}
}

// Replicas spend one office budget between them, as they do every shared bucket.
func TestOfficeBudgetHoldsAcrossReplicas(t *testing.T) {
	limiters := replicaLimiters(t, 3)
	now := time.Now()
	for _, m := range limiters {
		m.now = func() time.Time { return now }
		m.exemptEnv = officeRange
		m.reloadExemptNetworks(true)
	}
	var wg sync.WaitGroup
	for i, m := range limiters {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h := m.RateLimitExemptible("login", 10, 0.2)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			for n := range officeBudget {
				r := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
				r.RemoteAddr = fmt.Sprintf("203.0.113.%d:41000", 1+(i*officeBudget+n)%250)
				h.ServeHTTP(httptest.NewRecorder(), r)
			}
		}()
	}
	wg.Wait()
	var total uint64
	for _, m := range limiters {
		total += m.exempt.Load().list.Exempted()
	}
	if total != officeBudget {
		t.Fatalf("%d replicas exempted %d requests between them, want one budget of %d", len(limiters), total, officeBudget)
	}
}

// Concurrent wrong passwords at one account from an office address reach the password
// check no more often than the account lockout allows: the attempt is reserved first.
func TestConcurrentOfficeGuessesStayWithinTheAccountLockout(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServerWith(t, withOffice)
	defer cleanup()
	freeze(srv)
	victim := newUser(t, db, "user")
	for range 4 { // waves no wider than the Argon2 slots, so none is refused as busy
		var wg sync.WaitGroup
		start := make(chan struct{})
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if code := loginFrom(t, srv, officeIP, "", victim.Username, "wrong-password"); code != http.StatusUnauthorized {
					t.Errorf("wrong password answered %d", code)
				}
			}()
		}
		close(start)
		wg.Wait()
	}
	raw, err := store.OpenRawForTest(srv.cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var checked int
	if err := raw.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action='auth.login' AND target_id='` + victim.ID + `' AND details_json LIKE '%invalid_password%'`).Scan(&checked); err != nil {
		t.Fatal(err)
	}
	if checked != store.MaxFailedLogins {
		t.Fatalf("%d concurrent guesses reached the password check, want exactly %d", checked, store.MaxFailedLogins)
	}
	if code := loginFrom(t, srv, officeIP, "", victim.Username, "correct-horse-battery"); code != http.StatusUnauthorized {
		t.Fatalf("locked account signed in: %d", code)
	}
}

// The second-factor step goes through the office budget too, and its per-account lockout is
// reserved before each code is checked, so concurrent guesses over many tokens from an
// office address check no more codes than the lockout allows.
func TestConcurrentOfficeTOTPGuessesStayWithinTheAccountLockout(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()
	f.srv.middleware.exemptEnv = officeRange
	f.srv.middleware.exempt.Store(nil) // reload skips an unchanged stored list
	f.srv.middleware.reloadExemptNetworks(true)
	enrolTOTP(t, f)
	var tokens []string
	for range 6 {
		tokens = append(tokens, passwordLogin(t, f.srv, f.user.Username, f.pass))
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	start := make(chan struct{})
	checked, throttled := 0, 0
	for i := range len(tokens) * mfa.MaxMFAAttempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rec := anonPostFrom(t, f.srv, officeIP, "/api/auth/mfa/totp/verify", map[string]string{"mfaToken": tokens[i%len(tokens)], "code": "invalid"})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case strings.Contains(rec.Body.String(), "invalid_totp_code"):
				checked++
			case strings.Contains(rec.Body.String(), "rate_limit_exceeded"):
				throttled++
			}
		}()
	}
	close(start)
	wg.Wait()
	if throttled != 0 {
		t.Fatalf("%d second-factor requests from the office met the per-IP limit", throttled)
	}
	if checked != store.MaxFailedLogins {
		t.Fatalf("%d concurrent codes were checked, want exactly the lockout's %d", checked, store.MaxFailedLogins)
	}
	assertLocked(t, f, true)
}
