package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kyidentity-server/internal/crypto"
	"github.com/Busness-app/kyidentity-server/internal/store"
)

// Keep a real browser's cookies across password/MFA completion and redirects.
func interactionBrowser(t *testing.T, srv *Server) func(string, string, any) *httptest.ResponseRecorder {
	t.Helper()
	cookies := map[string]string{}
	return func(method, path string, body any) *httptest.ResponseRecorder {
		t.Helper()
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(method, path, strings.NewReader(string(data)))
		csrf := srv.middleware.IssueCSRFToken(cookies["kyidentity_session"])
		cookies["kyidentity_csrf"] = csrf
		for name, value := range cookies {
			req.AddCookie(&http.Cookie{Name: name, Value: value})
		}
		req.Header.Set("X-CSRF-Token", csrf)
		req.Header.Set("Content-Type", "application/json")
		r := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(r, req)
		for _, c := range r.Result().Cookies() {
			cookies[c.Name] = c.Value
		}
		return r
	}
}

func TestAuthorizationInteraction(t *testing.T) {
	srv, db, _, _, engine, cleanup := setupTestServer(t)
	defer cleanup()
	u := newUser(t, db, "user")
	newClient(t, db, "app", []string{"https://app.example/cb"}, []string{"openid"})
	// Bind the authorization code to this browser flow with PKCE.
	verifier := strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"client_id": {"app"}, "redirect_uri": {"https://app.example/cb"}, "response_type": {"code"}, "scope": {"openid"}, "state": {"bound-state"}, "nonce": {"bound-nonce"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}, "prompt": {"login"}}
	browser := interactionBrowser(t, srv)
	begin := func() string {
		t.Helper()
		r := browser("GET", "/oauth/authorize?"+q.Encode(), nil)
		location, _ := url.Parse(r.Header().Get("Location"))
		raw := location.Query().Get("interaction")
		if r.Code != 302 || raw == "" {
			t.Fatalf("begin: %d %s %s", r.Code, r.Header().Get("Location"), r.Body.String())
		}
		return raw
	}
	login := func(raw string) {
		t.Helper()
		r := browser("POST", "/api/auth/login", map[string]string{"username": u.Username, "password": "correct-horse-battery", "interaction": raw})
		if r.Code != 200 {
			t.Fatalf("login: %d %s", r.Code, r.Body.String())
		}
	}
	raw := begin()
	if r := browser("GET", "/oauth/authorize?interaction="+raw, nil); r.Code != 400 {
		t.Fatal("unfinished interaction issued code")
	}
	other := interactionBrowser(t, srv)
	if r := other("POST", "/api/auth/login", map[string]string{"username": u.Username, "password": "correct-horse-battery", "interaction": raw}); r.Code != 400 {
		t.Fatal("other browser completed interaction")
	}
	login(raw)
	if r := browser("GET", "/oauth/authorize?interaction="+raw+"&nonce=changed", nil); r.Code != 400 {
		t.Fatal("request override accepted")
	}
	r := browser("GET", "/oauth/authorize?interaction="+raw, nil)
	location, _ := url.Parse(r.Header().Get("Location"))
	code := location.Query().Get("code")
	if r.Code != 302 || code == "" || location.Query().Get("state") != "bound-state" {
		t.Fatalf("resume: %d %s", r.Code, r.Header().Get("Location"))
	}
	saved, err := db.GetValidAuthorizationCode(crypto.HashSHA256(code))
	if err != nil || saved == nil || saved.Nonce != "bound-nonce" || saved.PrimaryAuthenticatedAt == nil {
		t.Fatalf("snapshot: %+v %v", saved, err)
	}
	if _, err := engine.ExchangeAuthorizationCode(code, "app", "", "https://app.example/cb", verifier); err != nil {
		t.Fatal(err)
	}
	if r := browser("GET", "/oauth/authorize?interaction="+raw, nil); r.Code != 400 {
		t.Fatal("interaction replay issued code")
	}
	// Each new prompt=login requires its own proof even with a just-created session.
	raw = begin()
	if r := browser("GET", "/oauth/authorize?interaction="+raw, nil); r.Code != 400 {
		t.Fatal("old session satisfied new prompt")
	}
	if r := browser("POST", "/api/auth/authorization/cancel", map[string]string{"interaction": raw}); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	if r := browser("POST", "/api/auth/login", map[string]string{"username": u.Username, "password": "correct-horse-battery", "interaction": raw}); r.Code != 400 {
		t.Fatal("cancelled interaction logged in")
	}
	// Two tabs are isolated: completing one cannot satisfy the other.
	a, b := begin(), begin()
	login(a)
	if r := browser("GET", "/oauth/authorize?interaction="+b, nil); r.Code != 400 {
		t.Fatal("other tab login satisfied interaction")
	}
	login(b)
	if r := browser("GET", "/oauth/authorize?interaction="+a, nil); r.Code != 400 {
		t.Fatal("different session spent first tab interaction")
	}
	if r := browser("GET", "/oauth/authorize?interaction="+b, nil); r.Code != 302 {
		t.Fatal(r.Body.String())
	}
}

func TestAuthorizationSilentAndAge(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	u := newUser(t, db, "user")
	newClient(t, db, "app", []string{"https://app.example/cb"}, []string{"openid"})
	raw := "session"
	old := time.Now().UTC().Add(-time.Hour)
	if err := db.CreateSession(&store.Session{ID: "old", UserID: u.ID, SessionTokenHash: crypto.HashSHA256(raw), ExpiresAt: time.Now().UTC().Add(time.Hour), AuthenticationEvidence: store.AuthenticationEvidence{PrimaryAuthenticatedAt: &old}}); err != nil {
		t.Fatal(err)
	}
	q := url.Values{"client_id": {"app"}, "redirect_uri": {"https://app.example/cb"}, "response_type": {"code"}, "scope": {"openid"}, "code_challenge": {"challenge"}, "code_challenge_method": {"S256"}, "prompt": {"none"}, "state": {"state"}}
	for _, tt := range []struct{ cookie, age, want string }{{"", "", "login_required"}, {raw, "60", "login_required"}, {raw, "0", "login_required"}, {raw, "bad", "invalid_request"}, {raw, "7200", ""}} {
		if tt.age != "" {
			q.Set("max_age", tt.age)
		} else {
			q.Del("max_age")
		}
		r := adminRequestNoStepUp(t, srv, "GET", "/oauth/authorize?"+q.Encode(), tt.cookie, "")
		location, _ := url.Parse(r.Header().Get("Location"))
		if r.Code != 302 || location.Host != "app.example" || location.Query().Get("error") != tt.want || location.Query().Get("state") != "state" {
			t.Fatalf("silent %+v: %d %s", tt, r.Code, r.Header().Get("Location"))
		}
		if len(r.Result().Cookies()) != 0 {
			t.Fatal("silent request created interaction cookie")
		}
	}
}

func TestAuthorizationInteractionMFA(t *testing.T) {
	for _, method := range []string{"totp", "recovery", "cancelled", "cancelled_recovery"} {
		t.Run(method, func(t *testing.T) {
			srv, db, _, _, _, cleanup := setupTestServer(t)
			defer cleanup()
			u := newUser(t, db, "user")
			newClient(t, db, "app", []string{"https://app.example/cb"}, []string{"openid"})
			secret, _, err := srv.mfaEngine.GenerateTOTPSecret(u.Username, "KyIdentity")
			if err != nil {
				t.Fatal(err)
			}
			if err := srv.mfaEngine.SaveUserTOTP(u.ID, secret, nil); err != nil {
				t.Fatal(err)
			}
			recovery, err := srv.mfaEngine.GenerateRecoveryCodes(u.ID, nil)
			if err != nil {
				t.Fatal(err)
			}
			browser := interactionBrowser(t, srv)
			q := url.Values{"client_id": {"app"}, "redirect_uri": {"https://app.example/cb"}, "response_type": {"code"}, "scope": {"openid"}, "code_challenge": {"challenge"}, "code_challenge_method": {"S256"}, "acr_values": {"urn:kyidentity:acr:mfa"}}
			r := browser("GET", "/oauth/authorize?"+q.Encode(), nil)
			location, _ := url.Parse(r.Header().Get("Location"))
			raw := location.Query().Get("interaction")
			if raw == "" {
				t.Fatal("no interaction")
			}
			r = browser("POST", "/api/auth/login", map[string]string{"username": u.Username, "password": "correct-horse-battery", "interaction": raw})
			var begun LoginResponse
			if err := json.Unmarshal(r.Body.Bytes(), &begun); err != nil || !begun.MFARequired || begun.MFAToken == "" {
				t.Fatalf("MFA begin: %s", r.Body.String())
			}
			// Server persists the interaction on the MFA token; the finish body cannot choose it.
			token, err := srv.mfaEngine.ValidateMFAToken(begun.MFAToken)
			if err != nil || token.InteractionHash != crypto.HashSHA256(raw) {
				t.Fatalf("MFA binding: %+v %v", token, err)
			}
			if strings.HasPrefix(method, "cancelled") {
				browser("POST", "/api/auth/authorization/cancel", map[string]string{"interaction": raw})
			}
			code := testTOTPCode(t, secret)
			path := "/api/auth/mfa/totp/verify"
			if method == "recovery" || method == "cancelled_recovery" {
				path = "/api/auth/mfa/recovery/verify"
				code = recovery[0]
			}
			r = browser("POST", path, map[string]string{"mfaToken": begun.MFAToken, "code": code})
			if strings.HasPrefix(method, "cancelled") {
				if r.Code != 200 || !strings.Contains(r.Body.String(), `"restartAuthorization":true`) {
					t.Fatalf("completed MFA lost login: %d %s", r.Code, r.Body.String())
				}
				if r := browser("GET", "/api/auth/me", nil); r.Code != 200 {
					t.Fatal("completed MFA not authenticated")
				}
				if r := browser("GET", "/oauth/authorize?interaction="+raw, nil); r.Code != 400 {
					t.Fatal("cancelled interaction revived")
				}
				return
			}
			if r.Code != 200 {
				t.Fatalf("MFA finish: %d %s", r.Code, r.Body.String())
			}
			r = browser("GET", "/oauth/authorize?interaction="+raw, nil)
			location, _ = url.Parse(r.Header().Get("Location"))
			if method == "recovery" {
				if location.Query().Get("error") != "login_required" {
					t.Fatal("recovery claimed MFA", location)
				}
			} else if location.Query().Get("code") == "" {
				t.Fatal("TOTP did not satisfy MFA", location)
			}
		})
	}
}

func TestAuthorizationRateLimitUsesProtocolErrors(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	newClient(t, db, "app", []string{"https://app.example/cb"}, []string{"openid"})
	path := "/oauth/authorize?client_id=app&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&response_type=code&scope=openid&code_challenge=challenge&code_challenge_method=S256&prompt=none"
	now := time.Now()
	srv.middleware.now = func() time.Time { return now }
	browser := interactionBrowser(t, srv)
	if r := browser("GET", strings.Replace(path, "prompt=none", "prompt=login", 1), nil); r.Code != 302 {
		t.Fatal("browser cookie not issued")
	}
	for n := range 302 {
		r := adminRequestNoStepUp(t, srv, "GET", path, "", "")
		location, _ := url.Parse(r.Header().Get("Location"))
		if r.Code != 302 || location.Host != "app.example" || location.Query().Get("error") == "" {
			t.Fatalf("request %d: %d %s", n+1, r.Code, r.Body.String())
		}
		if n == 301 && location.Query().Get("error") != "temporarily_unavailable" {
			t.Fatal("throttle not exercised")
		}
	}
	r := browser("GET", path, nil)
	location, _ := url.Parse(r.Header().Get("Location"))
	if location.Query().Get("error") != "temporarily_unavailable" {
		t.Fatal("signed cookie bypassed the exhausted IP allowance")
	}
	req := httptest.NewRequest("GET", path, nil)
	req.AddCookie(&http.Cookie{Name: authorizationBrowserCookie, Value: strings.Repeat("f", 64) + ".forged"})
	r = httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(r, req)
	location, _ = url.Parse(r.Header().Get("Location"))
	if location.Query().Get("error") != "temporarily_unavailable" {
		t.Fatal("forged browser cookie bypassed IP limit")
	}
}

func TestAuthorizationInteractionDatabaseError(t *testing.T) {
	srv, db, _, _, engine, cleanup := setupTestServer(t)
	defer cleanup()
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	h := NewOAuthHandler(db, engine, srv.audit, srv.middleware)
	r := httptest.NewRecorder()
	// beginInteraction is called only after these routing fields are validated.
	h.beginInteraction(r, httptest.NewRequest("GET", "/oauth/authorize", nil), url.Values{"client_id": {"app"}, "redirect_uri": {"https://app.example/cb"}, "state": {"kept"}})
	location, _ := url.Parse(r.Header().Get("Location"))
	if r.Code != 302 || location.Query().Get("error") != "server_error" || location.Query().Get("state") != "kept" {
		t.Fatalf("database outage reported as throttling: %d %s", r.Code, r.Header().Get("Location"))
	}
}

func TestAuthorizationRateLimitSignedCookieRotation(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	newClient(t, db, "app", []string{"https://app.example/cb"}, []string{"openid"})
	now := time.Now()
	srv.middleware.now = func() time.Time { return now }
	path := "/oauth/authorize?client_id=app&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&response_type=code&scope=openid&code_challenge=challenge&code_challenge_method=S256&prompt=none"
	cookies := []*http.Cookie{}
	for range 10 {
		r := adminRequestNoStepUp(t, srv, "GET", strings.Replace(path, "prompt=none", "prompt=login", 1), "", "")
		for _, c := range r.Result().Cookies() {
			if c.Name == authorizationBrowserCookie {
				cookies = append(cookies, c)
			}
		}
	}
	if len(cookies) != 10 {
		t.Fatal("did not mint ten distinct browser identities")
	}
	for n := range 301 {
		req := httptest.NewRequest("GET", path, nil)
		req.AddCookie(cookies[n%len(cookies)])
		r := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(r, req)
		location, _ := url.Parse(r.Header().Get("Location"))
		want := "login_required"
		if n >= 290 {
			want = "temporarily_unavailable"
		}
		if r.Code != 302 || location.Query().Get("error") != want {
			t.Fatalf("rotated request %d: %d %s, want %s", n+11, r.Code, r.Header().Get("Location"), want)
		}
	}
}

func TestAuthorizationRateLimitCookiesCannotExhaustSharedMap(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	newClient(t, db, "app", []string{"https://app.example/cb"}, []string{"openid"})
	now := time.Now()
	srv.middleware.now = func() time.Time { return now }
	// Exercise shared-map saturation without allocating the production-sized map.
	srv.middleware.maxLimiters = 16
	path := "/oauth/authorize?client_id=app&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&response_type=code&scope=openid&code_challenge=challenge&code_challenge_method=S256&prompt=none"
	cookies := []*http.Cookie{}
	for range 32 {
		r := adminRequestNoStepUp(t, srv, "GET", strings.Replace(path, "prompt=none", "prompt=login", 1), "", "")
		for _, c := range r.Result().Cookies() {
			if c.Name == authorizationBrowserCookie {
				cookies = append(cookies, c)
			}
		}
	}
	if len(cookies) != 32 {
		t.Fatalf("minted %d cookies", len(cookies))
	}
	for _, cookie := range cookies {
		req := httptest.NewRequest("GET", path, nil)
		req.AddCookie(cookie)
		r := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(r, req)
	}
	if count := srv.middleware.TrackedLimiters(); count != 1 {
		t.Errorf("one source allocated %d buckets by rotating cookies", count)
	}
	// The same pressure must not deny a fresh source a login bucket.
	csrf := srv.middleware.IssueCSRFToken("")
	req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"unknown","password":"wrong"}`))
	req.RemoteAddr = "198.51.100.42:12345"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(&http.Cookie{Name: "kyidentity_csrf", Value: csrf})
	r := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(r, req)
	if r.Code != 401 {
		t.Fatalf("new source could not attempt login: %d %s", r.Code, r.Body.String())
	}
}
