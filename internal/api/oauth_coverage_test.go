package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/oauth"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

const (
	covRedirect  = "https://notes.example.com/callback"
	covChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	covVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

// covAuthorizeQuery is a complete, valid authorization request for client id.
func covAuthorizeQuery(id string) url.Values {
	return url.Values{
		"client_id": {id}, "redirect_uri": {covRedirect}, "response_type": {"code"},
		"scope": {"openid"}, "state": {"s-123"}, "code_challenge": {covChallenge}, "code_challenge_method": {"S256"},
	}
}

// covAuthorize sends a raw-query authorization request, as cookie when cookie is set.
func covAuthorize(t *testing.T, srv *Server, cookie, rawQuery string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", "/oauth/authorize", nil)
	req.URL.RawQuery = rawQuery
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "kyidentity_session", Value: cookie})
	}
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)
	return rr
}

// covOAuthPost posts a form to an OAuth endpoint, with HTTP Basic client credentials when user is set.
func covOAuthPost(t *testing.T, srv *Server, path string, form url.Values, user, pass string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)
	return rr
}

// covAuditOutcomes counts audit rows for action by outcome.
func covAuditOutcomes(t *testing.T, db *store.Store, action string) map[string]int {
	t.Helper()
	events, _, err := db.ListAuditEvents(500, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	for _, e := range events {
		if e.Action == action {
			out[e.Outcome]++
		}
	}
	return out
}

// covUserWith creates an active user after applying mutate, for states newUser does not set.
func covUserWith(t *testing.T, db *store.Store, role string, mutate func(*store.User)) *store.User {
	t.Helper()
	u := newUser(t, db, role)
	if _, err := db.EditUser(u.ID, nil, func(row *store.User) (bool, error) {
		mutate(row)
		return false, nil
	}); err != nil {
		t.Fatalf("EditUser: %v", err)
	}
	got, err := db.GetUserByID(u.ID)
	if err != nil || got == nil {
		t.Fatal(err)
	}
	return got
}

// Until client_id and redirect_uri are proven to belong together, the redirect URI is
// attacker-controlled: every refusal before that point must be a direct 400/401 body, never
// a redirect, and never cacheable. An unregistered redirect is also audited as a denial.
func TestAuthorizeRefusesWithoutRedirectingToUnverifiedURI(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	newClient(t, db, "notes", []string{covRedirect}, []string{"openid"})
	newClient(t, db, "off", []string{covRedirect}, []string{"openid"})
	off, _ := db.GetOAuthClientByID("off")
	off.Enabled = false
	if err := db.UpdateOAuthClient(off); err != nil {
		t.Fatal(err)
	}

	with := func(mutate func(url.Values)) string {
		q := covAuthorizeQuery("notes")
		mutate(q)
		return q.Encode()
	}
	for _, tc := range []struct {
		name, query string
		status      int
		errCode     string
	}{
		{"oversized query", with(func(q url.Values) { q.Set("state", strings.Repeat("a", 9000)) }), 400, "invalid_request"},
		{"unparseable query", "client_id=notes&redirect_uri=%zz", 400, "invalid_request"},
		{"duplicate redirect_uri", with(func(q url.Values) { q.Add("redirect_uri", "https://evil.example/cb") }), 400, "invalid_request"},
		{"duplicate client_id", with(func(q url.Values) { q.Add("client_id", "off") }), 400, "invalid_request"},
		{"missing response_type", with(func(q url.Values) { q.Set("response_type", "") }), 400, "invalid_request"},
		{"implicit flow", with(func(q url.Values) { q.Set("response_type", "token") }), 400, "invalid_request"},
		{"unknown client", with(func(q url.Values) { q.Set("client_id", "ghost") }), 401, "unauthorized_client"},
		{"disabled client", with(func(q url.Values) { q.Set("client_id", "off") }), 401, "unauthorized_client"},
		{"unregistered redirect", with(func(q url.Values) { q.Set("redirect_uri", "https://evil.example/cb") }), 400, "invalid_redirect_uri"},
		{"redirect prefix trick", with(func(q url.Values) { q.Set("redirect_uri", covRedirect+"/../../evil") }), 400, "invalid_redirect_uri"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := covAuthorize(t, srv, "", tc.query)
			if rr.Code != tc.status || rr.Header().Get("Location") != "" {
				t.Fatalf("got %d Location=%q: %s", rr.Code, rr.Header().Get("Location"), rr.Body.String())
			}
			if body := decodeAPIError(t, rr); body["error"] != tc.errCode {
				t.Fatalf("error %q, want %q", body["error"], tc.errCode)
			}
			if rr.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("authorization refusal is cacheable")
			}
		})
	}
	denied := auditRows(t, db, "oauth.authorize")
	found := 0
	for _, e := range denied {
		if e.Outcome == "denied" && strings.Contains(e.DetailsJSON, "redirect_uri_not_registered") && strings.Contains(e.DetailsJSON, "evil") {
			found++
		}
	}
	if found != 2 {
		t.Fatalf("unregistered redirect denials audited %d times, want 2: %+v", found, denied)
	}
}

// Once the redirect URI is verified, protocol errors go back to the client through it with
// the caller's state: a request without S256 PKCE, or for no permitted scope, never gets a code.
func TestAuthorizeProtocolErrorsRedirectWithState(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	newClient(t, db, "notes", []string{covRedirect}, []string{"openid"})
	cookie := newSession(t, db, newUser(t, db, "user"), time.Now().UTC().Add(time.Hour))

	for _, tc := range []struct {
		name   string
		mutate func(url.Values)
		code   string
	}{
		{"no challenge", func(q url.Values) { q.Del("code_challenge") }, "invalid_request"},
		{"plain challenge method", func(q url.Values) { q.Set("code_challenge_method", "plain") }, "invalid_request"},
		{"no permitted scope", func(q url.Values) { q.Set("scope", "email profile") }, "invalid_scope"},
		{"bad max_age", func(q url.Values) { q.Set("max_age", "soon") }, "invalid_request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := covAuthorizeQuery("notes")
			tc.mutate(q)
			rr := covAuthorize(t, srv, cookie, q.Encode())
			loc, err := url.Parse(rr.Header().Get("Location"))
			if rr.Code != http.StatusFound || err != nil || !strings.HasPrefix(loc.String(), covRedirect) {
				t.Fatalf("got %d %q", rr.Code, rr.Header().Get("Location"))
			}
			if loc.Query().Get("error") != tc.code || loc.Query().Get("state") != "s-123" || loc.Query().Get("code") != "" {
				t.Fatalf("redirect %q, want error=%s with state and no code", loc, tc.code)
			}
		})
	}
}

// A signed-in user who must still change an administrator-set password gets no code for
// any app: the relying party is told interaction is required instead.
func TestAuthorizeRefusesUserWhoMustChangePassword(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	newClient(t, db, "notes", []string{covRedirect}, []string{"openid"})
	u := covUserWith(t, db, "user", func(u *store.User) { u.PasswordChangeRequired = true })
	cookie := newSession(t, db, u, time.Now().UTC().Add(time.Hour))

	rr := covAuthorize(t, srv, cookie, covAuthorizeQuery("notes").Encode())
	loc, _ := url.Parse(rr.Header().Get("Location"))
	if rr.Code != http.StatusFound || loc.Query().Get("error") != "interaction_required" || loc.Query().Get("code") != "" ||
		!strings.Contains(loc.Query().Get("error_description"), "password_change_required") {
		t.Fatalf("got %d %q", rr.Code, rr.Header().Get("Location"))
	}
	if n := covAuditOutcomes(t, db, "oauth.authorize")["success"]; n != 0 {
		t.Fatalf("refused authorization audited as success %d times", n)
	}
}

// The interaction page learns only what it needs (app name, account, factor demands) and
// only for the browser that started the sign-in; an unknown id, another browser, a disabled
// client or a disabled account all get invalid_interaction.
func TestInteractionDetailsBoundToBrowserAndLiveState(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	newClient(t, db, "notes", []string{covRedirect}, []string{"openid"})
	u := newUser(t, db, "user")
	cookie := newSession(t, db, u, time.Now().UTC().Add(time.Hour))

	start := func(browser func(string, string, any) *httptest.ResponseRecorder, extra url.Values) string {
		t.Helper()
		q := covAuthorizeQuery("notes")
		for k, v := range extra {
			q[k] = v
		}
		r := browser("GET", "/oauth/authorize?"+q.Encode(), nil)
		loc, _ := url.Parse(r.Header().Get("Location"))
		raw := loc.Query().Get("interaction")
		if r.Code != http.StatusFound || raw == "" {
			t.Fatalf("start: %d %q %s", r.Code, r.Header().Get("Location"), r.Body.String())
		}
		return raw
	}
	details := func(browser func(string, string, any) *httptest.ResponseRecorder, raw string) (int, map[string]any) {
		t.Helper()
		r := browser("GET", "/api/auth/authorization/"+raw, nil)
		var body map[string]any
		_ = json.Unmarshal(r.Body.Bytes(), &body)
		return r.Code, body
	}

	anon := interactionBrowser(t, srv)
	raw := start(anon, url.Values{"acr_values": {oauth.MFAACR}})
	if code, body := details(anon, raw); code != http.StatusOK || body["appName"] != "notes" || body["username"] != "" || body["requiresMFA"] != true || body["requiresPasskey"] != false {
		t.Fatalf("anonymous details: %d %v", code, body)
	}
	if code, body := details(interactionBrowser(t, srv), raw); code != http.StatusBadRequest || body["error"] != "invalid_interaction" {
		t.Fatalf("another browser read the interaction: %d %v", code, body)
	}
	if code, _ := details(anon, strings.Repeat("0", 64)); code != http.StatusBadRequest {
		t.Fatalf("unknown interaction: %d", code)
	}

	// A signed-in browser asked to log in again sees which account it is re-proving.
	{
		q := covAuthorizeQuery("notes")
		q.Set("prompt", "login")
		req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
		req.AddCookie(&http.Cookie{Name: "kyidentity_session", Value: cookie})
		rr := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rr, req)
		loc, _ := url.Parse(rr.Header().Get("Location"))
		var browserCookie *http.Cookie
		for _, c := range rr.Result().Cookies() {
			if c.Name == authorizationBrowserCookie {
				browserCookie = c
			}
		}
		if browserCookie == nil || loc.Query().Get("interaction") == "" {
			t.Fatalf("prompt=login: %d %q", rr.Code, rr.Header().Get("Location"))
		}
		get := httptest.NewRequest("GET", "/api/auth/authorization/"+loc.Query().Get("interaction"), nil)
		get.AddCookie(browserCookie)
		got := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(got, get)
		var body map[string]any
		_ = json.Unmarshal(got.Body.Bytes(), &body)
		if got.Code != http.StatusOK || body["username"] != u.Username {
			t.Fatalf("signed-in details: %d %v", got.Code, body)
		}
		// Disabling the account voids the pending interaction for it.
		if _, err := db.EditUser(u.ID, nil, func(row *store.User) (bool, error) { row.Status = "disabled"; return false, nil }); err != nil {
			t.Fatal(err)
		}
		again := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(again, get)
		if again.Code != http.StatusBadRequest || !strings.Contains(again.Body.String(), "invalid_interaction") {
			t.Fatalf("disabled account's interaction still described: %d %s", again.Code, again.Body.String())
		}
	}

	// Disabling the client voids interactions already in flight for it.
	c, _ := db.GetOAuthClientByID("notes")
	c.Enabled = false
	if err := db.UpdateOAuthClient(c); err != nil {
		t.Fatal(err)
	}
	if code, body := details(anon, raw); code != http.StatusBadRequest || body["error"] != "invalid_interaction" {
		t.Fatalf("disabled client's interaction described: %d %v", code, body)
	}
}

// Cancelling needs a well-formed interaction handle; garbage is a 400, not a 500 or a no-op 200.
func TestCancelInteractionValidatesHandle(t *testing.T) {
	srv, _, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	browser := interactionBrowser(t, srv)
	for _, body := range []any{"not an object", map[string]string{"interaction": "short"}} {
		if r := browser("POST", "/api/auth/authorization/cancel", body); r.Code != http.StatusBadRequest || decodeAPIError(t, r)["error"] != "invalid_request" {
			t.Fatalf("cancel %v: %d %s", body, r.Code, r.Body.String())
		}
	}
}

// The token endpoint names no reason for a failed exchange (that would be an oracle for
// which half of a guess was right), records the reason in the audit log instead, and never
// lets the error be cached.
func TestTokenEndpointRefusals(t *testing.T) {
	srv, db, _, _, oe, cleanup := setupTestServer(t)
	defer cleanup()
	newClient(t, db, "notes", []string{covRedirect}, []string{"openid"})

	for _, form := range []url.Values{
		{"grant_type": {"password"}, "code": {"x"}, "client_id": {"notes"}},
		{"grant_type": {"authorization_code"}, "client_id": {"notes"}},
		{"grant_type": {"authorization_code"}, "code": {"x"}},
	} {
		if rr := covOAuthPost(t, srv, "/oauth/token", form, "", ""); rr.Code != http.StatusBadRequest || decodeAPIError(t, rr)["error"] != "invalid_request" {
			t.Fatalf("%v: %d %s", form, rr.Code, rr.Body.String())
		}
	}

	u := newUser(t, db, "user")
	cookie := newSession(t, db, u, time.Now().UTC().Add(time.Hour))
	code, err := oe.CreateAuthorizationCode("notes", sessionIDFor(t, db, cookie), covRedirect, "openid", covChallenge, "S256")
	if err != nil {
		t.Fatal(err)
	}
	before := covAuditOutcomes(t, db, "oauth.token_exchange")
	exchange := func(verifier, redirect, user string) *httptest.ResponseRecorder {
		form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}, "code_verifier": {verifier}}
		if user == "" {
			form.Set("client_id", "notes")
		}
		return covOAuthPost(t, srv, "/oauth/token", form, user, "")
	}
	for name, rr := range map[string]*httptest.ResponseRecorder{
		"wrong verifier":               exchange(strings.Repeat("x", 43), covRedirect, ""),
		"wrong redirect":               exchange(covVerifier, "https://notes.example.com/other", ""),
		"basic auth as another client": exchange(covVerifier, covRedirect, "ghost"),
	} {
		body := decodeAPIError(t, rr)
		if rr.Code != http.StatusBadRequest || body["error"] != "invalid_grant" || strings.Contains(body["error_description"], "PKCE verifier mismatch") {
			t.Fatalf("%s: %d %v", name, rr.Code, body)
		}
		if rr.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: token error is cacheable", name)
		}
	}
	if got := covAuditOutcomes(t, db, "oauth.token_exchange")["failure"] - before["failure"]; got < 1 {
		t.Fatalf("failed exchanges left no audit trail")
	}

	// A jwt-bearer grant without its assertion is malformed, not an authentication failure.
	if rr := covOAuthPost(t, srv, "/oauth/token", url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "client_id": {"notes"}}, "", ""); rr.Code != http.StatusBadRequest || decodeAPIError(t, rr)["error"] != "invalid_request" || rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("assertion-less jwt-bearer: %d %s", rr.Code, rr.Body.String())
	}
}

// The OAuth handlers refuse non-POST methods themselves, independent of the router.
func TestOAuthPostOnlyHandlersRefuseGet(t *testing.T) {
	srv, db, _, _, oe, cleanup := setupTestServer(t)
	defer cleanup()
	h := NewOAuthHandler(db, oe, srv.audit, srv.middleware)
	for name, fn := range map[string]http.HandlerFunc{"token": h.Token, "revoke": h.Revoke} {
		rr := httptest.NewRecorder()
		fn(rr, httptest.NewRequest("GET", "/oauth/"+name+"?token=x&client_id=y", nil))
		if rr.Code != http.StatusMethodNotAllowed || decodeAPIError(t, rr)["error"] != "invalid_request" {
			t.Fatalf("%s via GET: %d %s", name, rr.Code, rr.Body.String())
		}
	}
}

// Userinfo requires a Bearer token; another scheme or none at all is invalid_token.
func TestUserinfoRequiresBearer(t *testing.T) {
	srv, _, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	for _, auth := range []string{"", "Basic dXNlcjpwYXNz", "bearer lowercase-scheme"} {
		req := httptest.NewRequest("GET", "/oauth/userinfo", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rr := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized || decodeAPIError(t, rr)["error"] != "invalid_token" {
			t.Fatalf("Authorization %q: %d %s", auth, rr.Code, rr.Body.String())
		}
	}
}

// Revocation authenticates the client the token was issued to: a confidential client's
// wrong secret is invalid_client (and audited) and leaves the token working; the right
// secret, in the form or as HTTP Basic, revokes it so userinfo stops accepting it.
func TestRevokeAuthenticatesClientAndKillsToken(t *testing.T) {
	srv, db, _, _, oe, cleanup := setupTestServer(t)
	defer cleanup()
	secret := "s3cret-for-revocation-test"
	uris, _ := json.Marshal([]string{covRedirect})
	if err := db.CreateOAuthClient(&store.OAuthClient{
		ID: "vault", ClientName: "Vault", ClientType: "confidential", ClientSecretHash: crypto.HashSHA256(secret),
		RedirectURIsJSON: string(uris), AllowedScopesJSON: `["openid"]`, Enabled: true,
	}, nil); err != nil {
		t.Fatal(err)
	}
	allowTestAppAccess(t, db, "vault")
	cookie := newSession(t, db, newUser(t, db, "user"), time.Now().UTC().Add(time.Hour))
	mint := func() string {
		t.Helper()
		code, err := oe.CreateAuthorizationCode("vault", sessionIDFor(t, db, cookie), covRedirect, "openid", covChallenge, "S256")
		if err != nil {
			t.Fatal(err)
		}
		resp, err := oe.ExchangeAuthorizationCode(code, "vault", secret, covRedirect, covVerifier)
		if err != nil {
			t.Fatal(err)
		}
		return resp.AccessToken
	}
	userinfo := func(token string) int {
		req := httptest.NewRequest("GET", "/oauth/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rr, req)
		return rr.Code
	}

	if rr := covOAuthPost(t, srv, "/oauth/revoke", url.Values{"client_id": {"vault"}}, "", ""); rr.Code != http.StatusBadRequest || decodeAPIError(t, rr)["error"] != "invalid_request" {
		t.Fatalf("no token: %d %s", rr.Code, rr.Body.String())
	}
	if rr := covOAuthPost(t, srv, "/oauth/revoke", url.Values{"token": {"x"}}, "", ""); rr.Code != http.StatusBadRequest {
		t.Fatalf("no client: %d %s", rr.Code, rr.Body.String())
	}

	first := mint()
	before := covAuditOutcomes(t, db, "oauth.revoke")
	for name, rr := range map[string]*httptest.ResponseRecorder{
		"wrong form secret":  covOAuthPost(t, srv, "/oauth/revoke", url.Values{"token": {first}, "client_id": {"vault"}, "client_secret": {"guess"}}, "", ""),
		"wrong basic secret": covOAuthPost(t, srv, "/oauth/revoke", url.Values{"token": {first}}, "vault", "guess"),
		"unknown client":     covOAuthPost(t, srv, "/oauth/revoke", url.Values{"token": {first}, "client_id": {"ghost"}}, "", ""),
	} {
		if rr.Code != http.StatusUnauthorized || decodeAPIError(t, rr)["error"] != "invalid_client" {
			t.Fatalf("%s: %d %s", name, rr.Code, rr.Body.String())
		}
	}
	if got := covAuditOutcomes(t, db, "oauth.revoke")["failure"] - before["failure"]; got != 3 {
		t.Fatalf("failed revocations audited %d times, want 3", got)
	}
	if code := userinfo(first); code != http.StatusOK {
		t.Fatalf("a refused revocation still killed the token: userinfo %d", code)
	}

	rr := covOAuthPost(t, srv, "/oauth/revoke", url.Values{"token": {first}}, "vault", secret)
	if rr.Code != http.StatusOK || rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("basic-auth revoke: %d %s", rr.Code, rr.Body.String())
	}
	if code := userinfo(first); code != http.StatusUnauthorized {
		t.Fatalf("revoked token still accepted by userinfo: %d", code)
	}
	second := mint()
	if rr := covOAuthPost(t, srv, "/oauth/revoke", url.Values{"token": {second}, "client_id": {"vault"}, "client_secret": {secret}}, "", ""); rr.Code != http.StatusOK {
		t.Fatalf("form revoke: %d", rr.Code)
	}
	if code := userinfo(second); code != http.StatusUnauthorized {
		t.Fatalf("form-revoked token still accepted: %d", code)
	}
	// RFC 7009: an unknown token is still a 200, so the endpoint is no validity oracle.
	if rr := covOAuthPost(t, srv, "/oauth/revoke", url.Values{"token": {"not-a-token"}}, "vault", secret); rr.Code != http.StatusOK {
		t.Fatalf("unknown token: %d", rr.Code)
	}
	if got := covAuditOutcomes(t, db, "oauth.revoke")["success"] - before["success"]; got != 3 {
		t.Fatalf("successful revocations audited %d times, want 3", got)
	}
}
