package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/oauth"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

const xcredsRedirect = "http://127.0.0.1/xcreds"

// xcredsAuthorize is the authorize query XCreds' OIDCLite sends: code, PKCE S256, a nonce.
func xcredsAuthorize(clientID, verifier string) url.Values {
	sum := sha256.Sum256([]byte(verifier))
	return url.Values{"client_id": {clientID}, "redirect_uri": {xcredsRedirect}, "response_type": {"code"},
		"scope": {"openid profile email offline_access"}, "state": {uuid.NewString()}, "nonce": {uuid.NewString()},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
}

// xcredsCode takes the code out of the redirect the way XCreds' web view does: split on
// "&", strip "<redirectURI>?" and "code=".
func xcredsCode(t *testing.T, location string) string {
	t.Helper()
	if !strings.HasPrefix(location, xcredsRedirect+"?") {
		t.Fatalf("redirect %q is not to %s", location, xcredsRedirect)
	}
	for _, part := range strings.Split(location, "&") {
		if strings.Contains(part, "code=") {
			return strings.ReplaceAll(strings.ReplaceAll(part, xcredsRedirect+"?", ""), "code=", "")
		}
	}
	t.Fatalf("no code in %q", location)
	return ""
}

func (f *wsFixture) exchange(code, verifier string) (int, map[string]any) {
	f.t.Helper()
	return f.form("/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {xcredsRedirect}, "client_id": {f.clientID}, "code_verifier": {verifier}})
}

// codeLogin signs in through the code flow with an existing browser session.
func (f *wsFixture) codeLogin(cookie string) map[string]any {
	f.t.Helper()
	verifier := uuid.NewString() + uuid.NewString()
	req := httptest.NewRequest("GET", "/oauth/authorize?"+xcredsAuthorize(f.clientID, verifier).Encode(), nil)
	req.AddCookie(&http.Cookie{Name: "kyidentity_session", Value: cookie})
	rr := httptest.NewRecorder()
	f.srv.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		f.t.Fatalf("authorize: %d %s", rr.Code, rr.Body.String())
	}
	status, body := f.exchange(xcredsCode(f.t, rr.Header().Get("Location")), verifier)
	if status != 200 || body["refresh_token"] == nil {
		f.t.Fatalf("exchange: %d %v", status, body)
	}
	return body
}

// xcredsBrowser starts XCreds' authorization in a fresh web view and returns the
// interaction the login page carries.
func xcredsBrowser(t *testing.T, f *wsFixture, verifier string) (func(string, string, any) *httptest.ResponseRecorder, url.Values, string) {
	t.Helper()
	browser := interactionBrowser(t, f.srv)
	q := xcredsAuthorize(f.clientID, verifier)
	r := browser("GET", "/oauth/authorize?"+q.Encode(), nil)
	location, _ := url.Parse(r.Header().Get("Location"))
	raw := location.Query().Get("interaction")
	if r.Code != http.StatusFound || raw == "" {
		t.Fatalf("authorize did not ask for a sign-in: %d %s", r.Code, r.Header().Get("Location"))
	}
	return browser, q, raw
}

// XCreds' exact flow against the server: a 72-character verifier of two UUIDs, the
// login page with a typed password, the loopback redirect, the exchange with client_id
// in the body and no secret, then refresh.
func TestXCredsFlow(t *testing.T) {
	f, done := newWSFixture(t)
	defer done()
	f.macSignIn, f.requirePassword = true, true
	f.settings(true, 300, 604800)
	u, _ := f.assignedUser()

	verifier := uuid.NewString() + uuid.NewString()
	if len(verifier) != 72 {
		t.Fatalf("verifier is %d characters", len(verifier))
	}
	browser, q, raw := xcredsBrowser(t, f, verifier)
	if r := browser("POST", "/api/auth/login", map[string]string{"username": u.Username, "password": "correct-horse-battery", "interaction": raw}); r.Code != 200 {
		t.Fatalf("login: %d %s", r.Code, r.Body.String())
	}
	r := browser("GET", "/oauth/authorize?interaction="+raw, nil)
	location := r.Header().Get("Location")
	if r.Code != http.StatusFound || !strings.Contains(location, "state="+q.Get("state")) {
		t.Fatalf("resume: %d %s", r.Code, location)
	}
	status, tokens := f.exchange(xcredsCode(t, location), verifier)
	rt, _ := tokens["refresh_token"].(string)
	if status != 200 || rt == "" || tokens["access_token"] == nil {
		t.Fatalf("exchange: %d %v", status, tokens)
	}
	var claims map[string]any
	parts := strings.Split(tokens["id_token"].(string), ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if json.Unmarshal(payload, &claims) != nil || claims["nonce"] != q.Get("nonce") || claims["preferred_username"] != u.Username {
		t.Fatalf("id token claims: %v", claims)
	}
	if f.workstationSessions(u.ID) != 1 {
		t.Fatal("no workstation session")
	}
	var expires time.Time
	if err := f.raw.QueryRow(`SELECT expires_at FROM sessions WHERE workstation_client_id=?`, f.clientID).Scan(&expires); err != nil || time.Until(expires) < 6*24*time.Hour {
		t.Fatalf("session does not last the offline window: %v %v", expires, err)
	}
	status, rotated := f.refresh(rt)
	next, _ := rotated["refresh_token"].(string)
	if status != 200 || next == "" || next == rt {
		t.Fatalf("refresh: %d %v", status, rotated)
	}
	if status, body := f.refresh(rt); status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("refresh replay: %d %v", status, body)
	}
	if status, _ := f.refresh(next); status != 400 {
		t.Fatal("family survived a replay")
	}

	// The same web view, still signed in, must type the password again.
	r = browser("GET", "/oauth/authorize?"+xcredsAuthorize(f.clientID, verifier).Encode(), nil)
	if loc, _ := url.Parse(r.Header().Get("Location")); r.Code != http.StatusFound || loc.Query().Get("interaction") == "" {
		t.Fatalf("an existing session satisfied require-password: %d %s", r.Code, r.Header().Get("Location"))
	}
}

// MFA after the password still satisfies require-password.
func TestRequirePasswordAllowsMFAAfterPassword(t *testing.T) {
	f, done := newWSFixture(t)
	defer done()
	f.macSignIn, f.requirePassword = true, true
	f.settings(true, 300, 604800)
	u, _ := f.assignedUser()
	secret, _, err := f.srv.mfaEngine.GenerateTOTPSecret(u.Username, "KyIdentity")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.srv.mfaEngine.SaveUserTOTP(u.ID, secret, nil); err != nil {
		t.Fatal(err)
	}
	verifier := uuid.NewString() + uuid.NewString()
	browser, _, raw := xcredsBrowser(t, f, verifier)
	r := browser("POST", "/api/auth/login", map[string]string{"username": u.Username, "password": "correct-horse-battery", "interaction": raw})
	var begun LoginResponse
	if err := json.Unmarshal(r.Body.Bytes(), &begun); err != nil || !begun.MFARequired {
		t.Fatalf("MFA begin: %s", r.Body.String())
	}
	if r := browser("POST", "/api/auth/mfa/totp/verify", map[string]string{"mfaToken": begun.MFAToken, "code": testTOTPCode(t, secret)}); r.Code != 200 {
		t.Fatalf("MFA finish: %d %s", r.Code, r.Body.String())
	}
	r = browser("GET", "/oauth/authorize?interaction="+raw, nil)
	if status, body := f.exchange(xcredsCode(t, r.Header().Get("Location")), verifier); status != 200 || body["refresh_token"] == nil {
		t.Fatalf("exchange: %d %v", status, body)
	}
}

// A sign-in that completes the interaction without the password step (a passkey-only
// or push-only login) gets no code for a require-password app; the same login with the
// password step does. Device approval is refused outright.
func TestRequirePasswordRefusesPasswordlessSignIn(t *testing.T) {
	f, done := newWSFixture(t)
	defer done()
	f.macSignIn, f.requirePassword = true, true
	f.settings(true, 300, 604800)
	u, cookie := f.assignedUser()
	now := time.Now().UTC()
	signIn := func(method string, password bool) error {
		t.Helper()
		hash := crypto.HashSHA256(uuid.NewString())
		if err := f.db.CreateAuthorizationInteraction(&store.AuthorizationInteraction{Hash: hash, BrowserHash: "b", Request: "x", ClientID: f.clientID, CreatedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
		if password {
			if err := f.db.RecordInteractionPassword(hash, "b", u.ID, now); err != nil {
				t.Fatal(err)
			}
		}
		raw, _ := crypto.GenerateRandomHex(32)
		sess := &store.Session{ID: uuid.NewString(), UserID: u.ID, SessionTokenHash: crypto.HashSHA256(raw), ExpiresAt: now.Add(time.Hour),
			AuthenticationEvidence: store.AuthenticationEvidence{PrimaryAuthenticatedAt: &now, FactorAuthenticatedAt: &now, FactorMethod: method}}
		if err := f.db.CreateSessionForInteraction(sess, hash, "b"); err != nil {
			t.Fatal(err)
		}
		_, err := f.srv.oauthEngine.CreateAuthorizationCodeForInteraction(f.clientID, sess.ID, xcredsRedirect, "openid", "challenge", "S256", "", oauth.AuthenticationRequest{}, hash)
		return err
	}
	for _, method := range []string{"webauthn", "push"} {
		if err := signIn(method, false); err != store.ErrAppAuthentication {
			t.Fatalf("%s-only sign-in: %v", method, err)
		}
		if err := signIn(method, true); err != nil {
			t.Fatalf("password then %s: %v", method, err)
		}
	}
	// No interaction at all: an existing session.
	sess, _ := f.db.GetSessionByTokenHash(crypto.HashSHA256(cookie), time.Hour)
	if _, err := f.srv.oauthEngine.CreateAuthorizationCodeForInteraction(f.clientID, sess.ID, xcredsRedirect, "openid", "challenge", "S256", "", oauth.AuthenticationRequest{}, ""); err != store.ErrAppAuthentication {
		t.Fatalf("existing session: %v", err)
	}
	_, userCode := f.start()
	if rr := f.decide(cookie, userCode, true); rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "sign_in_again") {
		t.Fatalf("device approval under require-password: %d %s", rr.Code, rr.Body.String())
	}
}

// The password step binds an interaction to the account only for a require-password app,
// and never past the per-account cap a completing session enforces.
func TestInteractionPasswordScopeAndCap(t *testing.T) {
	f, done := newWSFixture(t)
	defer done()
	f.macSignIn = true
	f.settings(true, 300, 604800)
	u, _ := f.assignedUser()
	now := time.Now().UTC()
	interaction := func(browser, owner string) string {
		t.Helper()
		hash := crypto.HashSHA256(uuid.NewString())
		if err := f.db.CreateAuthorizationInteraction(&store.AuthorizationInteraction{Hash: hash, BrowserHash: browser, UserID: owner, Request: "x", ClientID: f.clientID, CreatedAt: now, ExpiresAt: now.Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
		return hash
	}
	bound := func(hash, browser string) bool {
		t.Helper()
		if err := f.db.RecordInteractionPassword(hash, browser, u.ID, now); err != nil {
			t.Fatal(err)
		}
		i, err := f.db.GetAuthorizationInteraction(hash, browser)
		if err != nil {
			t.Fatal(err)
		}
		return i.UserID == u.ID
	}
	if bound(interaction("off", ""), "off") {
		t.Fatal("bound to the account although the app does not require a password")
	}
	f.requirePassword = true
	f.settings(true, 300, 604800)
	if !bound(interaction("on", ""), "on") {
		t.Fatal("not bound for a require-password app")
	}
	for i := 0; i < 9; i++ {
		interaction(fmt.Sprintf("owned-%d", i), u.ID)
	}
	if bound(interaction("over", ""), "over") {
		t.Fatal("bound past the per-account cap")
	}
}

// Refresh stays a workstation-only exception for public clients, on the code path too.
func TestPublicClientRefreshStillRefused(t *testing.T) {
	f, done := newWSFixture(t)
	defer done()
	f.macSignIn = true
	f.settings(true, 300, 604800)
	u, cookie := f.assignedUser()
	workstation := f.codeLogin(cookie)

	newClient(t, f.db, "public-app", []string{xcredsRedirect}, []string{"openid"})
	if err := f.db.DefaultOrg().SetAppAssignment(appIDFor(t, f.db, "public-app"), "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	verifier := uuid.NewString() + uuid.NewString()
	req := httptest.NewRequest("GET", "/oauth/authorize?"+xcredsAuthorize("public-app", verifier).Encode(), nil)
	req.AddCookie(&http.Cookie{Name: "kyidentity_session", Value: cookie})
	rr := httptest.NewRecorder()
	f.srv.httpServer.Handler.ServeHTTP(rr, req)
	status, body := f.form("/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {xcredsCode(t, rr.Header().Get("Location"))}, "redirect_uri": {xcredsRedirect}, "client_id": {"public-app"}, "code_verifier": {verifier}})
	if status != 200 || body["refresh_token"] != nil {
		t.Fatalf("public client exchange: %d %v", status, body)
	}
	status, body = f.form("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {workstation["refresh_token"].(string)}, "client_id": {"public-app"}})
	if status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("public client refresh: %d %v", status, body)
	}
}

func appIDFor(t *testing.T, db *store.Store, clientID string) string {
	t.Helper()
	rows, _, err := db.ListAppRecords(clientID, 10, 0)
	if err != nil || len(rows) != 1 {
		t.Fatalf("app for %s: %v", clientID, err)
	}
	return rows[0].ID
}

// The switches persist, Mac sign-in owns the redirect list, and both are required.
func TestWorkstationMacSettings(t *testing.T) {
	f, done := newWSFixture(t)
	defer done()
	app, _ := f.db.GetWorkstationApp(f.clientID)
	if app.MacSignIn || app.RequirePassword {
		t.Fatalf("new app defaults: %+v", app)
	}
	// Without Mac sign-in the loopback redirect is not registered.
	verifier := uuid.NewString() + uuid.NewString()
	rr := httptest.NewRecorder()
	f.srv.httpServer.Handler.ServeHTTP(rr, httptest.NewRequest("GET", "/oauth/authorize?"+xcredsAuthorize(f.clientID, verifier).Encode(), nil))
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid_redirect_uri") {
		t.Fatalf("authorize without Mac sign-in: %d %s", rr.Code, rr.Body.String())
	}
	f.macSignIn, f.requirePassword = true, true
	f.settings(true, 300, 604800)
	client, _ := f.db.GetOAuthClientByID(f.clientID)
	app, _ = f.db.GetWorkstationApp(f.clientID)
	if client.RedirectURIsJSON != `["http://127.0.0.1/xcreds"]` || !app.MacSignIn || !app.RequirePassword {
		t.Fatalf("on: %s %+v", client.RedirectURIsJSON, app)
	}
	f.macSignIn = false
	f.settings(true, 300, 604800)
	client, _ = f.db.GetOAuthClientByID(f.clientID)
	if client.RedirectURIsJSON != `[]` {
		t.Fatalf("off: %s", client.RedirectURIsJSON)
	}
	if rr := adminRequest(t, f.srv, "PUT", "/api/admin/workstation-apps/"+f.clientID, f.admin, `{"deviceGrantEnabled":true,"deviceCodeTtl":300,"offlineWindow":0}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("missing switches accepted: %d", rr.Code)
	}
	if f.audits("admin.workstation_app_updated") < 3 {
		t.Fatal("settings changes not audited")
	}
}

// Turning require-password on withdraws everything authorized under the old rule: an
// unredeemed code, an approved device code and open workstation sessions.
func TestRequirePasswordInvalidatesEarlierGrants(t *testing.T) {
	f, done := newWSFixture(t)
	defer done()
	f.macSignIn = true
	f.settings(true, 300, 604800)
	u, cookie := f.assignedUser()
	open := f.codeLogin(cookie)

	verifier := uuid.NewString() + uuid.NewString()
	req := httptest.NewRequest("GET", "/oauth/authorize?"+xcredsAuthorize(f.clientID, verifier).Encode(), nil)
	req.AddCookie(&http.Cookie{Name: "kyidentity_session", Value: cookie})
	rr := httptest.NewRecorder()
	f.srv.httpServer.Handler.ServeHTTP(rr, req)
	code := xcredsCode(t, rr.Header().Get("Location"))
	device, userCode := f.start()
	if rr := f.decide(cookie, userCode, true); rr.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rr.Code, rr.Body.String())
	}

	f.requirePassword = true
	f.settings(true, 300, 604800)

	if status, body := f.exchange(code, verifier); status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("code from before the rule: %d %v", status, body)
	}
	if status, body := f.poll(f.clientID, device); status == 200 {
		t.Fatalf("approval from before the rule: %d %v", status, body)
	}
	if status, body := f.refresh(open["refresh_token"].(string)); status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("session from before the rule: %d %v", status, body)
	}
	if f.workstationSessions(u.ID) != 0 {
		t.Fatal("a workstation session survived the rule change")
	}
}

// The race the store closes: an authorization whose engine checks ran before
// require-password was turned on reaches the code insert afterwards. The insert itself
// refuses it, so no code, session or refresh family exists.
func TestRequirePasswordCheckedAtCodeInsert(t *testing.T) {
	f, done := newWSFixture(t)
	defer done()
	f.macSignIn = true
	f.settings(true, 300, 604800)
	u, cookie := f.assignedUser()
	sess, _ := f.db.GetSessionByTokenHash(crypto.HashSHA256(cookie), time.Hour)
	f.requirePassword = true
	f.settings(true, 300, 604800)
	code := &store.AuthorizationCode{ID: uuid.NewString(), CodeHash: crypto.HashSHA256(uuid.NewString()), ClientID: f.clientID, UserID: u.ID,
		RedirectURI: xcredsRedirect, Scope: "openid", CodeChallenge: "challenge", CodeChallengeMethod: "S256", SessionID: sess.ID,
		AuthenticationEvidence: sess.AuthenticationEvidence, ExpiresAt: time.Now().UTC().Add(time.Minute)}
	if err := f.db.CreateAuthorizationCode(code); err != store.ErrAppAuthentication {
		t.Fatalf("code insert after the rule: %v", err)
	}
	var codes, families int
	if err := f.raw.QueryRow(`SELECT (SELECT COUNT(*) FROM authorization_codes WHERE client_id=?), (SELECT COUNT(*) FROM refresh_families)`, f.clientID).Scan(&codes, &families); err != nil {
		t.Fatal(err)
	}
	if codes != 0 || families != 0 || f.workstationSessions(u.ID) != 0 {
		t.Fatalf("left %d codes, %d families, %d sessions", codes, families, f.workstationSessions(u.ID))
	}
}
