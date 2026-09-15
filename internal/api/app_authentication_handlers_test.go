package api

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kyidentity-server/internal/store"
)

func setTestAuthenticationPolicy(t *testing.T, db *store.Store, client string, p store.AppAuthenticationPolicy) {
	t.Helper()
	apps, _, err := db.ListAppRecords(client, 25, 0)
	if err != nil || len(apps) != 1 {
		t.Fatal("app lookup", err)
	}
	if err := db.SetAppAuthenticationPolicy(apps[0].ID, p, apps[0].Revision, nil); err != nil {
		t.Fatal(err)
	}
}
func appAuthQuery(client string) url.Values {
	return url.Values{"client_id": {client}, "redirect_uri": {"https://app.example/cb"}, "response_type": {"code"}, "scope": {"openid"}, "state": {"original"}, "code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"}}
}

func TestAdminAppAuthenticationPolicy(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin, user := newUser(t, db, "admin"), newUser(t, db, "user")
	adminCookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	userCookie := newSession(t, db, user, time.Now().UTC().Add(time.Hour))
	newClient(t, db, "app", []string{"https://app.example/cb"}, []string{"openid"})
	apps, _, _ := db.ListAppRecords("app", 25, 0)
	app := apps[0]
	path := "/api/admin/app-registry/" + app.ID + "/authentication-policy"
	body, _ := json.Marshal(map[string]any{"revision": app.Revision, "policy": store.AppAuthenticationPolicy{Mode: "fresh", Factor: "passkey", FactorMaxAge: 300}})
	if r := adminRequestNoStepUp(t, srv, "PUT", path, userCookie, string(body)); r.Code != 403 {
		t.Fatal("non-admin", r.Code)
	}
	if r := adminRequestNoStepUp(t, srv, "PUT", path, adminCookie, string(body)); r.Code != 403 {
		t.Fatal("missing step-up", r.Code)
	}
	wrong := mintStepUp(t, srv, adminCookie, "PUT /api/admin/app-registry/other/authentication-policy")
	if r := adminRequestWithStepUp(t, srv, "PUT", path, adminCookie, string(body), wrong); r.Code != 403 {
		t.Fatal("wrong-operation grant", r.Code)
	}
	for _, raw := range []string{
		`{"revision":2,"policy":null}`,
		`{"revision":2,"policy":{"mode":"fresh","factor":"password","factorMaxAge":1}}`,
		`{"revision":2,"policy":{"mode":"max_age","primaryMaxAge":0,"factor":"mfa"}}`,
		`{"revision":2,"policy":{"mode":"reuse","factor":"mfa","factorMaxAge":-1}}`,
		`{"revision":2,"policy":{"mode":"reuse","factor":"mfa","factorMaxAge":1.5}}`,
		`{"revision":2,"policy":{"mode":"reuse","factor":"mfa","factorMaxAge":2147483648}}`,
		`{"revision":2,"policy":{"mode":"reuse","factor":"mfa","bypass":true}}`,
		string(body) + ` {}`,
	} {
		if r := adminRequest(t, srv, "PUT", path, adminCookie, raw); r.Code != 400 {
			t.Fatalf("invalid policy %s: %d %s", raw, r.Code, r.Body.String())
		}
	}
	if r := adminRequest(t, srv, "PUT", path, adminCookie, string(body)); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	if r := adminRequest(t, srv, "PUT", path, adminCookie, string(body)); r.Code != 409 {
		t.Fatal("stale policy", r.Code)
	}
}

func TestAppAuthenticationFreshAndSilent(t *testing.T) {
	srv, db, _, _, engine, cleanup := setupTestServer(t)
	defer cleanup()
	u := newUser(t, db, "user")
	for _, client := range []string{"notes", "passwords"} {
		newClient(t, db, client, []string{"https://app.example/cb"}, []string{"openid"})
	}
	setTestAuthenticationPolicy(t, db, "passwords", store.AppAuthenticationPolicy{Mode: "fresh", Factor: "password"})
	browser := interactionBrowser(t, srv)
	login := func(raw string) {
		t.Helper()
		if r := browser("POST", "/api/auth/login", map[string]string{"username": u.Username, "password": "correct-horse-battery", "interaction": raw}); r.Code != 200 {
			t.Fatal(r.Body.String())
		}
	}
	login("")
	authorize := func(q url.Values) *url.URL {
		t.Helper()
		r := browser("GET", "/oauth/authorize?"+q.Encode(), nil)
		location, _ := url.Parse(r.Header().Get("Location"))
		if r.Code != 302 {
			t.Fatalf("authorize %d %s", r.Code, r.Body.String())
		}
		return location
	}
	if location := authorize(appAuthQuery("notes")); location.Query().Get("code") == "" {
		t.Fatal("SSO failed", location)
	}
	q := appAuthQuery("passwords")
	q.Set("prompt", "none")
	if location := authorize(q); location.Query().Get("error") != "login_required" || location.Query().Get("state") != "original" {
		t.Fatal("silent policy weakened", location)
	}
	q.Del("prompt")
	q.Set("acr_values", "urn:kyidentity:acr:password")
	q.Set("max_age", "2147483647")
	for range 2 {
		raw := authorize(q).Query().Get("interaction")
		if raw == "" {
			t.Fatal("fresh policy reused SSO")
		}
		login(raw)
		r := browser("GET", "/oauth/authorize?interaction="+raw, nil)
		location, _ := url.Parse(r.Header().Get("Location"))
		code := location.Query().Get("code")
		if code == "" {
			t.Fatalf("fresh proof did not resume: %d %s", r.Code, location)
		}
		if _, err := engine.ExchangeAuthorizationCode(code, "passwords", "", "https://app.example/cb", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); err != nil {
			t.Fatal(err)
		}
	}
	// A policy change after proof invalidates the completed interaction too.
	raw := authorize(q).Query().Get("interaction")
	login(raw)
	setTestAuthenticationPolicy(t, db, "passwords", store.AppAuthenticationPolicy{Mode: "reuse", Factor: "password"})
	if r := browser("GET", "/oauth/authorize?interaction="+raw, nil); r.Code != 400 {
		t.Fatal("changed policy kept completed interaction")
	}
}

func TestAppAuthenticationPasskeyLogin(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	u := newUser(t, db, "user")
	newClient(t, db, "app", []string{"https://app.example/cb"}, []string{"openid"})
	setTestAuthenticationPolicy(t, db, "app", store.AppAuthenticationPolicy{Mode: "reuse", Factor: "passkey", FactorMaxAge: 120})
	browser := interactionBrowser(t, srv)
	r := browser("GET", "/oauth/authorize?"+appAuthQuery("app").Encode(), nil)
	location, _ := url.Parse(r.Header().Get("Location"))
	raw := location.Query().Get("interaction")
	if raw == "" {
		t.Fatal("missing interaction")
	}
	if r := browser("GET", "/api/auth/authorization/"+raw, nil); r.Code != 200 || !strings.Contains(r.Body.String(), `"requiresPasskey":true`) {
		t.Fatal("missing passkey details", r.Body.String())
	}
	login := func() LoginResponse {
		t.Helper()
		r := browser("POST", "/api/auth/login", map[string]string{"username": u.Username, "password": "correct-horse-battery", "interaction": raw})
		var response LoginResponse
		if r.Code != 200 {
			t.Fatal(r.Body.String())
		}
		if err := json.Unmarshal(r.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		return response
	}
	if r := browser("POST", "/api/auth/login", map[string]string{"username": u.Username, "password": "correct-horse-battery", "interaction": raw}); r.Code != 403 || !strings.Contains(r.Body.String(), "factor_enrollment_required") {
		t.Fatal("missing enrollment accepted", r.Code, r.Body.String())
	}
	key := newTestAuthenticator(t, "passkey")
	enrolPasskey(t, db, u.ID, key)
	resp := login()
	if len(resp.MFAMethods) != 1 || resp.MFAMethods[0] != "webauthn" {
		t.Fatal("wrong offered factors", resp.MFAMethods)
	}
	fields := assertionFields(t, srv, resp.MFAToken, key, true)
	if r := browser("POST", "/api/auth/mfa/webauthn/verify", fields); r.Code != 200 {
		t.Fatal("passkey failed", r.Body.String())
	}
	r = browser("GET", "/oauth/authorize?interaction="+raw, nil)
	location, _ = url.Parse(r.Header().Get("Location"))
	if location.Query().Get("code") == "" {
		t.Fatal("verified passkey rejected", r.Code, r.Body.String(), location)
	}
}

func TestAppAuthenticationRejectsWeakerMFACompletion(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	u := newUser(t, db, "user")
	newClient(t, db, "app", []string{"https://app.example/cb"}, []string{"openid"})
	key := newTestAuthenticator(t, "key")
	enrolPasskey(t, db, u.ID, key)
	secret, _, err := srv.mfaEngine.GenerateTOTPSecret(u.Username, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.mfaEngine.SaveUserTOTP(u.ID, secret, nil); err != nil {
		t.Fatal(err)
	}
	setTestAuthenticationPolicy(t, db, "app", store.AppAuthenticationPolicy{Mode: "reuse", Factor: "passkey"})
	browser := interactionBrowser(t, srv)
	r := browser("GET", "/oauth/authorize?"+appAuthQuery("app").Encode(), nil)
	location, _ := url.Parse(r.Header().Get("Location"))
	raw := location.Query().Get("interaction")
	r = browser("POST", "/api/auth/login", map[string]string{"username": u.Username, "password": "correct-horse-battery", "interaction": raw})
	var response LoginResponse
	if err := json.Unmarshal(r.Body.Bytes(), &response); err != nil || !response.MFARequired {
		t.Fatal(r.Body.String())
	}
	// Calling a hidden weaker endpoint may establish an ordinary login, never app access.
	r = browser("POST", "/api/auth/mfa/totp/verify", map[string]string{"mfaToken": response.MFAToken, "code": testTOTPCode(t, secret)})
	if r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	r = browser("GET", "/oauth/authorize?interaction="+raw, nil)
	location, _ = url.Parse(r.Header().Get("Location"))
	if location.Query().Get("error") != "login_required" || location.Query().Get("code") != "" {
		t.Fatal("weaker factor satisfied policy", location)
	}
}
