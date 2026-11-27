package api

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Busnes-app/ky-primitives/xwing"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

func testHandoffPoint(t *testing.T) string {
	t.Helper()
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
}

func testHandoffQuery(clientID, redirectURI, pk string) (url.Values, string) {
	verifier := strings.Repeat("k", 43)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"state":                 {"handoff-state"},
		"nonce":                 {"handoff-nonce"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	if pk != "" {
		q.Set("keyring_pk", pk)
	}
	return q, verifier
}

func TestKeyringHandoffFullFlow(t *testing.T) {
	t.Run("legacy-p256", func(t *testing.T) { testKeyringHandoffFullFlow(t, testHandoffPoint(t)) })
	t.Run("xwing", func(t *testing.T) {
		key, err := xwing.Generate()
		if err != nil {
			t.Fatal(err)
		}
		pk := base64.RawURLEncoding.EncodeToString(key.Public().Bytes())
		if len(pk) != 1622 {
			t.Fatal("incorrect X-Wing query size")
		}
		testKeyringHandoffFullFlow(t, pk)
	})
}

func testKeyringHandoffFullFlow(t *testing.T, pk string) {
	srv, db, _, _, engine, cleanup := setupTestServer(t)
	defer cleanup()

	u := newUser(t, db, "user")
	newClient(t, db, "kypost", []string{"https://mail.example/cb"}, []string{"openid"})
	q, verifier := testHandoffQuery("kypost", "https://mail.example/cb", pk)

	if len("https://identity.example.test/oauth/authorize?"+q.Encode()) >= 2048 {
		t.Fatal("authorize URL exceeds fixture budget")
	}
	browser := interactionBrowser(t, srv)

	// 1. Unauthenticated /oauth/authorize with keyring_pk starts a login interaction.
	r := browser("GET", "/oauth/authorize?"+q.Encode(), nil)
	loc, _ := url.Parse(r.Header().Get("Location"))
	raw := loc.Query().Get("interaction")
	if r.Code != http.StatusFound || loc.Path != "/login" || raw == "" {
		t.Fatalf("begin login: %d %s %s", r.Code, r.Header().Get("Location"), r.Body.String())
	}

	// Cannot read handoff before login completes.
	if r := browser("GET", "/api/user/keyring/handoff/"+raw, nil); r.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated handoff read: %d", r.Code)
	}

	// 2. Complete login with the interaction.
	if r := browser("POST", "/api/auth/login", map[string]string{
		"username": u.Username, "password": "correct-horse-battery", "interaction": raw,
	}); r.Code != http.StatusOK {
		t.Fatalf("login: %d %s", r.Code, r.Body.String())
	}

	// 3. Returning to /oauth/authorize?interaction=... routes to /keyring-handoff?interaction=...
	r = browser("GET", "/oauth/authorize?interaction="+raw, nil)
	loc, _ = url.Parse(r.Header().Get("Location"))
	if r.Code != http.StatusFound || loc.Path != "/keyring-handoff" || loc.Query().Get("interaction") != raw {
		t.Fatalf("handoff redirect: %d %s", r.Code, r.Header().Get("Location"))
	}
	if got := r.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("handoff redirect Cache-Control=%q, want no-store", got)
	}

	// 4. Another browser (even signed in as the same user) cannot inspect or complete the handoff.
	other := interactionBrowser(t, srv)
	if r := other("POST", "/api/auth/login", map[string]string{
		"username": u.Username, "password": "correct-horse-battery",
	}); r.Code != http.StatusOK {
		t.Fatalf("other login: %d %s", r.Code, r.Body.String())
	}
	if r := other("GET", "/api/user/keyring/handoff/"+raw, nil); r.Code != http.StatusNotFound {
		t.Fatalf("other browser read handoff: %d", r.Code)
	}
	if r := other("POST", "/api/user/keyring/handoff/"+raw+"/complete", nil); r.Code != http.StatusNotFound {
		t.Fatalf("other browser completed handoff: %d", r.Code)
	}

	// 5. Original browser reads handoff details.
	r = browser("GET", "/api/user/keyring/handoff/"+raw, nil)
	if r.Code != http.StatusOK {
		t.Fatalf("handoff details: %d %s", r.Code, r.Body.String())
	}
	var details struct {
		Issuer         string `json:"issuer"`
		OrgID          string `json:"org_id"`
		UserID         string `json:"user_id"`
		ClientID       string `json:"client_id"`
		AppName        string `json:"app_name"`
		RedirectURI    string `json:"redirect_uri"`
		State          string `json:"state"`
		KeyringPK      string `json:"keyring_pk"`
		Nonce          string `json:"nonce"`
		KeyringVersion string `json:"keyring_version"`
		Wrappers       []any  `json:"wrappers"`
		AppKey         any    `json:"app_key"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &details); err != nil {
		t.Fatal(err)
	}
	if details.UserID != u.ID || details.OrgID == "" || details.ClientID != "kypost" ||
		details.RedirectURI != "https://mail.example/cb" || details.State != "handoff-state" ||
		details.KeyringPK != pk || details.Nonce != "handoff-nonce" || details.Issuer == "" || details.Wrappers == nil || details.AppKey != nil {
		t.Fatalf("unexpected details: %+v", details)
	}

	// 6. Complete handoff atomically mints a fresh authorization code and consumes the interaction.
	r = browser("POST", "/api/user/keyring/handoff/"+raw+"/complete", nil)
	if r.Code != http.StatusOK {
		t.Fatalf("handoff complete: %d %s", r.Code, r.Body.String())
	}
	var done struct {
		RedirectURI string `json:"redirect_uri"`
		Code        string `json:"code"`
		State       string `json:"state"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &done); err != nil {
		t.Fatal(err)
	}
	if done.Code == "" || done.RedirectURI != "https://mail.example/cb" || done.State != "handoff-state" {
		t.Fatalf("unexpected complete payload: %+v", done)
	}

	// 7. Replay of complete or details fails (single-use).
	if r := browser("POST", "/api/user/keyring/handoff/"+raw+"/complete", nil); r.Code != http.StatusNotFound {
		t.Fatalf("replayed complete: %d", r.Code)
	}
	if r := browser("GET", "/api/user/keyring/handoff/"+raw, nil); r.Code != http.StatusNotFound {
		t.Fatalf("details after complete: %d", r.Code)
	}

	// 8. Authorization code exchanges cleanly with PKCE verifier.
	saved, err := db.GetValidAuthorizationCode(crypto.HashSHA256(done.Code))
	if err != nil || saved == nil {
		t.Fatalf("saved code lookup: %v %v", saved, err)
	}
	tokens, err := engine.ExchangeAuthorizationCode(done.Code, "kypost", "", "https://mail.example/cb", verifier)
	if err != nil || tokens.IDToken == "" {
		t.Fatalf("exchange code: %v", err)
	}
}

func TestKeyringHandoffAlreadySignedInAndCancel(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	u := newUser(t, db, "user")
	newClient(t, db, "kynotes", []string{"https://notes.example/cb"}, []string{"openid"})
	browser := interactionBrowser(t, srv)
	if r := browser("POST", "/api/auth/login", map[string]string{
		"username": u.Username, "password": "correct-horse-battery",
	}); r.Code != http.StatusOK {
		t.Fatalf("login: %d %s", r.Code, r.Body.String())
	}

	pk := testHandoffPoint(t)
	q, _ := testHandoffQuery("kynotes", "https://notes.example/cb", pk)
	r := browser("GET", "/oauth/authorize?"+q.Encode(), nil)
	loc, _ := url.Parse(r.Header().Get("Location"))
	raw := loc.Query().Get("interaction")
	if r.Code != http.StatusFound || loc.Path != "/keyring-handoff" || raw == "" {
		t.Fatalf("signed-in handoff redirect: %d %s", r.Code, r.Header().Get("Location"))
	}

	var secureBinding bool
	for _, c := range r.Result().Cookies() {
		if c.Name == authorizationBrowserCookie {
			secureBinding = c.Secure
		}
	}
	if !secureBinding {
		t.Fatal("signed-in handoff did not issue a Secure binding cookie")
	}

	// Cancel deletes the interaction and returns redirect_uri + state.
	r = browser("DELETE", "/api/user/keyring/handoff/"+raw, nil)
	if r.Code != http.StatusOK {
		t.Fatalf("cancel: %d %s", r.Code, r.Body.String())
	}
	var cancelled struct {
		RedirectURI string `json:"redirect_uri"`
		State       string `json:"state"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &cancelled); err != nil {
		t.Fatal(err)
	}
	if cancelled.RedirectURI != "https://notes.example/cb" || cancelled.State != "handoff-state" {
		t.Fatalf("unexpected cancel payload: %+v", cancelled)
	}
	if r := browser("POST", "/api/user/keyring/handoff/"+raw+"/complete", nil); r.Code != http.StatusNotFound {
		t.Fatalf("complete after cancel: %d", r.Code)
	}
}

func TestKeyringHandoffValidationAndAdminBypass(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	admin := newUser(t, db, "admin")
	newClient(t, db, "kycal", []string{"https://cal.example/cb"}, []string{"openid"})
	browser := interactionBrowser(t, srv)
	if r := browser("POST", "/api/auth/login", map[string]string{
		"username": admin.Username, "password": "correct-horse-battery",
	}); r.Code != http.StatusOK {
		t.Fatalf("admin login: %d %s", r.Code, r.Body.String())
	}

	// Invalid keyring_pk returns OIDC invalid_request redirect error.
	badQ, _ := testHandoffQuery("kycal", "https://cal.example/cb", "not-a-p256-point")
	r := browser("GET", "/oauth/authorize?"+badQ.Encode(), nil)
	loc, _ := url.Parse(r.Header().Get("Location"))
	if r.Code != http.StatusFound || loc.Query().Get("error") != "invalid_request" {
		t.Fatalf("invalid keyring_pk: %d %s", r.Code, r.Header().Get("Location"))
	}

	// A present but empty key must fail, rather than silently bypassing handoff.
	emptyQ, _ := testHandoffQuery("kycal", "https://cal.example/cb", "")
	emptyQ.Set("keyring_pk", "")
	r = browser("GET", "/oauth/authorize?"+emptyQ.Encode(), nil)
	loc, _ = url.Parse(r.Header().Get("Location"))
	if r.Code != http.StatusFound || loc.Query().Get("error") != "invalid_request" {
		t.Fatalf("empty keyring_pk: %d %s", r.Code, r.Header().Get("Location"))
	}

	// Duplicate keyring_pk returns OIDC invalid_request redirect error.
	pk := testHandoffPoint(t)
	dupQ, _ := testHandoffQuery("kycal", "https://cal.example/cb", pk)
	dupQ.Add("keyring_pk", pk)
	r = browser("GET", "/oauth/authorize?"+dupQ.Encode(), nil)
	loc, _ = url.Parse(r.Header().Get("Location"))
	if r.Code != http.StatusFound || loc.Query().Get("error") != "invalid_request" {
		t.Fatalf("duplicate keyring_pk: %d %s", r.Code, r.Header().Get("Location"))
	}

	// prompt=none with keyring_pk returns interaction_required.
	silentQ, _ := testHandoffQuery("kycal", "https://cal.example/cb", pk)
	silentQ.Set("prompt", "none")
	r = browser("GET", "/oauth/authorize?"+silentQ.Encode(), nil)
	loc, _ = url.Parse(r.Header().Get("Location"))
	if r.Code != http.StatusFound || loc.Query().Get("error") != "interaction_required" {
		t.Fatalf("prompt=none keyring_pk: %d %s", r.Code, r.Header().Get("Location"))
	}

	// Admin accounts have no keyring: authorize skips /keyring-handoff and issues code directly.
	adminQ, _ := testHandoffQuery("kycal", "https://cal.example/cb", pk)
	r = browser("GET", "/oauth/authorize?"+adminQ.Encode(), nil)
	loc, _ = url.Parse(r.Header().Get("Location"))
	if r.Code != http.StatusFound || loc.Host != "cal.example" || loc.Query().Get("code") == "" {
		t.Fatalf("admin bypass: %d %s", r.Code, r.Header().Get("Location"))
	}
}

func TestKeyringHandoffRequiresCSRFAndEnforcesAccessRevocation(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	u := newUser(t, db, "user")
	newClient(t, db, "kydrive", []string{"https://drive.example/cb"}, []string{"openid"})

	// Start signed-in handoff while capturing raw cookies so we can test missing CSRF.
	loginReq := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"`+u.Username+`","password":"correct-horse-battery"}`))
	csrfAnon := srv.middleware.IssueCSRFToken("")
	loginReq.AddCookie(&http.Cookie{Name: "kyidentity_csrf", Value: csrfAnon})
	loginReq.Header.Set("X-CSRF-Token", csrfAnon)
	loginReq.Header.Set("Content-Type", "application/json")
	lr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(lr, loginReq)
	if lr.Code != http.StatusOK {
		t.Fatalf("login: %d %s", lr.Code, lr.Body.String())
	}
	cookies := map[string]*http.Cookie{}
	for _, c := range lr.Result().Cookies() {
		cookies[c.Name] = c
	}

	pk := testHandoffPoint(t)
	q, _ := testHandoffQuery("kydrive", "https://drive.example/cb", pk)
	authReq := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
	for _, c := range cookies {
		authReq.AddCookie(c)
	}
	ar := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(ar, authReq)
	for _, c := range ar.Result().Cookies() {
		cookies[c.Name] = c
	}
	loc, _ := url.Parse(ar.Header().Get("Location"))
	raw := loc.Query().Get("interaction")
	if ar.Code != http.StatusFound || loc.Path != "/keyring-handoff" || raw == "" {
		t.Fatalf("authorize: %d %s", ar.Code, ar.Header().Get("Location"))
	}

	// Missing X-CSRF-Token on complete must be rejected with 403.
	noCSRF := httptest.NewRequest("POST", "/api/user/keyring/handoff/"+raw+"/complete", nil)
	for _, c := range cookies {
		noCSRF.AddCookie(c)
	}
	nr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(nr, noCSRF)
	if nr.Code != http.StatusForbidden {
		t.Fatalf("complete without CSRF: %d, want 403", nr.Code)
	}

	// Disable client before completion -> fails closed (404 from loadKeyringHandoff).
	client, err := db.GetOAuthClientByID("kydrive")
	if err != nil {
		t.Fatal(err)
	}
	client.Enabled = false
	if err := db.UpdateOAuthClient(client); err != nil {
		t.Fatal(err)
	}
	csrf := srv.middleware.IssueCSRFToken(cookies["kyidentity_session"].Value)
	cookies["kyidentity_csrf"] = &http.Cookie{Name: "kyidentity_csrf", Value: csrf}
	compReq := httptest.NewRequest("POST", "/api/user/keyring/handoff/"+raw+"/complete", nil)
	for _, c := range cookies {
		compReq.AddCookie(c)
	}
	compReq.Header.Set("X-CSRF-Token", csrf)
	cr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(cr, compReq)
	if cr.Code != http.StatusNotFound {
		t.Fatalf("complete after client disabled: %d, want 404", cr.Code)
	}

	// Ensure store.ErrKeyringDenied is still exported cleanly (compile-time sanity).
	_ = store.ErrKeyringDenied
}
