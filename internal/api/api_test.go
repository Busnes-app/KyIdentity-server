package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/audit"
	"github.com/Busnes-app/kyidentity-server/internal/auth"
	"github.com/Busnes-app/kyidentity-server/internal/config"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/mfa"
	"github.com/Busnes-app/kyidentity-server/internal/oauth"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/Busnes-app/kyidentity-server/internal/sync"
	"github.com/google/uuid"
)

func setupTestServer(t *testing.T) (*Server, *store.Store, *sync.Engine, *mfa.Engine, *oauth.Engine, func()) {
	tmpDir, err := os.MkdirTemp("", "kyidentity-api-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	dbStore, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("store.New failed: %v", err)
	}

	keyPath := filepath.Join(tmpDir, "test_jwt.key")
	km, err := crypto.LoadOrCreateRSAKey(keyPath)
	if err != nil {
		t.Fatalf("crypto.LoadOrCreateRSAKey failed: %v", err)
	}

	encKey, _ := crypto.GenerateRandomBytes(32)
	cfg := &config.Config{
		Port:          "5867",
		IssuerURL:     "http://localhost:5867",
		RPID:          "localhost",
		Origin:        "http://localhost:5867",
		DBPath:        dbPath,
		DataDir:       tmpDir,
		RSAKeyPath:    keyPath,
		EncryptionKey: encKey,
		SecretKey:     encKey,
		AppName:       config.DefaultAppName,
	}

	auditLogger := audit.NewLogger(dbStore)
	syncEngine := sync.NewEngine(dbStore, encKey)
	mfaEngine := mfa.NewEngine(dbStore, encKey)
	oauthEngine := oauth.NewEngine(dbStore, km, cfg.IssuerURL)

	server := NewServer(
		cfg,
		dbStore,
		km,
		syncEngine,
		mfaEngine,
		oauthEngine,
		auditLogger,
		nil,
	)

	cleanup := func() {
		_ = dbStore.Close()
		_ = os.RemoveAll(tmpDir)
	}

	return server, dbStore, syncEngine, mfaEngine, oauthEngine, cleanup
}

func TestHealthAndOIDCDiscoveryEndpoints(t *testing.T) {
	server, _, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	// 1. Healthz
	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /healthz, got %d", rec.Code)
	}

	// 2. OpenID Configuration
	req = httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
	rec = httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /.well-known/openid-configuration, got %d", rec.Code)
	}

	var oidcCfg oauth.OIDCConfiguration
	if err := json.NewDecoder(rec.Body).Decode(&oidcCfg); err != nil {
		t.Fatalf("failed to decode OIDC config: %v", err)
	}
	if oidcCfg.Issuer != "http://localhost:5867" || oidcCfg.JwksURI == "" {
		t.Fatalf("unexpected OIDC config: %+v", oidcCfg)
	}

	// 3. Favicon SVG & ICO
	req = httptest.NewRequest("GET", "/favicon.svg", nil)
	rec = httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /favicon.svg, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "image/svg+xml" {
		t.Fatalf("expected Content-Type image/svg+xml, got %s", ct)
	}

	req = httptest.NewRequest("GET", "/favicon.ico", nil)
	rec = httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /favicon.ico, got %d", rec.Code)
	}
}

func TestLoginAndCSRFAuthenticationFlow(t *testing.T) {
	server, dbStore, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	// Create test user
	passHash, _ := auth.HashPassword("valid-secret-password-123")
	user := &store.User{
		ID:           uuid.New().String(),
		Username:     "alice",
		DisplayName:  "Alice",
		Email:        "alice@example.com",
		PasswordHash: passHash,
		Role:         "user",
		Status:       "active",
	}
	_ = dbStore.CreateUser(user)

	// 1. Fetch CSRF token
	req := httptest.NewRequest("GET", "/api/auth/csrf", nil)
	rec := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/auth/csrf, got %d", rec.Code)
	}

	var csrfResp struct {
		CSRFToken string `json:"csrfToken"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&csrfResp)
	csrfCookie := rec.Result().Cookies()[0]

	// 2. Login with password and CSRF token
	loginBody, _ := json.Marshal(map[string]string{
		"username": "alice",
		"password": "valid-secret-password-123",
	})
	loginReq := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.Header.Set("X-CSRF-Token", csrfResp.CSRFToken)
	loginReq.AddCookie(csrfCookie)
	loginRec := httptest.NewRecorder()

	server.httpServer.Handler.ServeHTTP(loginRec, loginReq)

	if loginRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from login, got %d: %s", loginRec.Code, loginRec.Body.String())
	}

	// 3. Verify session cookie issued
	var sessionCookie *http.Cookie
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == "kyidentity_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil || sessionCookie.Value == "" {
		t.Fatal("missing session cookie in login response")
	}

	// 4. Access /api/auth/me with session cookie
	meReq := httptest.NewRequest("GET", "/api/auth/me", nil)
	meReq.AddCookie(sessionCookie)
	meRec := httptest.NewRecorder()

	server.httpServer.Handler.ServeHTTP(meRec, meReq)
	if meRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/auth/me, got %d", meRec.Code)
	}

	var meResp struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	_ = json.NewDecoder(meRec.Body).Decode(&meResp)
	if meResp.Username != "alice" || meResp.Role != "user" {
		t.Fatalf("unexpected /api/auth/me response: %+v", meResp)
	}
}

func TestAdminSystemPairingHandshakeViaAPI(t *testing.T) {
	server, dbStore, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	// 1. Create Admin
	adminPassHash, _ := auth.HashPassword("admin-secure-password-123")
	admin := &store.User{
		ID:           uuid.New().String(),
		Username:     "admin",
		DisplayName:  "System Administrator",
		Email:        "admin@example.com",
		PasswordHash: adminPassHash,
		Role:         "admin",
		Status:       "active",
	}
	_ = dbStore.CreateUser(admin)

	// Create session for admin
	adminSessionToken, _ := crypto.GenerateRandomHex(32)
	_ = dbStore.CreateSession(&store.Session{
		ID:               uuid.New().String(),
		UserID:           admin.ID,
		SessionTokenHash: crypto.HashSHA256(adminSessionToken),
		IPAddress:        "127.0.0.1",
		UserAgent:        "Go-Test",
		ExpiresAt:        timeNowUTC().Add(24 * timeHour),
	})
	adminCookie := &http.Cookie{Name: "kyidentity_session", Value: adminSessionToken}

	// Fetch CSRF
	// The CSRF token is bound to the session it was issued for, so it must come from the
	// server rather than be invented here.
	csrfToken := server.middleware.IssueCSRFToken(adminSessionToken)
	csrfCookie := &http.Cookie{Name: "kyidentity_csrf", Value: csrfToken}

	// 2. Admin calls POST /api/admin/systems to connect a SCIM target
	scimReqBody, _ := json.Marshal(map[string]string{
		"name":        "Production KyPost Cluster",
		"systemType":  "kypost",
		"description": "Primary email cluster",
		"callbackUrl": "https://kypost.example.com/scim/v2",
	})
	pairReq := httptest.NewRequest("POST", "/api/admin/systems", bytes.NewReader(scimReqBody))
	pairReq.Header.Set("Content-Type", "application/json")
	pairReq.Header.Set("X-CSRF-Token", csrfToken)
	pairReq.Header.Set(StepUpHeader, mintStepUp(t, server, adminSessionToken, "POST /api/admin/systems"))
	pairReq.AddCookie(adminCookie)
	pairReq.AddCookie(csrfCookie)
	pairRec := httptest.NewRecorder()

	server.httpServer.Handler.ServeHTTP(pairRec, pairReq)
	if pairRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from POST /api/admin/systems, got %d: %s", pairRec.Code, pairRec.Body.String())
	}

	var pairResp struct {
		System      store.PairedSystem `json:"system"`
		BearerToken string             `json:"bearerToken"`
	}
	_ = json.NewDecoder(pairRec.Body).Decode(&pairResp)
	if pairResp.System.ID == "" || len(pairResp.BearerToken) < 32 {
		t.Fatalf("unexpected system creation response: %+v", pairResp)
	}

	// 3. Admin lists systems via GET /api/admin/systems
	listReq := httptest.NewRequest("GET", "/api/admin/systems", nil)
	listReq.AddCookie(adminCookie)
	listRec := httptest.NewRecorder()

	server.httpServer.Handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from GET /api/admin/systems, got %d", listRec.Code)
	}

	var listResp struct {
		Systems []store.PairedSystem `json:"systems"`
	}
	_ = json.NewDecoder(listRec.Body).Decode(&listResp)
	if len(listResp.Systems) != 1 || listResp.Systems[0].Name != "Production KyPost Cluster" {
		t.Fatalf("unexpected systems list: %+v", listResp)
	}
}

func TestOIDCAuthorizeAndPKCETokenFlowViaHTTP(t *testing.T) {
	server, dbStore, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	// 1. Create User
	passHash, _ := auth.HashPassword("valid-secret-password-123")
	user := &store.User{
		ID:           uuid.New().String(),
		Username:     "carol",
		DisplayName:  "Carol Danvers",
		Email:        "carol@example.com",
		PasswordHash: passHash,
		Role:         "user",
		Status:       "active",
	}
	_ = dbStore.CreateUser(user)

	sessionToken, _ := crypto.GenerateRandomHex(32)
	_ = dbStore.CreateSession(&store.Session{
		ID:               uuid.New().String(),
		UserID:           user.ID,
		SessionTokenHash: crypto.HashSHA256(sessionToken),
		IPAddress:        "127.0.0.1",
		UserAgent:        "Go-Test",
		ExpiresAt:        timeNowUTC().Add(24 * timeHour),
	})
	userCookie := &http.Cookie{Name: "kyidentity_session", Value: sessionToken}

	// 2. Create OIDC Client
	client := &store.OAuthClient{
		ID:                uuid.New().String(),
		ClientName:        "KyBookmarks Client",
		ClientType:        "public",
		RedirectURIsJSON:  `["https://bookmarks.local/callback"]`,
		AllowedScopesJSON: `["openid","profile","email"]`,
		Enabled:           true,
	}
	_ = dbStore.CreateOAuthClient(client)
	allowTestAppAccess(t, dbStore, client.ID)

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	// 3. GET /oauth/authorize with active session
	authParams := url.Values{
		"client_id":             {client.ID},
		"redirect_uri":          {"https://bookmarks.local/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid profile email"},
		"state":                 {"random-state-12345"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}

	authReq := httptest.NewRequest("GET", "/oauth/authorize?"+authParams.Encode(), nil)
	authReq.AddCookie(userCookie)
	authRec := httptest.NewRecorder()

	server.httpServer.Handler.ServeHTTP(authRec, authReq)
	if authRec.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect from /oauth/authorize, got %d: %s", authRec.Code, authRec.Body.String())
	}

	redirectLocation := authRec.Header().Get("Location")
	targetURL, err := url.Parse(redirectLocation)
	if err != nil {
		t.Fatalf("invalid redirect location: %s", redirectLocation)
	}

	code := targetURL.Query().Get("code")
	state := targetURL.Query().Get("state")
	if code == "" || state != "random-state-12345" {
		t.Fatalf("unexpected redirect query params: %s", targetURL.RawQuery)
	}

	// 4. POST /oauth/token exchanging code and PKCE verifier
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {client.ID},
		"redirect_uri":  {"https://bookmarks.local/callback"},
		"code_verifier": {verifier},
	}

	tokenReq := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(tokenForm.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRec := httptest.NewRecorder()

	server.httpServer.Handler.ServeHTTP(tokenRec, tokenReq)
	if tokenRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /oauth/token, got %d: %s", tokenRec.Code, tokenRec.Body.String())
	}

	var tokenResp oauth.TokenResponse
	if err := json.NewDecoder(tokenRec.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("failed to decode token response: %v", err)
	}

	if tokenResp.AccessToken == "" || tokenResp.IDToken == "" {
		t.Fatalf("missing tokens: %+v", tokenResp)
	}

	// 5. GET /oauth/userinfo with Access Token
	userinfoReq := httptest.NewRequest("GET", "/oauth/userinfo", nil)
	userinfoReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	userinfoRec := httptest.NewRecorder()

	server.httpServer.Handler.ServeHTTP(userinfoRec, userinfoReq)
	if userinfoRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /oauth/userinfo, got %d", userinfoRec.Code)
	}

	var userinfo map[string]any
	_ = json.NewDecoder(userinfoRec.Body).Decode(&userinfo)
	if userinfo["preferred_username"] != "carol" || userinfo["email"] != "carol@example.com" {
		t.Fatalf("unexpected userinfo: %+v", userinfo)
	}
}

// Helpers
var (
	timeNowUTC = func() time.Time { return time.Now().UTC() }
	timeHour   = 1 * time.Hour
)

// setupTestServerWith builds a test server after applying opts to the config, for
// behaviour that is captured at construction time rather than read per request.
func setupTestServerWith(t *testing.T, opts ...func(*config.Config)) (*Server, *store.Store, *sync.Engine, *mfa.Engine, *oauth.Engine, func()) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "kyidentity-api-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	dbStore, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("store.New failed: %v", err)
	}

	keyPath := filepath.Join(tmpDir, "test_jwt.key")
	km, err := crypto.LoadOrCreateRSAKey(keyPath)
	if err != nil {
		t.Fatalf("crypto.LoadOrCreateRSAKey failed: %v", err)
	}

	encKey, _ := crypto.GenerateRandomBytes(32)
	cfg := &config.Config{
		Port:          "5867",
		IssuerURL:     "http://localhost:5867",
		RPID:          "localhost",
		Origin:        "http://localhost:5867",
		DBPath:        dbPath,
		DataDir:       tmpDir,
		RSAKeyPath:    keyPath,
		EncryptionKey: encKey,
		SecretKey:     encKey,
		AppName:       config.DefaultAppName,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	auditLogger := audit.NewLogger(dbStore)
	syncEngine := sync.NewEngine(dbStore, encKey)
	mfaEngine := mfa.NewEngine(dbStore, encKey)
	oauthEngine := oauth.NewEngine(dbStore, km, cfg.IssuerURL)

	server := NewServer(cfg, dbStore, km, syncEngine, mfaEngine, oauthEngine, auditLogger, nil)

	return server, dbStore, syncEngine, mfaEngine, oauthEngine, func() {
		_ = dbStore.Close()
		_ = os.RemoveAll(tmpDir)
	}
}

func TestAdminListAuditEventsPagination(t *testing.T) {
	server, dbStore, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	// 1. Create Admin & Session
	adminPassHash, _ := auth.HashPassword("admin-secure-password-123")
	admin := &store.User{
		ID:           "admin-user-id",
		Username:     "admin",
		DisplayName:  "System Administrator",
		Email:        "admin@example.com",
		PasswordHash: adminPassHash,
		Role:         "admin",
		Status:       "active",
	}
	_ = dbStore.CreateUser(admin)

	adminSessionToken, _ := crypto.GenerateRandomHex(32)
	_ = dbStore.CreateSession(&store.Session{
		ID:               "admin-sess-id",
		UserID:           admin.ID,
		SessionTokenHash: crypto.HashSHA256(adminSessionToken),
		IPAddress:        "127.0.0.1",
		UserAgent:        "TestAdminBrowser",
		ExpiresAt:        time.Now().UTC().Add(time.Hour),
	})
	adminCookie := &http.Cookie{Name: "kyidentity_session", Value: adminSessionToken}

	// 2. Insert test audit events
	for i := 1; i <= 20; i++ {
		_ = dbStore.RecordAuditEvent(&store.AuditEvent{
			ID:            uuid.New().String(),
			ActorUsername: "admin",
			Action:        "admin.test_action",
			Outcome:       "success",
			IPAddress:     "127.0.0.1",
		})
	}

	// 3. Query page 1 with limit 5
	req := httptest.NewRequest("GET", "/api/admin/audit-events?page=1&limit=5", nil)
	req.AddCookie(adminCookie)
	rec := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from GET /api/admin/audit-events, got %d", rec.Code)
	}

	var resp struct {
		AuditEvents []store.AuditEvent `json:"auditEvents"`
		Total       int                `json:"total"`
		Page        int                `json:"page"`
		Limit       int                `json:"limit"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Total != 20 {
		t.Fatalf("expected total 20, got %d", resp.Total)
	}
	if len(resp.AuditEvents) != 5 {
		t.Fatalf("expected 5 events on page 1, got %d", len(resp.AuditEvents))
	}
	if resp.Page != 1 || resp.Limit != 5 {
		t.Fatalf("expected page 1, limit 5, got page %d, limit %d", resp.Page, resp.Limit)
	}

	// 4. Query page 2 with limit 5
	req2 := httptest.NewRequest("GET", "/api/admin/audit-events?page=2&limit=5", nil)
	req2.AddCookie(adminCookie)
	rec2 := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(rec2, req2)

	var resp2 struct {
		AuditEvents []store.AuditEvent `json:"auditEvents"`
		Total       int                `json:"total"`
		Page        int                `json:"page"`
		Limit       int                `json:"limit"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(resp2.AuditEvents) != 5 {
		t.Fatalf("expected 5 events on page 2, got %d", len(resp2.AuditEvents))
	}
	if resp2.Page != 2 {
		t.Fatalf("expected page 2, got %d", resp2.Page)
	}
}

func TestAdminCreatePairedSystemSCIM(t *testing.T) {
	server, dbStore, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	// Create Admin & Session
	adminPassHash, _ := auth.HashPassword("admin-secure-password-123")
	admin := &store.User{
		ID:           "admin-user-id",
		Username:     "admin",
		DisplayName:  "System Administrator",
		Email:        "admin@example.com",
		PasswordHash: adminPassHash,
		Role:         "admin",
		Status:       "active",
	}
	_ = dbStore.CreateUser(admin)

	adminSessionToken, _ := crypto.GenerateRandomHex(32)
	_ = dbStore.CreateSession(&store.Session{
		ID:               "admin-sess-id",
		UserID:           admin.ID,
		SessionTokenHash: crypto.HashSHA256(adminSessionToken),
		IPAddress:        "127.0.0.1",
		UserAgent:        "TestAdminBrowser",
		ExpiresAt:        time.Now().UTC().Add(time.Hour),
	})
	adminCookie := &http.Cookie{Name: "kyidentity_session", Value: adminSessionToken}

	// 1. Create SCIM system directly via POST /api/admin/systems
	csrfToken := server.middleware.IssueCSRFToken(adminSessionToken)
	body := `{"name":"Nextcloud SCIM","systemType":"scim","description":"Cloud storage","iconUrl":"https://example.com/icon.svg","callbackUrl":"https://cloud.example.com/scim/v2","bearerToken":"target-issued-token"}`
	req := httptest.NewRequest("POST", "/api/admin/systems", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrfToken)
	req.Header.Set(StepUpHeader, mintStepUp(t, server, adminSessionToken, "POST /api/admin/systems"))
	req.AddCookie(adminCookie)
	req.AddCookie(&http.Cookie{Name: "kyidentity_csrf", Value: csrfToken})
	rec := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		System      store.PairedSystem `json:"system"`
		BearerToken string             `json:"bearerToken"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.System.Name != "Nextcloud SCIM" {
		t.Fatalf("expected system name 'Nextcloud SCIM', got '%s'", resp.System.Name)
	}
	if resp.System.Description != "Cloud storage" || resp.System.IconURL != "https://example.com/icon.svg" {
		t.Fatalf("unexpected metadata in created system: %+v", resp.System)
	}
	if resp.BearerToken != "" {
		t.Fatal("configured bearer token returned")
	}

	// 2. Verify system is in list
	listReq := httptest.NewRequest("GET", "/api/admin/systems", nil)
	listReq.AddCookie(adminCookie)
	listRec := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(listRec, listReq)

	var listResp struct {
		Systems []store.PairedSystem `json:"systems"`
	}
	_ = json.Unmarshal(listRec.Body.Bytes(), &listResp)
	if len(listResp.Systems) != 1 {
		t.Fatalf("expected 1 system in list, got %d", len(listResp.Systems))
	}
	if listResp.Systems[0].CallbackURL != "https://cloud.example.com/scim/v2" {
		t.Fatalf("unexpected callback URL: %s", listResp.Systems[0].CallbackURL)
	}
}

func oauthSession(t *testing.T, db *store.Store, userID string) string {
	t.Helper()
	id := uuid.NewString()
	if err := db.CreateSession(&store.Session{ID: id, UserID: userID, SessionTokenHash: uuid.NewString(), ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	return id
}
