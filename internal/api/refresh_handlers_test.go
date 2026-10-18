package api

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// The refresh grant through the real token route: rotation, generic refusal, the reuse
// audit row and discovery.
func TestRefreshGrantViaHTTP(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	u := newUser(t, db, "user")
	cookie := newSession(t, db, u, time.Now().UTC().Add(time.Hour))
	if err := db.CreateOAuthClient(&store.OAuthClient{ID: "kynotes", ClientName: "KyNotes", ClientType: "confidential", ClientSecretHash: crypto.HashSHA256("s3cret"),
		RedirectURIsJSON: `["https://notes.example/cb"]`, AllowedScopesJSON: `["openid"]`, Enabled: true}, nil); err != nil {
		t.Fatal(err)
	}
	allowTestAppAccess(t, db, "kynotes")
	rows, _, _ := db.ListAppRecords("kynotes", 10, 0)
	if err := db.SetAppAuthenticationPolicy(rows[0].ID, store.AppAuthenticationPolicy{Mode: "reuse", Factor: "password", RefreshIdle: 3600, RefreshLifetime: 86400}, rows[0].Revision, nil); err != nil {
		t.Fatal(err)
	}
	verifier := strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"client_id": {"kynotes"}, "redirect_uri": {"https://notes.example/cb"}, "response_type": {"code"}, "scope": {"openid"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: "kyidentity_session", Value: cookie})
	r := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(r, req)
	loc, _ := url.Parse(r.Header().Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("authorize: %d %s", r.Code, r.Header().Get("Location"))
	}
	token := func(form url.Values) (int, map[string]any) {
		t.Helper()
		req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("kynotes", "s3cret")
		r := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(r, req)
		if r.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("token response cacheable: %q", r.Header().Get("Cache-Control"))
		}
		var body map[string]any
		_ = json.Unmarshal(r.Body.Bytes(), &body)
		return r.Code, body
	}
	status, first := token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://notes.example/cb"}, "code_verifier": {verifier}})
	rt, _ := first["refresh_token"].(string)
	if status != 200 || rt == "" {
		t.Fatalf("code exchange: %d %v", status, first)
	}
	status, second := token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}})
	if status != 200 || second["refresh_token"] == rt || second["id_token"] == nil {
		t.Fatalf("refresh: %d %v", status, second)
	}
	status, replay := token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}})
	if status != 400 || replay["error"] != "invalid_grant" || replay["error_description"] != "The refresh token or client credentials are invalid" {
		t.Fatalf("replay: %d %v", status, replay)
	}
	raw, err := sql.Open("sqlite", srv.cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var audited int
	if err := raw.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action='oauth.refresh_reuse' AND actor_id=?`, u.ID).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("reuse audit rows: %d %v", audited, err)
	}

	r = httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(r, httptest.NewRequest("GET", "/.well-known/openid-configuration", nil))
	if !strings.Contains(r.Body.String(), `"grant_types_supported":["authorization_code","refresh_token",`) {
		t.Fatalf("discovery: %s", r.Body.String())
	}
}
