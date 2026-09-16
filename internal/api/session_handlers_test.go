package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kyidentity-server/internal/crypto"
	"github.com/Busness-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// call performs a browser request as the holder of cookie, with the CSRF pair set.
func call(t *testing.T, srv *Server, cookie, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.AddCookie(&http.Cookie{Name: "kyidentity_session", Value: cookie})
	csrf := srv.middleware.IssueCSRFToken(cookie)
	req.AddCookie(&http.Cookie{Name: "kyidentity_csrf", Value: csrf})
	req.Header.Set("X-CSRF-Token", csrf)
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)
	return rr
}

type inventory struct {
	Sessions []struct {
		ID           string `json:"id"`
		Current      bool   `json:"current"`
		IPAddress    string `json:"ipAddress"`
		FactorMethod string `json:"factorMethod"`
	} `json:"sessions"`
	Apps []store.AppGrant `json:"apps"`
}

func decodeInventory(t *testing.T, rr *httptest.ResponseRecorder) inventory {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var inv inventory
	if err := json.Unmarshal(rr.Body.Bytes(), &inv); err != nil {
		t.Fatal(err)
	}
	return inv
}

// tokenFor registers a live token for clientID bound to an existing session, so the
// inventory under test contains exactly the sessions each test created.
func tokenFor(t *testing.T, db *store.Store, userID, sessionID, clientID string) string {
	t.Helper()
	if c, err := db.GetOAuthClientByID(clientID); err != nil {
		t.Fatal(err)
	} else if c == nil {
		newClient(t, db, clientID, []string{"https://example.com/cb"}, []string{"openid"})
	}
	jti := uuid.NewString()
	if err := db.RecordIssuedToken(&store.IssuedToken{JTI: jti, UserID: userID, ClientID: clientID, SessionID: sessionID, ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatalf("RecordIssuedToken: %v", err)
	}
	return jti
}

func sessionIDFor(t *testing.T, db *store.Store, cookie string) string {
	t.Helper()
	sess, err := db.GetSessionByTokenHash(crypto.HashSHA256(cookie), time.Hour)
	if err != nil || sess == nil {
		t.Fatalf("session lookup: %v %v", sess, err)
	}
	return sess.ID
}

func TestSessionInventoryMarksTheCallingSessionAndListsApps(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	u := newUser(t, db, "user")
	exp := time.Now().UTC().Add(time.Hour)
	mine := newSession(t, db, u, exp)
	newSession(t, db, u, exp)
	newSession(t, db, newUser(t, db, "user"), exp)
	tokenFor(t, db, u.ID, sessionIDFor(t, db, mine), "kynotes")

	resp := call(t, srv, mine, "GET", "/api/user/sessions")
	if strings.Contains(resp.Body.String(), "sessionTokenHash") {
		t.Fatal("token hash leaked")
	}
	inv := decodeInventory(t, resp)
	if len(inv.Sessions) != 2 {
		t.Fatalf("sessions = %d, want 2", len(inv.Sessions))
	}
	current := 0
	for _, s := range inv.Sessions {
		if s.Current {
			current++
			if s.ID != sessionIDFor(t, db, mine) {
				t.Fatal("wrong session marked current")
			}
		}
	}
	if current != 1 {
		t.Fatalf("current sessions = %d, want 1", current)
	}
	if len(inv.Apps) != 1 || inv.Apps[0].ClientID != "kynotes" {
		t.Fatalf("apps = %+v", inv.Apps)
	}
}

func TestRevokingOneSessionLeavesTheOtherValid(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	u := newUser(t, db, "user")
	exp := time.Now().UTC().Add(time.Hour)
	mine, other := newSession(t, db, u, exp), newSession(t, db, u, exp)

	if got := call(t, srv, mine, "DELETE", "/api/user/sessions/"+sessionIDFor(t, db, other)); got.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", got.Code, got.Body.String())
	}
	if got := call(t, srv, other, "GET", "/api/auth/me"); got.Code != http.StatusUnauthorized {
		t.Fatalf("revoked session still authenticates: %d", got.Code)
	}
	if got := call(t, srv, mine, "GET", "/api/auth/me"); got.Code != http.StatusOK {
		t.Fatalf("surviving session lost: %d", got.Code)
	}
	if n := countAudit(t, db, "user.session_revoked"); n != 1 {
		t.Fatalf("audit rows = %d, want 1", n)
	}
}

func TestRevokingTheCurrentSessionClearsBothCookies(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	u := newUser(t, db, "user")
	mine := newSession(t, db, u, time.Now().UTC().Add(time.Hour))

	got := call(t, srv, mine, "DELETE", "/api/user/sessions/"+sessionIDFor(t, db, mine))
	if got.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", got.Code, got.Body.String())
	}
	cleared := map[string]bool{}
	for _, c := range got.Result().Cookies() {
		if c.MaxAge < 0 {
			cleared[c.Name] = true
		}
	}
	if !cleared["kyidentity_session"] || !cleared["kyidentity_csrf"] {
		t.Fatalf("cookies cleared: %v", cleared)
	}
	if got := call(t, srv, mine, "GET", "/api/auth/me"); got.Code != http.StatusUnauthorized {
		t.Fatalf("self-revoked session still authenticates: %d", got.Code)
	}
}

func TestCrossUserSessionIDsAreRejected(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	exp := time.Now().UTC().Add(time.Hour)
	attacker := newSession(t, db, newUser(t, db, "user"), exp)
	victim := newSession(t, db, newUser(t, db, "user"), exp)

	if got := call(t, srv, attacker, "DELETE", "/api/user/sessions/"+sessionIDFor(t, db, victim)); got.Code != http.StatusNotFound {
		t.Fatalf("cross-user revoke: %d", got.Code)
	}
	if got := call(t, srv, victim, "GET", "/api/auth/me"); got.Code != http.StatusOK {
		t.Fatalf("victim session lost: %d", got.Code)
	}
}

func TestRevokeOthersKeepsTheCallerSignedIn(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	u := newUser(t, db, "user")
	exp := time.Now().UTC().Add(time.Hour)
	mine, other := newSession(t, db, u, exp), newSession(t, db, u, exp)

	if got := call(t, srv, mine, "POST", "/api/user/sessions/revoke-others"); got.Code != http.StatusOK {
		t.Fatalf("revoke-others: %d %s", got.Code, got.Body.String())
	}
	if got := call(t, srv, other, "GET", "/api/auth/me"); got.Code != http.StatusUnauthorized {
		t.Fatalf("other session survived: %d", got.Code)
	}
	if got := call(t, srv, mine, "GET", "/api/auth/me"); got.Code != http.StatusOK {
		t.Fatalf("caller lost: %d", got.Code)
	}
}

// Token registration is the last gate before an access token exists. A code minted by a
// session cannot be exchanged after that session is revoked, whichever request wins the race.
func TestCodeExchangeCannotEscapeSessionRevocation(t *testing.T) {
	srv, db, _, _, oe, cleanup := setupTestServer(t)
	defer cleanup()
	u := newUser(t, db, "user")
	exp := time.Now().UTC().Add(time.Hour)
	mine, other := newSession(t, db, u, exp), newSession(t, db, u, exp)
	newClient(t, db, "kynotes", []string{"https://notes.urlxl.com/callback"}, []string{"openid"})
	code, err := oe.CreateAuthorizationCode("kynotes", sessionIDFor(t, db, other), "https://notes.urlxl.com/callback", "openid", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "S256")
	if err != nil {
		t.Fatal(err)
	}

	if got := call(t, srv, mine, "DELETE", "/api/user/sessions/"+sessionIDFor(t, db, other)); got.Code != http.StatusOK {
		t.Fatalf("revoke: %d", got.Code)
	}
	if _, err := oe.ExchangeAuthorizationCode(code, "kynotes", "", "https://notes.urlxl.com/callback", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); err == nil {
		t.Fatal("code from a revoked session was exchanged")
	}
}

func TestAdminSessionRoutesRequireAdminAndRevokeScopedAccess(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	exp := time.Now().UTC().Add(time.Hour)
	admin := newSession(t, db, newUser(t, db, "admin"), exp)
	target := newUser(t, db, "user")
	targetCookie := newSession(t, db, target, exp)
	targetSID := sessionIDFor(t, db, targetCookie)
	notes := tokenFor(t, db, target.ID, targetSID, "kynotes")
	mail := tokenFor(t, db, target.ID, targetSID, "kypost")
	plain := newSession(t, db, newUser(t, db, "user"), exp)

	for _, p := range []struct{ method, path string }{
		{"GET", "/api/admin/users/" + target.ID + "/sessions"},
		{"DELETE", "/api/admin/users/" + target.ID + "/sessions/" + targetSID},
		{"POST", "/api/admin/users/" + target.ID + "/apps/kynotes/revoke"},
	} {
		if got := call(t, srv, plain, p.method, p.path); got.Code != http.StatusForbidden {
			t.Fatalf("%s %s as non-admin: %d", p.method, p.path, got.Code)
		}
	}

	inv := decodeInventory(t, call(t, srv, admin, "GET", "/api/admin/users/"+target.ID+"/sessions"))
	if len(inv.Sessions) != 1 || inv.Sessions[0].Current || len(inv.Apps) != 2 {
		t.Fatalf("admin inventory = %+v", inv)
	}

	if got := call(t, srv, admin, "POST", "/api/admin/users/"+target.ID+"/apps/kynotes/revoke"); got.Code != http.StatusOK {
		t.Fatalf("app revoke: %d %s", got.Code, got.Body.String())
	}
	assertRevoked(t, db, notes, true, "kynotes token after app revoke")
	assertRevoked(t, db, mail, false, "kypost token after kynotes revoke")
	if got := call(t, srv, targetCookie, "GET", "/api/auth/me"); got.Code != http.StatusOK {
		t.Fatalf("browser session lost on app revoke: %d", got.Code)
	}

	if got := call(t, srv, admin, "DELETE", "/api/admin/users/"+target.ID+"/sessions/"+targetSID); got.Code != http.StatusOK {
		t.Fatalf("admin session revoke: %d %s", got.Code, got.Body.String())
	}
	if got := call(t, srv, targetCookie, "GET", "/api/auth/me"); got.Code != http.StatusUnauthorized {
		t.Fatalf("target session survived admin revoke: %d", got.Code)
	}
	if got := call(t, srv, admin, "DELETE", "/api/admin/users/"+target.ID+"/sessions/"+targetSID); got.Code != http.StatusNotFound {
		t.Fatalf("second revoke: %d", got.Code)
	}
	for _, a := range []string{"admin.session_revoked", "admin.app_access_revoked"} {
		if n := countAudit(t, db, a); n != 1 {
			t.Fatalf("%s audit rows = %d", a, n)
		}
	}
}

func TestSessionRoutesRejectMissingCSRF(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	u := newUser(t, db, "user")
	exp := time.Now().UTC().Add(time.Hour)
	mine, other := newSession(t, db, u, exp), newSession(t, db, u, exp)

	req := httptest.NewRequest("DELETE", "/api/user/sessions/"+sessionIDFor(t, db, other), nil)
	req.AddCookie(&http.Cookie{Name: "kyidentity_session", Value: mine})
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("no CSRF: %d", w.Code)
	}
	if got := call(t, srv, other, "GET", "/api/auth/me"); got.Code != http.StatusOK {
		t.Fatalf("session revoked without CSRF: %d", got.Code)
	}
}

func countAudit(t *testing.T, db *store.Store, action string) int {
	t.Helper()
	events, _, err := db.ListAuditEvents(200, 0)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range events {
		if e.Action == action && e.Outcome == "success" {
			n++
		}
	}
	return n
}
