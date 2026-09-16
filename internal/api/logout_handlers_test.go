package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kyidentity-server/internal/oauth"
	"github.com/Busness-app/kyidentity-server/internal/store"
)

const bye = "https://notes.urlxl.com/bye"

// logoutClient registers a public client with one post-logout redirect URI.
func logoutClient(t *testing.T, db *store.Store, id string) {
	t.Helper()
	newClient(t, db, id, []string{"https://notes.urlxl.com/callback"}, []string{"openid"})
	c, err := db.GetOAuthClientByID(id)
	if err != nil || c == nil {
		t.Fatal(err)
	}
	c.PostLogoutRedirectURIsJSON = `["` + bye + `"]`
	if err := db.UpdateOAuthClient(c); err != nil {
		t.Fatal(err)
	}
}

// idTokenFor completes a code exchange for the session behind cookie and returns its ID token.
func idTokenFor(t *testing.T, db *store.Store, oe *oauth.Engine, cookie, clientID string) string {
	t.Helper()
	code, err := oe.CreateAuthorizationCode(clientID, sessionIDFor(t, db, cookie), "https://notes.urlxl.com/callback", "openid", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "S256")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := oe.ExchangeAuthorizationCode(code, clientID, "", "https://notes.urlxl.com/callback", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
	if err != nil {
		t.Fatal(err)
	}
	return resp.IDToken
}

func endSession(t *testing.T, srv *Server, cookie string, params url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", "/oauth/logout?"+params.Encode(), nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "kyidentity_session", Value: cookie})
	}
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)
	return rr
}

func sessionAlive(t *testing.T, srv *Server, cookie string) bool {
	t.Helper()
	return call(t, srv, cookie, "GET", "/api/auth/me").Code == http.StatusOK
}

func TestRPInitiatedLogoutWithValidHintEndsSessionAndRedirectsWithState(t *testing.T) {
	srv, db, _, _, oe, cleanup := setupTestServer(t)
	defer cleanup()
	u := newUser(t, db, "user")
	cookie := newSession(t, db, u, time.Now().UTC().Add(time.Hour))
	logoutClient(t, db, "kynotes")
	hint := idTokenFor(t, db, oe, cookie, "kynotes")

	rr := endSession(t, srv, cookie, url.Values{"id_token_hint": {hint}, "post_logout_redirect_uri": {bye}, "state": {"xyz"}})
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != bye+"?state=xyz" {
		t.Fatalf("got %d %q", rr.Code, rr.Header().Get("Location"))
	}
	if sessionAlive(t, srv, cookie) {
		t.Fatal("session survived RP-initiated logout")
	}
	cleared := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == "kyidentity_session" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("session cookie not cleared")
	}
	if n := countAudit(t, db, "auth.logout"); n != 1 {
		t.Fatalf("auth.logout audit rows = %d", n)
	}
}

func TestUnregisteredPostLogoutRedirectIsNeverFollowed(t *testing.T) {
	srv, db, _, _, oe, cleanup := setupTestServer(t)
	defer cleanup()
	u := newUser(t, db, "user")
	cookie := newSession(t, db, u, time.Now().UTC().Add(time.Hour))
	logoutClient(t, db, "kynotes")
	hint := idTokenFor(t, db, oe, cookie, "kynotes")

	for _, bad := range []string{"https://evil.example/", bye + "/", strings.ToUpper(bye), "javascript:alert(1)"} {
		rr := endSession(t, srv, cookie, url.Values{"id_token_hint": {hint}, "post_logout_redirect_uri": {bad}})
		if rr.Code != http.StatusBadRequest || rr.Header().Get("Location") != "" {
			t.Fatalf("%q: got %d %q", bad, rr.Code, rr.Header().Get("Location"))
		}
		if !sessionAlive(t, srv, cookie) {
			t.Fatalf("%q: a rejected request must not end the session", bad)
		}
	}
	// Without a client there is nothing to validate the redirect against.
	rr := endSession(t, srv, cookie, url.Values{"post_logout_redirect_uri": {bye}})
	if rr.Code != http.StatusBadRequest || rr.Header().Get("Location") != "" {
		t.Fatalf("anonymous redirect: got %d %q", rr.Code, rr.Header().Get("Location"))
	}
}

func TestForgedOrMismatchedHintsAreRejected(t *testing.T) {
	srv, db, _, _, oe, cleanup := setupTestServer(t)
	defer cleanup()
	u := newUser(t, db, "user")
	cookie := newSession(t, db, u, time.Now().UTC().Add(time.Hour))
	logoutClient(t, db, "kynotes")
	logoutClient(t, db, "kypost")
	hint := idTokenFor(t, db, oe, cookie, "kynotes")
	parts := strings.Split(hint, ".")
	forged := parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-3] + "AAA"

	for name, params := range map[string]url.Values{
		"forged signature": {"id_token_hint": {forged}, "post_logout_redirect_uri": {bye}},
		"client mismatch":  {"id_token_hint": {hint}, "client_id": {"kypost"}, "post_logout_redirect_uri": {bye}},
		"oversized hint":   {"id_token_hint": {strings.Repeat("a", 9000)}},
	} {
		rr := endSession(t, srv, cookie, params)
		if rr.Code != http.StatusBadRequest || rr.Header().Get("Location") != "" {
			t.Fatalf("%s: got %d %q", name, rr.Code, rr.Header().Get("Location"))
		}
		if !sessionAlive(t, srv, cookie) {
			t.Fatalf("%s: session ended on a rejected request", name)
		}
	}
}

func TestLogoutWithoutHintAsksForConfirmation(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	u := newUser(t, db, "user")
	cookie := newSession(t, db, u, time.Now().UTC().Add(time.Hour))
	logoutClient(t, db, "kynotes")

	rr := endSession(t, srv, cookie, url.Values{"client_id": {"kynotes"}, "post_logout_redirect_uri": {bye}, "state": {"s1"}})
	if rr.Code != http.StatusOK || !strings.Contains(rr.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("got %d %q", rr.Code, rr.Header().Get("Content-Type"))
	}
	body := rr.Body.String()
	if !strings.Contains(body, "kynotes") || !strings.Contains(body, `name="confirm"`) {
		t.Fatalf("confirmation page missing client name or confirm token: %s", body)
	}
	if !sessionAlive(t, srv, cookie) {
		t.Fatal("asking for confirmation must not end the session")
	}

	// Cross-site POST without the confirmation token: no effect.
	req := httptest.NewRequest("POST", "/oauth/logout", strings.NewReader(url.Values{"client_id": {"kynotes"}, "post_logout_redirect_uri": {bye}, "confirm": {"nope"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "kyidentity_session", Value: cookie})
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || !sessionAlive(t, srv, cookie) {
		t.Fatalf("bad confirm token: %d alive=%v", w.Code, sessionAlive(t, srv, cookie))
	}

	// The form the page rendered carries a valid token; submitting it signs out and redirects.
	confirm := extractInput(t, body, "confirm")
	req = httptest.NewRequest("POST", "/oauth/logout", strings.NewReader(url.Values{"client_id": {"kynotes"}, "post_logout_redirect_uri": {bye}, "state": {"s1"}, "confirm": {confirm}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "kyidentity_session", Value: cookie})
	w = httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusFound || w.Header().Get("Location") != bye+"?state=s1" {
		t.Fatalf("confirmed logout: %d %q", w.Code, w.Header().Get("Location"))
	}
	if sessionAlive(t, srv, cookie) {
		t.Fatal("session survived confirmed logout")
	}
}

func TestHintForAnotherUserRequiresConfirmation(t *testing.T) {
	srv, db, _, _, oe, cleanup := setupTestServer(t)
	defer cleanup()
	exp := time.Now().UTC().Add(time.Hour)
	victim := newSession(t, db, newUser(t, db, "user"), exp)
	other := newSession(t, db, newUser(t, db, "user"), exp)
	logoutClient(t, db, "kynotes")
	hint := idTokenFor(t, db, oe, other, "kynotes")

	rr := endSession(t, srv, victim, url.Values{"id_token_hint": {hint}, "post_logout_redirect_uri": {bye}})
	if rr.Code != http.StatusOK || !sessionAlive(t, srv, victim) {
		t.Fatalf("someone else's hint must not silently end this browser's session: %d", rr.Code)
	}
}

func TestAnonymousLogoutJustRedirects(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	logoutClient(t, db, "kynotes")

	rr := endSession(t, srv, "", url.Values{"client_id": {"kynotes"}, "post_logout_redirect_uri": {bye}, "state": {"q"}})
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != bye+"?state=q" {
		t.Fatalf("got %d %q", rr.Code, rr.Header().Get("Location"))
	}
	rr = endSession(t, srv, "", nil)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("no redirect target: got %d", rr.Code)
	}
}

func extractInput(t *testing.T, body, name string) string {
	t.Helper()
	marker := `name="` + name + `" value="`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("input %q not found", name)
	}
	rest := body[i+len(marker):]
	return rest[:strings.Index(rest, `"`)]
}
