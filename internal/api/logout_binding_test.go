package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// A hint proves a login, not a person. An ID token minted in one session must not end a
// different session of the same user without confirmation; otherwise any relying party
// holding any old token could sign the user out of every browser, forever.
func TestHintFromAnotherSessionOfTheSameUserRequiresConfirmation(t *testing.T) {
	srv, db, _, _, oe, cleanup := setupTestServer(t)
	defer cleanup()
	u := newUser(t, db, "user")
	exp := time.Now().UTC().Add(time.Hour)
	a, b := newSession(t, db, u, exp), newSession(t, db, u, exp)
	logoutClient(t, db, "kynotes")
	hint := idTokenFor(t, db, oe, a, "kynotes")

	rr := endSession(t, srv, b, url.Values{"id_token_hint": {hint}, "post_logout_redirect_uri": {bye}})
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `name="confirm"`) {
		t.Fatalf("expected the confirmation page, got %d %q", rr.Code, rr.Header().Get("Location"))
	}
	if !sessionAlive(t, srv, b) {
		t.Fatal("session B was ended by a hint issued to session A")
	}
	if !sessionAlive(t, srv, a) {
		t.Fatal("session A was ended although the browser holds session B")
	}
}

// A cross-site POST does not carry the Lax session cookie, so the server cannot see the
// session it is asked to end. Answering "signed out" there would be a lie; instead the
// request is bounced to a top-level GET on this origin, which does carry the cookie.
func TestCookielessPostIsBouncedToATopLevelGet(t *testing.T) {
	srv, db, _, _, oe, cleanup := setupTestServer(t)
	defer cleanup()
	u := newUser(t, db, "user")
	cookie := newSession(t, db, u, time.Now().UTC().Add(time.Hour))
	logoutClient(t, db, "kynotes")
	hint := idTokenFor(t, db, oe, cookie, "kynotes")

	form := url.Values{"id_token_hint": {hint}, "post_logout_redirect_uri": {bye}, "state": {"s9"}, "confirm": {"junk"}}
	req := httptest.NewRequest("POST", "/oauth/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	loc := rr.Header().Get("Location")
	if rr.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "/oauth/logout?") {
		t.Fatalf("got %d %q, want 303 to a same-origin GET", rr.Code, loc)
	}
	target, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	got := target.Query()
	if got.Get("id_token_hint") != hint || got.Get("post_logout_redirect_uri") != bye || got.Get("state") != "s9" || got.Has("confirm") {
		t.Fatalf("bounced query lost or leaked parameters: %v", got)
	}
	if !sessionAlive(t, srv, cookie) {
		t.Fatal("a cookieless POST ended a session it could not see")
	}
}
