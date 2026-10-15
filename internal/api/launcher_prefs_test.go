package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

type launcherResponse struct {
	Applications []store.Application  `json:"applications"`
	Preferences  *store.LauncherPrefs `json:"preferences"`
}

func launcherState(t *testing.T, srv *Server, cookie string) launcherResponse {
	t.Helper()
	rr := call(t, srv, cookie, "GET", "/api/user/applications")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/user/applications returned %d: %s", rr.Code, rr.Body.String())
	}
	var resp launcherResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func putPrefs(t *testing.T, srv *Server, cookie, body string) int {
	t.Helper()
	return adminRequestNoStepUp(t, srv, "PUT", "/api/user/launcher-preferences", cookie, body).Code
}

// Client and custom ids are separate spaces. Before keys, a client sharing a custom
// card's id silently vanished from the launcher.
func TestLauncherKeysKeepClientAndCustomCardsApart(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	u := newUser(t, db, "user")
	cookie := newSession(t, db, u, time.Now().UTC().Add(time.Hour))

	app := &store.Application{ID: uuid.NewString(), Name: "Wiki", URL: "https://wiki.example.test", IconName: "favicon", Enabled: true}
	if err := db.CreateApplication(app, nil); err != nil {
		t.Fatal(err)
	}
	newClient(t, db, app.ID, []string{"https://sso.example.test/cb"}, []string{"openid"})

	keys := map[string]bool{}
	for _, c := range launcherState(t, srv, cookie).Applications {
		if c.Key != c.Source+":"+c.ID {
			t.Errorf("card %s key = %q, want source:id", c.Name, c.Key)
		}
		keys[c.Key] = true
	}
	if !keys["custom:"+app.ID] || !keys["client:"+app.ID] {
		t.Fatalf("both cards should be on the launcher, got %v", keys)
	}
}

func TestLauncherPrefsSaveResetAndStayPerUser(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	exp := time.Now().UTC().Add(time.Hour)
	alice, bob := newUser(t, db, "user"), newUser(t, db, "user")
	ac, bc := newSession(t, db, alice, exp), newSession(t, db, bob, exp)

	if p := launcherState(t, srv, ac).Preferences; p != nil {
		t.Fatalf("fresh preferences = %+v, want null", p)
	}
	body := `{"layout":"dock","groups":[{"name":"Daily","apps":["client:kypost"]}],"hidden":["client:kyrecovery"]}`
	if code := putPrefs(t, srv, ac, body); code != http.StatusNoContent {
		t.Fatalf("PUT returned %d", code)
	}
	got := launcherState(t, srv, ac).Preferences
	if got == nil || got.Layout != "dock" || got.Groups[0].Apps[0] != "client:kypost" || got.Hidden[0] != "client:kyrecovery" {
		t.Fatalf("saved preferences = %+v", got)
	}
	if p := launcherState(t, srv, bc).Preferences; p != nil {
		t.Fatalf("another user sees %+v", p)
	}

	if rr := call(t, srv, ac, "DELETE", "/api/user/launcher-preferences"); rr.Code != http.StatusNoContent {
		t.Fatalf("DELETE returned %d", rr.Code)
	}
	if p := launcherState(t, srv, ac).Preferences; p != nil {
		t.Fatalf("after reset = %+v, want null", p)
	}
}

// Preferences only arrange; they can never add an app the user cannot reach.
func TestLauncherPrefsCannotRevealInaccessibleApps(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	u := newUser(t, db, "user")
	cookie := newSession(t, db, u, time.Now().UTC().Add(time.Hour))
	if err := db.CreateOAuthClient(&store.OAuthClient{
		ID: "secret-app", ClientName: "Secret", ClientType: "public",
		RedirectURIsJSON: `["https://secret.example.test/cb"]`, AllowedScopesJSON: `["openid"]`, Enabled: true,
	}, nil); err != nil {
		t.Fatal(err)
	}

	if code := putPrefs(t, srv, cookie, `{"layout":"tiles","groups":[{"name":"Mine","apps":["client:secret-app"]}],"hidden":[]}`); code != http.StatusNoContent {
		t.Fatalf("PUT returned %d", code)
	}
	for _, c := range launcherState(t, srv, cookie).Applications {
		if c.ID == "secret-app" {
			t.Fatal("an unassigned app reached the launcher through preferences")
		}
	}
}

func TestLauncherPrefsRejectsBadInput(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	u := newUser(t, db, "user")
	cookie := newSession(t, db, u, time.Now().UTC().Add(time.Hour))

	for name, body := range map[string]string{
		"not json":      `{`,
		"unknown field": `{"layout":"tiles","groups":[],"hidden":[],"admin":true}`,
		"bad layout":    `{"layout":"grid","groups":[],"hidden":[]}`,
		"bad key":       `{"layout":"tiles","groups":[],"hidden":["system:x"]}`,
		"duplicate key": `{"layout":"tiles","groups":[{"name":"a","apps":["client:x"]}],"hidden":["client:x"]}`,
		"oversized":     `{"layout":"tiles","groups":[],"hidden":["client:` + strings.Repeat("a", 70*1024) + `"]}`,
	} {
		if code := putPrefs(t, srv, cookie, body); code != http.StatusBadRequest {
			t.Errorf("%s: PUT returned %d, want 400", name, code)
		}
	}
	if p := launcherState(t, srv, cookie).Preferences; p != nil {
		t.Fatalf("rejected input was stored: %+v", p)
	}
}

func TestLauncherPrefsRequireSessionAndCSRF(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	u := newUser(t, db, "user")
	cookie := newSession(t, db, u, time.Now().UTC().Add(time.Hour))
	body := `{"layout":"tiles","groups":[],"hidden":[]}`

	req := httptest.NewRequest("PUT", "/api/user/launcher-preferences", strings.NewReader(body))
	req.AddCookie(&http.Cookie{Name: "kyidentity_session", Value: cookie})
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("no CSRF: %d, want 403", rr.Code)
	}

	req = httptest.NewRequest("PUT", "/api/user/launcher-preferences", strings.NewReader(body))
	rr = httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized && rr.Code != http.StatusForbidden {
		t.Errorf("no session: %d, want 401 or 403", rr.Code)
	}
	if p := launcherState(t, srv, cookie).Preferences; p != nil {
		t.Fatalf("unauthenticated write was stored: %+v", p)
	}
}
