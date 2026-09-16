package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// launcherCards reads the launcher exactly as a signed-in user's dashboard does.
func launcherCards(t *testing.T, srv *Server, cookie string) []store.Application {
	t.Helper()
	req := httptest.NewRequest("GET", "/api/user/applications", nil)
	req.AddCookie(&http.Cookie{Name: "kyidentity_session", Value: cookie})
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/user/applications returned %d: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Applications []store.Application `json:"applications"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.Applications
}

func cardByID(cards []store.Application, id string) *store.Application {
	for i := range cards {
		if cards[i].ID == id {
			return &cards[i]
		}
	}
	return nil
}

// An admin describing a launcher card is a cosmetic edit. Step-up grants are single-use, so
// routing this through the client-editing endpoint would cost one MFA prompt per card.
func TestClientLauncherEditNeedsNoStepUpAndReachesTheLauncher(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	newClient(t, db, "kydns", []string{"https://dns.example.test/cb"}, []string{"openid"})

	rr := adminRequestNoStepUp(t, srv, "PUT", "/api/admin/clients/kydns/launcher", cookie,
		`{"description":"Homelab DNS with subnet views","iconName":"globe"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("launcher edit returned %d: %s", rr.Code, rr.Body.String())
	}

	card := cardByID(launcherCards(t, srv, cookie), "kydns")
	if card == nil {
		t.Fatal("edited client is not on the launcher")
	}
	if card.Description != "Homelab DNS with subnet views" {
		t.Errorf("description = %q, want the admin's text", card.Description)
	}
	if card.IconName != "globe" {
		t.Errorf("iconName = %q, want globe", card.IconName)
	}
}

// The whole point of a separate endpoint is that it cannot reach the security-relevant
// fields the step-up gate protects. Sending them must change nothing.
func TestClientLauncherEditCannotTouchClientSecurityFields(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	newClient(t, db, "kypost", []string{"https://mail.example.test/cb"}, []string{"openid"})

	before, err := db.GetOAuthClientByID("kypost")
	if err != nil || before == nil {
		t.Fatalf("client setup failed: %v", err)
	}

	rr := adminRequestNoStepUp(t, srv, "PUT", "/api/admin/clients/kypost/launcher", cookie,
		`{"description":"Mail","iconName":"mail","enabled":false,"clientType":"public",
		  "rotateSecret":true,"redirectUris":["https://evil.example.test/cb"],
		  "allowedScopes":["openid","admin"],"launchUrl":"https://evil.example.test",
		  "clientName":"Renamed"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("launcher edit returned %d: %s", rr.Code, rr.Body.String())
	}

	after, err := db.GetOAuthClientByID("kypost")
	if err != nil || after == nil {
		t.Fatalf("client vanished: %v", err)
	}
	if !after.Enabled {
		t.Error("a cosmetic edit disabled the client")
	}
	if after.ClientType != before.ClientType {
		t.Errorf("clientType changed to %q", after.ClientType)
	}
	if after.ClientSecretHash != before.ClientSecretHash {
		t.Error("a cosmetic edit rotated the client secret")
	}
	if after.RedirectURIsJSON != before.RedirectURIsJSON {
		t.Errorf("redirect URIs changed to %s", after.RedirectURIsJSON)
	}
	if after.AllowedScopesJSON != before.AllowedScopesJSON {
		t.Errorf("scopes changed to %s", after.AllowedScopesJSON)
	}
	if after.LaunchURL != before.LaunchURL {
		t.Errorf("launch URL changed to %q", after.LaunchURL)
	}
	if after.ClientName != before.ClientName {
		t.Errorf("client name changed to %q", after.ClientName)
	}
}

func TestClientLauncherEditRejectsUnknownIconAndOverlongText(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	newClient(t, db, "kynotes", []string{"https://notes.example.test/cb"}, []string{"openid"})

	bad := adminRequestNoStepUp(t, srv, "PUT", "/api/admin/clients/kynotes/launcher", cookie,
		`{"description":"Notes","iconName":"javascript"}`)
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("unknown icon returned %d, want 400", bad.Code)
	}

	long := adminRequestNoStepUp(t, srv, "PUT", "/api/admin/clients/kynotes/launcher", cookie,
		`{"description":"`+strings.Repeat("x", maxLauncherDescription+1)+`","iconName":"globe"}`)
	if long.Code != http.StatusBadRequest {
		t.Fatalf("overlong description returned %d, want 400", long.Code)
	}

	missing := adminRequestNoStepUp(t, srv, "PUT", "/api/admin/clients/nope/launcher", cookie,
		`{"description":"Nothing","iconName":"globe"}`)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("unknown client returned %d, want 404", missing.Code)
	}
}

func TestClientLauncherEditIsAdminOnly(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	user := newUser(t, db, "user")
	cookie := newSession(t, db, user, time.Now().UTC().Add(time.Hour))
	newClient(t, db, "kybookmarks", []string{"https://bm.example.test/cb"}, []string{"openid"})

	rr := adminRequestNoStepUp(t, srv, "PUT", "/api/admin/clients/kybookmarks/launcher", cookie,
		`{"description":"Mine now","iconName":"bookmark"}`)
	if rr.Code != http.StatusForbidden && rr.Code != http.StatusUnauthorized {
		t.Fatalf("non-admin launcher edit returned %d, want 401/403", rr.Code)
	}
	client, err := db.GetOAuthClientByID("kybookmarks")
	if err != nil || client == nil {
		t.Fatalf("client lookup failed: %v", err)
	}
	if client.Description != "" {
		t.Errorf("a non-admin wrote %q to the launcher", client.Description)
	}
}

// An undescribed client card carries no description at all: inventing
// "OAuth 2.0 / OIDC SSO App (confidential)" told the user nothing they could act on.
func TestUndescribedClientCardHasNoInventedText(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	newClient(t, db, "portainer", []string{"https://portainer.example.test/cb"}, []string{"openid"})

	card := cardByID(launcherCards(t, srv, cookie), "portainer")
	if card == nil {
		t.Fatal("client card is missing from the launcher")
	}
	if card.Description != "" {
		t.Errorf("description = %q, want empty until an admin writes one", card.Description)
	}
	if card.IconName != "favicon" {
		t.Errorf("iconName = %q, want favicon for an unedited client", card.IconName)
	}
	if card.Source != "client" {
		t.Errorf("source = %q, want client", card.Source)
	}
}

func TestApplicationUpdateEditsCustomCards(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))

	app := &store.Application{
		ID: uuid.New().String(), Name: "Portainer", URL: "https://portainer.example.test",
		IconName: "favicon", Enabled: true,
	}
	if err := db.CreateApplication(app); err != nil {
		t.Fatal(err)
	}

	rr := adminRequest(t, srv, "PUT", "/api/admin/applications/"+app.ID, cookie,
		`{"name":"Portainer.io","url":"https://portainer.example.test","description":"Container management","iconName":"globe"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("application update returned %d: %s", rr.Code, rr.Body.String())
	}

	allowTestAppAccess(t, db, app.ID)
	card := cardByID(launcherCards(t, srv, cookie), app.ID)
	if card == nil {
		t.Fatal("edited application is not on the launcher")
	}
	if card.Name != "Portainer.io" || card.Description != "Container management" || card.IconName != "globe" {
		t.Errorf("edit did not take: %+v", card)
	}
	if card.Source != "custom" {
		t.Errorf("source = %q, want custom", card.Source)
	}
}

func TestApplicationUpdateValidatesLikeCreation(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))

	app := &store.Application{
		ID: uuid.New().String(), Name: "Portainer", URL: "https://portainer.example.test",
		IconName: "favicon", Enabled: true,
	}
	if err := db.CreateApplication(app); err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"javascript URL": `{"name":"X","url":"javascript:alert(1)"}`,
		"unknown icon":   `{"name":"X","url":"https://x.example.test","iconName":"javascript"}`,
		"empty name":     `{"name":"","url":"https://x.example.test"}`,
	}
	for name, body := range cases {
		rr := adminRequest(t, srv, "PUT", "/api/admin/applications/"+app.ID, cookie, body)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("%s returned %d, want 400", name, rr.Code)
		}
	}

	missing := adminRequest(t, srv, "PUT", "/api/admin/applications/"+uuid.New().String(), cookie,
		`{"name":"X","url":"https://x.example.test"}`)
	if missing.Code != http.StatusNotFound {
		t.Errorf("unknown application returned %d, want 404", missing.Code)
	}

	unchanged, err := db.GetApplicationByID(app.ID)
	if err != nil || unchanged == nil {
		t.Fatalf("application lookup failed: %v", err)
	}
	if unchanged.Name != "Portainer" || unchanged.URL != "https://portainer.example.test" {
		t.Errorf("a rejected edit still changed the row: %+v", unchanged)
	}
}
