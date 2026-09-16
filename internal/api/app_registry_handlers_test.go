package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
)

func TestAppRegistryAdminAPI(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	user := newUser(t, db, "user")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	userCookie := newSession(t, db, user, time.Now().UTC().Add(time.Hour))
	if err := db.CreateOAuthClient(&store.OAuthClient{ID: "client", ClientName: "Client", ClientType: "confidential", ClientSecretHash: "private-client-hash", RedirectURIsJSON: `["https://example.com/cb"]`, AllowedScopesJSON: `["openid"]`, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateApplication(&store.Application{ID: "launcher", Name: "Launcher", URL: "https://example.com", IconName: "globe", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rows, _, err := db.ListAppRecords("", 25, 0)
	if err != nil || len(rows) != 2 {
		t.Fatal(err)
	}
	var target, source store.AppRecord
	for _, a := range rows {
		if a.LauncherID != "" {
			target = a
		} else {
			source = a
		}
	}
	linkPath := "/api/admin/app-registry/" + target.ID + "/link"
	unlinkPath := "/api/admin/app-registry/" + target.ID + "/unlink"
	payload, _ := json.Marshal(map[string]any{"sourceId": source.ID, "targetRevision": 1, "sourceRevision": 1})
	for _, route := range []struct{ method, path, body string }{{"GET", "/api/admin/app-registry", ""}, {"POST", linkPath, string(payload)}, {"POST", unlinkPath, `{"kind":"client","revision":2}`}} {
		for _, token := range []string{"", userCookie} {
			r := adminRequestNoStepUp(t, srv, route.method, route.path, token, route.body)
			if r.Code != 401 && r.Code != 403 {
				t.Fatalf("non-admin: %d", r.Code)
			}
		}
		if route.method == "POST" {
			r := adminRequestNoStepUp(t, srv, route.method, route.path, cookie, route.body)
			if r.Code != 403 {
				t.Fatal("missing stepup allowed")
			}
		}
	}
	r := adminRequestNoStepUp(t, srv, "GET", "/api/admin/app-registry?limit=1", cookie, "")
	var page struct {
		Records []store.AppRecord
		Total   int
	}
	if err = json.Unmarshal(r.Body.Bytes(), &page); err != nil || page.Total != 2 || len(page.Records) != 1 {
		t.Fatalf("invalid page: %s", r.Body.String())
	}
	if strings.Contains(r.Body.String(), "private-client-hash") || strings.Contains(r.Body.String(), "Secret") {
		t.Fatal("secret exposed")
	}
	wrong := mintStepUp(t, srv, cookie, "POST "+unlinkPath)
	if r := adminRequestWithStepUp(t, srv, "POST", linkPath, cookie, string(payload), wrong); r.Code != 403 {
		t.Fatal("cross-operation grant allowed")
	}
	if r := adminRequest(t, srv, "POST", linkPath, cookie, string(payload)); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	if r := adminRequest(t, srv, "POST", unlinkPath, cookie, `{"kind":"client","revision":1}`); r.Code != 409 {
		t.Fatal("stale edit allowed", r.Code)
	}
	if r := adminRequest(t, srv, "POST", unlinkPath, cookie, `{"kind":"client","revision":2}`); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	if r := adminRequestNoStepUp(t, srv, "GET", "/api/admin/app-registry?limit=101", cookie, ""); r.Code != 400 {
		t.Fatal("invalid pagination allowed")
	}
	if r := adminRequest(t, srv, "POST", unlinkPath, cookie, `{"kind":"bogus","revision":3}`); r.Code != 400 {
		t.Fatal("invalid kind allowed")
	}
	if r := adminRequest(t, srv, "POST", linkPath, cookie, `{"sourceId":"","targetRevision":1,"sourceRevision":1}`); r.Code != 400 {
		t.Fatal("invalid source allowed")
	}
	events, _, err := db.ListAuditEvents(100, 0)
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]bool{}
	for _, e := range events {
		if e.Action == "admin.app_linked" || e.Action == "admin.app_unlinked" {
			actions[e.Action] = true
			if e.TargetID != target.ID || !strings.Contains(e.DetailsJSON, "Client") || !strings.Contains(e.DetailsJSON, "Launcher") {
				t.Fatalf("missing readable audit: %+v", e)
			}
		}
	}
	if len(actions) != 2 {
		t.Fatal("missing link audit", actions)
	}
	allowTestAppAccess(t, db, "client")
	allowTestAppAccess(t, db, "launcher")
	// Legacy launcher cards retain their original IDs and remain visible.
	r = adminRequestNoStepUp(t, srv, "GET", "/api/user/applications", userCookie, "")
	if r.Code != 200 || !strings.Contains(r.Body.String(), `"id":"launcher"`) || !strings.Contains(r.Body.String(), `"id":"client"`) {
		t.Fatalf("launcher changed: %s", r.Body.String())
	}
}
