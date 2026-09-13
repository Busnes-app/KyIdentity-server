package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kysignon-server/internal/store"
)

// Every roles route is admin-only and every write needs a step-up; the flow maps a group
// to a role, lists it, and an unknown scope on a client is refused.
func TestAppRolesAdminAPI(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	user := newUser(t, db, "user")
	adminCookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	cookie := newSession(t, db, user, time.Now().UTC().Add(time.Hour))
	if err := db.CreateOAuthClient(&store.OAuthClient{ID: "roles-app", ClientName: "Roles app", ClientType: "public", RedirectURIsJSON: `["https://app.example/cb"]`, AllowedScopesJSON: `["openid"]`, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rows, _, _ := db.ListAppRecords("roles-app", 25, 0)
	app := rows[0]
	base := "/api/admin/app-registry/" + app.ID
	if err := db.CreateGroup(&store.Group{ID: "finance", Name: "Finance"}, nil); err != nil {
		t.Fatal(err)
	}

	created := adminRequest(t, srv, "POST", base+"/roles", adminCookie, `{"name":"billing.admin","description":"Runs invoices"}`)
	if created.Code != http.StatusOK {
		t.Fatalf("create role: %d %s", created.Code, created.Body.String())
	}
	var out struct {
		Role struct {
			ID string `json:"id"`
		} `json:"role"`
	}
	_ = json.Unmarshal(created.Body.Bytes(), &out)
	roleID := out.Role.ID
	mapping := base + "/roles/" + roleID + "/assignments/groups/finance"
	for _, route := range []struct{ method, path, body string }{
		{"GET", base + "/roles", ""}, {"POST", base + "/roles", `{"name":"x"}`}, {"DELETE", base + "/roles/" + roleID, ""},
		{"PUT", mapping, ""}, {"DELETE", mapping, ""}, {"PUT", base + "/claims", `{"legacyRoleClaim":false,"groupsClaim":false,"revision":1}`},
	} {
		if r := adminRequestNoStepUp(t, srv, route.method, route.path, cookie, route.body); r.Code != http.StatusForbidden {
			t.Fatalf("non-admin accessed %s %s: %d", route.method, route.path, r.Code)
		}
		if route.method != "GET" {
			if r := adminRequestNoStepUp(t, srv, route.method, route.path, adminCookie, route.body); r.Code != http.StatusForbidden {
				t.Fatalf("missing step-up on %s %s: %d", route.method, route.path, r.Code)
			}
		}
	}
	if r := adminRequest(t, srv, "POST", base+"/roles", adminCookie, `{"name":"billing.admin"}`); r.Code != http.StatusConflict {
		t.Fatalf("duplicate role: %d", r.Code)
	}
	if r := adminRequest(t, srv, "POST", base+"/roles", adminCookie, `{"name":"bad name"}`); r.Code != http.StatusBadRequest {
		t.Fatalf("invalid role name: %d", r.Code)
	}
	if r := adminRequest(t, srv, "PUT", mapping, adminCookie, ""); r.Code != http.StatusOK {
		t.Fatalf("map group: %d %s", r.Code, r.Body.String())
	}
	listed := adminRequestNoStepUp(t, srv, "GET", base+"/roles", adminCookie, "")
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"name":"Finance"`) || !strings.Contains(listed.Body.String(), `"legacyRoleClaim":false`) {
		t.Fatalf("list roles: %d %s", listed.Code, listed.Body.String())
	}
	app, _ = db.GetAppRecord(app.ID)
	if r := adminRequest(t, srv, "PUT", base+"/claims", adminCookie, `{"legacyRoleClaim":true,"groupsClaim":true,"revision":`+itoa(app.Revision)+`}`); r.Code != http.StatusOK {
		t.Fatalf("claim settings: %d %s", r.Code, r.Body.String())
	}
	if r := adminRequest(t, srv, "PUT", base+"/claims", adminCookie, `{"legacyRoleClaim":true,"groupsClaim":true,"revision":1}`); r.Code != http.StatusConflict {
		t.Fatalf("stale revision: %d", r.Code)
	}
	if r := adminRequest(t, srv, "DELETE", base+"/roles/"+roleID, adminCookie, ""); r.Code != http.StatusOK {
		t.Fatalf("delete role: %d", r.Code)
	}
	if n := countAudit(t, db, "admin.app_role_mapped"); n != 1 {
		t.Fatalf("mapping audit rows = %d", n)
	}

	// Unknown scopes are refused on client create and update.
	if r := adminRequest(t, srv, "PUT", "/api/admin/clients/roles-app", adminCookie, `{"allowedScopes":["openid","admin:everything"]}`); r.Code != http.StatusBadRequest || !strings.Contains(r.Body.String(), "unknown_scope") {
		t.Fatalf("unknown scope on update: %d %s", r.Code, r.Body.String())
	}
	if r := adminRequest(t, srv, "POST", "/api/admin/clients", adminCookie, `{"clientName":"x","clientType":"public","redirectUris":["https://x/cb"],"allowedScopes":["openid","groups"]}`); r.Code != http.StatusBadRequest || !strings.Contains(r.Body.String(), "unknown_scope") {
		t.Fatalf("unknown scope on create: %d %s", r.Code, r.Body.String())
	}
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}
