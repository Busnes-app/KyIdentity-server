package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kysignon-server/internal/store"
)

// Expiry instants arrive as RFC 3339, must lie in the future, ride the existing
// assignment, membership and user routes, and come back on the listings.
func TestExpiringAccessAdminAPI(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	exp := time.Now().UTC().Add(time.Hour)
	me := newUser(t, db, "admin")
	admin := newSession(t, db, me, exp)
	u := newUser(t, db, "user")
	if err := db.CreateOAuthClient(&store.OAuthClient{ID: "app-a", ClientName: "A", ClientType: "public", RedirectURIsJSON: `["https://a/cb"]`, AllowedScopesJSON: `["openid"]`, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	apps, _, _ := db.ListAppRecords("app-a", 1, 0)
	if err := db.CreateGroup(&store.Group{ID: "staff", Name: "Staff"}, nil); err != nil {
		t.Fatal(err)
	}
	future := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Second).Format(time.RFC3339)
	past := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	assign := "/api/admin/app-registry/" + apps[0].ID + "/assignments/users/" + u.ID

	if res := adminRequest(t, srv, "PUT", assign, admin, `{"expiresAt":"`+past+`"}`); res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "expiry_in_past") {
		t.Fatalf("past expiry: %d %s", res.Code, res.Body.String())
	}
	if res := adminRequest(t, srv, "PUT", assign, admin, `{"expiresAt":"yesterday"}`); res.Code != http.StatusBadRequest {
		t.Fatalf("garbage expiry: %d", res.Code)
	}
	if res := adminRequest(t, srv, "PUT", "/api/admin/app-registry/"+apps[0].ID+"/assignments/groups/staff", admin, `{"expiresAt":"`+future+`"}`); res.Code != http.StatusBadRequest {
		t.Fatalf("group assignment expiry accepted: %d", res.Code)
	}
	if res := adminRequest(t, srv, "PUT", assign, admin, `{"expiresAt":"`+future+`"}`); res.Code != http.StatusOK {
		t.Fatalf("future expiry: %d %s", res.Code, res.Body.String())
	}
	list := adminRequestWithStepUp(t, srv, "GET", "/api/admin/app-registry/"+apps[0].ID+"/access-users?q="+u.Username, admin, "", "")
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"directExpiresAt":"`+future+`"`) {
		t.Fatalf("listing lacks the expiry: %d %s", list.Code, list.Body.String())
	}
	// A repeat with no instant lifts the bound; a plain remove still works.
	if res := adminRequest(t, srv, "PUT", assign, admin, ""); res.Code != http.StatusOK {
		t.Fatalf("unbounded repeat: %d", res.Code)
	}
	if list := adminRequestWithStepUp(t, srv, "GET", "/api/admin/app-registry/"+apps[0].ID+"/access-users?q="+u.Username, admin, "", ""); strings.Contains(list.Body.String(), "directExpiresAt") {
		t.Fatal("bound survived an unbounded repeat")
	}

	member := "/api/admin/groups/staff/members/" + u.ID
	if res := adminRequest(t, srv, "PUT", member, admin, `{"expiresAt":"`+past+`"}`); res.Code != http.StatusBadRequest {
		t.Fatalf("past membership expiry: %d", res.Code)
	}
	if res := adminRequest(t, srv, "PUT", member, admin, `{"expiresAt":"`+future+`"}`); res.Code != http.StatusOK {
		t.Fatalf("membership expiry: %d %s", res.Code, res.Body.String())
	}
	if members := adminRequestWithStepUp(t, srv, "GET", "/api/admin/groups/staff/members", admin, "", ""); !strings.Contains(members.Body.String(), `"expiresAt":"`+future+`"`) {
		t.Fatalf("member listing lacks the expiry: %s", members.Body.String())
	}

	userPath := "/api/admin/users/" + u.ID
	if res := adminRequest(t, srv, "PUT", userPath, admin, `{"displayName":"`+u.DisplayName+`","email":"`+u.Email+`","role":"user","status":"active","endsAt":"`+past+`"}`); res.Code != http.StatusBadRequest {
		t.Fatalf("past end date: %d", res.Code)
	}
	if res := adminRequest(t, srv, "PUT", userPath, admin, `{"displayName":"`+u.DisplayName+`","email":"`+u.Email+`","role":"user","status":"active","endsAt":"`+future+`"}`); res.Code != http.StatusOK {
		t.Fatalf("end date: %d %s", res.Code, res.Body.String())
	}
	if users := adminRequestWithStepUp(t, srv, "GET", "/api/admin/users", admin, "", ""); !strings.Contains(users.Body.String(), `"endsAt":"`+future+`"`) {
		t.Fatalf("user listing lacks the end date: %s", users.Body.String())
	}
	if res := adminRequest(t, srv, "PUT", userPath, admin, `{"displayName":"`+u.DisplayName+`","email":"`+u.Email+`","role":"user","status":"active"}`); res.Code != http.StatusOK {
		t.Fatalf("clear end date: %d", res.Code)
	}
	if users := adminRequestWithStepUp(t, srv, "GET", "/api/admin/users", admin, "", ""); strings.Contains(users.Body.String(), `"endsAt"`) {
		t.Fatal("end date survived being cleared")
	}
	// The last administrator cannot be scheduled to end.
	if res := adminRequest(t, srv, "PUT", "/api/admin/users/"+me.ID, admin, `{"displayName":"`+me.DisplayName+`","email":"`+me.Email+`","role":"admin","status":"active","endsAt":"`+future+`"}`); res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "cannot_remove_last_admin") {
		t.Fatalf("last admin scheduled: %d %s", res.Code, res.Body.String())
	}
}
