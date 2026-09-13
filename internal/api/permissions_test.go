package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kysignon-server/internal/store"
)

// The permission matrix: every admin route, every kind of actor. A route is allowed
// when the answer is anything but the permission refusal; the handler may still reject
// the placeholder input, which is not this test's concern.
func TestPermissionMatrixCoversEveryAdminRoute(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	exp := time.Now().UTC().Add(time.Hour)
	for _, id := range []string{"app-a", "app-b"} {
		if err := db.CreateOAuthClient(&store.OAuthClient{ID: id, ClientName: id, ClientType: "public", RedirectURIsJSON: `["https://a/cb"]`, AllowedScopesJSON: `["openid"]`, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	appA, _, _ := db.ListAppRecords("app-a", 1, 0)
	appB, _, _ := db.ListAppRecords("app-b", 1, 0)
	target := newUser(t, db, "user")
	targetAdmin := newUser(t, db, "admin")

	delegate := func(d store.Delegations) (*store.User, string) {
		u := newUser(t, db, "user")
		if err := db.SetDelegations(u.ID, d, nil); err != nil {
			t.Fatal(err)
		}
		return u, newSession(t, db, u, exp)
	}
	_, plain := delegate(store.Delegations{})
	_, auditor := delegate(store.Delegations{Auditor: true})
	_, helpdesk := delegate(store.Delegations{Helpdesk: true})
	ownerA, ownerACookie := delegate(store.Delegations{AppOwner: []string{appA[0].ID}})
	_, ownerB := delegate(store.Delegations{AppOwner: []string{appB[0].ID}})
	admin := newSession(t, db, newUser(t, db, "admin"), exp)
	personas := map[string]string{"plain": plain, "auditor": auditor, "helpdesk": helpdesk, "ownerA": ownerACookie, "ownerB": ownerB, "admin": admin}

	// Hand-written expectations per permission; the route table names the permission.
	allowed := map[string][]string{
		"admin":      {"admin"},
		"read":       {"admin", "auditor"},
		"directory":  {"admin", "auditor", "helpdesk", "ownerA", "ownerB"},
		"user_read":  {"admin", "auditor", "helpdesk"},
		"recovery":   {"admin", "helpdesk"},
		"app_read":   {"admin", "auditor", "ownerA"},
		"app_grants": {"admin", "ownerA"},
	}
	forbidden := func(method, path, cookie string) bool {
		res := adminRequestWithStepUp(t, srv, method, path, cookie, `{}`, mintStepUp(t, srv, cookie, method+" "+path))
		return res.Code == http.StatusForbidden && strings.Contains(res.Body.String(), `"error":"forbidden"`)
	}
	pathFor := func(rt adminRoute, userID string) string {
		p := rt.path
		if rt.perm.appOwner {
			p = strings.Replace(p, "{id}", appA[0].ID, 1)
		} else {
			p = strings.Replace(p, "{id}", userID, 1)
		}
		p = strings.Replace(p, "{kind}", "users", 1)
		for _, ph := range []string{"{sid}", "{clientId}", "{deliveryId}", "{roleId}", "{principal}", "{token}", "{userId}", "{tokenId}"} {
			p = strings.Replace(p, ph, "x", 1)
		}
		return p
	}
	if len(srv.adminRoutes) < 80 {
		t.Fatalf("route table lost routes: %d", len(srv.adminRoutes))
	}
	for _, rt := range srv.adminRoutes {
		expect, known := allowed[rt.perm.name]
		if !known {
			t.Fatalf("%s %s uses a permission outside the matrix: %q", rt.method, rt.path, rt.perm.name)
		}
		path := pathFor(rt, target.ID)
		for name, cookie := range personas {
			want := !containsName(expect, name)
			if got := forbidden(rt.method, path, cookie); got != want {
				t.Errorf("%s %s as %s: forbidden=%v want %v", rt.method, path, name, got, want)
			}
		}
		// Helpdesk may recover ordinary accounts, never administrators.
		if rt.perm.protectAdmins {
			if !forbidden(rt.method, pathFor(rt, targetAdmin.ID), helpdesk) {
				t.Errorf("%s %s: helpdesk reached an administrator", rt.method, rt.path)
			}
			if forbidden(rt.method, pathFor(rt, targetAdmin.ID), admin) {
				t.Errorf("%s %s: admin blocked from an administrator", rt.method, rt.path)
			}
		}
	}

	// An owner's listing is only their app; a removed delegation is gone on the next call.
	list := adminRequestWithStepUp(t, srv, "GET", "/api/admin/app-registry", ownerACookie, "", "")
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), appA[0].ID) || strings.Contains(list.Body.String(), appB[0].ID) {
		t.Fatalf("owner listing: %d %s", list.Code, list.Body.String())
	}
	if err := db.SetDelegations(ownerA.ID, store.Delegations{}, nil); err != nil {
		t.Fatal(err)
	}
	if !forbidden("GET", "/api/admin/app-registry/"+appA[0].ID+"/roles", ownerACookie) {
		t.Fatal("removed delegation still honoured on the same session")
	}
	if !forbidden("GET", "/api/admin/app-registry", ownerACookie) {
		t.Fatal("removed owner still lists apps")
	}
}

// Delegations are set by global administrators over the API, with step-up and audit,
// and appear in the acting user's own profile.
func TestDelegationsAdminAPI(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	exp := time.Now().UTC().Add(time.Hour)
	admin := newSession(t, db, newUser(t, db, "admin"), exp)
	u := newUser(t, db, "user")
	cookie := newSession(t, db, u, exp)
	if err := db.CreateOAuthClient(&store.OAuthClient{ID: "app-a", ClientName: "A", ClientType: "public", RedirectURIsJSON: `["https://a/cb"]`, AllowedScopesJSON: `["openid"]`, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	apps, _, _ := db.ListAppRecords("app-a", 1, 0)
	path := "/api/admin/users/" + u.ID + "/delegations"

	if res := adminRequestNoStepUp(t, srv, "PUT", path, admin, `{"helpdesk":true}`); res.Code != http.StatusForbidden || !strings.Contains(res.Body.String(), "step_up_required") {
		t.Fatalf("delegation without step-up: %d %s", res.Code, res.Body.String())
	}
	if res := adminRequest(t, srv, "PUT", path, admin, `{"appOwner":["nope"]}`); res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "unknown_app") {
		t.Fatalf("unknown app: %d %s", res.Code, res.Body.String())
	}
	if res := adminRequest(t, srv, "PUT", "/api/admin/users/missing/delegations", admin, `{}`); res.Code != http.StatusNotFound {
		t.Fatalf("missing user: %d", res.Code)
	}
	res := adminRequest(t, srv, "PUT", path, admin, `{"helpdesk":true,"appOwner":["`+apps[0].ID+`"]}`)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"helpdesk":true`) {
		t.Fatalf("set: %d %s", res.Code, res.Body.String())
	}
	if res := adminRequestWithStepUp(t, srv, "GET", path, admin, "", ""); res.Code != http.StatusOK || !strings.Contains(res.Body.String(), apps[0].ID) {
		t.Fatalf("get: %d %s", res.Code, res.Body.String())
	}
	events, _, _ := db.ListAuditEvents(50, 0)
	audited := 0
	for _, e := range events {
		if e.Action == "admin.delegations_updated" && e.TargetID == u.ID {
			audited++
		}
	}
	if audited != 1 {
		t.Fatalf("audit rows = %d", audited)
	}
	me := adminRequestWithStepUp(t, srv, "GET", "/api/auth/me", cookie, "", "")
	if me.Code != http.StatusOK || !strings.Contains(me.Body.String(), `"access":{"admin":false,"helpdesk":true,"auditor":false,"appOwner":["`+apps[0].ID+`"]}`) {
		t.Fatalf("me: %d %s", me.Code, me.Body.String())
	}
	// A delegate cannot delegate, however much they hold.
	if res := adminRequest(t, srv, "PUT", path, cookie, `{"auditor":true}`); res.Code != http.StatusForbidden {
		t.Fatalf("delegate changed delegations: %d", res.Code)
	}
}

func containsName(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
