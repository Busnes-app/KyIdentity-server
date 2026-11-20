package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

type wireGroup struct {
	ID, Name, Slug, State string
	Members               []string
}

func suiteGroups(t *testing.T, srv *Server, id, secret string) []wireGroup {
	t.Helper()
	rr := suiteGet(t, srv, "/api/suite/groups", id, secret)
	if rr.Code != http.StatusOK {
		t.Fatalf("%s groups: %d %s", id, rr.Code, rr.Body.String())
	}
	var body struct{ Groups []wireGroup }
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || body.Groups == nil {
		t.Fatalf("groups body %s: %v", rr.Body.String(), err)
	}
	return body.Groups
}

func findGroup(groups []wireGroup, id string) *wireGroup {
	for i := range groups {
		if groups[i].ID == id {
			return &groups[i]
		}
	}
	return nil
}

// TestSuiteGroupLifecycle walks create, rename, add, remove, disable, re-enable, app off
// and delete through the admin API and the wire every app polls.
func TestSuiteGroupLifecycle(t *testing.T) {
	srv, db, cleanup := suiteFixture(t)
	defer cleanup()
	createClient(t, db, "kydrive", "confidential", crypto.HashSHA256("drive-secret"), "", "https://drive.example.test/cb")
	createClient(t, db, "other", "confidential", crypto.HashSHA256("other-secret"), "", "https://other.example.test/cb")
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	call := func(method, path, body string) map[string]any {
		t.Helper()
		r := adminRequest(t, srv, method, path, cookie, body)
		if r.Code != 200 {
			t.Fatalf("%s %s: %d %s", method, path, r.Code, r.Body.String())
		}
		var out map[string]any
		_ = json.Unmarshal(r.Body.Bytes(), &out)
		return out
	}
	alice := person(t, db, "user", "Alice", "alice", "alice@example.test")
	bob := person(t, db, "user", "Bob", "bob", "bob@example.test")
	noAccess := person(t, db, "user", "Nora", "nora", "nora@example.test")
	gone := person(t, db, "user", "Gail", "gail", "gail@example.test")
	for _, u := range []*store.User{alice, bob, gone, admin} {
		assignApp(t, db, "kydrive", u.ID)
		assignApp(t, db, "kypost", u.ID)
	}
	created := call("POST", "/api/admin/groups", `{"name":"Sales & Ops"}`)
	id := created["group"].(map[string]any)["id"].(string)
	path := "/api/admin/groups/" + id
	for _, u := range []*store.User{alice, bob, noAccess, gone, admin} {
		call("PUT", path+"/members/"+u.ID, "")
	}
	if _, err := db.DefaultOrg().EditUser(gone.ID, nil, func(row *store.User) (bool, error) { row.Status = "disabled"; return false, nil }); err != nil {
		t.Fatal(err)
	}

	// Off by default: nothing on the wire, defaults shown.
	if got := suiteGroups(t, srv, "kydrive", "drive-secret"); len(got) != 0 {
		t.Fatalf("group not marked yet listed: %+v", got)
	}
	settings := call("GET", path+"/suite", "")
	if settings["enabled"] != false || settings["slug"] != nil {
		t.Fatalf("default settings: %v", settings)
	}

	// Enable twice: one row, one slug.
	for range 2 {
		settings = call("PUT", path+"/suite", `{"enabled":true}`)
	}
	if settings["slug"] != "sales-ops" {
		t.Fatalf("slug: %v", settings)
	}
	drive := suiteGroups(t, srv, "kydrive", "drive-secret")
	if len(drive) != 1 || drive[0].ID != id || drive[0].State != "active" || drive[0].Name != "Sales & Ops" {
		t.Fatalf("drive wire: %+v", drive)
	}
	want := []string{alice.ID, bob.ID}
	slices.Sort(want)
	if !slices.Equal(drive[0].Members, want) {
		t.Fatalf("members %v, want only active everyday users with access %v", drive[0].Members, want)
	}
	// KyPost's distribution list is off by default; unpaired apps see nothing.
	if g := findGroup(suiteGroups(t, srv, "kypost", "post-secret"), id); g == nil || g.State != "archived" || len(g.Members) != 0 {
		t.Fatalf("kypost default: %+v", g)
	}
	if got := suiteGroups(t, srv, "other", "other-secret"); len(got) != 0 {
		t.Fatalf("unpaired app saw groups: %+v", got)
	}
	if list := call("GET", "/api/admin/groups", ""); !strings.Contains(fmt.Sprint(list), "suite:true") {
		t.Fatalf("list lacks suite flag: %v", list)
	}

	// Rename keeps the slug; removing a member drops them at the next poll.
	call("PUT", path, `{"name":"Revenue"}`)
	call("DELETE", path+"/members/"+bob.ID, "")
	g := findGroup(suiteGroups(t, srv, "kydrive", "drive-secret"), id)
	if g.Name != "Revenue" || g.Slug != "sales-ops" || !slices.Equal(g.Members, []string{alice.ID}) {
		t.Fatalf("after rename/remove: %+v", g)
	}

	// One app off, then KyPost on.
	call("PUT", path+"/suite", `{"enabled":true,"apps":{"kydrive":false,"kypost":true}}`)
	if g := findGroup(suiteGroups(t, srv, "kydrive", "drive-secret"), id); g.State != "archived" || len(g.Members) != 0 {
		t.Fatalf("drive off: %+v", g)
	}
	if g := findGroup(suiteGroups(t, srv, "kypost", "post-secret"), id); g.State != "active" || !slices.Equal(g.Members, []string{alice.ID}) {
		t.Fatalf("kypost on: %+v", g)
	}
	call("PUT", path+"/suite", `{"enabled":true,"apps":{"kydrive":true}}`)

	// Disable archives; re-enable is the same group and the same resource.
	call("PUT", path+"/suite", `{"enabled":false}`)
	if g := findGroup(suiteGroups(t, srv, "kydrive", "drive-secret"), id); g.State != "archived" || len(g.Members) != 0 {
		t.Fatalf("disabled: %+v", g)
	}
	call("PUT", path+"/suite", `{"enabled":true}`)
	if g := findGroup(suiteGroups(t, srv, "kydrive", "drive-secret"), id); g.State != "active" || g.Slug != "sales-ops" {
		t.Fatalf("re-enabled: %+v", g)
	}

	// Delete leaves a tombstone; a recreated namesake is a new group with a new slug.
	call("DELETE", path, "")
	g = findGroup(suiteGroups(t, srv, "kydrive", "drive-secret"), id)
	if g == nil || g.State != "archived" || g.Name != "Revenue" || len(g.Members) != 0 {
		t.Fatalf("deleted: %+v", g)
	}
	again := call("POST", "/api/admin/groups", `{"name":"Sales & Ops"}`)
	newID := again["group"].(map[string]any)["id"].(string)
	if s := call("PUT", "/api/admin/groups/"+newID+"/suite", `{"enabled":true}`); s["slug"] != "sales-ops-2" {
		t.Fatalf("recreated slug: %v", s)
	}
	if r := adminRequest(t, srv, "PUT", path+"/suite", cookie, `{"enabled":true}`); r.Code != 404 {
		t.Fatalf("deleted group re-enabled: %d", r.Code)
	}
	if n := len(suiteGroups(t, srv, "kydrive", "drive-secret")); n != 2 {
		t.Fatalf("want tombstone and new group, got %d", n)
	}

	// Audit: every change committed its row.
	events, _, err := db.SearchAuditEvents(store.AuditFilter{Action: "admin.group_suite_updated", Limit: 100})
	if err != nil || len(events) != 7 {
		t.Fatalf("audit rows %d %v", len(events), err)
	}
}

func TestSuiteGroupRefusals(t *testing.T) {
	srv, db, cleanup := suiteFixture(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	user := newUser(t, db, "user")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	userCookie := newSession(t, db, user, time.Now().UTC().Add(time.Hour))
	g := &store.Group{ID: "g1", Name: "Team"}
	if err := db.DefaultOrg().CreateGroup(g, nil); err != nil {
		t.Fatal(err)
	}
	path := "/api/admin/groups/g1/suite"
	for _, token := range []string{"", userCookie} {
		for _, m := range []string{"GET", "PUT"} {
			if r := adminRequestNoStepUp(t, srv, m, path, token, `{"enabled":true}`); r.Code != 401 && r.Code != 403 {
				t.Fatalf("non-admin %s: %d", m, r.Code)
			}
		}
	}
	if r := adminRequestNoStepUp(t, srv, "PUT", path, cookie, `{"enabled":true}`); r.Code != 403 || !strings.Contains(r.Body.String(), "step_up_required") {
		t.Fatalf("no step-up: %d", r.Code)
	}
	for _, body := range []string{`{}`, `{"enabled":"yes"}`, `{"enabled":true,"apps":{"kyfoo":true}}`, `{"enabled":true,"extra":1}`,
		`{"enabled":true,"apps":{"` + strings.Repeat("a", 5000) + `":true}}`} {
		if r := adminRequest(t, srv, "PUT", path, cookie, body); r.Code != 400 {
			t.Fatalf("accepted %.60s: %d %s", body, r.Code, r.Body.String())
		}
	}
	if r := adminRequest(t, srv, "PUT", "/api/admin/groups/missing/suite", cookie, `{"enabled":true}`); r.Code != 404 {
		t.Fatalf("missing group: %d", r.Code)
	}
	// Wrong credentials on the wire are the directory's uniform 401.
	for _, cred := range [][2]string{{"", ""}, {"kycalendar", "wrong"}, {"pub", ""}, {"off", "off-secret"}} {
		if rr := suiteGet(t, srv, "/api/suite/groups", cred[0], cred[1]); rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "invalid_client") {
			t.Fatalf("%v: %d %s", cred, rr.Code, rr.Body.String())
		}
	}
}
