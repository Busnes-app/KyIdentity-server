package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGroupAdminAPI(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	user := newUser(t, db, "user")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	userCookie := newSession(t, db, user, time.Now().UTC().Add(time.Hour))
	call := func(method, path, body string) *httptest.ResponseRecorder {
		return adminRequest(t, srv, method, path, cookie, body)
	}
	created := call("POST", "/api/admin/groups", `{"name":" Operations ","description":" Ops "}`)
	if created.Code != 200 {
		t.Fatal(created.Body.String())
	}
	var response struct {
		Group struct{ ID, Name, Description string }
	}
	if err := json.Unmarshal(created.Body.Bytes(), &response); err != nil || response.Group.ID == "" || response.Group.Name != "Operations" || response.Group.Description != "Ops" {
		t.Fatalf("invalid group response: %s", created.Body.String())
	}
	path := "/api/admin/groups/" + response.Group.ID
	memberPath := path + "/members/" + user.ID
	for _, route := range []struct{ method, path, body string }{
		{"GET", "/api/admin/groups", ""}, {"GET", path + "/members", ""},
		{"POST", "/api/admin/groups", `{"name":"Other"}`}, {"PUT", path, `{"name":"Other"}`},
		{"DELETE", path, ""}, {"PUT", memberPath, ""}, {"DELETE", memberPath, ""},
	} {
		for _, token := range []string{"", userCookie} {
			r := adminRequestNoStepUp(t, srv, route.method, route.path, token, route.body)
			if r.Code != 401 && r.Code != 403 {
				t.Fatalf("non-admin reached %s %s: %d", route.method, route.path, r.Code)
			}
		}
		if route.method != "GET" {
			r := adminRequestNoStepUp(t, srv, route.method, route.path, cookie, route.body)
			if r.Code != 403 || !strings.Contains(r.Body.String(), "step_up_required") {
				t.Fatalf("unprotected mutation %s %s: %d", route.method, route.path, r.Code)
			}
		}
	}
	wrong := mintStepUp(t, srv, cookie, "PUT "+path+"/members/"+admin.ID)
	if r := adminRequestWithStepUp(t, srv, "PUT", memberPath, cookie, "", wrong); r.Code != 403 {
		t.Fatal("grant used for different user")
	}
	for range 2 {
		if r := call("PUT", memberPath, ""); r.Code != 200 {
			t.Fatal(r.Body.String())
		}
	}
	r := adminRequestNoStepUp(t, srv, "GET", path+"/members?limit=1", cookie, "")
	var members struct {
		Total int
		Users []struct {
			ID     string
			Member bool
		}
	}
	if err := json.Unmarshal(r.Body.Bytes(), &members); err != nil || members.Total != 1 || len(members.Users) != 1 || members.Users[0].ID != user.ID || !members.Users[0].Member {
		t.Fatalf("members: %s", r.Body.String())
	}
	if strings.Contains(r.Body.String(), "password") || strings.Contains(r.Body.String(), "session") {
		t.Fatal("sensitive user data exposed")
	}
	r = adminRequestNoStepUp(t, srv, "GET", "/api/admin/groups?userId="+user.ID, cookie, "")
	if !strings.Contains(r.Body.String(), `"member":true`) {
		t.Fatal("user membership view missing membership")
	}
	for _, url := range []string{"/api/admin/groups?limit=101", "/api/admin/groups?offset=-1", "/api/admin/groups?limit=no", path + "/members?includeNonMembers=maybe"} {
		if r := adminRequestNoStepUp(t, srv, "GET", url, cookie, ""); r.Code != 400 {
			t.Fatalf("invalid page accepted: %s", url)
		}
	}
	if r := call("POST", "/api/admin/groups", `{"name":"OPERATIONS"}`); r.Code != 409 {
		t.Fatal("duplicate accepted")
	}
	for _, body := range []string{`{"name":"  "}`, `{"name":"line\nbreak"}`, `{"name":"ops\u202Ehidden"}`, `{"name":"ops\u200Bhidden"}`, `{"name":"ops\u00A0team"}`, `{"name":"ops\u2028team"}`, `{"name":"ops\uE000team"}`, `{"name":"ops","description":"hidden\u200Btext"}`, `{"name":"` + strings.Repeat("x", 129) + `"}`} {
		if r := call("POST", "/api/admin/groups", body); r.Code != 400 {
			t.Errorf("invalid name accepted: %s: %d", body, r.Code)
		}
	}
	if r := call("PUT", path, `{"name":"Renamed","description":"Updated"}`); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	for range 2 {
		if r := call("DELETE", memberPath, ""); r.Code != 200 {
			t.Fatal(r.Body.String())
		}
	}
	if r := call("PUT", path+"/members/missing", ""); r.Code != 404 {
		t.Fatal("missing user accepted")
	}
	if r := call("DELETE", path, ""); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	if r := adminRequestNoStepUp(t, srv, "GET", path+"/members", cookie, ""); r.Code != 404 {
		t.Fatal("deleted group visible")
	}
	events, _, err := db.ListAuditEvents(100, 0)
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]bool{}
	for _, e := range events {
		if e.ActorID == admin.ID && e.TargetID == response.Group.ID && e.Outcome == "success" {
			actions[e.Action] = true
			var details map[string]string
			if err := json.Unmarshal([]byte(e.DetailsJSON), &details); err != nil {
				t.Errorf("invalid audit details for %s: %v", e.Action, err)
			}
			switch e.Action {
			case "admin.group_deleted":
				if details["name"] != "Renamed" {
					t.Errorf("deleted group name missing: %v", details)
				}
			case "admin.group_member_added", "admin.group_member_removed":
				want := "Operations"
				if e.Action == "admin.group_member_removed" {
					want = "Renamed"
				}
				if details["userId"] != user.ID || details["username"] != user.Username || details["groupName"] != want {
					t.Errorf("membership identifiers missing: %v", details)
				}
			}
		}
	}
	for _, action := range []string{"admin.group_created", "admin.group_updated", "admin.group_deleted", "admin.group_member_added", "admin.group_member_removed"} {
		if !actions[action] {
			t.Errorf("missing audit %s", action)
		}
	}
	saved, err := db.DefaultOrg().GetUserByID(user.ID)
	if err != nil || saved.Role != "user" {
		t.Fatal("membership granted administrator role")
	}
}
