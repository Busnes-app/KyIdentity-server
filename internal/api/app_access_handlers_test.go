package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
)

func TestAppAssignmentOAuthAndLauncherEnforcement(t *testing.T) {
	srv, db, _, _, oe, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	user := newUser(t, db, "user")
	adminCookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	cookie := newSession(t, db, user, time.Now().UTC().Add(time.Hour))
	if err := db.CreateOAuthClient(&store.OAuthClient{ID: "assigned-app", ClientName: "Restricted app", ClientType: "public", RedirectURIsJSON: `["https://app.example/cb"]`, AllowedScopesJSON: `["openid"]`, LaunchURL: "https://app.example", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rows, _, err := db.ListAppRecords("assigned-app", 25, 0)
	if err != nil || len(rows) != 1 {
		t.Fatal(err)
	}
	app := rows[0]
	base := "/api/admin/app-registry/" + app.ID
	if err := db.CreateGroup(&store.Group{ID: "engineering", Name: "Engineering"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.SetGroupMembership("engineering", user.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	assignment := base + "/assignments/groups/engineering"
	for _, route := range []struct{ method, path, body string }{{"GET", base + "/access-users", ""}, {"GET", base + "/access-groups", ""}, {"PUT", assignment, ""}, {"DELETE", assignment, ""}, {"PUT", base + "/access-policy", `{"mode":"all_active_users","enabled":true,"revision":1}`}} {
		if r := adminRequestNoStepUp(t, srv, route.method, route.path, cookie, route.body); r.Code != 403 {
			t.Fatalf("non-admin accessed %s: %d", route.path, r.Code)
		}
		if route.method != "GET" {
			if r := adminRequestNoStepUp(t, srv, route.method, route.path, adminCookie, route.body); r.Code != 403 {
				t.Fatalf("missing step-up: %d", r.Code)
			}
		}
	}
	verifier := strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	authorize := func(session string) url.Values {
		q := url.Values{"client_id": {"assigned-app"}, "redirect_uri": {"https://app.example/cb"}, "response_type": {"code"}, "scope": {"openid"}, "state": {"kept"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
		r := adminRequestNoStepUp(t, srv, "GET", "/oauth/authorize?"+q.Encode(), session, "")
		location, err := url.Parse(r.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		if location.Query().Get("state") != "kept" {
			t.Fatal("state lost", r.Body.String())
		}
		return location.Query()
	}
	for _, session := range []string{cookie, adminCookie} {
		if q := authorize(session); q.Get("error") != "access_denied" {
			t.Fatal("direct URL bypass", q)
		}
		r := adminRequestNoStepUp(t, srv, "GET", "/api/user/applications", session, "")
		if strings.Contains(r.Body.String(), "assigned-app") {
			t.Fatal("unassigned app visible")
		}
	}
	wrong := mintStepUp(t, srv, adminCookie, "PUT "+base+"/assignments/users/"+user.ID)
	if r := adminRequestWithStepUp(t, srv, "PUT", assignment, adminCookie, "", wrong); r.Code != 403 {
		t.Fatal("cross-target grant allowed")
	}
	for range 2 {
		if r := adminRequest(t, srv, "PUT", assignment, adminCookie, ""); r.Code != 200 {
			t.Fatal(r.Body.String())
		}
	}
	r := adminRequestNoStepUp(t, srv, "GET", base+"/access-users?limit=1&q="+url.QueryEscape(user.Username), adminCookie, "")
	var preview struct {
		Users []store.AppAccessUser
		App   store.AppRecord
	}
	if err := json.Unmarshal(r.Body.Bytes(), &preview); err != nil || len(preview.Users) != 1 || !preview.Users[0].Effective || !preview.Users[0].GroupAssigned || preview.Users[0].Direct {
		t.Fatalf("wrong effective access: %s", r.Body.String())
	}
	r = adminRequestNoStepUp(t, srv, "GET", "/api/user/applications", cookie, "")
	if !strings.Contains(r.Body.String(), "assigned-app") {
		t.Fatal("assigned app hidden")
	}
	q := authorize(cookie)
	if q.Get("code") == "" {
		t.Fatal(q)
	}
	tokens, err := oe.ExchangeAuthorizationCode(q.Get("code"), "assigned-app", "", "https://app.example/cb", verifier)
	if err != nil {
		t.Fatal(err)
	}
	pending := authorize(cookie).Get("code")
	if pending == "" {
		t.Fatal("missing pending code")
	}
	// Membership removal uses the existing group API, and revokes in that same transaction.
	if r := adminRequest(t, srv, "DELETE", "/api/admin/groups/engineering/members/"+user.ID, adminCookie, ""); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	if _, err := oe.ExchangeAuthorizationCode(pending, "assigned-app", "", "https://app.example/cb", verifier); err == nil {
		t.Fatal("membership removal did not block exchange")
	}
	request := httptest.NewRequest("GET", "/oauth/userinfo", nil)
	request.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, request)
	if rec.Code != 401 {
		t.Fatalf("revoked online token accepted: %d", rec.Code)
	}
	if q := authorize(cookie); q.Get("error") != "access_denied" {
		t.Fatal("lost membership kept authorization", q)
	}
	// Previews and policy validation remain admin-only and revision protected.
	if r := adminRequest(t, srv, "PUT", base+"/access-policy", adminCookie, `{"mode":"all_active_users","enabled":true,"revision":1}`); r.Code != 409 {
		t.Fatal("stale policy accepted")
	}
	if r := adminRequest(t, srv, "PUT", base+"/access-policy", adminCookie, `{"mode":"all_active_users","revision":3}`); r.Code != 400 {
		t.Fatal("missing enabled allowed")
	}
	if r := adminRequestNoStepUp(t, srv, "GET", base+"/access-users?mode=bogus", adminCookie, ""); r.Code != 400 {
		t.Fatal("invalid preview allowed")
	}
	events, _, err := db.ListAuditEvents(100, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Action == "admin.app_assignment_added" {
			found = true
			if !strings.Contains(e.DetailsJSON, "Engineering") || !strings.Contains(e.DetailsJSON, "Restricted app") {
				t.Fatal("audit lost identifiers")
			}
		}
	}
	if !found {
		t.Fatal("missing assignment audit")
	}
}

func TestAppAccessEnabledPreview(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	newClient(t, db, "preview-app", []string{"https://app.example/cb"}, []string{"openid"})
	apps, _, err := db.ListAppRecords("preview-app", 25, 0)
	if err != nil || len(apps) != 1 {
		t.Fatalf("app lookup: %+v %v", apps, err)
	}
	path := "/api/admin/app-registry/" + apps[0].ID + "/access-users?enabled="
	for _, enabled := range []string{"false", "true"} {
		r := adminRequestNoStepUp(t, srv, "GET", path+enabled, cookie, "")
		var p store.AppAccessUsers
		if r.Code != 200 {
			t.Fatalf("preview status=%d: %s", r.Code, r.Body.String())
		}
		if err := json.Unmarshal(r.Body.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		wantLoss := 1
		if enabled == "true" {
			wantLoss = 0
		}
		if p.LosingAccess != wantLoss || len(p.Users) != 1 || !p.Users[0].Effective || p.Users[0].Preview != (enabled == "true") || !p.App.Enabled {
			t.Fatalf("enabled=%s: wrong preview: %s", enabled, r.Body.String())
		}
	}
	if r := adminRequestNoStepUp(t, srv, "GET", path+"maybe", cookie, ""); r.Code != 400 {
		t.Fatalf("invalid enabled accepted: %d %s", r.Code, r.Body.String())
	}
}
