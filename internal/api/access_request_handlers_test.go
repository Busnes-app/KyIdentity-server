package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kysignon-server/internal/store"
)

// A user sees only requestable apps, files one request per app, and an owner or
// administrator answers it with step-up; an approval is a bounded ordinary grant.
func TestAccessRequestsEndToEnd(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	exp := time.Now().UTC().Add(time.Hour)
	admin := newSession(t, db, newUser(t, db, "admin"), exp)
	requester := newUser(t, db, "user")
	userCookie := newSession(t, db, requester, exp)
	owner := newUser(t, db, "user")
	ownerCookie := newSession(t, db, owner, exp)
	for _, id := range []string{"open-app", "private-app"} {
		if err := db.CreateOAuthClient(&store.OAuthClient{ID: id, ClientName: id, ClientType: "public", RedirectURIsJSON: `["https://a/cb"]`, AllowedScopesJSON: `["openid"]`, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	open, _, _ := db.ListAppRecords("open-app", 1, 0)
	private, _, _ := db.ListAppRecords("private-app", 1, 0)
	if err := db.SetDelegations(owner.ID, store.Delegations{AppOwner: []string{open[0].ID}}, nil); err != nil {
		t.Fatal(err)
	}
	// Only a global administrator opens an app to requests; the owner cannot.
	if res := adminRequest(t, srv, "PUT", "/api/admin/app-registry/"+open[0].ID+"/requestable", ownerCookie, `{"requestable":true,"revision":1}`); res.Code != http.StatusForbidden {
		t.Fatalf("owner opened the app: %d", res.Code)
	}
	if res := adminRequest(t, srv, "PUT", "/api/admin/app-registry/"+open[0].ID+"/requestable", admin, `{"requestable":true,"revision":1}`); res.Code != http.StatusOK {
		t.Fatalf("open app: %d %s", res.Code, res.Body.String())
	}

	// The user sees the open app and nothing about the private one, by listing or by id.
	own := call(t, srv, userCookie, "GET", "/api/user/access-requests")
	if own.Code != http.StatusOK || !strings.Contains(own.Body.String(), open[0].ID) || strings.Contains(own.Body.String(), private[0].ID) {
		t.Fatalf("requestable listing: %d %s", own.Code, own.Body.String())
	}
	post := func(cookie, body string) int {
		return adminRequestWithStepUp(t, srv, "POST", "/api/user/access-requests", cookie, body, "").Code
	}
	if code := post(userCookie, `{"appId":"`+private[0].ID+`","reason":"let me in"}`); code != http.StatusNotFound {
		t.Fatalf("private app request: %d", code)
	}
	if code := post(userCookie, `{"appId":"missing","reason":"let me in"}`); code != http.StatusNotFound {
		t.Fatalf("missing app request distinguishable: %d", code)
	}
	if code := post(userCookie, `{"appId":"`+open[0].ID+`","reason":""}`); code != http.StatusBadRequest {
		t.Fatalf("empty reason: %d", code)
	}
	created := adminRequestWithStepUp(t, srv, "POST", "/api/user/access-requests", userCookie, `{"appId":"`+open[0].ID+`","reason":"Quarter close","durationSeconds":3600}`, "")
	if created.Code != http.StatusOK {
		t.Fatalf("request: %d %s", created.Code, created.Body.String())
	}
	var out struct {
		Request store.AccessRequest `json:"request"`
	}
	_ = json.Unmarshal(created.Body.Bytes(), &out)
	if code := post(userCookie, `{"appId":"`+open[0].ID+`","reason":"again"}`); code != http.StatusConflict {
		t.Fatalf("duplicate: %d", code)
	}

	// The owner's inbox holds it; a user with no authority has no inbox; the requester
	// cannot decide it; the decision needs step-up.
	inbox := adminRequestWithStepUp(t, srv, "GET", "/api/admin/access-requests", ownerCookie, "", "")
	if inbox.Code != http.StatusOK || !strings.Contains(inbox.Body.String(), out.Request.ID) {
		t.Fatalf("owner inbox: %d %s", inbox.Code, inbox.Body.String())
	}
	if res := adminRequestWithStepUp(t, srv, "GET", "/api/admin/access-requests", userCookie, "", ""); res.Code != http.StatusForbidden {
		t.Fatalf("requester reached the inbox: %d", res.Code)
	}
	approve := "/api/admin/access-requests/" + out.Request.ID + "/approve"
	if res := adminRequestNoStepUp(t, srv, "POST", approve, ownerCookie, `{}`); res.Code != http.StatusForbidden || !strings.Contains(res.Body.String(), "step_up_required") {
		t.Fatalf("approval without step-up: %d %s", res.Code, res.Body.String())
	}
	// A second owner of a different app is refused by the store's recheck.
	other := newUser(t, db, "user")
	otherCookie := newSession(t, db, other, exp)
	if err := db.SetDelegations(other.ID, store.Delegations{AppOwner: []string{private[0].ID}}, nil); err != nil {
		t.Fatal(err)
	}
	if res := adminRequest(t, srv, "POST", approve, otherCookie, `{}`); res.Code != http.StatusForbidden {
		t.Fatalf("other owner approved: %d %s", res.Code, res.Body.String())
	}
	res := adminRequest(t, srv, "POST", approve, ownerCookie, `{"note":"Enjoy"}`)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"status":"approved"`) {
		t.Fatalf("approve: %d %s", res.Code, res.Body.String())
	}
	if res := adminRequest(t, srv, "POST", approve, admin, `{}`); res.Code != http.StatusConflict {
		t.Fatalf("second approval: %d", res.Code)
	}
	if allowed, _ := db.ClientAccessAllowed(requester.ID, "open-app"); !allowed {
		t.Fatal("approval granted no access")
	}
	if end, _ := db.AccessEndsAt(requester.ID, "open-app"); end == nil {
		t.Fatal("approval lost the requested duration")
	}
	list := adminRequestWithStepUp(t, srv, "GET", "/api/admin/app-registry/"+open[0].ID+"/access-users?q="+requester.Username, admin, "", "")
	if !strings.Contains(list.Body.String(), `"direct":true`) || !strings.Contains(list.Body.String(), "directExpiresAt") {
		t.Fatalf("approval is not an ordinary bounded assignment: %s", list.Body.String())
	}
	// Own listing shows the decision; cancelling a decided request is refused.
	own = call(t, srv, userCookie, "GET", "/api/user/access-requests")
	if !strings.Contains(own.Body.String(), `"status":"approved"`) || !strings.Contains(own.Body.String(), `"decisionNote":"Enjoy"`) {
		t.Fatalf("own listing after decision: %s", own.Body.String())
	}
	if res := call(t, srv, userCookie, "DELETE", "/api/user/access-requests/"+out.Request.ID); res.Code != http.StatusConflict {
		t.Fatalf("cancel after decision: %d", res.Code)
	}
	events, _, _ := db.ListAuditEvents(20, 0)
	seen := map[string]bool{}
	for _, e := range events {
		seen[e.Action] = true
	}
	if !seen["access.request_created"] || !seen["access.request_approved"] {
		t.Fatalf("decisions not audited: %v", seen)
	}
}
