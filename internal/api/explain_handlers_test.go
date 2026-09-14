package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kysignon-server/internal/store"
)

// Explanations follow viewer permissions: owners and auditors see their app's
// explanation, a user sees only their own verdict and the actionable next step, and a
// denial's audit row carries the reason and the policy revisions of that moment.
func TestExplanationsFollowViewerPermissions(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	exp := time.Now().UTC().Add(time.Hour)
	admin := newSession(t, db, newUser(t, db, "admin"), exp)
	u := newUser(t, db, "user")
	userCookie := newSession(t, db, u, exp)
	for _, id := range []string{"app-a", "app-b"} {
		if err := db.CreateOAuthClient(&store.OAuthClient{ID: id, ClientName: id, ClientType: "public", RedirectURIsJSON: `["https://a/cb"]`, AllowedScopesJSON: `["openid"]`, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	appA, _, _ := db.ListAppRecords("app-a", 1, 0)
	appB, _, _ := db.ListAppRecords("app-b", 1, 0)
	ownerB := newUser(t, db, "user")
	ownerBCookie := newSession(t, db, ownerB, exp)
	if err := db.SetDelegations(ownerB.ID, store.Delegations{AppOwner: []string{appB[0].ID}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateGroup(&store.Group{ID: "secret", Name: "Secret Project"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.SetAppAssignment(appA[0].ID, "groups", "secret", true, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.SetGroupMembership("secret", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	explainA := "/api/admin/app-registry/" + appA[0].ID + "/access-users/" + u.ID + "/explain"

	// The administrator sees the contributing group; the owner of another app cannot
	// reach this app's explanation at all, so it discloses no group name to them.
	res := adminRequestWithStepUp(t, srv, "GET", explainA, admin, "", "")
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"groupName":"Secret Project"`) || !strings.Contains(res.Body.String(), `"reason":"group_assignment"`) {
		t.Fatalf("admin explanation: %d %s", res.Code, res.Body.String())
	}
	if res := adminRequestWithStepUp(t, srv, "GET", explainA, ownerBCookie, "", ""); res.Code != http.StatusForbidden {
		t.Fatalf("other owner explained a foreign app: %d", res.Code)
	}
	if res := adminRequestWithStepUp(t, srv, "GET", explainA, userCookie, "", ""); res.Code != http.StatusForbidden {
		t.Fatalf("user reached the admin explanation: %d", res.Code)
	}
	if res := adminRequestWithStepUp(t, srv, "GET", "/api/admin/app-registry/"+appA[0].ID+"/access-users/nobody/explain", admin, "", ""); res.Code != http.StatusNotFound {
		t.Fatalf("missing user: %d", res.Code)
	}

	// The user's own view: allowed for app-a with no group named; denied for app-b with
	// no app name until it is requestable.
	own := call(t, srv, userCookie, "GET", "/api/user/access-explanation?clientId=app-a")
	if own.Code != http.StatusOK || !strings.Contains(own.Body.String(), `"allowed":true`) || strings.Contains(own.Body.String(), "Secret") {
		t.Fatalf("own explanation: %d %s", own.Code, own.Body.String())
	}
	own = call(t, srv, userCookie, "GET", "/api/user/access-explanation?clientId=app-b")
	if own.Code != http.StatusOK || !strings.Contains(own.Body.String(), `"allowed":false`) || strings.Contains(own.Body.String(), "appName") || !strings.Contains(own.Body.String(), `"requestable":false`) {
		t.Fatalf("own denial: %d %s", own.Code, own.Body.String())
	}
	if err := db.SetAppRequestable(appB[0].ID, true, appB[0].Revision, nil); err != nil {
		t.Fatal(err)
	}
	own = call(t, srv, userCookie, "GET", "/api/user/access-explanation?clientId=app-b")
	if !strings.Contains(own.Body.String(), `"requestable":true`) || !strings.Contains(own.Body.String(), `"appName":"app-b"`) {
		t.Fatalf("own actionable denial: %s", own.Body.String())
	}
	if res := call(t, srv, userCookie, "GET", "/api/user/access-explanation?clientId=nope"); res.Code != http.StatusNotFound {
		t.Fatalf("unknown client: %d", res.Code)
	}

	// A denied authorization is audited with the reason and revisions of that moment,
	// and the redirect tells a user of a requestable app what to do.
	res = call(t, srv, userCookie, "GET", "/oauth/authorize?client_id=app-b&redirect_uri=https%3A%2F%2Fa%2Fcb&response_type=code&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&state=s")
	if loc := res.Header().Get("Location"); !strings.Contains(loc, "access_denied") || !strings.Contains(loc, "request") {
		t.Fatalf("denial redirect: %d %s", res.Code, loc)
	}
	events, _, _ := db.ListAuditEvents(10, 0)
	found := false
	for _, e := range events {
		if e.Action == "oauth.authorize" && e.Outcome == "denied" && e.TargetID == "app-b" {
			found = strings.Contains(e.DetailsJSON, `"reason":"not_assigned"`) && strings.Contains(e.DetailsJSON, `"revision":`) && strings.Contains(e.DetailsJSON, `"authenticationRevision":`)
		}
	}
	if !found {
		t.Fatal("denial audit lacks the reason and revisions")
	}
}
