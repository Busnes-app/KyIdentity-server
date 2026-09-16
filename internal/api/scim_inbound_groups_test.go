package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kyidentity-server/internal/store"
)

func scimGroupBody(t *testing.T, body []byte) (map[string]any, []string) {
	t.Helper()
	m := scimUser(t, body)
	var members []string
	if list, ok := m["members"].([]any); ok {
		for _, item := range list {
			if mm, ok := item.(map[string]any); ok {
				members = append(members, mm["value"].(string))
			}
		}
	}
	return m, members
}

func provisionedUpstreamUser(t *testing.T, srv *Server, db *store.Store, token, external, username string) string {
	t.Helper()
	created := scimCall(t, srv, token, "POST", "/scim/v2/Users", `{"externalId":"`+external+`","userName":"`+username+`","emails":[{"value":"`+username+`@up.test"}],"active":true}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("create user: %d %s", created.Code, created.Body.String())
	}
	id, _ := scimUser(t, created.Body.Bytes())["id"].(string)
	return id
}

// Upstream group lifecycle: discovery advertises Groups; create with members, filter by
// displayName, PATCH add/remove/rename atomically, replace, conditional writes, delete.
func TestInboundSCIMGroupLifecycle(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newSession(t, db, newUser(t, db, "admin"), time.Now().UTC().Add(time.Hour))
	_, token := connectorWithToken(t, srv, db, admin, "write")
	alice := provisionedUpstreamUser(t, srv, db, token, "e-a", "alice")
	bob := provisionedUpstreamUser(t, srv, db, token, "e-b", "bob")

	if got := scimCall(t, srv, token, "GET", "/scim/v2/ResourceTypes", ""); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"id":"Group"`) {
		t.Fatalf("resource types: %d %s", got.Code, got.Body.String())
	}
	if got := scimCall(t, srv, token, "GET", "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group", ""); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "nested groups are refused") {
		t.Fatalf("group schema: %d", got.Code)
	}

	created := scimCall(t, srv, token, "POST", "/scim/v2/Groups", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"externalId":"g-1","displayName":"Engineering","members":[{"value":"`+alice+`"}]}`)
	if created.Code != http.StatusCreated || created.Header().Get("ETag") == "" {
		t.Fatalf("create group: %d %s", created.Code, created.Body.String())
	}
	res, members := scimGroupBody(t, created.Body.Bytes())
	gid, _ := res["id"].(string)
	if gid == "" || res["displayName"] != "Engineering" || len(members) != 1 || members[0] != alice {
		t.Fatalf("created group: %+v", res)
	}
	if got := scimCall(t, srv, token, "GET", "/scim/v2/Groups?filter=displayName%20eq%20%22Engineering%22", ""); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"totalResults":1`) {
		t.Fatalf("filter: %d %s", got.Code, got.Body.String())
	}

	// PATCH: add bob, rename; then remove alice by filter path. Each applied atomically.
	patched := scimCall(t, srv, token, "PATCH", "/scim/v2/Groups/"+gid, `{"Operations":[{"op":"add","path":"members","value":[{"value":"`+bob+`"}]},{"op":"replace","path":"displayName","value":"Engineering Team"}]}`)
	if patched.Code != http.StatusOK {
		t.Fatalf("patch: %d %s", patched.Code, patched.Body.String())
	}
	res, members = scimGroupBody(t, patched.Body.Bytes())
	if res["displayName"] != "Engineering Team" || len(members) != 2 {
		t.Fatalf("after patch: %+v", res)
	}
	removed := scimCall(t, srv, token, "PATCH", "/scim/v2/Groups/"+gid, `{"Operations":[{"op":"remove","path":"members[value eq \"`+alice+`\"]"}]}`)
	if _, members = scimGroupBody(t, removed.Body.Bytes()); removed.Code != http.StatusOK || len(members) != 1 || members[0] != bob {
		t.Fatalf("remove by filter: %d %s", removed.Code, removed.Body.String())
	}

	// An invalid operation anywhere in a PATCH changes nothing.
	local := newUser(t, db, "user")
	bad := scimCall(t, srv, token, "PATCH", "/scim/v2/Groups/"+gid, `{"Operations":[{"op":"replace","path":"displayName","value":"Should not land"},{"op":"add","path":"members","value":[{"value":"`+local.ID+`"}]}]}`)
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("patch with a local member: %d %s", bad.Code, bad.Body.String())
	}
	res, members = scimGroupBody(t, scimCall(t, srv, token, "GET", "/scim/v2/Groups/"+gid, "").Body.Bytes())
	if res["displayName"] != "Engineering Team" || len(members) != 1 {
		t.Fatalf("invalid patch partially applied: %+v", res)
	}
	if got := scimCall(t, srv, token, "PATCH", "/scim/v2/Groups/"+gid, `{"Operations":[{"op":"add","path":"members","value":[{"value":"`+gid+`","type":"Group"}]}]}`); got.Code != http.StatusBadRequest || !strings.Contains(got.Body.String(), "nested") {
		t.Fatalf("nested group: %d %s", got.Code, got.Body.String())
	}
	if got := scimCall(t, srv, token, "PATCH", "/scim/v2/Groups/"+gid, `{"Operations":[{"op":"replace","path":"externalId","value":"g-2"}]}`); got.Code != http.StatusBadRequest {
		t.Fatalf("externalId patch: %d", got.Code)
	}

	// Conditional replace.
	etag := scimCall(t, srv, token, "GET", "/scim/v2/Groups/"+gid, "").Header().Get("ETag")
	if got := scimCall(t, srv, token, "PUT", "/scim/v2/Groups/"+gid, `{"displayName":"Eng","members":[]}`, "If-Match", `W/"stale"`); got.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale If-Match: %d", got.Code)
	}
	replaced := scimCall(t, srv, token, "PUT", "/scim/v2/Groups/"+gid, `{"externalId":"g-1","displayName":"Eng","members":[{"value":"`+alice+`"},{"value":"`+bob+`"}]}`, "If-Match", etag)
	if res, members = scimGroupBody(t, replaced.Body.Bytes()); replaced.Code != http.StatusOK || res["displayName"] != "Eng" || len(members) != 2 {
		t.Fatalf("replace: %d %s", replaced.Code, replaced.Body.String())
	}

	// Delete removes the group, never its users.
	if got := scimCall(t, srv, token, "DELETE", "/scim/v2/Groups/"+gid, ""); got.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", got.Code, got.Body.String())
	}
	if got := scimCall(t, srv, token, "GET", "/scim/v2/Groups/"+gid, ""); got.Code != http.StatusNotFound {
		t.Fatalf("deleted group readable: %d", got.Code)
	}
	for _, id := range []string{alice, bob} {
		if got := scimCall(t, srv, token, "GET", "/scim/v2/Users/"+id, ""); got.Code != http.StatusOK {
			t.Fatalf("group deletion removed a user: %d", got.Code)
		}
	}
}

// Ownership: another connector's accounts and groups are out of reach, local admins
// cannot rename an upstream group, and the connector listing counts groups.
func TestInboundSCIMGroupBoundaries(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newSession(t, db, newUser(t, db, "admin"), time.Now().UTC().Add(time.Hour))
	connectorID, token := connectorWithToken(t, srv, db, admin, "write")
	_, other := connectorWithToken(t, srv, db, admin, "write")
	alice := provisionedUpstreamUser(t, srv, db, token, "e-a", "alice")
	foreign := provisionedUpstreamUser(t, srv, db, other, "e-f", "foreign")

	if got := scimCall(t, srv, token, "POST", "/scim/v2/Groups", `{"displayName":"Mixed","members":[{"value":"`+alice+`"},{"value":"`+foreign+`"}]}`); got.Code != http.StatusBadRequest {
		t.Fatalf("cross-connector membership: %d %s", got.Code, got.Body.String())
	}
	created := scimCall(t, srv, token, "POST", "/scim/v2/Groups", `{"displayName":"Own","members":[{"value":"`+alice+`"}]}`)
	gid, _ := scimUser(t, created.Body.Bytes())["id"].(string)
	if got := scimCall(t, srv, other, "GET", "/scim/v2/Groups/"+gid, ""); got.Code != http.StatusNotFound {
		t.Fatalf("other connector read the group: %d", got.Code)
	}
	if got := scimCall(t, srv, other, "DELETE", "/scim/v2/Groups/"+gid, ""); got.Code != http.StatusNotFound {
		t.Fatalf("other connector deleted the group: %d", got.Code)
	}
	if got := adminRequest(t, srv, "PUT", "/api/admin/groups/"+gid, admin, `{"name":"Renamed locally","description":""}`); got.Code != http.StatusBadRequest || !strings.Contains(got.Body.String(), "source_owned") {
		t.Fatalf("local rename: %d %s", got.Code, got.Body.String())
	}
	if got := adminRequest(t, srv, "PUT", "/api/admin/groups/"+gid, admin, `{"name":"Own","description":"note"}`); got.Code != http.StatusOK {
		t.Fatalf("local description edit: %d %s", got.Code, got.Body.String())
	}
	listing := call(t, srv, admin, "GET", "/api/admin/scim-connectors")
	var view struct {
		Connectors []struct {
			ID     string `json:"id"`
			Groups int    `json:"groups"`
		} `json:"connectors"`
	}
	_ = json.Unmarshal(listing.Body.Bytes(), &view)
	for _, c := range view.Connectors {
		if c.ID == connectorID && c.Groups != 1 {
			t.Fatalf("connector group count: %+v", c)
		}
	}
	groups := call(t, srv, admin, "GET", "/api/admin/groups?q=Own")
	if !strings.Contains(groups.Body.String(), `"sourceConnectorId":"`+connectorID+`"`) {
		t.Fatalf("admin listing lacks the source: %s", groups.Body.String())
	}
}
