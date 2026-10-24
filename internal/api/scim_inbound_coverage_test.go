package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// scimRefusal asserts a SCIM error response: status, scimType and a detail fragment, in
// the RFC 7644 error envelope, never cached.
func scimRefusal(t *testing.T, rec *httptest.ResponseRecorder, status int, scimType, detail string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("want %d, got %d: %s", status, rec.Code, rec.Body.String())
	}
	body := scimUser(t, rec.Body.Bytes())
	if body["status"] != fmt.Sprint(status) {
		t.Fatalf("status field %v, want %d", body["status"], status)
	}
	if got, _ := body["scimType"].(string); got != scimType {
		t.Fatalf("scimType %q, want %q (%s)", got, scimType, rec.Body.String())
	}
	if got, _ := body["detail"].(string); !strings.Contains(got, detail) {
		t.Fatalf("detail %q does not mention %q", got, detail)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("SCIM error is cacheable: %q", rec.Header().Get("Cache-Control"))
	}
}

// scimGroupFixture is a write connector with two provisioned users and one group holding alice.
type scimGroupFixture struct {
	srv          *Server
	db           *store.Store
	token        string
	alice, bob   string
	gid, admin   string
	connectorID  string
	cleanupTasks func()
}

func newSCIMGroupFixture(t *testing.T) *scimGroupFixture {
	t.Helper()
	srv, db, _, _, _, cleanup := setupTestServer(t)
	admin := newSession(t, db, newUser(t, db, "admin"), time.Now().UTC().Add(time.Hour))
	cid, token := connectorWithToken(t, srv, db, admin, "write")
	f := &scimGroupFixture{srv: srv, db: db, token: token, admin: admin, connectorID: cid, cleanupTasks: cleanup}
	f.alice = provisionedUpstreamUser(t, srv, db, token, "e-a", "alice")
	f.bob = provisionedUpstreamUser(t, srv, db, token, "e-b", "bob")
	created := scimCall(t, srv, token, "POST", "/scim/v2/Groups", `{"externalId":"g-1","displayName":"Engineering","members":[{"value":"`+f.alice+`"}]}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("create group: %d %s", created.Code, created.Body.String())
	}
	f.gid, _ = scimUser(t, created.Body.Bytes())["id"].(string)
	return f
}

func (f *scimGroupFixture) group(t *testing.T) (string, []string) {
	t.Helper()
	got := scimCall(t, f.srv, f.token, "GET", "/scim/v2/Groups/"+f.gid, "")
	if got.Code != http.StatusOK {
		t.Fatalf("get group: %d %s", got.Code, got.Body.String())
	}
	res, members := scimGroupBody(t, got.Body.Bytes())
	slices.Sort(members)
	name, _ := res["displayName"].(string)
	return name, members
}

func (f *scimGroupFixture) patch(t *testing.T, ops string) *httptest.ResponseRecorder {
	t.Helper()
	return scimCall(t, f.srv, f.token, "PATCH", "/scim/v2/Groups/"+f.gid, `{"Operations":[`+ops+`]}`)
}

// Every malformed group PATCH is refused with the right SCIM error and, because operations
// apply atomically, leaves the group's name and members exactly as they were, even when a
// valid operation precedes the bad one.
func TestSCIMGroupPatchRefusalsAreAtomic(t *testing.T) {
	f := newSCIMGroupFixture(t)
	defer f.cleanupTasks()
	before := countAudit(t, f.db, "scim.group_updated")

	tooMany := strings.TrimSuffix(strings.Repeat(`{"op":"replace","path":"displayName","value":"x"},`, 101), ",")
	for _, tc := range []struct {
		name, body, scimType, detail string
	}{
		{"malformed json", `{"Operations":`, "invalidSyntax", "1 to 100"},
		{"no operations", `{"Operations":[]}`, "invalidSyntax", "1 to 100"},
		{"too many operations", `{"Operations":[` + tooMany + `]}`, "invalidSyntax", "1 to 100"},
	} {
		got := scimCall(t, f.srv, f.token, "PATCH", "/scim/v2/Groups/"+f.gid, tc.body)
		t.Run(tc.name, func(t *testing.T) { scimRefusal(t, got, http.StatusBadRequest, tc.scimType, tc.detail) })
	}

	for _, tc := range []struct {
		name, ops, scimType, detail string
	}{
		{"members not a list", `{"op":"remove","path":"members","value":"nope"}`, "invalidValue", "members must be a list"},
		{"nested group member", `{"op":"add","path":"members","value":[{"value":"x","type":"Group"}]}`, "invalidValue", "nested groups"},
		{"blank member value", `{"op":"add","path":"members","value":[{"value":"  "}]}`, "invalidValue", "each member needs a value"},
		{"empty displayName", `{"op":"replace","path":"displayName","value":"  "}`, "invalidValue", "displayName must be a non-empty string"},
		{"non-string displayName", `{"op":"replace","path":"displayName","value":7}`, "invalidValue", "displayName must be a non-empty string"},
		{"path-less scalar", `{"op":"replace","value":"Engineering"}`, "invalidValue", "needs an object value"},
		{"path-less externalId change", `{"op":"replace","value":{"externalId":"g-2"}}`, "mutability", "externalId is immutable"},
		{"path-less blank displayName", `{"op":"add","value":{"displayName":" "}}`, "invalidValue", "displayName must be a non-empty string"},
		{"path-less nested member", `{"op":"add","value":{"members":[{"value":"x","type":"group"}]}}`, "invalidValue", "nested groups"},
		{"externalId path", `{"op":"replace","path":"externalId","value":"g-2"}`, "mutability", "externalId is immutable"},
		{"unsupported op", `{"op":"move","path":"members","value":[]}`, "invalidPath", "unsupported operation move"},
		{"unsupported path", `{"op":"add","path":"owner","value":"x"}`, "invalidPath", `"owner"`},
		{"malformed member filter", `{"op":"remove","path":"members[value eq \"\\q\"]"}`, "invalidPath", "malformed member filter"},
		{"valid op then bad op", `{"op":"replace","path":"displayName","value":"Renamed"},{"op":"add","path":"members","value":[{"value":"` + f.bob + `"}]},{"op":"replace","path":"externalId","value":"g-9"}`, "mutability", "immutable"},
	} {
		got := f.patch(t, tc.ops)
		t.Run(tc.name, func(t *testing.T) { scimRefusal(t, got, http.StatusBadRequest, tc.scimType, tc.detail) })
	}

	if name, members := f.group(t); name != "Engineering" || !slices.Equal(members, []string{f.alice}) {
		t.Fatalf("a refused PATCH changed the group: %q %v", name, members)
	}
	if after := countAudit(t, f.db, "scim.group_updated"); after != before {
		t.Fatalf("refused PATCHes recorded %d success audit rows", after-before)
	}
}

// The accepted PATCH forms do what RFC 7644 says: remove by list removes only those ids,
// a bare remove of members clears the group, replace swaps the set, a single member object
// is accepted as a one-item list, and a path-less replace renames and replaces members.
func TestSCIMGroupPatchMembershipForms(t *testing.T) {
	f := newSCIMGroupFixture(t)
	defer f.cleanupTasks()
	carol := provisionedUpstreamUser(t, f.srv, f.db, f.token, "e-c", "carol")
	want := func(label string, wantName string, ids ...string) {
		t.Helper()
		slices.Sort(ids)
		if name, members := f.group(t); name != wantName || !slices.Equal(members, ids) {
			t.Fatalf("%s: got %q %v, want %q %v", label, name, members, wantName, ids)
		}
	}

	if got := f.patch(t, `{"op":"add","path":"members","value":{"value":"`+f.bob+`"}}`); got.Code != http.StatusOK {
		t.Fatalf("single member object: %d %s", got.Code, got.Body.String())
	}
	want("single object add", "Engineering", f.alice, f.bob)

	if got := f.patch(t, `{"op":"remove","path":"members","value":[{"value":"`+f.alice+`"}]}`); got.Code != http.StatusOK {
		t.Fatalf("remove listed: %d %s", got.Code, got.Body.String())
	}
	want("remove listed", "Engineering", f.bob)

	if got := f.patch(t, `{"op":"replace","path":"members","value":[{"value":"`+carol+`"}]}`); got.Code != http.StatusOK {
		t.Fatalf("replace members: %d %s", got.Code, got.Body.String())
	}
	want("replace members", "Engineering", carol)

	if got := f.patch(t, `{"op":"remove","path":"members"}`); got.Code != http.StatusOK {
		t.Fatalf("clear members: %d %s", got.Code, got.Body.String())
	}
	want("clear members", "Engineering")

	if got := f.patch(t, `{"op":"replace","value":{"displayName":"Platform","externalId":"g-1","members":[{"value":"`+f.alice+`"},{"value":"`+f.bob+`"}]}}`); got.Code != http.StatusOK {
		t.Fatalf("path-less replace: %d %s", got.Code, got.Body.String())
	}
	want("path-less replace", "Platform", f.alice, f.bob)

	if got := f.patch(t, `{"op":"replace","value":{"members":[{"value":"`+carol+`"}]}}`); got.Code != http.StatusOK {
		t.Fatalf("path-less replace members: %d %s", got.Code, got.Body.String())
	}
	want("path-less replace members only", "Platform", carol)

	if got := f.patch(t, `{"op":"add","value":{"members":[{"value":"`+f.alice+`"}]}}`); got.Code != http.StatusOK {
		t.Fatalf("path-less add members: %d %s", got.Code, got.Body.String())
	}
	want("path-less add members", "Platform", carol, f.alice)
}

// A connector's group writes cannot reach accounts it does not own, collide with another
// group's name or externalId, or proceed against a stale If-Match version.
func TestSCIMGroupWriteConflictsAndPreconditions(t *testing.T) {
	f := newSCIMGroupFixture(t)
	defer f.cleanupTasks()
	local := newUser(t, f.db, "user")

	scimRefusal(t, f.patch(t, `{"op":"add","path":"members","value":[{"value":"`+local.ID+`"}]}`), http.StatusBadRequest, "invalidValue", "not an account of this connector")

	scimRefusal(t, scimCall(t, f.srv, f.token, "POST", "/scim/v2/Groups", `{"displayName":"Engineering"}`), http.StatusConflict, "uniqueness", "displayName")
	scimRefusal(t, scimCall(t, f.srv, f.token, "POST", "/scim/v2/Groups", `{"displayName":"Other","externalId":"g-1"}`), http.StatusConflict, "uniqueness", "externalId")
	scimRefusal(t, scimCall(t, f.srv, f.token, "POST", "/scim/v2/Groups", `{"displayName":`), http.StatusBadRequest, "invalidValue", "Malformed JSON")
	scimRefusal(t, scimCall(t, f.srv, f.token, "POST", "/scim/v2/Groups", `{"displayName":"`+strings.Repeat("n", 129)+`"}`), http.StatusBadRequest, "invalidValue", "at most 128")
	scimRefusal(t, scimCall(t, f.srv, f.token, "POST", "/scim/v2/Groups", `{"displayName":"Nested","members":[{"value":"x","type":"Group"}]}`), http.StatusBadRequest, "invalidValue", "nested groups")
	many := make([]string, 1001)
	for i := range many {
		many[i] = `{"value":"m` + itoa(i) + `"}`
	}
	scimRefusal(t, scimCall(t, f.srv, f.token, "POST", "/scim/v2/Groups", `{"displayName":"Huge","members":[`+strings.Join(many, ",")+`]}`), http.StatusBadRequest, "invalidValue", "too many members")

	// PUT: malformed, blank member, externalId change, and a stale version are all refused.
	path := "/scim/v2/Groups/" + f.gid
	scimRefusal(t, scimCall(t, f.srv, f.token, "PUT", path, `{"displayName":""}`), http.StatusBadRequest, "invalidValue", "displayName is required")
	scimRefusal(t, scimCall(t, f.srv, f.token, "PUT", path, `{"displayName":"X","members":[{"value":""}]}`), http.StatusBadRequest, "invalidValue", "each member needs a value")
	scimRefusal(t, scimCall(t, f.srv, f.token, "PUT", path, `{"displayName":"X","externalId":"g-other"}`), http.StatusBadRequest, "mutability", "externalId is immutable")
	scimRefusal(t, scimCall(t, f.srv, f.token, "PUT", path, `{"displayName":"X"}`, "If-Match", `W/"1"`), http.StatusPreconditionFailed, "", "If-Match")
	scimRefusal(t, scimCall(t, f.srv, f.token, "DELETE", path, "", "If-Match", `W/"1"`), http.StatusPreconditionFailed, "", "If-Match")
	scimRefusal(t, scimCall(t, f.srv, f.token, "GET", "/scim/v2/Groups/does-not-exist", ""), http.StatusNotFound, "", "Resource not found")
	scimRefusal(t, scimCall(t, f.srv, f.token, "PATCH", "/scim/v2/Groups/does-not-exist", `{"Operations":[{"op":"replace","path":"displayName","value":"x"}]}`), http.StatusNotFound, "", "Resource not found")
	scimRefusal(t, scimCall(t, f.srv, f.token, "DELETE", "/scim/v2/Groups/does-not-exist", ""), http.StatusNotFound, "", "Resource not found")

	if name, members := f.group(t); name != "Engineering" || !slices.Equal(members, []string{f.alice}) {
		t.Fatalf("refused writes changed the group: %q %v", name, members)
	}

	// A matching version is accepted: If-Match lists may name the current ETag among others.
	etag := scimCall(t, f.srv, f.token, "GET", path, "").Header().Get("ETag")
	if got := scimCall(t, f.srv, f.token, "PUT", path, `{"displayName":"Renamed","externalId":"g-1"}`, "If-Match", `W/"1", `+etag); got.Code != http.StatusOK {
		t.Fatalf("matching If-Match refused: %d %s", got.Code, got.Body.String())
	}
	etag = scimCall(t, f.srv, f.token, "GET", path, "").Header().Get("ETag")
	if got := scimCall(t, f.srv, f.token, "DELETE", path, "", "If-Match", etag); got.Code != http.StatusNoContent || got.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("conditional delete: %d %q", got.Code, got.Header().Get("Cache-Control"))
	}
}

// Group listing validates its filter and paging parameters instead of guessing.
func TestSCIMGroupListValidation(t *testing.T) {
	f := newSCIMGroupFixture(t)
	defer f.cleanupTasks()
	if got := scimCall(t, f.srv, f.token, "POST", "/scim/v2/Groups", `{"displayName":"Sales"}`); got.Code != http.StatusCreated {
		t.Fatalf("second group: %d", got.Code)
	}
	for _, tc := range []struct{ query, scimType, detail string }{
		{"filter=displayName%20sw%20%22E%22", "invalidFilter", "eq"},
		{"filter=displayName%20eq%20%22%5Cq%22", "invalidFilter", "malformed filter value"},
		{"filter=members%20eq%20%22x%22", "invalidFilter", "displayName, externalId or id"},
		{"startIndex=0", "invalidValue", "startIndex"},
		{"startIndex=abc", "invalidValue", "startIndex"},
		{"count=-1", "invalidValue", "count"},
	} {
		got := scimCall(t, f.srv, f.token, "GET", "/scim/v2/Groups?"+tc.query, "")
		t.Run(tc.query, func(t *testing.T) { scimRefusal(t, got, http.StatusBadRequest, tc.scimType, tc.detail) })
	}
	page := scimCall(t, f.srv, f.token, "GET", "/scim/v2/Groups?startIndex=2&count=1", "")
	body := scimUser(t, page.Body.Bytes())
	if page.Code != http.StatusOK || body["totalResults"] != float64(2) || body["startIndex"] != float64(2) || body["itemsPerPage"] != float64(1) {
		t.Fatalf("paging: %d %s", page.Code, page.Body.String())
	}
}

// User listing applies the same parameter checks, and caps an oversized count rather than
// letting one request page through an unbounded directory.
func TestSCIMUserListValidation(t *testing.T) {
	f := newSCIMGroupFixture(t)
	defer f.cleanupTasks()
	for _, tc := range []struct{ query, scimType, detail string }{
		{"filter=userName%20eq%20%22%5Cq%22", "invalidFilter", "malformed filter value"},
		{"filter=title%20eq%20%22x%22", "invalidFilter", "userName, externalId"},
		{"startIndex=-3", "invalidValue", "startIndex"},
		{"count=x", "invalidValue", "count"},
	} {
		got := scimCall(t, f.srv, f.token, "GET", "/scim/v2/Users?"+tc.query, "")
		t.Run(tc.query, func(t *testing.T) { scimRefusal(t, got, http.StatusBadRequest, tc.scimType, tc.detail) })
	}
	page := scimCall(t, f.srv, f.token, "GET", "/scim/v2/Users?startIndex=1&count=100000", "")
	body := scimUser(t, page.Body.Bytes())
	if page.Code != http.StatusOK || body["totalResults"] != float64(2) || body["itemsPerPage"] != float64(2) {
		t.Fatalf("capped count: %d %s", page.Code, page.Body.String())
	}
}

// Discovery endpoints answer the known resource types and schemas and refuse unknown ones.
func TestSCIMDiscoveryLookups(t *testing.T) {
	f := newSCIMGroupFixture(t)
	defer f.cleanupTasks()
	for path, want := range map[string]string{
		"/scim/v2/ResourceTypes/User":                                 `"endpoint":"/Users"`,
		"/scim/v2/ResourceTypes/Group":                                `"endpoint":"/Groups"`,
		"/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User": `"name":"User"`,
		"/scim/v2/Schemas":                                            `"totalResults":2`,
	} {
		if got := scimCall(t, f.srv, f.token, "GET", path, ""); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), want) {
			t.Errorf("%s: %d %s", path, got.Code, got.Body.String())
		}
	}
	scimRefusal(t, scimCall(t, f.srv, f.token, "GET", "/scim/v2/ResourceTypes/Device", ""), http.StatusNotFound, "", "Unknown resource type")
	scimRefusal(t, scimCall(t, f.srv, f.token, "GET", "/scim/v2/Schemas/urn:example:Other", ""), http.StatusNotFound, "", "Unknown schema")
}

// User creation and replacement refuse incomplete payloads, and a second account with the
// same userName is a uniqueness conflict, not a silent merge into the first.
func TestSCIMUserWriteValidation(t *testing.T) {
	f := newSCIMGroupFixture(t)
	defer f.cleanupTasks()
	before := countAudit(t, f.db, "scim.user_created")
	scimRefusal(t, scimCall(t, f.srv, f.token, "POST", "/scim/v2/Users", `[1]`), http.StatusBadRequest, "invalidValue", "Malformed JSON")
	scimRefusal(t, scimCall(t, f.srv, f.token, "POST", "/scim/v2/Users", `{"userName":7}`), http.StatusBadRequest, "invalidValue", "Malformed JSON")
	scimRefusal(t, scimCall(t, f.srv, f.token, "POST", "/scim/v2/Users", `{"userName":"dave","emails":[{"value":"d@up.test"}]}`), http.StatusBadRequest, "invalidValue", "userName and externalId are required")
	scimRefusal(t, scimCall(t, f.srv, f.token, "POST", "/scim/v2/Users", `{"userName":"dave","externalId":"e-d"}`), http.StatusBadRequest, "invalidValue", "an email is required")
	scimRefusal(t, scimCall(t, f.srv, f.token, "POST", "/scim/v2/Users", `{"userName":"alice","externalId":"e-z","emails":[{"value":"other@up.test"}]}`), http.StatusConflict, "uniqueness", "already in use")
	if after := countAudit(t, f.db, "scim.user_created"); after != before {
		t.Fatalf("refused creates recorded %d success audit rows", after-before)
	}

	path := "/scim/v2/Users/" + f.alice
	scimRefusal(t, scimCall(t, f.srv, f.token, "PUT", path, `{`), http.StatusBadRequest, "invalidValue", "Malformed JSON")
	scimRefusal(t, scimCall(t, f.srv, f.token, "PUT", path, `{"externalId":"e-a","emails":[{"value":"a@up.test"}]}`), http.StatusBadRequest, "invalidValue", "userName is required")
	if u := mustUser(t, f.db, f.alice); u.Username != "alice" {
		t.Fatalf("refused replace changed the account: %+v", u)
	}

	// A display name falls back to name.formatted when no displayName is sent.
	created := scimCall(t, f.srv, f.token, "POST", "/scim/v2/Users", `{"userName":"erin","externalId":"e-e","name":{"formatted":" Erin Example "},"emails":[{"value":"erin@up.test"}]}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("create erin: %d %s", created.Code, created.Body.String())
	}
	id, _ := scimUser(t, created.Body.Bytes())["id"].(string)
	if u := mustUser(t, f.db, id); u.DisplayName != "Erin Example" {
		t.Fatalf("name.formatted not used: %q", u.DisplayName)
	}
}

// User PATCH validates each attribute it accepts and refuses everything else; a refused
// operation leaves the account untouched.
func TestSCIMUserPatchAttributes(t *testing.T) {
	f := newSCIMGroupFixture(t)
	defer f.cleanupTasks()
	path := "/scim/v2/Users/" + f.alice
	patch := func(ops string) *httptest.ResponseRecorder {
		return scimCall(t, f.srv, f.token, "PATCH", path, `{"Operations":[`+ops+`]}`)
	}
	original := mustUser(t, f.db, f.alice)

	scimRefusal(t, scimCall(t, f.srv, f.token, "PATCH", path, `{"Operations":[]}`), http.StatusBadRequest, "invalidSyntax", "1 to 50")
	for _, tc := range []struct{ name, ops, detail string }{
		{"remove op", `{"op":"remove","path":"displayName"}`, "only add and replace"},
		{"path-less scalar", `{"op":"replace","value":"x"}`, "needs an object value"},
		{"path-less bad attr", `{"op":"replace","value":{"nickName":"x"}}`, `"nickName" is not supported`},
		{"active number", `{"op":"replace","path":"active","value":3}`, "active must be a boolean"},
		{"empty userName", `{"op":"replace","path":"userName","value":""}`, "userName must be a non-empty string"},
		{"non-string displayName", `{"op":"replace","path":"displayName","value":5}`, "displayName must be a string"},
		{"name not object", `{"op":"replace","path":"name","value":"x"}`, "name must be an object"},
		{"emails not list", `{"op":"replace","path":"emails","value":"x"}`, "emails must be a list"},
		{"emails empty", `{"op":"replace","path":"emails","value":[{"type":"work"}]}`, "emails needs at least one value"},
		{"email value empty", `{"op":"replace","path":"emails[type eq \"work\"].value","value":""}`, "email value must be a non-empty string"},
		{"externalId", `{"op":"replace","path":"externalId","value":"e-x"}`, "externalId is immutable"},
		{"good then bad", `{"op":"replace","path":"displayName","value":"Changed"},{"op":"replace","path":"title","value":"x"}`, "not supported"},
	} {
		got := patch(tc.ops)
		t.Run(tc.name, func(t *testing.T) { scimRefusal(t, got, http.StatusBadRequest, "invalidPath", tc.detail) })
	}
	if u := mustUser(t, f.db, f.alice); u.DisplayName != original.DisplayName || u.Email != original.Email || u.Username != original.Username {
		t.Fatalf("a refused PATCH changed the account: %+v", u)
	}

	if got := patch(`{"op":"replace","path":"name","value":{"givenName":" Alice ","familyName":"Liddell"}}`); got.Code != http.StatusOK {
		t.Fatalf("name parts: %d %s", got.Code, got.Body.String())
	}
	if u := mustUser(t, f.db, f.alice); u.DisplayName != "Alice Liddell" {
		t.Fatalf("given+family name: %q", u.DisplayName)
	}
	if got := patch(`{"op":"replace","path":"name","value":{"formatted":"Dr. Alice"}}`); got.Code != http.StatusOK {
		t.Fatalf("formatted name: %d", got.Code)
	}
	if got := patch(`{"op":"replace","path":"emails[primary eq true].value","value":"alice.new@up.test"}`); got.Code != http.StatusOK {
		t.Fatalf("email value path: %d %s", got.Code, got.Body.String())
	}
	if u := mustUser(t, f.db, f.alice); u.Email != "alice.new@up.test" {
		t.Fatalf("primary email path not applied: %q", u.Email)
	}
	if got := patch(`{"op":"replace","path":"emails","value":[{"value":"second@up.test"},{"value":"primary@up.test","primary":true}]}`); got.Code != http.StatusOK {
		t.Fatalf("emails list: %d", got.Code)
	}
	if u := mustUser(t, f.db, f.alice); u.DisplayName != "Dr. Alice" || u.Email != "primary@up.test" {
		t.Fatalf("patched attributes: %q %q", u.DisplayName, u.Email)
	}

	// The string form of active, which some directories send, deactivates the account.
	if got := patch(`{"op":"replace","path":"active","value":"False"}`); got.Code != http.StatusOK {
		t.Fatalf("active string: %d %s", got.Code, got.Body.String())
	}
	if u := mustUser(t, f.db, f.alice); u.Status != "disabled" {
		t.Fatalf("string active=False left the account %q", u.Status)
	}
}
