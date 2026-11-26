package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/config"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// A single-tenant install has no mailbox address route and lists users as before.
func TestSingleTenantHasNoMailboxAddress(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	if _, _, err := db.SetSuiteEmailDomains([]string{"example.com"}, nil); err != nil {
		t.Fatal(err)
	}
	admin := newOrgUser(t, db, db.DefaultOrg().ID(), "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	res := adminRequest(t, srv, "PUT", "/api/admin/users/"+admin.ID+"/mailbox-address", cookie, `{"mailboxAddress":"a@example.com"}`)
	if res.Code != http.StatusNotFound || strings.TrimSpace(res.Body.String()) != `{"error":"not_found"}` {
		t.Errorf("PUT: %d %s", res.Code, res.Body)
	}
	res = adminRequest(t, srv, "GET", "/api/admin/users", cookie, "")
	var body map[string]json.RawMessage
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil || len(body) != 1 || body["users"] == nil {
		t.Errorf("list keys %v %v", body, err)
	}
	if strings.Contains(res.Body.String(), "mailbox") {
		t.Errorf("list names a mailbox: %s", res.Body)
	}
	// Removing a domain is unchanged: no mailbox address can hold it.
	if res := adminRequest(t, srv, "PUT", "/api/admin/suite-settings/email-domains", cookie, `{"domains":[]}`); res.Code != http.StatusOK {
		t.Errorf("clearing the domains: %d %s", res.Code, res.Body)
	}
}

func multiMailboxServer(t *testing.T) (*Server, *store.Store, store.OrgID, *store.User, string, func()) {
	t.Helper()
	srv, db, _, _, _, cleanup := setupTestServerWith(t, func(c *config.Config) { c.Tenancy = "multi" })
	if _, _, err := db.SetSuiteEmailDomains([]string{"example.com", "other.example"}, nil); err != nil {
		t.Fatal(err)
	}
	staffOrg, err := store.CreateOrgForTest(db, "staff")
	if err != nil {
		t.Fatal(err)
	}
	staff := newOrgUser(t, db, staffOrg, "admin")
	return srv, db, staffOrg, staff, newSession(t, db, staff, time.Now().UTC().Add(time.Hour)), cleanup
}

// Over HTTP, with the staff org selected: a staff account is refused a mailbox address,
// another org's member answers exactly as a missing one, and the route needs step-up. With
// the member's org selected (build plan PR 5), staff set it.
func TestMailboxAddressRouteRefusals(t *testing.T) {
	srv, db, staffOrg, _, cookie, cleanup := multiMailboxServer(t)
	defer cleanup()
	orgB, err := store.CreateOrgForTest(db, "customer")
	if err != nil {
		t.Fatal(err)
	}
	userB := newOrgUser(t, db, orgB, "user")
	put := func(id, body string) (int, string) {
		res := staffCall(t, srv, "PUT", "/api/admin/users/"+id+"/mailbox-address", cookie, staffOrg.String(), body)
		return res.Code, strings.TrimSpace(res.Body.String())
	}
	colleague := newOrgUser(t, db, staffOrg, "user")
	if code, body := put(colleague.ID, `{"mailboxAddress":"c@example.com"}`); code != http.StatusBadRequest || !strings.Contains(body, `"mailbox_customer_only"`) {
		t.Errorf("staff account: %d %s", code, body)
	}
	missingCode, missing := put(uuid.NewString(), `{"mailboxAddress":"b@example.com"}`)
	crossCode, cross := put(userB.ID, `{"mailboxAddress":"b@example.com"}`)
	if missingCode != http.StatusNotFound || crossCode != missingCode || cross != missing {
		t.Errorf("another org's member %d %s, a missing one %d %s", crossCode, cross, missingCode, missing)
	}
	if got, _ := db.Org(orgB).GetUserByID(userB.ID); got.MailboxAddress != "" {
		t.Errorf("B's member got %q", got.MailboxAddress)
	}
	for _, body := range []string{``, `{"mailboxAddress":"b@example.com","extra":1}`, `{"mailboxAddress":"` + strings.Repeat("a", 5000) + `@example.com"}`} {
		if code, _ := put(colleague.ID, body); code != http.StatusBadRequest {
			t.Errorf("body %.40q: %d", body, code)
		}
	}
	if res := staffRequest(t, srv, "PUT", "/api/admin/users/"+colleague.ID+"/mailbox-address", cookie, staffOrg.String(), `{"mailboxAddress":"c@example.com"}`, false); res.Code != http.StatusForbidden {
		t.Errorf("without step-up: %d %s", res.Code, res.Body)
	}
	member := newOrgUser(t, db, orgB, "user")
	memberCookie := newSession(t, db, member, time.Now().UTC().Add(time.Hour))
	if res := adminRequest(t, srv, "PUT", "/api/admin/users/"+member.ID+"/mailbox-address", memberCookie, `{"mailboxAddress":"m@example.com"}`); res.Code != http.StatusForbidden {
		t.Errorf("a member on their own account: %d %s", res.Code, res.Body)
	}
	// The staff org's list carries no mailbox domains.
	if res := staffCall(t, srv, "GET", "/api/admin/users", cookie, staffOrg.String(), ""); res.Code != http.StatusOK || strings.Contains(res.Body.String(), "mailboxDomains") {
		t.Errorf("staff list: %d %s", res.Code, res.Body)
	}
	// With B selected, staff set B's member's address.
	if res := staffCall(t, srv, "PUT", "/api/admin/users/"+userB.ID+"/mailbox-address", cookie, orgB.String(), `{"mailboxAddress":"b@example.com"}`); res.Code != http.StatusOK {
		t.Errorf("B selected: %d %s", res.Code, res.Body)
	}
	if got, _ := db.Org(orgB).GetUserByID(userB.ID); got.MailboxAddress != "b@example.com" {
		t.Errorf("B's member has %q", got.MailboxAddress)
	}
}

// boundTo calls an admin handler as staff with the request bound to org, as staff org
// selection (build plan PR 5) binds it.
func boundTo(h http.HandlerFunc, db *store.Store, org store.OrgID, staff *store.User, method, path, id, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.SetPathValue("id", id)
	ctx := context.WithValue(req.Context(), userContextKey, staff)
	req = req.WithContext(context.WithValue(ctx, orgContextKey, db.Org(org)))
	rr := httptest.NewRecorder()
	h(rr, req)
	return rr
}

func TestMailboxAddressRouteInACustomerOrg(t *testing.T) {
	srv, db, _, staff, cookie, cleanup := multiMailboxServer(t)
	defer cleanup()
	h := &AdminHandler{store: db, audit: srv.audit, middleware: srv.middleware, multiTenant: true}
	orgA, err := store.CreateOrgForTest(db, "customer")
	if err != nil {
		t.Fatal(err)
	}
	alice, bob := newOrgUser(t, db, orgA, "user"), newOrgUser(t, db, orgA, "user")
	put := func(id, body string) (int, string) {
		rr := boundTo(h.PutMailboxAddress, db, orgA, staff, "PUT", "/x", id, body)
		return rr.Code, strings.TrimSpace(rr.Body.String())
	}
	if code, body := put(alice.ID, `{"mailboxAddress":"Alice@Example.com"}`); code != http.StatusOK || !strings.Contains(body, `"mailboxAddress":"alice@example.com"`) {
		t.Fatalf("set: %d %s", code, body)
	}
	if code, body := put(bob.ID, `{"mailboxAddress":"ALICE@example.com"}`); code != http.StatusConflict || !strings.Contains(body, `"mailbox_address_taken"`) {
		t.Errorf("taken: %d %s", code, body)
	}
	if code, body := put(bob.ID, `{"mailboxAddress":"bob@elsewhere.example"}`); code != http.StatusBadRequest || !strings.Contains(body, `"mailbox_domain"`) {
		t.Errorf("off the list: %d %s", code, body)
	}
	if code, body := put(bob.ID, `{"mailboxAddress":"bob+x@example.com"}`); code != http.StatusBadRequest || strings.Contains(body, "bob") {
		t.Errorf("malformed: %d %s", code, body)
	}
	// Staff change it; the change is audited with the domains only.
	if code, body := put(alice.ID, `{"mailboxAddress":"alice@other.example"}`); code != http.StatusOK {
		t.Fatalf("staff change: %d %s", code, body)
	}
	events, _, err := db.Org(orgA).SearchAuditEvents(store.AuditFilter{Action: "admin.user_mailbox_address_changed", Limit: 10})
	if err != nil || len(events) != 2 {
		t.Fatalf("audit %v %v", events, err)
	}
	for _, e := range events {
		if e.ActorID != staff.ID || e.TargetID != alice.ID || strings.Contains(e.DetailsJSON, "alice") {
			t.Errorf("audit row %+v", e)
		}
	}
	// The customer org's list tells the UI the domains.
	rr := boundTo(h.ListUsers, db, orgA, staff, "GET", "/api/admin/users", "", "")
	if !strings.Contains(rr.Body.String(), `"mailboxDomains":["example.com","other.example"]`) || !strings.Contains(rr.Body.String(), `"mailboxAddress":"alice@other.example"`) {
		t.Errorf("list: %s", rr.Body)
	}
	// The domain in use cannot be removed over HTTP (a platform route, staff admin).
	res := adminRequest(t, srv, "PUT", "/api/admin/suite-settings/email-domains", cookie, `{"domains":["example.com"]}`)
	if res.Code != http.StatusConflict || !strings.Contains(res.Body.String(), `"domain_in_use"`) || strings.Contains(res.Body.String(), "alice") {
		t.Errorf("removing a used domain: %d %s", res.Code, res.Body)
	}
	if got, _ := db.SuiteEmailDomains(); len(got) != 2 {
		t.Errorf("domains now %v", got)
	}
}

// An inbound SCIM connector sets only the sign-in email: no create, replace or patch of
// its accounts reads or writes the mailbox address, whatever emails it sends.
func TestInboundSCIMCannotSetTheMailboxAddress(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	if _, _, err := db.SetSuiteEmailDomains([]string{"example.com"}, nil); err != nil {
		t.Fatal(err)
	}
	orgA, err := store.CreateOrgForTest(db, "customer")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := db.Org(orgA).CreateSCIMConnector("upstream", nil)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := db.Org(orgA).IssueSCIMToken(conn.ID, "write", nil)
	if err != nil {
		t.Fatal(err)
	}
	created := scimCall(t, srv, token, "POST", "/scim/v2/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"ext-m","userName":"m","emails":[{"value":"m@up.test","type":"work","primary":true},{"value":"evil@example.com","type":"mailbox"}],"active":true}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", created.Code, created.Body)
	}
	id, _ := scimUser(t, created.Body.Bytes())["id"].(string)
	if u := mustOrgUser(t, db, orgA, id); u.MailboxAddress != "" || u.Email != "m@up.test" {
		t.Fatalf("created %+v", u)
	}
	if _, _, err := db.Org(orgA).SetMailboxAddress(id, "m@example.com", false, nil); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ method, body string }{
		{"PUT", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"ext-m","userName":"m","emails":[{"value":"evil@example.com","type":"mailbox","primary":true}],"active":true}`},
		{"PATCH", `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"emails[type eq \"mailbox\"].value","value":"evil@example.com"}]}`},
		{"PATCH", `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"mailboxAddress","value":"evil@example.com"}]}`},
		{"PATCH", `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"mailboxAddress":"evil@example.com"}}]}`},
	} {
		res := scimCall(t, srv, token, c.method, "/scim/v2/Users/"+id, c.body)
		if u := mustOrgUser(t, db, orgA, id); u.MailboxAddress != "m@example.com" {
			t.Errorf("%s %s (%d) moved the mailbox address to %q", c.method, c.body, res.Code, u.MailboxAddress)
		}
	}
}

func mustOrgUser(t *testing.T, db *store.Store, org store.OrgID, id string) *store.User {
	t.Helper()
	u, err := db.Org(org).GetUserByID(id)
	if err != nil || u == nil {
		t.Fatalf("user %s: %v", id, err)
	}
	return u
}

// With no suite domains set, a customer org's list says [] (never null), so the dialog
// can say none is set.
func TestMailboxDomainsAreAnEmptyListWhenUnset(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServerWith(t, func(c *config.Config) { c.Tenancy = "multi" })
	defer cleanup()
	staffOrg, err := store.CreateOrgForTest(db, "staff")
	if err != nil {
		t.Fatal(err)
	}
	org, err := store.CreateOrgForTest(db, "customer")
	if err != nil {
		t.Fatal(err)
	}
	h := &AdminHandler{store: db, audit: srv.audit, middleware: srv.middleware, multiTenant: true}
	rr := boundTo(h.ListUsers, db, org, newOrgUser(t, db, staffOrg, "admin"), "GET", "/api/admin/users", "", "")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"mailboxDomains":[]`) {
		t.Errorf("%d %s", rr.Code, rr.Body)
	}
}
