package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/config"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// staffCall is an admin call with CSRF, a fresh step-up grant and, when org is set, X-Ky-Org.
func staffCall(t *testing.T, srv *Server, method, path, cookie, org, body string) *httptest.ResponseRecorder {
	t.Helper()
	return staffRequest(t, srv, method, path, cookie, org, body, true)
}

func staffRequest(t *testing.T, srv *Server, method, path, cookie, org, body string, stepUp bool) *httptest.ResponseRecorder {
	t.Helper()
	csrf := srv.middleware.IssueCSRFToken(cookie)
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	if stepUp {
		req.Header.Set(StepUpHeader, mintStepUp(t, srv, cookie, method+" "+path))
	}
	req.AddCookie(&http.Cookie{Name: "kyidentity_session", Value: cookie})
	req.AddCookie(&http.Cookie{Name: "kyidentity_csrf", Value: csrf})
	if org != "" {
		req.Header.Set(OrgHeader, org)
	}
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)
	return rr
}

func staffAudit(t *testing.T, db *store.Store, org store.OrgID, action string) []store.AuditEvent {
	t.Helper()
	rows, _, err := db.Org(org).SearchAuditEvents(store.AuditFilter{Action: action, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	var own []store.AuditEvent
	for _, e := range rows {
		if e.Action == action {
			own = append(own, e)
		}
	}
	return own
}

// Staff select the org they work in with X-Ky-Org (tenancy design, "Roles", build plan 5).
// An org route needs it in a multi-tenant install, binds the request to that org only,
// and audits a read in that org's log; a customer never reaches it; the finder reads
// across orgs and is audited as one platform row.
func TestStaffOrgSelection(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServerWith(t, func(c *config.Config) { c.Tenancy = "multi" })
	defer cleanup()
	exp := time.Now().UTC().Add(time.Hour)
	mk := func(kind string) store.OrgID {
		id, err := store.CreateOrgForTest(db, kind)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	orgA, orgB, staffOrg := mk("customer"), mk("customer"), mk("staff")
	memberA, userB := newOrgUser(t, db, orgA, "user"), newOrgUser(t, db, orgB, "user")
	admin := newSession(t, db, newOrgUser(t, db, staffOrg, "admin"), exp)
	helpdeskUser := newOrgUser(t, db, staffOrg, "user")
	if err := db.Org(staffOrg).SetDelegations(helpdeskUser.ID, store.Delegations{Helpdesk: true}, nil); err != nil {
		t.Fatal(err)
	}
	helpdesk := newSession(t, db, helpdeskUser, exp)
	member := newSession(t, db, memberA, exp)

	for _, c := range []struct {
		org, wantErr string
		code         int
	}{
		{"", "org_required", 400},
		{"nope", "unknown_org", 404},
		{store.DefaultOrgID, "unknown_org", 404},
	} {
		rr := staffCall(t, srv, "GET", "/api/admin/users", admin, c.org, "")
		if rr.Code != c.code || !strings.Contains(rr.Body.String(), `"error":"`+c.wantErr+`"`) {
			t.Errorf("org %q: %d %s", c.org, rr.Code, rr.Body.String())
		}
	}
	for name, cookie := range map[string]string{"admin": admin, "helpdesk": helpdesk} {
		rr := staffCall(t, srv, "GET", "/api/admin/users", cookie, orgA.String(), "")
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), memberA.ID) || strings.Contains(rr.Body.String(), userB.ID) {
			t.Fatalf("%s lists A: %d %s", name, rr.Code, rr.Body.String())
		}
	}
	reads := staffAudit(t, db, orgA, "staff.read")
	if len(reads) != 2 || !strings.Contains(reads[0].DetailsJSON, `GET /api/admin/users`) || reads[0].TargetID != orgA.String() {
		t.Fatalf("staff reads in A's log: %+v", reads)
	}
	if n := len(staffAudit(t, db, orgB, "staff.read")); n != 0 {
		t.Fatalf("A's reads are in B's log: %d", n)
	}
	// With A selected, B's user answers as a missing one does, and B is unchanged.
	missing := staffCall(t, srv, "PUT", "/api/admin/users/"+uuid.NewString(), admin, orgA.String(), `{"displayName":"x"}`)
	got := staffCall(t, srv, "PUT", "/api/admin/users/"+userB.ID, admin, orgA.String(), `{"displayName":"x"}`)
	if got.Code != missing.Code || got.Code != 404 {
		t.Fatalf("B's user with A selected: %d %s, missing %d", got.Code, got.Body.String(), missing.Code)
	}
	if u, _ := db.Org(orgB).GetUserByID(userB.ID); u.DisplayName != userB.DisplayName {
		t.Fatalf("B's user changed: %+v", u)
	}
	// B selected: the same write reaches B's user.
	if rr := staffCall(t, srv, "PUT", "/api/admin/users/"+userB.ID, admin, orgB.String(), `{"displayName":"Renamed"}`); rr.Code != 200 {
		t.Fatalf("B's user with B selected: %d %s", rr.Code, rr.Body.String())
	}
	// A customer never reaches the selection, whatever it names.
	for _, org := range []string{"", orgA.String(), orgB.String(), staffOrg.String()} {
		for _, path := range []string{"/api/admin/users", "/api/admin/orgs"} {
			if rr := staffCall(t, srv, "GET", path, member, org, ""); rr.Code != http.StatusForbidden {
				t.Errorf("member, org %q, %s: %d %s", org, path, rr.Code, rr.Body.String())
			}
		}
	}
	// Platform routes take no org.
	if rr := staffCall(t, srv, "GET", "/api/admin/enrollment-policies", admin, "", ""); rr.Code != 200 {
		t.Fatalf("platform route: %d %s", rr.Code, rr.Body.String())
	}

	// The finder: by ID, billing_ref or a member's exact email; empty is the staff org.
	raw, err := store.OpenRawForTest(srv.cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	q := `UPDATE orgs SET billing_ref='ref-a' WHERE id=?`
	if store.OnPostgresTest() {
		q = strings.Replace(q, "?", "$1", 1)
	}
	if _, err := raw.Exec(q, orgA.String()); err != nil {
		t.Fatal(err)
	}
	find := func(cookie, q string) []string {
		t.Helper()
		rr := staffCall(t, srv, "GET", "/api/admin/orgs?q="+q, cookie, "", "")
		var out struct {
			Orgs []store.StaffOrgRow `json:"orgs"`
		}
		if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &out) != nil {
			t.Fatalf("find %q: %d %s", q, rr.Code, rr.Body.String())
		}
		ids := []string{}
		for _, o := range out.Orgs {
			if strings.Contains(rr.Body.String(), memberA.Email) {
				t.Fatalf("the finder answered with an email: %s", rr.Body.String())
			}
			ids = append(ids, o.ID)
		}
		return ids
	}
	for q, want := range map[string]string{
		"":                                   staffOrg.String(),
		orgA.String():                        orgA.String(),
		"ref-a":                              orgA.String(),
		strings.ToUpper(memberA.Email):       orgA.String(),
		"u" + memberA.Email:                  "",
		store.DefaultOrgID:                   "",
		memberA.Email[:len(memberA.Email)-2]: "",
	} {
		if got := strings.Join(find(helpdesk, q), ","); got != want {
			t.Errorf("find %q = %q, want %q", q, got, want)
		}
	}
	// Every staff persona that can open an admin page can pick an org: an app owner too.
	createClient(t, db, "owned-app", "confidential", crypto.HashSHA256("owned-secret"), "", "https://owned.example.test/cb")
	ownerUser := newOrgUser(t, db, staffOrg, "user")
	if err := db.Org(staffOrg).SetDelegations(ownerUser.ID, store.Delegations{AppOwner: []string{suiteAppRecord(t, db, "owned-app")}}, nil); err != nil {
		t.Fatal(err)
	}
	if got := find(newSession(t, db, ownerUser, exp), ""); len(got) != 1 || got[0] != staffOrg.String() {
		t.Fatalf("an app owner's finder: %v", got)
	}
	var platformRows int
	var details string
	q = `SELECT COUNT(*),MAX(details_json) FROM audit_events WHERE action='staff.orgs_read' AND org_id IS NULL AND details_json LIKE ?`
	if store.OnPostgresTest() {
		q = strings.Replace(q, "?", "$1", 1)
	}
	if err := raw.QueryRow(q, "%"+orgA.String()+"%").Scan(&platformRows, &details); err != nil || platformRows != 3 {
		t.Fatalf("finder platform rows naming A: %d %s %v", platformRows, details, err)
	}
	if n := len(staffAudit(t, db, orgA, "staff.orgs_read")); n != 0 {
		t.Fatalf("the finder's platform row is in A's log: %d", n)
	}
}

// Single-tenant: no finder, and X-Ky-Org changes nothing.
func TestSingleTenantIgnoresTheOrgHeader(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newSession(t, db, newOrgUser(t, db, db.DefaultOrg().ID(), "admin"), time.Now().UTC().Add(time.Hour))
	if rr := staffCall(t, srv, "GET", "/api/admin/orgs", admin, "", ""); rr.Code != 404 {
		t.Fatalf("finder: %d", rr.Code)
	}
	plain := staffCall(t, srv, "GET", "/api/admin/users", admin, "", "")
	with := staffCall(t, srv, "GET", "/api/admin/users", admin, "nope", "")
	if plain.Code != 200 || with.Code != 200 || plain.Body.String() != with.Body.String() {
		t.Fatalf("header changed the answer: %d %d", plain.Code, with.Code)
	}
}

// The pinned staff passkey: staff without a passkey get an enrollment-only session, the
// administrators policy refuses every change, and a platform policy that would leave staff
// no passkey is refused.
func TestStaffPasskeyIsPinned(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServerWith(t, func(c *config.Config) { c.Tenancy = "multi" })
	defer cleanup()
	staffOrg, err := store.CreateOrgForTest(db, "staff")
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := db.PinStaffPasskey(); err != nil || !changed {
		t.Fatalf("pin: %v %v", changed, err)
	}
	if changed, err := db.PinStaffPasskey(); err != nil || changed {
		t.Fatalf("second pin: %v %v", changed, err)
	}
	exp := time.Now().UTC().Add(time.Hour)
	fresh := newSession(t, db, newOrgUser(t, db, staffOrg, "admin"), exp)
	if rr := staffCall(t, srv, "GET", "/api/admin/orgs", fresh, "", ""); rr.Code != 403 || !strings.Contains(rr.Body.String(), "enrollment_required") {
		t.Fatalf("staff without a passkey: %d %s", rr.Code, rr.Body.String())
	}
	// A staff admin signed in with a passkey works, and cannot unpin.
	admin := newOrgUser(t, db, staffOrg, "admin")
	if err := db.CreateWebAuthnCredential(&store.WebAuthnCredential{ID: uuid.NewString(), UserID: admin.ID, CredentialID: uuid.NewString(), PublicKeySPKI: "x", Name: "key"}, nil); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	cookie := "staff-passkey-cookie"
	if err := db.CreateSession(&store.Session{ID: uuid.NewString(), UserID: admin.ID, SessionTokenHash: crypto.HashSHA256(cookie), ExpiresAt: exp,
		AuthenticationEvidence: store.AuthenticationEvidence{PrimaryAuthenticatedAt: &now, FactorAuthenticatedAt: &now, FactorMethod: "webauthn"}}); err != nil {
		t.Fatal(err)
	}
	if rr := staffCall(t, srv, "GET", "/api/admin/orgs", cookie, "", ""); rr.Code != 200 {
		t.Fatalf("staff with a passkey: %d %s", rr.Code, rr.Body.String())
	}
	policies := func() string {
		ps, err := db.ListEnrollmentPolicies()
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(ps)
		return string(b)
	}
	before := policies()
	for _, body := range []string{
		`{"scope":"administrators","required":false,"allowedMethods":["webauthn"],"graceSeconds":0,"revision":2}`,
		`{"scope":"administrators","required":true,"allowedMethods":["webauthn","totp"],"graceSeconds":0,"revision":2}`,
		`{"scope":"administrators","required":true,"allowedMethods":["webauthn"],"graceSeconds":3600,"revision":2}`,
		`{"scope":"administrators","required":true,"allowedMethods":["webauthn"],"graceSeconds":0,"revision":2}`,
	} {
		for _, rt := range []struct{ method, path string }{{"PUT", "/api/admin/enrollment-policies"}, {"POST", "/api/admin/enrollment-policies/preview"}} {
			if rr := staffCall(t, srv, rt.method, rt.path, cookie, "", body); rr.Code != 409 || !strings.Contains(rr.Body.String(), "pinned_policy") {
				t.Errorf("%s %s: %d %s", rt.method, rt.path, rr.Code, rr.Body.String())
			}
		}
	}
	if rr := staffCall(t, srv, "PUT", "/api/admin/enrollment-policies", cookie, "", `{"scope":"organization","required":true,"allowedMethods":["totp"],"graceSeconds":0,"revision":1}`); rr.Code != 400 {
		t.Fatalf("a platform policy without passkeys: %d %s", rr.Code, rr.Body.String())
	}
	if after := policies(); after != before {
		t.Fatalf("policies changed:\n%s\n%s", before, after)
	}
}

func TestStaffCustomerAccountLinksRequireMail(t *testing.T) {
	srv, db, customer, staff := staffCredentialOrgs(t)
	exp := time.Now().Add(time.Hour)
	admin := newSession(t, db, newOrgUser(t, db, staff, "admin"), exp)
	helpdesk := newOrgUser(t, db, staff, "user")
	if err := db.Org(staff).SetDelegations(helpdesk.ID, store.Delegations{Helpdesk: true}, nil); err != nil {
		t.Fatal(err)
	}
	helpdeskSession := newSession(t, db, helpdesk, exp)
	active := newOrgUser(t, db, customer, "user")
	invited := staffCall(t, srv, http.MethodPost, "/api/admin/users", admin, customer.String(),
		`{"username":"invite","email":"invite@example.test"}`)
	var invite struct{ User store.User }
	if invited.Code != http.StatusOK || json.Unmarshal(invited.Body.Bytes(), &invite) != nil || !invite.User.Pending {
		t.Fatalf("customer invitation did not create a pending account: %d", invited.Code)
	}
	for _, tc := range []struct{ userID, kind string }{{active.ID, "reset"}, {invite.User.ID, "activation"}} {
		t.Run(tc.kind, func(t *testing.T) {
			path := "/api/admin/users/" + tc.userID + "/" + tc.kind + "-link"
			rr := staffCall(t, srv, http.MethodPost, path, helpdeskSession, customer.String(), `{"send":false}`)
			var response map[string]json.RawMessage
			err := json.Unmarshal(rr.Body.Bytes(), &response)
			if err != nil || rr.Code != http.StatusBadRequest || string(response["error"]) != `"mail_not_configured"` || response["link"] != nil {
				t.Fatalf("customer %s needs a configured relay and may not return a link: status %d, error %s, link present %t",
					tc.kind, rr.Code, response["error"], response["link"] != nil)
			}
		})
	}
	if events := staffAudit(t, db, customer, "admin.account_link_issued"); len(events) != 0 {
		t.Fatal("customer links were issued without a relay")
	}

	covDeadRelay(t, srv, admin)
	for kind, id := range map[string]string{"reset": active.ID, "activation": invite.User.ID} {
		path := "/api/admin/users/" + id + "/" + kind + "-link"
		rr := staffCall(t, srv, http.MethodPost, path, helpdeskSession, customer.String(), `{"send":false}`)
		var response map[string]json.RawMessage
		err := json.Unmarshal(rr.Body.Bytes(), &response)
		if err != nil || rr.Code != http.StatusBadGateway || string(response["error"]) != `"mail_failed"` || response["link"] != nil {
			t.Fatalf("customer %s fell back to manual delivery: status %d, link present %t", kind, rr.Code, response["link"] != nil)
		}
	}
	issued := staffAudit(t, db, customer, "admin.account_link_issued")
	if len(issued) != 2 {
		t.Fatalf("expected two audit records for mailed links, got %d", len(issued))
	}
	for _, event := range issued {
		if !strings.Contains(event.DetailsJSON, `"delivery":"email"`) {
			t.Fatal("a customer link was recorded as manual")
		}
	}

	staffMember := newOrgUser(t, db, staff, "user")
	rr := staffCall(t, srv, http.MethodPost, "/api/admin/users/"+staffMember.ID+"/reset-link", helpdeskSession, staff.String(), `{}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("manual link for a staff account returned %d", rr.Code)
	}
	var response struct{ Delivery string }
	if json.Unmarshal(rr.Body.Bytes(), &response) != nil || response.Delivery != "manual" {
		t.Fatal("manual link for a staff account lost its delivery mode")
	}
}

func TestStaffCannotSetCustomerCredentials(t *testing.T) {
	srv, db, customer, staff := staffCredentialOrgs(t)
	admin := newSession(t, db, newOrgUser(t, db, staff, "admin"), time.Now().Add(time.Hour))
	member := newOrgUser(t, db, customer, "user")
	for _, tc := range []struct{ name, method, path, body string }{
		{"create with password", http.MethodPost, "/api/admin/users", `{"username":"direct","email":"direct@example.test","password":"synthetic-password-123"}`},
		{"set password", http.MethodPut, "/api/admin/users/" + member.ID, `{"password":"synthetic-password-123"}`},
		{"change email", http.MethodPut, "/api/admin/users/" + member.ID, `{"email":"changed@example.test"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := staffCall(t, srv, tc.method, tc.path, admin, customer.String(), tc.body)
			if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), `"error":"customer_credentials_protected"`) {
				t.Fatalf("credential write was not refused: %d", rr.Code)
			}
		})
	}
	rr := staffCall(t, srv, http.MethodPut, "/api/admin/users/"+member.ID, admin, customer.String(),
		`{"displayName":"Updated","email":"`+member.Email+`"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("profile edit with an unchanged email: %d", rr.Code)
	}
	updated, err := db.Org(customer).GetUserByID(member.ID)
	if err != nil || updated == nil || updated.Email != member.Email || updated.PasswordHash != member.PasswordHash || updated.DisplayName != "Updated" {
		t.Fatal("allowed profile update changed the customer's credentials")
	}
	if u, err := db.GetUserByUsername("direct"); err != nil || u != nil {
		t.Fatal("customer account was created with an administrator-chosen password")
	}
}

func TestStaffCannotRedirectCustomerResetThroughSCIM(t *testing.T) {
	srv, db, customer, staff := staffCredentialOrgs(t)
	admin := newSession(t, db, newOrgUser(t, db, staff, "admin"), time.Now().Add(time.Hour))
	conn, err := db.Org(customer).CreateSCIMConnector("customer-directory", nil)
	if err != nil {
		t.Fatal(err)
	}
	const connectors = "/api/admin/scim-connectors"
	path := connectors + "/" + conn.ID
	// Invalid inputs distinguish an authorization refusal from reaching the handler
	// without changing customer connector state even if the guard is missing.
	for _, tc := range []struct{ name, method, path, body string }{
		{"create", http.MethodPost, connectors, "{"},
		{"update", http.MethodPut, path, "{"},
		{"issue token", http.MethodPost, path + "/tokens", `{"scope":"invalid"}`},
		{"configure HR", http.MethodPut, path + "/hr", "{"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := staffCall(t, srv, tc.method, tc.path, admin, customer.String(), tc.body)
			if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), `"error":"customer_credentials_protected"`) {
				t.Fatalf("customer connector request returned %d, want customer_credentials_protected", rr.Code)
			}
			rr = staffCall(t, srv, tc.method, tc.path, admin, staff.String(), tc.body)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("staff connector request returned %d, want validation error", rr.Code)
			}
		})
	}
	rr := staffCall(t, srv, http.MethodGet, connectors, admin, customer.String(), "")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), conn.ID) {
		t.Fatalf("customer connector list returned %d or omitted the connector", rr.Code)
	}
}

func staffCredentialOrgs(t *testing.T) (*Server, *store.Store, store.OrgID, store.OrgID) {
	t.Helper()
	srv, db, _, _, _, cleanup := setupTestServerWith(t, func(c *config.Config) { c.Tenancy = "multi" })
	t.Cleanup(cleanup)
	customer, err := store.CreateOrgForTest(db, "customer")
	if err != nil {
		t.Fatal(err)
	}
	staff, err := store.CreateOrgForTest(db, "staff")
	if err != nil {
		t.Fatal(err)
	}
	return srv, db, customer, staff
}
