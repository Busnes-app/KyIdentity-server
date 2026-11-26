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
	csrf := srv.middleware.IssueCSRFToken(cookie)
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	req.Header.Set(StepUpHeader, mintStepUp(t, srv, cookie, method+" "+path))
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
