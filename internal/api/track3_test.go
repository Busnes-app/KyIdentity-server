package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

func TestStaffAuditByActorAndOrgLimits(t *testing.T) {
	srv, db, customer, staff := staffCredentialOrgs(t)
	other, err := store.CreateOrgForTest(db, "customer")
	if err != nil {
		t.Fatal(err)
	}
	adminUser := newOrgUser(t, db, staff, "admin")
	admin := newSession(t, db, adminUser, time.Now().UTC().Add(time.Hour))
	ordinary := newSession(t, db, newOrgUser(t, db, customer, "user"), time.Now().UTC().Add(time.Hour))
	for _, org := range []store.OrgID{customer, other} {
		if err := db.Org(org).RecordStaffRead(&store.AuditEvent{ID: uuid.NewString(), ActorID: adminUser.ID, ActorUsername: adminUser.Username, Action: "test.staff", Outcome: "success", DetailsJSON: `{"password":"never-return"}`}); err != nil {
			t.Fatal(err)
		}
	}
	path := "/api/admin/audit-by-actor?actor=" + adminUser.ID + "&action=test.staff"
	res := staffCall(t, srv, "GET", path, admin, "", "")
	var result struct {
		Events []store.PlatformAuditEvent `json:"auditEvents"`
		Total  int                        `json:"total"`
	}
	if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &result) != nil || result.Total != 2 || len(result.Events) != 2 || result.Events[0].OrgID == nil || result.Events[1].OrgID == nil || *result.Events[0].OrgID == *result.Events[1].OrgID || strings.Contains(res.Body.String(), "never-return") {
		t.Fatal(res.Code, res.Body.String())
	}
	// Querying one's own actor without an action filter must not shift pages or grow totals from staff.audit_read.
	unfiltered := "/api/admin/audit-by-actor?actor=" + adminUser.ID
	var page1, page2 struct {
		Events []store.PlatformAuditEvent `json:"auditEvents"`
		Total  int                        `json:"total"`
	}
	r1 := staffCall(t, srv, "GET", unfiltered, admin, "", "")
	r2 := staffCall(t, srv, "GET", unfiltered, admin, "", "")
	if r1.Code != 200 || r2.Code != 200 || json.Unmarshal(r1.Body.Bytes(), &page1) != nil || json.Unmarshal(r2.Body.Bytes(), &page2) != nil {
		t.Fatal(r1.Code, r2.Code)
	}
	if page1.Total != page2.Total || len(page1.Events) != len(page2.Events) || strings.Contains(r2.Body.String(), "staff.audit_read") {
		t.Fatalf("unstable audit-by-actor pagination: first=%d (%d) second=%d (%d)", page1.Total, len(page1.Events), page2.Total, len(page2.Events))
	}
	if len(staffAudit(t, db, staff, "staff.audit_read")) < 3 {
		t.Fatal("staff.audit_read rows were not recorded")
	}
	if res := staffCall(t, srv, "GET", "/api/admin/audit-by-actor", admin, "", ""); res.Code != 400 {
		t.Fatal(res.Code)
	}
	for _, role := range []string{"auditor", "helpdesk"} {
		u := newOrgUser(t, db, staff, "user")
		if err := db.Org(staff).SetDelegations(u.ID, store.Delegations{Auditor: role == "auditor", Helpdesk: role == "helpdesk"}, nil); err != nil {
			t.Fatal(err)
		}
		cookie := newSession(t, db, u, time.Now().UTC().Add(time.Hour))
		if res := staffCall(t, srv, "GET", path, cookie, "", ""); res.Code != 403 {
			t.Fatal(role, res.Code)
		}
	}
	for _, p := range []string{path, "/api/admin/org/limits", "/api/admin/org/enrollment-policies"} {
		if res := staffCall(t, srv, "GET", p, ordinary, customer.String(), ""); res.Code != 403 {
			t.Fatal(p, res.Code)
		}
	}
	body := `{"max_seats":2,"storage_bytes":1073741824,"storage_per_seat_bytes":1073741824}`
	res = staffRequest(t, srv, "PUT", "/api/admin/org/limits", admin, customer.String(), body, false)
	if res.Code != 403 || !strings.Contains(res.Body.String(), "step_up_required") {
		t.Fatal(res.Code, res.Body.String())
	}
	res = staffCall(t, srv, "PUT", "/api/admin/org/limits", admin, customer.String(), body)
	if res.Code != 200 {
		t.Fatal(res.Code, res.Body.String())
	}
	res = staffCall(t, srv, "GET", "/api/admin/org/limits", admin, customer.String(), "")
	var limits store.PlatformOrg
	if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &limits) != nil || limits.MaxSeats != 2 || limits.PoolBytes != 3<<30 {
		t.Fatal(res.Code, res.Body.String())
	}
	if len(staffAudit(t, db, customer, "org.limits_changed")) != 1 {
		t.Fatal("no atomic org limits audit")
	}
	// A body cannot select a foreign MFA org; the route's selected org owns the scope.
	policy := fmt.Sprintf(`{"scope":"org:%s","required":true,"allowedMethods":["totp"],"graceSeconds":60,"revision":1}`, other)
	res = staffCall(t, srv, "POST", "/api/admin/org/enrollment-policies/preview", admin, customer.String(), policy)
	if res.Code != 404 {
		t.Fatal(res.Code, res.Body.String())
	}
	res = staffCall(t, srv, "GET", "/api/admin/org/enrollment-policies", admin, customer.String(), "")
	if res.Code != 200 || !strings.Contains(res.Body.String(), "org:"+customer.String()) || strings.Contains(res.Body.String(), other.String()) {
		t.Fatal(res.Code, res.Body.String())
	}
}

func TestRestoreGenerationRejectsIncrementalCache(t *testing.T) {
	srv, db, _, _, cleanup := multiSuite(t)
	defer cleanup()
	if err := db.SetSetting(store.TenancySetting, "multi"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ApplyRestoredState(time.Now().UTC(), nil); err != nil {
		t.Fatal(err)
	}
	generation, err := db.Platform().OrgRestoreGeneration()
	if err != nil || generation == "" {
		t.Fatal(generation, err)
	}
	for _, suffix := range []string{"?since=999999", "?since=1&restore_generation=old"} {
		rr := suiteGet(t, srv, "/api/suite/orgs"+suffix, "kycalendar", "cal-secret")
		if rr.Code != 409 || !strings.Contains(rr.Body.String(), "org_resync_required") {
			t.Fatal(rr.Code, rr.Body.String())
		}
	}
	rr := suiteGet(t, srv, "/api/suite/orgs", "kycalendar", "cal-secret")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), generation) {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = suiteGet(t, srv, "/api/suite/orgs?since=1&restore_generation="+generation, "kycalendar", "cal-secret")
	if rr.Code != 200 {
		t.Fatal(rr.Code, rr.Body.String())
	}
}

func TestPlatformOrgReportsAppUsage(t *testing.T) {
	ps := newPlatformSuite(t)
	code, out, body := ps.call(ps.billing, "POST", "/platform/v1/orgs", "usage-create", orgBody("usage", "usage@example.test", 1, `,"apps":{"kydrive":{"enabled":true}}`))
	// App clients must exist before enabling them.
	if code == 400 { // Create the suite app using the real registry path and retry the refused key.
		if err := ps.db.CreateOAuthClient(&store.OAuthClient{ID: "kydrive", ClientName: "Drive", ClientType: "confidential", RedirectURIsJSON: `["https://drive.test/cb"]`, AllowedScopesJSON: `["openid"]`, Enabled: true}, nil); err != nil {
			t.Fatal(err)
		}
		code, out, body = ps.call(ps.billing, "POST", "/platform/v1/orgs", "usage-create", orgBody("usage", "usage@example.test", 1, `,"apps":{"kydrive":{"enabled":true}}`))
	}
	if code != 201 {
		t.Fatal(code, body)
	}
	id, _ := out["id"].(string)
	reports, err := ps.db.Platform().ReportStorage("kydrive", []store.StorageReport{{OrgID: id, UsedBytes: 47, Seq: 3, WantBytes: 10}}, time.Now().UTC())
	if err != nil || reports[0].Result != "ok" {
		t.Fatal(reports, err)
	}
	code, out, body = ps.call(ps.billing, "GET", "/platform/v1/orgs/"+id, "", "")
	var org store.PlatformOrg
	if code != 200 || json.Unmarshal([]byte(body), &org) != nil || org.StorageUsage["kydrive"].UsedBytes != 47 || org.UsedBytes != 47 {
		t.Fatal(code, out)
	}
}

func TestHolderDirectoryExportOverHTTP(t *testing.T) {
	ps := newPlatformSuite(t)
	code, out, body := ps.call(ps.billing, "POST", "/platform/v1/orgs", "exp-create", orgBody("exp", "exp@example.test", 1, ""))
	if code != 201 {
		t.Fatal(code, body)
	}
	id := out["id"].(string)
	holder := out["account_holder_user_id"].(string)
	raw, err := store.OpenRawForTest(ps.srv.cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	q := `UPDATE users SET pending=FALSE,status='active' WHERE id=?`
	if store.OnPostgresTest() {
		q = `UPDATE users SET pending=FALSE,status='active' WHERE id=$1`
	}
	if _, err := raw.Exec(q, holder); err != nil {
		t.Fatal(err)
	}
	u, err := ps.db.GetUserByEmail("exp@example.test")
	if err != nil {
		t.Fatal(err)
	}
	cookie := newSession(t, ps.db, u, time.Now().UTC().Add(time.Hour))
	if rr := adminRequestNoStepUp(t, ps.srv, "GET", "/api/user/org-export", cookie, ""); rr.Code != 404 {
		t.Fatal(rr.Code, rr.Body.String())
	}
	code, _, body = ps.call(ps.billing, "POST", "/platform/v1/orgs/"+id+"/schedule-deletion", "exp-delete", `{"revision":2,"grace_days":7}`)
	if code != 200 {
		t.Fatal(code, body)
	}
	cookie = newSession(t, ps.db, u, time.Now().UTC().Add(time.Hour))
	for _, path := range []string{"/api/user/org-export/status", "/api/user/org-export"} {
		rr := adminRequestNoStepUp(t, ps.srv, "GET", path, cookie, "")
		if rr.Code != http.StatusOK {
			t.Fatal(path, rr.Code, rr.Body.String())
		}
		if strings.Contains(rr.Body.String(), "password_hash") {
			t.Fatal("credential in export")
		}
	}
}

// A billing retry from after the capsule can have a higher revision than the restored
// row. It still must not reopen a restored org without acknowledging this restore.
func TestRestoreRefusesOldBillingResume(t *testing.T) {
	ps := newPlatformSuite(t)
	org := ps.create("restore-resume", "restore-holder@example.test")
	id := org["id"].(string)
	if err := ps.db.SetSetting(store.TenancySetting, "multi"); err != nil {
		t.Fatal(err)
	}
	if _, err := ps.db.ApplyRestoredState(time.Now().UTC(), nil); err != nil {
		t.Fatal(err)
	}
	for key, body := range map[string]string{"old-retry": `{"revision":999}`, "old-generation": `{"revision":999,"restore_generation":"before-restore"}`} {
		code, _, out := ps.call(ps.billing, "POST", "/platform/v1/orgs/"+id+"/resume", key, body)
		if code != 409 || !strings.Contains(out, "restore_reconciliation_required") {
			t.Fatal(code, out)
		}
	}
	code, read, out := ps.call(ps.billing, "GET", "/platform/v1/orgs/"+id, "", "")
	generation, _ := read["restore_generation"].(string)
	if code != 200 || generation == "" || read["status"] != "suspended" {
		t.Fatal(code, out)
	}
	body := fmt.Sprintf(`{"revision":999,"restore_generation":%q}`, generation)
	code, resumed, out := ps.call(ps.billing, "POST", "/platform/v1/orgs/"+id+"/resume", "confirmed", body)
	if code != 200 || resumed["status"] != "active" {
		t.Fatal(code, out)
	}
}

func TestStaffResumeRefusesBillingSuspensionAndPreservesBillingRevision(t *testing.T) {
	ps := newPlatformSuite(t)
	if err := ps.db.SetSetting(store.TenancySetting, "multi"); err != nil {
		t.Fatal(err)
	}
	staffOrg, err := store.CreateOrgForTest(ps.db, "staff")
	if err != nil {
		t.Fatal(err)
	}
	adminUser := newOrgUser(t, ps.db, staffOrg, "admin")
	admin := newSession(t, ps.db, adminUser, time.Now().UTC().Add(time.Hour))

	// Create a customer org and suspend it through billing with reason=payment, with no restore.
	org := ps.create("billing-payment", "pay-holder@example.test")
	id := org["id"].(string)
	code, suspended, out := ps.call(ps.billing, "POST", "/platform/v1/orgs/"+id+"/suspend", "pay-suspend", `{"revision":2,"reason":"payment"}`)
	if code != 200 || suspended["status"] != "suspended" {
		t.Fatal(code, out)
	}
	orgRev := int64(suspended["org_revision"].(float64))

	// Staff admin cannot lift a billing-owned payment suspension.
	res := staffCall(t, ps.srv, "POST", "/api/admin/org/resume", admin, id, fmt.Sprintf(`{"org_revision":%d}`, orgRev))
	if res.Code != 409 {
		t.Fatalf("expected 409 for payment suspension, got %d: %s", res.Code, res.Body.String())
	}
	code, read, out := ps.call(ps.billing, "GET", "/platform/v1/orgs/"+id, "", "")
	if code != 200 || read["status"] != "suspended" || read["status_reason"] != "payment" {
		t.Fatal(code, out)
	}

	// Billing's own next resume at revision 3 still succeeds.
	code, resumed, out := ps.call(ps.billing, "POST", "/platform/v1/orgs/"+id+"/resume", "pay-resume", `{"revision":3}`)
	if code != 200 || resumed["status"] != "active" {
		t.Fatal(code, out)
	}

	// Also verify a billing-suspended org remains unresumable by staff even after a restore,
	// while a restore-held org resumes via org_revision without advancing billing_revision.
	other := ps.create("billing-payment-after-restore", "pay2-holder@example.test")
	otherID := other["id"].(string)
	code, otherSusp, out := ps.call(ps.billing, "POST", "/platform/v1/orgs/"+otherID+"/suspend", "pay2-suspend", `{"revision":2,"reason":"payment"}`)
	if code != 200 || otherSusp["status"] != "suspended" {
		t.Fatal(code, out)
	}
	if _, err := ps.db.ApplyRestoredState(time.Now().UTC(), nil); err != nil {
		t.Fatal(err)
	}
	admin = newSession(t, ps.db, adminUser, time.Now().UTC().Add(time.Hour))
	code, read, out = ps.call(ps.billing, "GET", "/platform/v1/orgs/"+id, "", "")
	if code != 200 || read["status"] != "suspended" || read["status_reason"] != "restore_reconciliation" {
		t.Fatal(code, out)
	}
	generation := read["restore_generation"].(string)
	heldOrgRev := int64(read["org_revision"].(float64))
	otherOrgRev := int64(otherSusp["org_revision"].(float64))

	// Payment-suspended org cannot be resumed by staff even with the current restore_generation.
	res = staffCall(t, ps.srv, "POST", "/api/admin/org/resume", admin, otherID, fmt.Sprintf(`{"org_revision":%d,"restore_generation":%q}`, otherOrgRev, generation))
	if res.Code != 409 {
		t.Fatalf("expected 409 for payment org after restore, got %d: %s", res.Code, res.Body.String())
	}

	// Stale org_revision is rejected with 409.
	res = staffCall(t, ps.srv, "POST", "/api/admin/org/resume", admin, id, fmt.Sprintf(`{"org_revision":%d,"restore_generation":%q}`, heldOrgRev-1, generation))
	if res.Code != 409 {
		t.Fatalf("expected 409 for stale org_revision, got %d: %s", res.Code, res.Body.String())
	}

	// Matching org_revision + restore_generation resumes the restore-held org without touching billing_revision (still 3).
	res = staffCall(t, ps.srv, "POST", "/api/admin/org/resume", admin, id, fmt.Sprintf(`{"org_revision":%d,"restore_generation":%q}`, heldOrgRev, generation))
	if res.Code != 200 {
		t.Fatalf("expected 200 for restore-held org, got %d: %s", res.Code, res.Body.String())
	}
	var staffResumed store.PlatformOrg
	if err := json.Unmarshal(res.Body.Bytes(), &staffResumed); err != nil || staffResumed.Status != "active" || staffResumed.Revision != 3 || staffResumed.OrgRevision <= heldOrgRev {
		t.Fatalf("unexpected staff resume result: %+v err=%v", staffResumed, err)
	}

	// Billing's next lifecycle write at revision 4 still succeeds.
	code, afterBilling, out := ps.call(ps.billing, "POST", "/platform/v1/orgs/"+id+"/suspend", "post-staff-suspend", `{"revision":4,"reason":"payment"}`)
	if code != 200 || afterBilling["status"] != "suspended" {
		t.Fatal(code, out)
	}
}
