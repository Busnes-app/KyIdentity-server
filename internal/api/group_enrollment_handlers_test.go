package api

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kyidentity-server/internal/store"
)

func TestGroupEnrollmentAdminAndRestrictedAccess(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := enrollmentAPIAdmin(t, srv, db)
	u := newUser(t, db, "user")
	cookie := newSession(t, db, u, time.Now().UTC().Add(time.Hour))
	for _, id := range []string{"a", "b"} {
		if err := db.CreateGroup(&store.Group{ID: id, Name: id}, nil); err != nil {
			t.Fatal(err)
		}
	}
	path := "/api/admin/enrollment-policies"
	if r := adminRequestNoStepUp(t, srv, "GET", path+"?groupId=a", cookie, ""); r.Code != 403 {
		t.Fatal("non-admin policy read", r.Code)
	}
	if r := adminRequestNoStepUp(t, srv, "GET", path+"?groupId=missing", admin, ""); r.Code != 404 {
		t.Fatal("missing group", r.Code)
	}
	r := adminRequestNoStepUp(t, srv, "GET", path+"?groupId=a", admin, "")
	var listed struct {
		Policies []store.EnrollmentPolicy `json:"policies"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &listed); err != nil || len(listed.Policies) != 1 || listed.Policies[0].Scope != "group:a" || listed.Policies[0].Required {
		t.Fatal("group default", r.Body.String(), err)
	}
	memberPath := "/api/admin/groups/a/members/" + u.ID
	if r := adminRequest(t, srv, "PUT", memberPath, admin, ""); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	p := store.EnrollmentPolicy{Scope: "group:a", Required: true, AllowedMethods: []string{"totp"}, Revision: 1}
	body := policyJSON(t, p)
	if r := adminRequestNoStepUp(t, srv, "POST", path+"/preview", admin, body); r.Code != 200 {
		t.Fatal("preview", r.Body.String())
	}
	if r := adminRequestNoStepUp(t, srv, "GET", "/api/user/applications", cookie, ""); r.Code != 200 {
		t.Fatal("preview restricted user", r.Code)
	}
	if r := adminRequestNoStepUp(t, srv, "PUT", path, admin, body); r.Code != 403 {
		t.Fatal("unprotected group policy", r.Code)
	}
	if r := adminRequest(t, srv, "PUT", path, admin, body); r.Code != 200 {
		t.Fatal("apply group policy", r.Code, r.Body.String())
	}
	if r := adminRequest(t, srv, "PUT", path, admin, body); r.Code != 409 {
		t.Fatal("stale policy", r.Code)
	}
	if r := adminRequestNoStepUp(t, srv, "GET", "/api/user/applications", cookie, ""); r.Code != 403 || !strings.Contains(r.Body.String(), "enrollment_required") {
		t.Fatal("group enrollment bypassed", r.Code, r.Body.String())
	}
	p.Scope = "group:b"
	p.AllowedMethods = []string{"webauthn"}
	if r := adminRequest(t, srv, "PUT", path, admin, policyJSON(t, p)); r.Code != 200 {
		t.Fatal("empty group policy", r.Body.String())
	}
	if r := adminRequest(t, srv, "PUT", "/api/admin/groups/b/members/"+u.ID, admin, ""); r.Code != 400 {
		t.Fatal("conflicting membership accepted", r.Code, r.Body.String())
	}
	// Adding the activating administrator cannot strand their own MFA login.
	adminSession, err := db.GetSessionByID("enrollment-admin")
	if err != nil {
		t.Fatal(err)
	}
	if r := adminRequest(t, srv, "PUT", "/api/admin/groups/b/members/"+adminSession.UserID, admin, ""); r.Code != 409 {
		t.Fatal("administrator lockout", r.Code, r.Body.String())
	}
	events, _, err := db.ListAuditEvents(100, 0)
	if err != nil {
		t.Fatal(err)
	}
	success, denied := false, false
	for _, e := range events {
		if e.Action == "admin.mfa_enrollment_policy_changed" && e.Outcome == "success" && strings.Contains(e.DetailsJSON, `"groupName":"a"`) {
			success = true
		}
		if e.Action == "admin.group_member_added" && e.Outcome == "denied" && strings.Contains(e.DetailsJSON, "conflicting_mfa_policies") {
			denied = true
		}
	}
	if !success || !denied {
		t.Fatal("missing group policy audit", success, denied)
	}
}

func TestGroupEnrollmentDeniedScope(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	cookie := enrollmentAPIAdmin(t, srv, db)
	p := store.EnrollmentPolicy{Scope: "group:bad\n\u202e", Required: true, AllowedMethods: []string{"invalid"}, Revision: 1}
	r := adminRequestNoStepUp(t, srv, "POST", "/api/admin/enrollment-policies/preview", cookie, policyJSON(t, p))
	if r.Code != 400 {
		t.Fatal(r.Code, r.Body.String())
	}
	events, _, err := db.ListAuditEvents(100, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.TargetType == "enrollment_policy" && e.Outcome == "denied" {
			if e.TargetID != "" {
				t.Fatalf("unsafe audit target: %q", e.TargetID)
			}
			return
		}
	}
	t.Fatal("missing denial audit")
}
func TestGroupEnrollmentJoinedError(t *testing.T) {
	if os.Getenv("KYIDENTITY_JOINED_ERROR_TEST") == "1" {
		debug.SetMaxStack(65536)
		w := httptest.NewRecorder()
		writeGroupError(w, errors.Join(store.ErrGroupTargetMissing, store.ErrEnrollmentPolicy))
		if w.Code != 400 {
			t.Fatal(w.Code)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestGroupEnrollmentJoinedError$")
	cmd.Env = append(os.Environ(), "KYIDENTITY_JOINED_ERROR_TEST=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("joined error crashed: %v\n%.1000s", err, out)
	}
}
