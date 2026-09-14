package store

import (
	"testing"
	"time"
)

// The explanation names what actually decides: the verdict is read from the access
// view itself, and the grants, roles, expiry and policy revisions come from the rows.
func TestExplainAccessMatchesTheDecision(t *testing.T) {
	s, u, a := appAccessFixture(t)
	if err := s.SetAppPolicy(a.ID, "assigned_only", true, a.Revision, nil); err != nil {
		t.Fatal(err)
	}
	check := func(step string, wantAllowed bool, wantReason string) *AccessExplanation {
		t.Helper()
		e, err := s.ExplainAccess(u.ID, a.ID)
		if err != nil {
			t.Fatalf("%s: %v", step, err)
		}
		allowed, _ := s.ClientAccessAllowed(u.ID, "client")
		if e.Allowed != allowed || e.Allowed != wantAllowed || e.Reason != wantReason {
			t.Fatalf("%s: explanation allowed=%v reason=%s, decision allowed=%v, want %v %s", step, e.Allowed, e.Reason, allowed, wantAllowed, wantReason)
		}
		return e
	}
	e := check("unassigned", false, "not_assigned")
	if len(e.Grants) != 0 || e.AppName != "App" || e.Revision < 1 {
		t.Fatalf("unassigned explanation = %+v", e)
	}
	until := future(time.Hour)
	if err := s.SetAppAssignmentUntil(a.ID, "users", u.ID, until, nil); err != nil {
		t.Fatal(err)
	}
	e = check("direct", true, "direct_assignment")
	if len(e.Grants) != 1 || e.Grants[0].Kind != "direct" || !e.Grants[0].Live || e.Grants[0].ExpiresAt == nil || e.AccessEndsAt == nil || !e.AccessEndsAt.Equal(*until) {
		t.Fatalf("direct explanation = %+v", e)
	}
	if err := s.CreateGroup(&Group{ID: "staff", Name: "Staff"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppAssignment(a.ID, "groups", "staff", true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGroupMembership("staff", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	role, _ := s.CreateAppRole(a.ID, "operator", "", nil)
	if err := s.SetAppRoleAssignment(a.ID, role.ID, "groups", "staff", true, nil); err != nil {
		t.Fatal(err)
	}
	// A role mapped through a group that is not assigned to the app names no group.
	if err := s.CreateGroup(&Group{ID: "hidden", Name: "Hidden Project"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGroupMembership("hidden", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppRoleAssignment(a.ID, role.ID, "groups", "hidden", true, nil); err != nil {
		t.Fatal(err)
	}
	e = check("direct and group", true, "direct_assignment")
	if len(e.Grants) != 2 || e.Grants[1].Kind != "group" || e.Grants[1].GroupName != "Staff" || e.AccessEndsAt != nil {
		t.Fatalf("union explanation = %+v", e)
	}
	if len(e.Roles) != 1 || e.Roles[0].Role != "operator" || e.Roles[0].Via != "group" || e.Roles[0].GroupName != "Staff" {
		t.Fatalf("roles = %+v", e.Roles)
	}
	if err := s.SetAppRoleAssignment(a.ID, role.ID, "groups", "hidden", false, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGroupMembership("hidden", u.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	// The direct grant expires: the group still carries access and the lapsed grant is shown as such.
	if _, err := s.db.Exec(`UPDATE app_user_assignments SET expires_at=unixepoch()-1 WHERE user_id=?`, u.ID); err != nil {
		t.Fatal(err)
	}
	e = check("expired direct, live group", true, "group_assignment")
	if e.Grants[0].Live || !e.Grants[1].Live {
		t.Fatalf("liveness = %+v", e.Grants)
	}
	// Every grant expired: denied, and the reason says so rather than "not assigned".
	if err := s.SetGroupMembership("staff", u.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	e = check("expired only", false, "grants_expired")
	if len(e.Roles) != 0 {
		t.Fatalf("roles after leaving the group = %+v", e.Roles)
	}
	// Disabled account, then an ended one.
	if err := s.SetAppAssignmentUntil(a.ID, "users", u.ID, nil, nil); err != nil {
		t.Fatal(err)
	}
	check("re-granted", true, "direct_assignment")
	disabled, _ := s.GetUserByID(u.ID)
	disabled.Status = "disabled"
	if err := s.UpdateUserWithSyncEvents(disabled, true, nil); err != nil {
		t.Fatal(err)
	}
	check("disabled", false, "user_disabled")
	if _, err := s.db.Exec(`UPDATE users SET status='active', ends_at=unixepoch()-1 WHERE id=?`, u.ID); err != nil {
		t.Fatal(err)
	}
	if e = check("ended", false, "account_ended"); e.UserEndsAt == nil {
		t.Fatal("end date missing from the explanation")
	}
	if _, err := s.ExplainAccess("missing", a.ID); err == nil {
		t.Fatal("missing user explained")
	}
	if _, err := s.ExplainClientAccess(u.ID, "no-such-client"); err == nil {
		t.Fatal("unknown client explained")
	}
}
