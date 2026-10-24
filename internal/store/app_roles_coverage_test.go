package store

import (
	"errors"
	"testing"
	"time"
)

func roleRevision(t *testing.T, s *Store, appID string) int {
	t.Helper()
	return count(t, s, `SELECT role_revision FROM app_registry WHERE id=?`, appID)
}

// Guards role mapping input checks: unknown kinds, roles of another app and missing
// principals are refused; a repeated mapping changes nothing, so it neither bumps the
// role revision nor revokes the holder's tokens.
func TestSetAppRoleAssignmentRefusalsAndNoop(t *testing.T) {
	s, u, a := appAccessFixture(t)
	if err := s.SetAppAssignment(a.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	role, err := s.CreateAppRole(a.ID, "operator", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ListAppRoles("missing"); !errors.Is(err, ErrAppRecordMissing) {
		t.Fatal("roles of missing app", err)
	}
	if err := s.SetAppRoleAssignment(a.ID, role.ID, "devices", u.ID, true, nil); !errors.Is(err, ErrAppLinkConflict) {
		t.Fatal("unknown kind", err)
	}
	if err := s.SetAppRoleAssignment(a.ID, "other-role", "users", u.ID, true, nil); !errors.Is(err, ErrAppRecordMissing) {
		t.Fatal("unknown role", err)
	}
	if err := s.SetAppRoleAssignment(a.ID, role.ID, "users", "nobody", true, nil); !errors.Is(err, ErrAppRecordMissing) {
		t.Fatal("unknown user", err)
	}
	if err := s.SetAppRoleAssignment(a.ID, role.ID, "groups", "nogroup", true, nil); !errors.Is(err, ErrAppRecordMissing) {
		t.Fatal("unknown group", err)
	}
	if err := s.SetAppRoleAssignment(a.ID, role.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordIssuedToken(accessToken(u, "tok", "")); err != nil {
		t.Fatal(err)
	}
	before := roleRevision(t, s, a.ID)
	if err := s.SetAppRoleAssignment(a.ID, role.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if roleRevision(t, s, a.ID) != before {
		t.Fatal("no-op mapping bumped the role revision")
	}
	assertRevoked(t, s, "tok", false)
	roles, err := s.ListAppRoles(a.ID)
	if err != nil || len(roles) != 1 || len(roles[0].Users) != 1 || roles[0].Users[0].ID != u.ID {
		t.Fatalf("roles = %+v, %v", roles, err)
	}
}

// Guards role deletion: an unknown role is ErrAppRecordMissing; deleting a held role
// revokes its holders' tokens for the app and bumps the role revision so codes issued
// before it cannot be exchanged; a failed audit rolls the deletion back.
func TestDeleteAppRoleRevokesHolders(t *testing.T) {
	s, u, a := appAccessFixture(t)
	if err := s.SetAppAssignment(a.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	role, _ := s.CreateAppRole(a.ID, "operator", "", nil)
	if err := s.SetAppRoleAssignment(a.ID, role.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordIssuedToken(accessToken(u, "tok", "")); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAppRole(a.ID, "missing", nil); !errors.Is(err, ErrAppRecordMissing) {
		t.Fatal("unknown role deleted", err)
	}
	if err := s.DeleteAppRole("missing-app", role.ID, nil); !errors.Is(err, ErrAppRecordMissing) {
		t.Fatal("role deleted through a missing app", err)
	}
	if err := s.CreateApplication(&Application{ID: "wiki", Name: "Wiki", URL: "https://wiki.example", Enabled: true}, nil); err != nil {
		t.Fatal(err)
	}
	wiki, _, _ := s.ListAppRecords("wiki", 25, 0)
	if err := s.DeleteAppRole(wiki[0].ID, role.ID, nil); !errors.Is(err, ErrAppRecordMissing) {
		t.Fatal("role deleted through another app", err)
	}
	before := roleRevision(t, s, a.ID)
	if err := s.DeleteAppRole(a.ID, role.ID, poisonedAudit(t, s, "admin.app_role_deleted", role.ID)); err == nil {
		t.Fatal("delete ignored audit failure")
	}
	if roles, _ := s.ListAppRoles(a.ID); len(roles) != 1 {
		t.Fatal("failed delete removed the role")
	}
	assertRevoked(t, s, "tok", false)
	audit := &AuditEvent{ID: "role-del", Action: "admin.app_role_deleted", Outcome: "success", CreatedAt: time.Now().UTC()}
	if err := s.DeleteAppRole(a.ID, role.ID, audit); err != nil {
		t.Fatal(err)
	}
	if roles, _ := s.ListAppRoles(a.ID); len(roles) != 0 {
		t.Fatal("role not deleted")
	}
	if roleRevision(t, s, a.ID) <= before {
		t.Fatal("role deletion did not bump the role revision")
	}
	assertRevoked(t, s, "tok", true)
	if count(t, s, `SELECT COUNT(*) FROM audit_events WHERE id='role-del' AND details_json LIKE '%"affectedUsers":1%'`) != 1 {
		t.Fatal("deletion audit missing affected users")
	}
}

// Guards claim settings: saving the current settings revokes nothing; changing the token
// shape revokes every live grant for the app; a stale revision is refused.
func TestSetAppClaimSettingsRevokesOnlyOnChange(t *testing.T) {
	s, u, a := appAccessFixture(t)
	if err := s.SetAppAssignment(a.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordIssuedToken(accessToken(u, "tok", "")); err != nil {
		t.Fatal(err)
	}
	a, _ = s.GetAppRecord(a.ID)
	if err := s.SetAppClaimSettings(a.ID, a.LegacyRoleClaim, a.GroupsClaim, a.Revision, nil); err != nil {
		t.Fatal(err)
	}
	assertRevoked(t, s, "tok", false)
	if err := s.SetAppClaimSettings(a.ID, a.LegacyRoleClaim, !a.GroupsClaim, a.Revision-1, nil); !errors.Is(err, ErrAppLinkConflict) {
		t.Fatal("stale revision", err)
	}
	if err := s.SetAppClaimSettings(a.ID, a.LegacyRoleClaim, !a.GroupsClaim, a.Revision, nil); err != nil {
		t.Fatal(err)
	}
	assertRevoked(t, s, "tok", true)
	if got, _ := s.GetAppRecord(a.ID); got.GroupsClaim == a.GroupsClaim || got.RoleRevision <= a.RoleRevision {
		t.Fatalf("claim change not applied: %+v", got)
	}
}
