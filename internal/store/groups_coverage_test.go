package store

import (
	"errors"
	"testing"
	"time"
)

// Guards the SCIM group listing filters: each supported attribute is an exact match
// scoped to the calling connector, unknown attributes are refused, and paging is clamped.
func TestListUpstreamGroupsFiltersAndPaging(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	a, _ := s.CreateSCIMConnector("A", nil)
	b, _ := s.CreateSCIMConnector("B", nil)
	alice := activated(t, s, a.ID, "ext-a", "alice")
	g1 := &Group{Name: "Engineering", SourceConnectorID: a.ID, ExternalID: "grp-1"}
	g2 := &Group{Name: "Sales", SourceConnectorID: a.ID, ExternalID: "grp-2"}
	foreign := &Group{Name: "Marketing", SourceConnectorID: b.ID, ExternalID: "grp-1"}
	for _, g := range []*Group{g1, g2, foreign} {
		var members []string
		if g == g1 {
			members = []string{alice.ID}
		}
		if err := s.CreateUpstreamGroup(g, members, nil); err != nil {
			t.Fatal(err)
		}
	}
	if list, total, err := s.ListUpstreamGroups(a.ID, "externalId", "grp-1", 1, 10); err != nil || total != 1 || len(list) != 1 || list[0].ID != g1.ID || len(list[0].Members) != 1 || list[0].Members[0] != alice.ID {
		t.Fatalf("externalId filter = %+v %d %v", list, total, err)
	}
	if list, total, err := s.ListUpstreamGroups(a.ID, "id", foreign.ID, 1, 10); err != nil || total != 0 || len(list) != 0 {
		t.Fatalf("id filter crossed connectors: %+v %d %v", list, total, err)
	}
	if list, _, _ := s.ListUpstreamGroups(b.ID, "id", foreign.ID, 1, 10); len(list) != 1 {
		t.Fatal("own group not found by id")
	}
	if _, _, err := s.ListUpstreamGroups(a.ID, "members", "x", 1, 10); err == nil {
		t.Fatal("unsupported filter accepted")
	}
	list, total, err := s.ListUpstreamGroups(a.ID, "", "", 0, 500)
	if err != nil || total != 2 || len(list) != 2 {
		t.Fatalf("unfiltered = %d %d %v", len(list), total, err)
	}
	first := list[0].ID
	if list, total, _ := s.ListUpstreamGroups(a.ID, "", "", 2, 10); total != 2 || len(list) != 1 || list[0].ID == first {
		t.Fatalf("second page = %+v %d", list, total)
	}
	if list, total, _ := s.ListUpstreamGroups(a.ID, "", "", 1, -1); total != 2 || len(list) != 0 {
		t.Fatalf("negative count = %+v %d", list, total)
	}
}

// Guards group deletion: an unknown group is ErrGroupTargetMissing; access granted only
// through the group ends with it (tokens revoked); a failed audit rolls everything back.
func TestDeleteGroupRevokesGrantedAccess(t *testing.T) {
	s, u, a := appAccessFixture(t)
	if err := s.DeleteGroup("missing", nil); !errors.Is(err, ErrGroupTargetMissing) {
		t.Fatal("missing group", err)
	}
	if err := s.CreateGroup(&Group{ID: "staff", Name: "Staff"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGroupMembership("staff", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppAssignment(a.ID, "groups", "staff", true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordIssuedToken(accessToken(u, "tok", "")); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGroup("staff", poisonedAudit(t, s, "admin.group_deleted", "staff")); err == nil {
		t.Fatal("delete ignored audit failure")
	}
	if allowed, _ := s.ClientAccessAllowed(u.ID, "client"); !allowed || count(t, s, `SELECT COUNT(*) FROM directory_groups WHERE id='staff'`) != 1 {
		t.Fatal("failed delete removed the group or its access")
	}
	assertRevoked(t, s, "tok", false)
	audit := &AuditEvent{ID: "del-group", Action: "admin.group_deleted", Outcome: "success", CreatedAt: time.Now().UTC()}
	if err := s.DeleteGroup("staff", audit); err != nil {
		t.Fatal(err)
	}
	if allowed, _ := s.ClientAccessAllowed(u.ID, "client"); allowed {
		t.Fatal("access survived group deletion")
	}
	assertRevoked(t, s, "tok", true)
	if count(t, s, `SELECT COUNT(*) FROM audit_events WHERE id='del-group' AND details_json LIKE '%Staff%'`) != 1 {
		t.Fatal("deletion audit does not name the group")
	}
	if got, _ := s.GetUserByID(u.ID); got == nil || got.Status != "active" {
		t.Fatal("group deletion touched the user")
	}
}

// Guards SetSessionLimits: shorter limits end sessions already beyond them, with their
// tokens, in the audited transaction; an audit failure keeps both limits and sessions;
// relaxing later never revives what was ended.
func TestSetSessionLimitsEndsSessionsBeyondLimit(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	now := time.Now().UTC()
	if err := s.LoadSessionLimits(SessionLimits{Absolute: 86400, Idle: 7200}); err != nil {
		t.Fatal(err)
	}
	stale := seedSession(t, s, u.ID, now.Add(time.Hour), now.Add(-time.Hour))
	fresh := seedSession(t, s, u.ID, now.Add(time.Hour), now)
	if _, err := s.SetSessionLimits(SessionLimits{Absolute: 86400, Idle: 900}, poisonedAudit(t, s, "admin.session_limits_changed", "")); err == nil {
		t.Fatal("limits ignored audit failure")
	}
	if s.SessionLimits().Idle != 7200 || count(t, s, `SELECT COUNT(*) FROM sessions WHERE id=?`, stale) != 1 {
		t.Fatal("failed audit applied the limits")
	}
	audit := &AuditEvent{ID: "limits", Action: "admin.session_limits_changed", Outcome: "success", CreatedAt: time.Now().UTC()}
	ended, err := s.SetSessionLimits(SessionLimits{Absolute: 86400, Idle: 900}, audit)
	if err != nil || ended != 1 {
		t.Fatalf("ended = %d, %v; want 1", ended, err)
	}
	if count(t, s, `SELECT COUNT(*) FROM sessions WHERE id=?`, stale) != 0 || count(t, s, `SELECT COUNT(*) FROM sessions WHERE id=?`, fresh) != 1 {
		t.Fatal("wrong sessions ended")
	}
	if count(t, s, `SELECT COUNT(*) FROM audit_events WHERE id='limits' AND details_json LIKE '%"sessionsEnded":1%'`) != 1 {
		t.Fatal("audit details missing the ended count")
	}
	if ended, err := s.SetSessionLimits(SessionLimits{Absolute: 86400, Idle: 7200}, nil); err != nil || ended != 0 {
		t.Fatal("relaxing ended sessions", ended, err)
	}
	if count(t, s, `SELECT COUNT(*) FROM sessions WHERE id=?`, stale) != 0 {
		t.Fatal("relaxing revived an ended session")
	}
}
