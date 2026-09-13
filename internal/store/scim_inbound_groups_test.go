package store

import (
	"errors"
	"testing"
	"time"
)

func activated(t *testing.T, s *Store, connectorID, external, username string) *User {
	t.Helper()
	u := upstream(t, s, connectorID, external, username)
	raw, _ := s.IssueAccountToken(u.ID, "activation", "manual", time.Hour, nil)
	if _, err := s.RedeemAccountToken(raw, "activation", "hash", nil); err != nil {
		t.Fatal(err)
	}
	return u
}

// An upstream group carries exactly its connector's accounts; a foreign member, a local
// account or a group in the member list fails the whole write.
func TestUpstreamGroupsHoldOnlyTheConnectorsAccounts(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	a, _ := s.CreateSCIMConnector("A", nil)
	b, _ := s.CreateSCIMConnector("B", nil)
	alice := activated(t, s, a.ID, "ext-a", "alice")
	bob := activated(t, s, a.ID, "ext-b", "bob")
	other := activated(t, s, b.ID, "ext-o", "other")
	local := createTestUser(t, s)

	g := &Group{Name: "Engineering", SourceConnectorID: a.ID, ExternalID: "grp-1"}
	if err := s.CreateUpstreamGroup(g, []string{alice.ID, bob.ID, alice.ID}, nil); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetUpstreamGroup(a.ID, g.ID)
	if got == nil || got.Name != "Engineering" || len(got.Members) != 2 || got.ExternalID != "grp-1" {
		t.Fatalf("created group: %+v", got)
	}
	for _, bad := range [][]string{{alice.ID, other.ID}, {local.ID}, {g.ID}} {
		bad := bad
		if err := s.CreateUpstreamGroup(&Group{Name: "Bad", SourceConnectorID: a.ID}, bad, nil); !errors.Is(err, ErrGroupMemberForeign) {
			t.Fatalf("foreign member accepted %v: %v", bad, err)
		}
	}
	if n := count(t, s, `SELECT COUNT(*) FROM directory_groups WHERE name='Bad'`); n != 0 {
		t.Fatal("a refused create left a group behind")
	}
	if err := s.CreateUpstreamGroup(&Group{Name: "Engineering", SourceConnectorID: a.ID}, nil, nil); !errors.Is(err, ErrGroupNameExists) {
		t.Fatalf("duplicate name: %v", err)
	}
	if err := s.CreateUpstreamGroup(&Group{Name: "Other name", SourceConnectorID: a.ID, ExternalID: "grp-1"}, nil, nil); !errors.Is(err, ErrGroupExternalExists) {
		t.Fatalf("duplicate external id: %v", err)
	}
	if got, _ := s.GetUpstreamGroup(b.ID, g.ID); got != nil {
		t.Fatal("another connector could read the group")
	}
	list, total, err := s.ListUpstreamGroups(a.ID, "displayName", "engineering", 1, 10)
	if err != nil || total != 1 || len(list) != 1 || len(list[0].Members) != 2 {
		t.Fatalf("filter: %+v %d %v", list, total, err)
	}

	// Replace is all or nothing: a foreign member in the new set rolls the rename back.
	g.Name = "Renamed"
	if err := s.ReplaceUpstreamGroup(a.ID, g, []string{alice.ID, other.ID}, nil); !errors.Is(err, ErrGroupMemberForeign) {
		t.Fatalf("cross-connector member accepted on replace: %v", err)
	}
	if got, _ = s.GetUpstreamGroup(a.ID, g.ID); got.Name != "Engineering" || len(got.Members) != 2 {
		t.Fatalf("refused replace changed the group: %+v", got)
	}
	if err := s.ReplaceUpstreamGroup(a.ID, g, []string{bob.ID}, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.GetUpstreamGroup(a.ID, g.ID); got.Name != "Renamed" || len(got.Members) != 1 || got.Members[0] != bob.ID {
		t.Fatalf("replace: %+v", got)
	}
	g.ExternalID = "grp-2"
	if err := s.ReplaceUpstreamGroup(a.ID, g, []string{bob.ID}, nil); err == nil {
		t.Fatal("external id changed")
	}
	if err := s.ReplaceUpstreamGroup(b.ID, &Group{ID: g.ID, Name: "Hijack"}, nil, nil); !errors.Is(err, ErrGroupTargetMissing) {
		t.Fatalf("another connector replaced the group: %v", err)
	}

	// A local rename of an upstream group is refused; a description edit is fine.
	local2, _ := s.GetUpstreamGroup(a.ID, g.ID)
	if err := s.UpdateGroup(&Group{ID: g.ID, Name: "Local name", Description: ""}, nil); !errors.Is(err, ErrGroupSourceOwned) {
		t.Fatalf("local rename of an upstream group: %v", err)
	}
	if err := s.UpdateGroup(&Group{ID: g.ID, Name: local2.Name, Description: "local note"}, nil); err != nil {
		t.Fatalf("local description edit refused: %v", err)
	}
}

// Upstream membership drives app access and downstream provisioning, and deleting the
// group removes what it granted without touching its users.
func TestUpstreamGroupMembershipDrivesAccessAndDeletionKeepsUsers(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	app := provisioningFixture(t, s, "target")
	a, _ := s.CreateSCIMConnector("A", nil)
	alice := activated(t, s, a.ID, "ext-a", "alice")
	g := &Group{Name: "Staff", SourceConnectorID: a.ID}
	if err := s.CreateUpstreamGroup(g, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppAssignment(app, "groups", g.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if got := pendingFor(t, s, "target", alice.ID); len(got) != 0 {
		t.Fatalf("access before membership: %+v", got)
	}
	if err := s.ReplaceUpstreamGroup(a.ID, g, []string{alice.ID}, nil); err != nil {
		t.Fatal(err)
	}
	if got := pendingFor(t, s, "target", alice.ID); len(got) != 1 || got[0].Type != "user.created" {
		t.Fatalf("join did not provision: %+v", got)
	}
	deliverAll(t, s)
	if err := s.ReplaceUpstreamGroup(a.ID, g, nil, nil); err != nil {
		t.Fatal(err)
	}
	if got := pendingFor(t, s, "target", alice.ID); len(got) != 1 || got[0].Active {
		t.Fatalf("leave did not deprovision: %+v", got)
	}
	if err := s.ReplaceUpstreamGroup(a.ID, g, []string{alice.ID}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUpstreamGroup(a.ID, g.ID, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetUserByID(alice.ID); got == nil || got.Status != "active" || got.SourceConnectorID != a.ID {
		t.Fatalf("group deletion touched the user: %+v", got)
	}
	if got := pendingFor(t, s, "target", alice.ID); len(got) != 1 || got[0].Active {
		t.Fatalf("group deletion did not remove the grant: %+v", got)
	}
	if err := s.DeleteUpstreamGroup(a.ID, g.ID, nil); !errors.Is(err, ErrGroupTargetMissing) {
		t.Fatalf("double delete: %v", err)
	}
	// Disconnecting releases the groups it owned as local groups.
	g2 := &Group{Name: "Kept", SourceConnectorID: a.ID, ExternalID: "k"}
	if err := s.CreateUpstreamGroup(g2, []string{alice.ID}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteSCIMConnector(a.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	groups, _, _ := s.ListGroups("Kept", "", 10, 0)
	if len(groups) != 1 || groups[0].SourceConnectorID != "" || groups[0].MemberCount != 1 {
		t.Fatalf("released group: %+v", groups)
	}
}

func TestUpstreamGroupCreateRollsBackWithoutItsAuditRow(t *testing.T) {
	s, _ := newStoreWithUser(t, "admin")
	a, _ := s.CreateSCIMConnector("A", nil)
	alice := activated(t, s, a.ID, "ext-a", "alice")
	g := &Group{Name: "Audited", SourceConnectorID: a.ID}
	if err := s.CreateUpstreamGroup(g, []string{alice.ID}, poisonedAudit(t, s, "scim.group_created", "")); err == nil {
		t.Fatal("group created without its audit row")
	}
	if n := count(t, s, `SELECT COUNT(*) FROM directory_groups WHERE name='Audited'`); n != 0 {
		t.Fatal("group survived the rollback")
	}
}
