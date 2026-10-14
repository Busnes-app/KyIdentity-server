package store

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGroupMembershipIntegrity(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	g := &Group{ID: "group", Name: "Administrators", Description: "A directory group, not a global role"}
	if err := s.CreateGroup(g, nil); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			if err := s.SetGroupMembership(g.ID, u.ID, true, nil); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	members, total, err := s.ListGroupUsers(g.ID, "", false, 25, 0)
	if err != nil || total != 1 || len(members) != 1 || !members[0].Member {
		t.Fatalf("duplicate members: %+v total=%d err=%v", members, total, err)
	}
	saved, err := s.GetUserByID(u.ID)
	if err != nil || saved.Role != "user" {
		t.Fatal("group membership changed global role")
	}
	if err := s.SetGroupMembership("missing", u.ID, true, nil); !errors.Is(err, ErrGroupTargetMissing) {
		t.Fatalf("missing group: %v", err)
	}
	if err := s.SetGroupMembership(g.ID, "missing", false, nil); !errors.Is(err, ErrGroupTargetMissing) {
		t.Fatalf("missing user: %v", err)
	}
	for range 12 {
		wg.Go(func() {
			if err := s.SetGroupMembership(g.ID, u.ID, false, nil); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	_, total, err = s.ListGroupUsers(g.ID, "", false, 25, 0)
	if err != nil || total != 0 {
		t.Fatalf("remove was not idempotent: %d %v", total, err)
	}
	users := []*User{u, createTestUser(t, s), createTestUser(t, s)}
	for _, user := range users {
		wg.Go(func() {
			if err := s.SetGroupMembership(g.ID, user.ID, true, nil); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	_, total, err = s.ListGroupUsers(g.ID, "", false, 25, 0)
	if err != nil || total != 3 {
		t.Fatalf("concurrent edits lost members: %d %v", total, err)
	}
	if err := s.DeleteUserWithSyncEvents(u.ID, nil); err != nil {
		t.Fatal(err)
	}
	_, total, err = s.ListGroupUsers(g.ID, "", false, 25, 0)
	if err != nil || total != 2 {
		t.Fatalf("deleted user left membership: %d %v", total, err)
	}
	if err := s.DeleteGroup(g.ID, nil); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM group_memberships").Scan(&count); err != nil || count != 0 {
		t.Fatalf("deleted group left memberships: %d %v", count, err)
	}
}

func TestGroupsNamesPaginationAndUpgrade(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	for _, g := range []Group{{ID: "a", Name: "Alpha"}, {ID: "b", Name: "Beta"}, {ID: "c", Name: "Gamma"}} {
		if err := s.CreateGroup(&g, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CreateGroup(&Group{ID: "duplicate", Name: "ALPHA"}, nil); !errors.Is(err, ErrGroupNameExists) {
		t.Fatalf("duplicate name: %v", err)
	}
	if err := s.UpdateGroup(&Group{ID: "b", Name: "alpha"}, nil); !errors.Is(err, ErrGroupNameExists) {
		t.Fatalf("duplicate rename: %v", err)
	}
	if err := s.SetGroupMembership("b", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.migrate(); err != nil {
		t.Fatal(err)
	}
	groups, total, err := s.ListGroups("a", u.ID, 1, 1)
	if err != nil || total != 3 || len(groups) != 1 || groups[0].ID != "b" || !groups[0].Member || groups[0].MemberCount != 1 {
		t.Fatalf("page or membership lost after upgrade: %+v %d %v", groups, total, err)
	}
	if err := s.UpdateGroup(&Group{ID: "b", Name: "Beta renamed", Description: "new"}, nil); err != nil {
		t.Fatal(err)
	}
	groups, total, err = s.ListGroups("RENAMED", "", 25, 0)
	if err != nil || total != 1 || groups[0].ID != "b" || groups[0].Description != "new" {
		t.Fatalf("rename changed identity: %+v %v", groups, err)
	}
	groups, total, err = s.ListGroups("%", "", 25, 0)
	if err != nil || total != 0 || len(groups) != 0 {
		t.Fatal("search treated literal percent as wildcard")
	}
	candidate := createTestUserNamed(t, s, "candidate")
	members, total, err := s.ListGroupUsers("b", "CANDIDATE", true, 25, 0)
	if err != nil || total != 1 || members[0].ID != candidate.ID || members[0].Member {
		t.Fatalf("candidate search: %+v %v", members, err)
	}
	_, total, err = s.ListGroupUsers("b", "CANDIDATE", false, 25, 0)
	if err != nil || total != 0 {
		t.Fatal("nonmember leaked into member list")
	}
}

func TestGroupMutationsRollbackWithAuditFailure(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	g := &Group{ID: "group", Name: "Before"}
	if err := s.CreateGroup(g, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER fail_group_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	audit := &AuditEvent{ID: "event", Action: "admin.group_mutation", Outcome: "success", CreatedAt: time.Now().UTC()}
	for _, write := range []func() error{
		func() error { return s.CreateGroup(&Group{ID: "new", Name: "New"}, audit) },
		func() error { return s.UpdateGroup(&Group{ID: g.ID, Name: "After"}, audit) },
		func() error { return s.SetGroupMembership(g.ID, u.ID, true, audit) },
		func() error { return s.DeleteGroup(g.ID, audit) },
	} {
		if err := write(); err == nil || !strings.Contains(err.Error(), "audit unavailable") {
			t.Fatalf("expected audit fault: %v", err)
		}
	}
	groups, total, err := s.ListGroups("", "", 25, 0)
	if err != nil || total != 1 || groups[0].Name != "Before" || groups[0].MemberCount != 0 {
		t.Fatalf("mutation survived failed audit: %+v %v", groups, err)
	}
	if err := s.SetGroupMembership(g.ID, u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGroupMembership(g.ID, u.ID, false, audit); err == nil {
		t.Fatal("removal ignored failed audit")
	}
	if err := s.DeleteGroup(g.ID, audit); err == nil {
		t.Fatal("cascade ignored failed audit")
	}
	_, total, err = s.ListGroupUsers(g.ID, "", false, 25, 0)
	if err != nil || total != 1 {
		t.Fatal("rollback lost membership")
	}
	if _, err := s.db.Exec("DROP TRIGGER fail_group_audit"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGroupMembership(g.ID, u.ID, false, audit); err != nil {
		t.Fatal(err)
	}
	events, count, err := s.ListAuditEvents(25, 0)
	if err != nil || count != 1 || len(events) != 1 {
		t.Fatalf("missing committed audit: %d %v", count, err)
	}
}
