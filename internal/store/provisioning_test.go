package store

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type queued struct {
	Type     string
	Revision int
	Active   bool
}

func pendingFor(t *testing.T, s *Store, systemID, resourceID string) []queued {
	t.Helper()
	rows, err := s.db.Query(`SELECT event_type,revision,payload_json FROM account_sync_events WHERE system_id=? AND user_id=? AND status IN ('pending','failed') ORDER BY rowid`, systemID, resourceID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []queued
	for rows.Next() {
		var q queued
		var payload string
		if err := rows.Scan(&q.Type, &q.Revision, &payload); err != nil {
			t.Fatal(err)
		}
		var body struct{ Active bool }
		_ = json.Unmarshal([]byte(payload), &body)
		q.Active = body.Active
		out = append(out, q)
	}
	return out
}

func deliverAll(t *testing.T, s *Store) []AccountSyncEvent {
	t.Helper()
	events, err := s.ClaimDueSyncEvents(50, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range events {
		if ok, err := s.BeginSyncDelivery(ev, time.Minute); err != nil || !ok {
			t.Fatal("begin", ok, err)
		}
		if err := s.FinishSyncDelivery(ev, "delivered", "", ev.Attempts+1, nil); err != nil {
			t.Fatal(err)
		}
	}
	return events
}

func provisioningFixture(t *testing.T, s *Store, systemID string) (appID string) {
	t.Helper()
	if err := s.CreatePairedSystem(&PairedSystem{ID: systemID, Name: systemID, SystemType: "scim", CallbackURL: "https://example.com/scim", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT id FROM app_registry WHERE system_id=?`, systemID).Scan(&appID); err != nil {
		t.Fatal(err)
	}
	return appID
}

func TestProvisioningFollowsEffectiveAccess(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	app := provisioningFixture(t, s, "target")
	u := createTestUser(t, s)
	g := &Group{ID: uuid.NewString(), Name: "staff"}
	if err := s.CreateGroup(g, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGroupMembership(g.ID, u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if got := pendingFor(t, s, "target", u.ID); len(got) != 0 {
		t.Fatal("unassigned user queued", got)
	}
	assign := func(kind, principal string, on bool) {
		t.Helper()
		if err := s.SetAppAssignment(app, kind, principal, on, nil); err != nil {
			t.Fatal(err)
		}
	}
	assign("users", u.ID, true)
	if got := pendingFor(t, s, "target", u.ID); len(got) != 1 || got[0] != (queued{"user.created", 1, true}) {
		t.Fatal("gain", got)
	}
	assign("groups", g.ID, true)
	assign("users", u.ID, false)
	if got := pendingFor(t, s, "target", u.ID); len(got) != 1 || got[0].Type != "user.created" {
		t.Fatal("second grant changed the queue", got)
	}
	// Final removal before anything was delivered forgets the account instead of disabling a ghost.
	assign("groups", g.ID, false)
	if got := pendingFor(t, s, "target", u.ID); len(got) != 0 {
		t.Fatal("undelivered create survived loss", got)
	}
	var rows int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sync_resource_state WHERE resource_id=?`, u.ID).Scan(&rows); err != nil || rows != 0 {
		t.Fatal("state row retained", rows, err)
	}
	assign("users", u.ID, true)
	assign("groups", g.ID, true)
	if events := deliverAll(t, s); len(events) != 1 || events[0].EventType != "user.created" {
		t.Fatal(events)
	}
	assign("users", u.ID, false)
	if got := pendingFor(t, s, "target", u.ID); len(got) != 0 {
		t.Fatal("removing one of two grants changed the account", got)
	}
	assign("groups", g.ID, false)
	if got := pendingFor(t, s, "target", u.ID); len(got) != 1 || got[0] != (queued{"user.updated", 2, false}) {
		t.Fatal("final removal", got)
	}
	assign("users", u.ID, true)
	if got := pendingFor(t, s, "target", u.ID); len(got) != 1 || got[0] != (queued{"user.updated", 3, true}) {
		t.Fatal("regain superseded the disable with a reactivation", got)
	}
	u.DisplayName = "Renamed"
	if err := s.UpdateUserWithSyncEvents(u, false, nil); err != nil {
		t.Fatal(err)
	}
	if got := pendingFor(t, s, "target", u.ID); len(got) != 1 || got[0] != (queued{"user.updated", 4, true}) {
		t.Fatal("profile update", got)
	}
	u.Status = "disabled"
	if err := s.UpdateUserWithSyncEvents(u, true, nil); err != nil {
		t.Fatal(err)
	}
	if got := pendingFor(t, s, "target", u.ID); len(got) != 1 || got[0] != (queued{"user.updated", 5, false}) {
		t.Fatal("local disable", got)
	}
	if err := s.ResetUserMFA(u.ID, nil); err != nil {
		t.Fatal(err)
	}
	if got := pendingFor(t, s, "target", u.ID); len(got) != 1 {
		t.Fatal("MFA reset notified a connector holding a disabled account", got)
	}
}

func TestProvisioningLossBehindFence(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	app := provisioningFixture(t, s, "target")
	u := createTestUser(t, s)
	if err := s.SetAppAssignment(app, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	events, err := s.ClaimDueSyncEvents(50, time.Minute)
	if err != nil || len(events) != 1 {
		t.Fatal(events, err)
	}
	if ok, err := s.BeginSyncDelivery(events[0], time.Minute); err != nil || !ok {
		t.Fatal(ok, err)
	}
	// The create may already have reached the receiver, so the disable queues behind it.
	if err := s.SetAppAssignment(app, "users", u.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	if got := pendingFor(t, s, "target", u.ID); len(got) != 2 || got[1] != (queued{"user.updated", 2, false}) {
		t.Fatal("loss behind fence", got)
	}
	if next, _ := s.ClaimDueSyncEvents(50, time.Minute); len(next) != 0 {
		t.Fatal("disable overtook the fenced create", next)
	}
	if err := s.FinishSyncDelivery(events[0], "delivered", "", 1, nil); err != nil {
		t.Fatal(err)
	}
	next, _ := s.ClaimDueSyncEvents(50, time.Minute)
	if len(next) != 1 || next[0].EventType != "user.updated" || next[0].Revision != 2 {
		t.Fatal("disable not released after create", next)
	}
	// An old create retry cannot run after the disable: nothing older remains queued.
	if got := pendingFor(t, s, "target", u.ID); len(got) != 1 {
		t.Fatal(got)
	}
}

func TestResyncNeverProvisionsUnassignedUsers(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	app := provisioningFixture(t, s, "target")
	assigned, other := createTestUser(t, s), createTestUser(t, s)
	if err := s.SetAppAssignment(app, "users", assigned.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	deliverAll(t, s)
	if err := s.ResyncSystem("target"); err != nil {
		t.Fatal(err)
	}
	if got := pendingFor(t, s, "target", assigned.ID); len(got) != 1 || got[0] != (queued{"user.created", 2, true}) {
		t.Fatal("resync of a held account", got)
	}
	if got := pendingFor(t, s, "target", other.ID); len(got) != 0 {
		t.Fatal("resync provisioned an unassigned user", got)
	}
	if err := s.ResyncSystem("missing"); err == nil {
		t.Fatal("resync of unknown system")
	}
}

func TestDeleteUserNotifiesEveryConnector(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	app := provisioningFixture(t, s, "target")
	provisioningFixture(t, s, "legacy")
	provisioningFixture(t, s, "stranger")
	u := createTestUser(t, s)
	if err := s.SetAppAssignment(app, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	deliverAll(t, s)
	// A pre-upgrade connector holds the account without any desired-state row.
	if err := s.SaveSCIMUserLink("legacy", u.ID, "remote"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUserWithSyncEvents(u.ID, nil); err != nil {
		t.Fatal(err)
	}
	if got := pendingFor(t, s, "target", u.ID); len(got) != 1 || got[0] != (queued{"user.deleted", 2, false}) {
		t.Fatal("deletion", got)
	}
	if got := pendingFor(t, s, "legacy", u.ID); len(got) != 1 || got[0] != (queued{"user.deleted", 1, false}) {
		t.Fatal("deletion skipped a connector without desired-state rows", got)
	}
	// A connector that never held the account learns only the identifier.
	var body string
	if err := s.db.QueryRow(`SELECT payload_json FROM account_sync_events WHERE system_id='stranger' AND user_id=?`, u.ID).Scan(&body); err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal([]byte(body), &fields); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"userName", "emails", "displayName", "name", "roles"} {
		if v, ok := fields[k]; ok && v != "" {
			t.Fatalf("profile field %s sent to a connector that never held the account: %s", k, body)
		}
	}
	if fields["id"] != u.ID || fields["active"] != false {
		t.Fatal(body)
	}
	if err := s.db.QueryRow(`SELECT payload_json FROM account_sync_events WHERE system_id='legacy' AND user_id=?`, u.ID).Scan(&body); err != nil || !strings.Contains(body, u.Username) {
		t.Fatal("holding connector lost the profile", body, err)
	}
}

func TestReconcileDiscardsSupersededFailedCreate(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	app := provisioningFixture(t, s, "target")
	u := createTestUser(t, s)
	if err := s.SetAppAssignment(app, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	creates, err := s.ClaimDueSyncEvents(10, time.Minute)
	if err != nil || len(creates) != 1 {
		t.Fatal(creates, err)
	}
	if ok, err := s.BeginSyncDelivery(creates[0], time.Minute); err != nil || !ok {
		t.Fatal(ok, err)
	}
	// Revoked while the create is fenced: the disable queues behind it.
	if err := s.SetAppAssignment(app, "users", u.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishSyncDelivery(creates[0], "failed", "boom", 5, nil); err != nil {
		t.Fatal(err)
	}
	if events := deliverAll(t, s); len(events) != 1 || events[0].EventType != "user.updated" {
		t.Fatal("disable did not deliver past the exhausted create", events)
	}
	if err := s.ReconcileProvisioning(); err != nil {
		t.Fatal(err)
	}
	for _, q := range pendingFor(t, s, "target", u.ID) {
		if q.Type == "user.created" {
			t.Fatal("superseded create revived after the disable", q)
		}
	}
	if pending, _ := s.GetPendingSyncEvents(10); len(pending) != 0 {
		t.Fatal(pending)
	}
}

func TestProvisioningRevivesExhaustedWork(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	app := provisioningFixture(t, s, "target")
	u := createTestUser(t, s)
	if err := s.SetAppAssignment(app, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	deliverAll(t, s)
	if err := s.SetAppAssignment(app, "users", u.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	events, err := s.ClaimDueSyncEvents(10, time.Minute)
	if err != nil || len(events) != 1 {
		t.Fatal(events, err)
	}
	if ok, err := s.BeginSyncDelivery(events[0], time.Minute); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if err := s.FinishSyncDelivery(events[0], "failed", "boom", 5, nil); err != nil {
		t.Fatal(err)
	}
	if pending, _ := s.GetPendingSyncEvents(10); len(pending) != 0 {
		t.Fatal("exhausted event still listed", pending)
	}
	if err := s.ReconcileProvisioning(); err != nil {
		t.Fatal(err)
	}
	pending, err := s.GetPendingSyncEvents(10)
	if err != nil || len(pending) != 1 || pending[0].EventType != "user.updated" || pending[0].Attempts != 0 || pending[0].NextAttempt == nil {
		t.Fatalf("disable not revived into backoff: %+v %v", pending, err)
	}
	if got := pendingFor(t, s, "target", u.ID); len(got) != 1 || got[0] != (queued{"user.updated", 2, false}) {
		t.Fatal(got)
	}
}

func TestGroupDeliveryFollowsAssignmentsAndMembers(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	app := provisioningFixture(t, s, "target")
	u := createTestUser(t, s)
	g := &Group{ID: uuid.NewString(), Name: "staff"}
	if err := s.CreateGroup(g, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGroupMembership(g.ID, u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppAssignment(app, "groups", g.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if got := pendingFor(t, s, "target", g.ID); len(got) != 0 {
		t.Fatal("group queued without capability", got)
	}
	if err := s.ConfigureSystem("target", "scim", "scim", "secret", true, 0, nil); err != nil {
		t.Fatal(err)
	}
	if got := pendingFor(t, s, "target", g.ID); len(got) != 1 || got[0].Type != "group.updated" {
		t.Fatal("enable groups", got)
	}
	name, exists, members, err := s.SCIMGroupMembers("target", g.ID)
	if err != nil || !exists || name != "staff" || len(members) != 0 {
		t.Fatal("members before the user exists remotely", name, exists, members, err)
	}
	// Delivering the member's create establishes its link and re-queues the group.
	if _, err := s.db.Exec(`DELETE FROM account_sync_events WHERE user_id=?`, g.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveSCIMUserLink("target", u.ID, "remote-user"); err != nil {
		t.Fatal(err)
	}
	events := deliverAll(t, s)
	if len(events) != 1 || events[0].EventType != "user.created" {
		t.Fatal(events)
	}
	if got := pendingFor(t, s, "target", g.ID); len(got) != 1 || got[0].Type != "group.updated" {
		t.Fatal("group not re-queued after member delivery", got)
	}
	if _, _, members, err = s.SCIMGroupMembers("target", g.ID); err != nil || len(members) != 1 || members[0] != "remote-user" {
		t.Fatal(members, err)
	}
	g.Name = "team"
	if err := s.UpdateGroup(g, nil); err != nil {
		t.Fatal(err)
	}
	if got := pendingFor(t, s, "target", g.ID); len(got) != 1 || got[0].Type != "group.updated" || got[0].Revision != 3 {
		t.Fatal("rename superseded", got)
	}
	deliverAll(t, s)
	if err := s.SetGroupMembership(g.ID, u.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	if got := pendingFor(t, s, "target", g.ID); len(got) != 1 || got[0].Type != "group.updated" {
		t.Fatal("membership change", got)
	}
	if got := pendingFor(t, s, "target", u.ID); len(got) != 1 || got[0] != (queued{"user.updated", 2, false}) {
		t.Fatal("member lost scope", got)
	}
	if err := s.SetAppAssignment(app, "groups", g.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	if got := pendingFor(t, s, "target", g.ID); len(got) != 1 || got[0].Type != "group.deleted" {
		t.Fatal("unassign", got)
	}
	deliverAll(t, s)
	var rows int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sync_resource_state WHERE resource_id=?`, g.ID).Scan(&rows); err != nil || rows != 0 {
		t.Fatal("deleted group state retained", rows, err)
	}
	if _, exists, _, err = s.SCIMGroupMembers("target", uuid.NewString()); err != nil || exists {
		t.Fatal("unknown group reported", exists, err)
	}
}

func TestProvisioningBackfillMarksExistingPairsProvisioned(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	app := provisioningFixture(t, s, "target")
	u := createTestUser(t, s)
	if err := s.SetAppPolicy(app, "all_active_users", true, 1, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DROP TABLE sync_resource_state; DELETE FROM account_sync_events`); err != nil {
		t.Fatal(err)
	}
	if err := s.migrateProvisioning(); err != nil {
		t.Fatal(err)
	}
	var active, provisioned bool
	if err := s.db.QueryRow(`SELECT active,provisioned FROM sync_resource_state WHERE system_id='target' AND resource_id=?`, u.ID).Scan(&active, &provisioned); err != nil || !active || !provisioned {
		t.Fatal("backfill", active, provisioned, err)
	}
	if err := s.ReconcileProvisioning(); err != nil {
		t.Fatal(err)
	}
	if got := pendingFor(t, s, "target", u.ID); len(got) != 0 {
		t.Fatal("upgrade re-sent the directory", got)
	}
}
