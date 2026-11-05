package store

import (
	"testing"
	"time"
)

func TestDeliveryVersionsPreserveDesiredStateAndUncertainEvidence(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	app := provisioningFixture(t, s, "target")
	u := createTestUser(t, s)
	if err := s.SetAppAssignment(app, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	first := deliverAll(t, s)
	if len(first) != 1 {
		t.Fatal(first)
	}
	if err := s.ResetUserMFA(u.ID, nil); err != nil {
		t.Fatal(err)
	}
	events, err := s.ClaimDueSyncEvents(50, time.Minute)
	if err != nil || len(events) != 1 {
		t.Fatal(events, err)
	}
	reset := events[0]
	if reset.Revision != first[0].Revision || reset.DeliveryRevision <= first[0].DeliveryRevision {
		t.Fatalf("desired/wire versions: first=%+v reset=%+v", first, reset)
	}
	if ok, err := s.BeginSyncDelivery(reset, time.Minute); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if err := s.MarkSyncDeliveryUncertain(reset); err != nil {
		t.Fatal(err)
	}
	if err := s.ResyncSystem("target", nil); err != nil {
		t.Fatal(err)
	}
	// Neither a new desired profile, reconciliation nor claim may rewrite an uncertain reset.
	if err := s.ReconcileProvisioning(); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ClaimDueSyncEvents(50, time.Minute); err != nil || len(got) != 0 {
		t.Fatal(got, err)
	}
	var body, eventType string
	var revision, wire int
	if err := s.db.QueryRow(`SELECT payload_json,event_type,revision,delivery_revision FROM account_sync_events WHERE id=?`, reset.ID).Scan(&body, &eventType, &revision, &wire); err != nil {
		t.Fatal(err)
	}
	if body != reset.PayloadJSON || eventType != reset.EventType || revision != reset.Revision || wire != reset.DeliveryRevision {
		t.Fatal("uncertain evidence changed")
	}
	if err := s.ResumeSyncDelivery("target", reset.ClaimToken, false, nil); err == nil {
		t.Fatal("live fence resumed")
	}
	if _, err := s.db.Exec(`UPDATE sync_delivery_attempts SET recover_after=?`, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.ResumeSyncDelivery("target", reset.ClaimToken, false, nil); err != nil {
		t.Fatal(err)
	}
	resumed := deliverAll(t, s)
	if len(resumed) != 1 || resumed[0].ID != reset.ID || resumed[0].DeliveryRevision <= wire {
		t.Fatal("recovered reset did not get a new safe version", resumed)
	}
	later := deliverAll(t, s)
	if len(later) != 1 || later[0].DeliveryRevision <= resumed[0].DeliveryRevision {
		t.Fatal("new state did not follow reset", later)
	}
}

func TestLegacyDeliveryVersionMigration(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	app := provisioningFixture(t, s, "target")
	u := createTestUser(t, s)
	if err := s.SetAppAssignment(app, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	deliverAll(t, s)
	if err := s.ResetUserMFA(u.ID, nil); err != nil {
		t.Fatal(err)
	}
	// Simulate the exact pre-upgrade schema, with a failed reset sharing revision 1.
	for _, sql := range []string{`ALTER TABLE account_sync_events DROP COLUMN delivery_revision`, `ALTER TABLE sync_resource_state DROP COLUMN delivery_revision`, `UPDATE sync_resource_state SET revision=20`, `UPDATE account_sync_events SET status='failed',attempts=5 WHERE event_type='user.mfa_reset'`} {
		if _, err := s.db.Exec(sql); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.migrateProvisioning(); err != nil {
		t.Fatal(err)
	}
	if err := s.migrateSyncDelivery(); err != nil {
		t.Fatal(err)
	}
	if err := s.ReconcileProvisioning(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE account_sync_events SET next_attempt_at=NULL`); err != nil {
		t.Fatal(err)
	}
	got := deliverAll(t, s)
	if len(got) != 1 || got[0].EventType != "user.mfa_reset" || got[0].Revision != 1 || got[0].DeliveryRevision <= 20 {
		t.Fatal("legacy reset not safely sequenced", got)
	}
}
