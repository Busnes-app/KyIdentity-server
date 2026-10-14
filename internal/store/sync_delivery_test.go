package store

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func TestSyncDeliveryOrderingAndCrashRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "delivery.db")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	u := createTestUser(t, s)
	if err := s.CreatePairedSystem(&PairedSystem{ID: "target", Name: "Target", SystemType: "scim", CallbackURL: "https://example.com/scim", Status: "active"}, nil); err != nil {
		t.Fatal(err)
	}
	enqueue := func(id, user string) {
		t.Helper()
		if err := s.CreateAccountSyncEvent(&AccountSyncEvent{ID: id, SystemID: "target", UserID: user, EventType: "user.updated", PayloadJSON: `{}`, Status: "pending"}); err != nil {
			t.Fatal(err)
		}
	}
	claim := func() []AccountSyncEvent {
		t.Helper()
		events, err := s.ClaimDueSyncEvents(50, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return events
	}
	enqueue("first", u.ID)
	enqueue("second", u.ID)
	enqueue("other", "other")
	events := claim()
	if len(events) != 2 || events[0].ID != "first" || events[1].ID != "other" {
		t.Fatalf("not one head per resource: %+v", events)
	}
	first := events[0]
	// A claimed-but-unsent worker cannot send after its claim was reassigned.
	if _, err := s.db.Exec(`UPDATE account_sync_events SET lease_until=? WHERE id='first'`, time.Now().UTC().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	newer := claim()
	if len(newer) != 1 {
		t.Fatal(newer)
	}
	if ok, err := s.BeginSyncDelivery(first, time.Minute); err != nil || ok {
		t.Fatal("stale claim began", ok, err)
	}
	first = newer[0]
	if ok, err := s.BeginSyncDelivery(first, -time.Second); err != nil || !ok {
		t.Fatal("begin", ok, err)
	}
	// Expiration and process restart do not mean a remote write has stopped.
	s.Close()
	s, err = New(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := claim(); len(got) != 0 {
		t.Fatalf("expired in-flight attempt reclaimed: %+v", got)
	}
	// Local deletion removes the old event but not its in-flight resource fence.
	if _, err := s.db.Exec(`INSERT INTO sync_resource_state(system_id,resource_id,active,provisioned,revision) VALUES('target',?,1,1,1)`, u.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUserWithSyncEvents(u.ID, nil); err != nil {
		t.Fatal(err)
	}
	if got := claim(); len(got) != 0 {
		t.Fatal("delete bypassed in-flight write", got)
	}
	if err := s.FinishSyncDelivery(first, "delivered", "", 1, nil); err != nil {
		t.Fatal(err)
	}
	got := claim()
	if len(got) != 1 || got[0].EventType != "user.deleted" || got[0].Revision != 2 {
		t.Fatal("delete not released", got)
	}
	if ok, err := s.BeginSyncDelivery(got[0], -time.Second); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if _, err := s.StartSCIMCreate("target", "user", u.ID); err != nil {
		t.Fatal(err)
	}
	// Failed audit rolls recovery back along with fence and create-marker removal.
	if _, err := s.db.Exec(`CREATE TRIGGER reject_delivery_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'audit failed'); END`); err != nil {
		t.Fatal(err)
	}
	audit := &AuditEvent{ID: "resume", Action: "admin.sync_delivery_resumed", Outcome: "success"}
	if err := s.ResumeSyncDelivery("target", got[0].ClaimToken, true, audit); err == nil {
		t.Fatal("recovery without audit")
	}
	if _, started, err := s.SCIMUserLink("target", u.ID); err != nil || !started {
		t.Fatal("audit rollback lost create marker", started, err)
	}
	attempts, err := s.ListSyncDeliveryAttempts("target")
	if err != nil || len(attempts) != 1 {
		t.Fatal(attempts, err)
	}
	if _, err := s.db.Exec(`DROP TRIGGER reject_delivery_audit`); err != nil {
		t.Fatal(err)
	}
	if err := s.ResumeSyncDelivery("target", got[0].ClaimToken, true, audit); err != nil {
		t.Fatal(err)
	}
	if _, started, err := s.SCIMUserLink("target", u.ID); err != nil || started {
		t.Fatal("confirmed create retry retained marker", started, err)
	}
	if err := s.FinishSyncDelivery(got[0], "delivered", "", 1, nil); err == nil {
		t.Fatal("old worker completed resumed attempt")
	}
	if len(claim()) != 1 {
		t.Fatal("recovered event not queued")
	}
}

func TestSyncDeliveryBackoffHoldsLaterEvents(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	for _, id := range []string{"first", "second"} {
		if err := s.CreateAccountSyncEvent(&AccountSyncEvent{ID: id, UserID: "u", SystemID: "s", EventType: "user.updated", Status: "pending", PayloadJSON: `{}`}); err != nil {
			t.Fatal(err)
		}
	}
	next := time.Now().UTC().Add(time.Hour)
	if err := s.UpdateSyncEventStatus("first", "pending", "retry", 1, &next); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ClaimDueSyncEvents(50, time.Minute); err != nil || len(got) != 0 {
		t.Fatal("backoff bypassed", got, err)
	}
	// Legacy rows exhausted by missing credentials used to remain pending at five.
	if err := s.UpdateSyncEventStatus("first", "pending", "exhausted", 5, nil); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ClaimDueSyncEvents(50, time.Minute); err != nil || len(got) != 1 || got[0].ID != "second" {
		t.Fatal("exhausted legacy head starved queue", got, err)
	}
}

func TestDeletedSystemEventsAreRemovedAndNeverRevived(t *testing.T) {
	path := filepath.Join(t.TempDir(), "orphans.db")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	for _, id := range []string{"gone", "kept"} {
		if err := s.CreatePairedSystem(&PairedSystem{ID: id, Name: id, SystemType: "scim", CallbackURL: "https://example.com/scim", Status: "active"}, nil); err != nil {
			t.Fatal(err)
		}
		if err := s.CreateAccountSyncEvent(&AccountSyncEvent{ID: id + "-deleted", SystemID: id, UserID: "u1", EventType: "user.deleted", PayloadJSON: `{}`, Status: "failed", Attempts: 5}); err != nil {
			t.Fatal(err)
		}
		if err := s.CreateAccountSyncEvent(&AccountSyncEvent{ID: id + "-fenced", SystemID: id, UserID: "u2", EventType: "user.updated", PayloadJSON: `{}`, Status: "pending"}); err != nil {
			t.Fatal(err)
		}
	}
	events, err := s.ClaimDueSyncEvents(50, time.Minute)
	if err != nil || len(events) != 2 {
		t.Fatal(events, err)
	}
	for _, ev := range events {
		if ok, err := s.BeginSyncDelivery(ev, time.Minute); err != nil || !ok {
			t.Fatal(ok, err)
		}
	}
	if ok, err := s.DeletePairedSystem("gone", nil); err != nil || !ok {
		t.Fatal(ok, err)
	}
	count := func(table, system string) int {
		t.Helper()
		var n int
		if err := s.db.QueryRow(`SELECT count(*) FROM `+table+` WHERE system_id=?`, system).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count("account_sync_events", "gone") != 0 || count("sync_delivery_attempts", "gone") != 0 {
		t.Fatal("deleted system left events or attempts")
	}
	if count("account_sync_events", "kept") != 2 || count("sync_delivery_attempts", "kept") != 1 {
		t.Fatal("another system's queue or fence changed")
	}
	// An orphan left by an older release must not be revived by reconcile...
	if _, err := s.db.Exec(`INSERT INTO account_sync_events(id,user_id,system_id,event_type,payload_json,attempts,status) VALUES('ghost','u1','ghost','user.deleted','{}',5,'failed')`); err != nil {
		t.Fatal(err)
	}
	if err := s.ReconcileProvisioning(); err != nil {
		t.Fatal(err)
	}
	var status string
	var attempts int
	if err := s.db.QueryRow(`SELECT status,attempts FROM account_sync_events WHERE id='ghost'`).Scan(&status, &attempts); err != nil || status != "failed" || attempts != 5 {
		t.Fatal("orphan revived", status, attempts, err)
	}
	if err := s.db.QueryRow(`SELECT status FROM account_sync_events WHERE id='kept-deleted'`).Scan(&status); err != nil || status != "pending" {
		t.Fatal("live system's stateless event not revived", status, err)
	}
	// ...and is removed at the next start, idempotently.
	for range 2 {
		s.Close()
		if s, err = New(path); err != nil {
			t.Fatal(err)
		}
		if count("account_sync_events", "ghost") != 0 || count("account_sync_events", "kept") != 2 {
			t.Fatal("startup cleanup wrong")
		}
	}
}

func TestResumeSyncDeliveriesReleasesOnlyExpiredAttempts(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	for _, id := range []string{"target", "other"} {
		if err := s.CreatePairedSystem(&PairedSystem{ID: id, Name: id, SystemType: "scim", CallbackURL: "https://example.com/scim", Status: "active"}, nil); err != nil {
			t.Fatal(err)
		}
	}
	window := map[string]time.Duration{"expired-a": -time.Second, "expired-b": -time.Second, "running": time.Minute, "other": -time.Second}
	for id := range window {
		system := "target"
		if id == "other" {
			system = "other"
		}
		if err := s.CreateAccountSyncEvent(&AccountSyncEvent{ID: id, SystemID: system, UserID: id, EventType: "user.created", PayloadJSON: `{}`, Status: "pending"}); err != nil {
			t.Fatal(err)
		}
	}
	events, err := s.ClaimDueSyncEvents(50, time.Minute)
	if err != nil || len(events) != 4 {
		t.Fatal(events, err)
	}
	for _, ev := range events {
		if ok, err := s.BeginSyncDelivery(ev, window[ev.ID]); err != nil || !ok {
			t.Fatal(ok, err)
		}
	}
	// An uncertain-create guard survives bulk resume.
	if _, err := s.db.Exec(`INSERT INTO scim_user_links(system_id,local_id,remote_id) VALUES('target','expired-a','')`); err != nil {
		t.Fatal(err)
	}
	audit := &AuditEvent{ID: "bulk", Action: "admin.sync_deliveries_resumed", Outcome: "success", DetailsJSON: `{"systemName":"target"}`}
	n, err := s.ResumeSyncDeliveries("target", audit)
	if err != nil || n != 2 {
		t.Fatal(n, err)
	}
	var details struct {
		SystemName    string
		AttemptTokens []string
	}
	if err := json.Unmarshal([]byte(audit.DetailsJSON), &details); err != nil || details.SystemName != "target" || len(details.AttemptTokens) != 2 {
		t.Fatal(audit.DetailsJSON, err)
	}
	left := map[string]bool{}
	rows, err := s.db.Query(`SELECT event_id FROM sync_delivery_attempts`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		_ = rows.Scan(&id)
		left[id] = true
	}
	rows.Close()
	if len(left) != 2 || !left["running"] || !left["other"] {
		t.Fatal("wrong attempts released", left)
	}
	var guard int
	if err := s.db.QueryRow(`SELECT count(*) FROM scim_user_links WHERE system_id='target' AND local_id='expired-a' AND remote_id=''`).Scan(&guard); err != nil || guard != 1 {
		t.Fatal("create guard cleared", guard, err)
	}
	var audits int
	if err := s.db.QueryRow(`SELECT count(*) FROM audit_events WHERE action='admin.sync_deliveries_resumed'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("audit count", audits, err)
	}
	if _, err := s.ResumeSyncDeliveries("target", &AuditEvent{ID: "again", Action: "admin.sync_deliveries_resumed"}); err == nil {
		t.Fatal("empty resume succeeded")
	}
}

// Read-only listings run on the read pool, so they neither wait behind a writer
// nor can write.
func TestReadOnlyListingsDoNotWaitForWriter(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	if err := s.CreatePairedSystem(&PairedSystem{ID: "target", Name: "target", SystemType: "scim", CallbackURL: "https://example.com/scim", Status: "active"}, nil); err != nil {
		t.Fatal(err)
	}
	writer, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback()
	if _, err := writer.Exec(`UPDATE paired_systems SET name='held' WHERE id='target'`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := s.ListGroups("", "", 10, 0)
		if err == nil {
			_, _, err = s.ListProvisioningState("target", "", 10, 0)
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("read-only listing waited for the writer")
	}
	if _, err := s.rdb.Exec(`DELETE FROM audit_events`); err == nil {
		t.Fatal("read pool accepted a write")
	}
}
