package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// Guards restore atomicity with its audit row: a failed audit (or malformed caller
// details) leaves the capsule's sessions, queue and connectors exactly as they were; a
// successful restore merges its counts into the caller's details rather than replacing them.
func TestApplyRestoredStateAuditAtomicity(t *testing.T) {
	s, cleanup := restoreFixture(t)
	defer cleanup()
	sessions := countRows(t, s, `SELECT COUNT(*) FROM sessions`)
	for name, audit := range map[string]*AuditEvent{
		"audit fails":       poisonedAudit(t, s, "admin.restore_applied", ""),
		"malformed details": {ID: "bad", Action: "admin.restore_applied", Outcome: "success", DetailsJSON: "{", CreatedAt: time.Now().UTC()},
	} {
		if _, err := s.ApplyRestoredState(time.Now().UTC(), audit); err == nil {
			t.Fatalf("%s: restore succeeded", name)
		}
		if countRows(t, s, `SELECT COUNT(*) FROM sessions`) != sessions || countRows(t, s, `SELECT COUNT(*) FROM paired_systems WHERE provisioning_hold`) != 0 ||
			countRows(t, s, `SELECT COUNT(*) FROM account_sync_events WHERE id='ev-old' AND status='pending'`) != 1 {
			t.Fatalf("%s: failed restore changed state", name)
		}
	}
	audit := &AuditEvent{ID: "restore", Action: "admin.restore_applied", Outcome: "success", DetailsJSON: `{"capsule":"cap-1"}`, CreatedAt: time.Now().UTC()}
	report, err := s.ApplyRestoredState(time.Now().UTC(), audit)
	if err != nil {
		t.Fatal(err)
	}
	var details map[string]any
	if err := json.Unmarshal([]byte(audit.DetailsJSON), &details); err != nil {
		t.Fatal(err)
	}
	if details["capsule"] != "cap-1" || int(details["credentialsInvalidated"].(float64)) != report.Credentials || int(details["logoutsQueued"].(float64)) != report.LogoutsQueued || report.Credentials == 0 {
		t.Fatalf("details = %v, report = %+v", details, report)
	}
	if countRows(t, s, `SELECT COUNT(*) FROM audit_events WHERE id='restore'`) != 1 {
		t.Fatal("restore not audited")
	}
	if held, err := s.HeldConnectors(); err != nil || len(held) != 1 || held[0] != "hr" {
		t.Fatalf("held = %v, %v", held, err)
	}
}

// Guards the manual hold release: an unknown connector is sql.ErrNoRows, an audit
// failure keeps the hold, and a disabled connector is never reported as held.
func TestResumeProvisioningRules(t *testing.T) {
	s, cleanup := restoreFixture(t)
	defer cleanup()
	if _, err := s.ApplyRestoredState(time.Now().UTC(), nil); err != nil {
		t.Fatal(err)
	}
	if err := s.ResumeProvisioning("missing", nil); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("unknown connector", err)
	}
	if err := s.ResumeProvisioning("hr", poisonedAudit(t, s, "admin.provisioning_resumed", "hr")); err == nil {
		t.Fatal("resume ignored audit failure")
	}
	if held, _ := s.HeldConnectors(); len(held) != 1 {
		t.Fatal("failed resume released the hold")
	}
	mustExec(t, s, `UPDATE paired_systems SET status='disabled' WHERE id='hr'`)
	if held, _ := s.HeldConnectors(); len(held) != 0 {
		t.Fatal("disabled connector reported as held")
	}
	mustExec(t, s, `UPDATE paired_systems SET status='active' WHERE id='hr'`)
	if err := s.ResumeProvisioning("hr", nil); err != nil {
		t.Fatal(err)
	}
	if held, _ := s.HeldConnectors(); len(held) != 0 {
		t.Fatal("resume kept the hold")
	}
}
