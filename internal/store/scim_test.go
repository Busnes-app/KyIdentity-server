package store

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestSCIMMappingDurability(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scim.db")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	u := createTestUser(t, s)
	for _, id := range []string{"a", "b"} {
		if err = s.CreatePairedSystem(&PairedSystem{ID: id, Name: id, SystemType: "scim", CallbackURL: "https://example.com/scim", Status: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	first, err := s.StartSCIMCreate("a", "user", u.ID)
	if err != nil || !first {
		t.Fatal("create not claimed", err)
	}
	first, err = s.StartSCIMCreate("a", "user", u.ID)
	if err != nil || first {
		t.Fatal("duplicate create claimed", err)
	}
	if err = s.SaveSCIMUserLink("a", u.ID, "remote"); err != nil {
		t.Fatal(err)
	}
	if err = s.SaveSCIMUserLink("a", "other", "remote"); err == nil {
		t.Fatal("same remote ID assigned twice")
	}
	if err = s.SaveSCIMUserLink("a", u.ID, "different"); err == nil {
		t.Fatal("mapping silently changed")
	}
	if err = s.SaveSCIMUserLink("b", u.ID, "remote"); err != nil {
		t.Fatal("connector mappings overlap", err)
	}
	if err = s.DeleteUserWithSyncEvents(u.ID, nil); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	id, started, err := s.SCIMUserLink("a", u.ID)
	if err != nil || !started || id != "remote" {
		t.Fatalf("mapping lost after delete/restart: %q %v %v", id, started, err)
	}
	if _, err = s.DeletePairedSystem("a", nil); err != nil {
		t.Fatal(err)
	}
	_, started, err = s.SCIMUserLink("a", u.ID)
	if err != nil || started {
		t.Fatal("connector mapping not cascaded", err)
	}
}

func TestSCIMConfigurationAuditRollback(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	sys := &PairedSystem{ID: "legacy", Name: "legacy", SystemType: "custom", CallbackURL: "https://example.com/scim", HMACSecretEncrypted: "original", Status: "active"}
	if err := s.CreatePairedSystem(sys); err != nil {
		t.Fatal(err)
	}
	// Force audit persistence to fail and prove the credential/protocol write rolls back.
	if _, err := s.db.Exec(`CREATE TRIGGER reject_scim_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	err := s.ConfigureSystem(sys.ID, "custom", "scim", "replacement", false, 0, &AuditEvent{ID: "audit", Action: "admin.system_configured"})
	if err == nil {
		t.Fatal("configuration succeeded without audit")
	}
	loaded, err := s.GetPairedSystemByID(sys.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.SystemType != "custom" || loaded.HMACSecretEncrypted != "original" {
		t.Fatal("configuration escaped rollback")
	}
}

func TestPausedConnectorsDoNotStarveDispatch(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	for _, sys := range []PairedSystem{
		{ID: "legacy", Name: "legacy", SystemType: "custom", Status: "active"},
		{ID: "disabled", Name: "disabled", SystemType: "scim", Status: "disabled"},
		{ID: "live", Name: "live", SystemType: "scim", Status: "active"},
	} {
		if err := s.CreatePairedSystem(&sys); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 55 {
		if err := s.CreateAccountSyncEvent(&AccountSyncEvent{ID: fmt.Sprintf("paused-%d", i), UserID: "user", SystemID: []string{"legacy", "disabled"}[i%2], EventType: "user.created", PayloadJSON: "{}", Status: "pending"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CreateAccountSyncEvent(&AccountSyncEvent{ID: "live-event", UserID: "user", SystemID: "live", EventType: "user.created", PayloadJSON: "{}", Status: "pending"}); err != nil {
		t.Fatal(err)
	}
	events, err := s.ClaimDueSyncEvents(50, time.Minute)
	if err != nil || len(events) != 1 || events[0].ID != "live-event" {
		t.Fatalf("active connector starved: %+v %v", events, err)
	}
	var untouched int
	if err = s.db.QueryRow(`SELECT count(*) FROM account_sync_events WHERE system_id IN ('legacy','disabled') AND attempts=0 AND lease_until IS NULL`).Scan(&untouched); err != nil || untouched != 55 {
		t.Fatalf("paused work changed: %d %v", untouched, err)
	}
}
