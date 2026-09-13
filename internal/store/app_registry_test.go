package store

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func registryFixtures(t *testing.T, s *Store) (AppRecord, AppRecord, AppRecord) {
	t.Helper()
	if err := s.CreateOAuthClient(&OAuthClient{ID: "client", ClientName: "Same app", ClientType: "confidential", ClientSecretHash: "keep-secret", RedirectURIsJSON: `["https://app.example/cb"]`, AllowedScopesJSON: `["openid"]`, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateApplication(&Application{ID: "launcher", Name: "Same app", URL: "https://app.example", IconName: "globe", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePairedSystem(&PairedSystem{ID: "system", Name: "Same app", SystemType: "scim", CallbackURL: "https://app.example/scim", HMACSecretEncrypted: "keep-sync-secret", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	rows, total, err := s.ListAppRecords("", 25, 0)
	if err != nil || total != 3 {
		t.Fatalf("separate records: %v %d", err, total)
	}
	var c, l, p AppRecord
	for _, a := range rows {
		switch {
		case a.ClientID != "":
			c = a
		case a.LauncherID != "":
			l = a
		case a.SystemID != "":
			p = a
		}
	}
	return c, l, p
}
func TestAppRegistryMigrationAndLinkLifecycle(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	c, l, p := registryFixtures(t, s)
	// Reconstruct pre-upgrade state without touching original connection rows.
	for _, table := range []string{"oauth_clients", "applications", "paired_systems"} {
		for _, prefix := range []string{"registry_insert_", "registry_delete_", "registry_cleanup_"} {
			if _, err := s.db.Exec("DROP TRIGGER " + prefix + table); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := s.db.Exec(`DROP VIEW effective_app_access; DROP VIEW app_access_facts;`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("DROP TABLE app_registry"); err != nil {
		t.Fatal(err)
	}
	if err := s.migrateAppRegistry(); err != nil {
		t.Fatal(err)
	}
	if err := s.migrateAppAccess(); err != nil {
		t.Fatal(err)
	}
	if err := s.migrateAppAuthentication(); err != nil {
		t.Fatal(err)
	}
	if err := s.migrateAppRoles(); err != nil {
		t.Fatal(err)
	}
	rows, total, err := s.ListAppRecords("Same", 25, 0)
	if err != nil || total != 3 {
		t.Fatal("migration inferred a link", err)
	}
	for _, a := range rows {
		switch {
		case a.ClientID != "":
			c = a
		case a.LauncherID != "":
			l = a
		case a.SystemID != "":
			p = a
		}
	}
	if err := s.LinkAppRecords(l.ID, c.ID, l.Revision, c.Revision, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.LinkAppRecords(l.ID, p.ID, l.Revision, p.Revision, nil); !errors.Is(err, ErrAppLinkConflict) {
		t.Fatal("stale revision accepted", err)
	}
	if err := s.LinkAppRecords(l.ID, p.ID, l.Revision+1, p.Revision, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.migrate(); err != nil {
		t.Fatal(err)
	}
	rows, total, err = s.ListAppRecords("", 25, 0)
	if err != nil || total != 1 || rows[0].ID != l.ID || rows[0].ClientID != "client" || rows[0].SystemID != "system" || rows[0].LauncherID != "launcher" {
		t.Fatalf("restart broke link: %+v %v", rows, err)
	}
	client, err := s.GetOAuthClientByID("client")
	if err != nil || client.ClientSecretHash != "keep-secret" || client.RedirectURIsJSON != `["https://app.example/cb"]` {
		t.Fatal("client connection changed")
	}
	system, err := s.GetPairedSystemByID("system")
	if err != nil || system.HMACSecretEncrypted != "keep-sync-secret" || system.CallbackURL != "https://app.example/scim" {
		t.Fatal("provisioning connection changed")
	}
	newID, err := s.UnlinkAppRecord(l.ID, "client", 3, nil)
	if err != nil {
		t.Fatal(err)
	}
	if newID == l.ID {
		t.Fatal("unlink reused identity")
	}
	if _, err = s.UnlinkAppRecord(newID, "client", 1, nil); !errors.Is(err, ErrAppLinkConflict) {
		t.Fatal("detached last connection")
	}
	if _, err = s.DeletePairedSystem("system", nil); err != nil {
		t.Fatal(err)
	}
	rows, _, err = s.ListAppRecords(l.ID, 25, 0)
	if err != nil || len(rows) != 1 || rows[0].SystemID != "" || rows[0].Revision != 5 {
		t.Fatalf("delete lost retained record: %+v %v", rows, err)
	}
	if _, err = s.DeleteApplication("launcher", nil); err != nil {
		t.Fatal(err)
	}
	rows, total, err = s.ListAppRecords("", 1, 0)
	if err != nil || total != 1 || rows[0].ID != newID {
		t.Fatal("empty identity survived", err)
	}
	// Insert trigger still creates a fresh record after migration and explicit links.
	if err := s.CreateApplication(&Application{ID: "new", Name: "New", URL: "https://example.com", IconName: "globe"}); err != nil {
		t.Fatal(err)
	}
	rows, total, err = s.ListAppRecords("", 1, 1)
	if err != nil || total != 2 || len(rows) != 1 {
		t.Fatal("paging", err)
	}
}
func TestAppRegistryConflictConcurrencyAndAuditRollback(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	c, l, p := registryFixtures(t, s)
	audit := &AuditEvent{ID: "audit", Action: "admin.app_linked", Outcome: "success", CreatedAt: time.Now().UTC()}
	if _, err := s.db.Exec(`CREATE TRIGGER fail_registry_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.LinkAppRecords(l.ID, c.ID, 1, 1, audit); err == nil {
		t.Fatal("link ignored audit failure")
	}
	rows, total, err := s.ListAppRecords("", 25, 0)
	if err != nil || total != 3 {
		t.Fatal("failed audit lost source", err)
	}
	for _, a := range rows {
		if a.Revision != 1 {
			t.Fatal("failed audit changed revision")
		}
	}
	if _, err = s.db.Exec("DROP TRIGGER fail_registry_audit"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, source := range []AppRecord{c, p} {
		wg.Go(func() { results <- s.LinkAppRecords(l.ID, source.ID, 1, 1, nil) })
	}
	wg.Wait()
	close(results)
	successes, conflicts := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrAppLinkConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent stale edits: %d %d", successes, conflicts)
	}
	rows, _, err = s.ListAppRecords(l.ID, 25, 0)
	if err != nil || len(rows) != 1 {
		t.Fatal(err)
	}
	kind := "client"
	if rows[0].SystemID != "" {
		kind = "system"
	}
	if _, err = s.db.Exec(`CREATE TRIGGER fail_registry_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.UnlinkAppRecord(l.ID, kind, 2, audit); err == nil {
		t.Fatal("unlink ignored audit failure")
	}
	rows, total, err = s.ListAppRecords("", 25, 0)
	if err != nil || total != 2 {
		t.Fatal("unlink rollback", err)
	}
	if _, err = s.db.Exec("DROP TRIGGER fail_registry_audit"); err != nil {
		t.Fatal(err)
	}
	if err = s.CreateApplication(&Application{ID: "other", Name: "Other", URL: "https://other.example", IconName: "globe"}); err != nil {
		t.Fatal(err)
	}
	rows, _, err = s.ListAppRecords("Other", 25, 0)
	if err != nil || len(rows) != 1 {
		t.Fatal(err)
	}
	if err = s.LinkAppRecords(l.ID, rows[0].ID, 2, 1, nil); !errors.Is(err, ErrAppLinkConflict) {
		t.Fatal("overlapping launcher refs accepted", err)
	}
	if err = s.LinkAppRecords(l.ID, l.ID, 2, 2, nil); !errors.Is(err, ErrAppLinkConflict) {
		t.Fatal("self link", err)
	}
	if err = s.LinkAppRecords(l.ID, "missing", 2, 1, nil); !errors.Is(err, ErrAppRecordMissing) {
		t.Fatal("missing link", err)
	}
}
