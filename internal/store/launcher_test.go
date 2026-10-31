package store

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func launcherEvent() *AuditEvent {
	return &AuditEvent{ID: uuid.NewString(), Action: "admin.client_launcher_updated", TargetType: "client", Outcome: "success", CreatedAt: time.Now().UTC()}
}

func TestLauncherColumnsMigrate(t *testing.T) {
	s, close := setupTestStore(t)
	defer close()
	if _, err := s.db.Exec(`ALTER TABLE oauth_clients DROP COLUMN launcher_name; ALTER TABLE oauth_clients DROP COLUMN launcher_audience; ALTER TABLE app_roles DROP COLUMN administrator`); err != nil {
		t.Fatal(err)
	}
	if err := s.migrate(); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateOAuthClient(&OAuthClient{ID: "c", ClientName: "C", ClientType: "public", RedirectURIsJSON: `[]`, AllowedScopesJSON: `[]`, Enabled: true}, nil); err != nil {
		t.Fatal(err)
	}
	c, err := s.GetOAuthClientByID("c")
	if err != nil || c.LauncherName != "" || c.LauncherAudience != "" {
		t.Fatalf("migrated client %+v: %v", c, err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM pragma_table_info('app_roles') WHERE name='administrator'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("app_roles.administrator missing: %v", err)
	}
	if err := s.migrate(); err != nil {
		t.Fatal("second migration", err)
	}
}

func TestSetInstallerLauncherSettings(t *testing.T) {
	s, close := setupTestStore(t)
	defer close()
	p := installerFixture()
	p.Clients[0].AdministratorRole = "owner:admin"
	p.Clients[0].EverydayRole = "editor"
	if _, err := s.ApplyInstallerSetup(p, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetInstallerLauncherName(uuid.NewString(), "kydrive", "Drive", launcherEvent()); err != ErrNotFound {
		t.Fatal("another setup set the launcher name", err)
	}
	audits := auditCount(t, s)
	for _, want := range []bool{true, false} {
		if changed, err := s.SetInstallerLauncherName(p.ID, "kydrive", "Drive", launcherEvent()); err != nil || changed != want {
			t.Fatalf("name changed %v: %v", changed, err)
		}
		if changed, err := s.SetInstallerLauncherAudience(p.ID, "kydrive", LauncherAdmins, "owner:admin", launcherEvent()); err != nil || changed != want {
			t.Fatalf("audience changed %v: %v", changed, err)
		}
	}
	// A value already set stays.
	if changed, _ := s.SetInstallerLauncherName(p.ID, "kydrive", "Other", launcherEvent()); changed {
		t.Fatal("installer replaced a set launcher name")
	}
	c, _ := s.GetOAuthClientByID("kydrive")
	if c.LauncherName != "Drive" || c.LauncherAudience != LauncherAdmins || auditCount(t, s) != audits+2 {
		t.Fatalf("client %q %q, audits %d", c.LauncherName, c.LauncherAudience, auditCount(t, s)-audits)
	}

	admin, _ := s.GetUserByUsername(p.Admin.Username)
	everyday, _ := s.GetUserByUsername(p.Everyday.Username)
	if got, err := s.LauncherAdminClients(admin.ID); err != nil || !got["kydrive"] {
		t.Fatalf("administrator role holder not an app admin: %v %v", got, err)
	}
	if got, _ := s.LauncherAdminClients(everyday.ID); got["kydrive"] {
		t.Fatal("everyday role holder counted as app admin")
	}
	// Setup intent is untouched: its own check still passes.
	if _, err := s.ApplyInstallerSetup(p, true); err != nil {
		t.Fatal(err)
	}
}

func TestLauncherAdminClientsFallsBackToGlobalAdmin(t *testing.T) {
	s, u, _ := appAccessFixture(t)
	admin := &User{ID: uuid.NewString(), Username: "boss", Email: "boss@x.test", Role: "admin", Status: "active"}
	if err := s.CreateUser(admin); err != nil {
		t.Fatal(err)
	}
	if got, err := s.LauncherAdminClients(admin.ID); err != nil || !got["client"] {
		t.Fatalf("global admin with no administrator roles: %v %v", got, err)
	}
	if got, _ := s.LauncherAdminClients(u.ID); got["client"] {
		t.Fatal("ordinary user counted as app admin")
	}
	// Once the app has an administrator role, only its holders count.
	recs, _, err := s.ListAppRecords("client", 25, 0)
	if err != nil || len(recs) != 1 {
		t.Fatal(err)
	}
	role, err := s.CreateAppRole(recs[0].ID, "ops", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE app_roles SET administrator=1 WHERE id=?`, role.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.LauncherAdminClients(admin.ID); got["client"] {
		t.Fatal("global admin without the administrator role still counted")
	}
	if err := s.SetAppRoleAssignment(recs[0].ID, role.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.LauncherAdminClients(u.ID); !got["client"] {
		t.Fatal("administrator role holder not counted")
	}
}
