package store

import (
	"github.com/google/uuid"
	"slices"
	"testing"
	"time"
)

func installerFixture() InstallerSetup {
	return InstallerSetup{ID: uuid.NewString(), Admin: InstallerUser{"owner-admin", "admin@example.test", "admin", "original-admin-hash"}, Everyday: InstallerUser{"owner", "owner@example.test", "user", "original-user-hash"}, Clients: []InstallerClient{{ID: "kydrive", Name: "KyDrive", SecretHash: "client-hash", RedirectURIs: []string{"https://drive.example.test/callback"}, PostLogoutURIs: []string{}}}}
}

func TestInstallerAppRolesAndManagementOnlyAccess(t *testing.T) {
	for _, mode := range []string{"separated", "management-only", "ordinary-role"} {
		t.Run(mode, func(t *testing.T) {
			s, close := setupTestStore(t)
			defer close()
			p := installerFixture()
			if mode != "ordinary-role" {
				p.Clients[0].AdministratorRole = "owner:admin"
			}
			if mode != "management-only" {
				p.Clients[0].EverydayRole = "editor"
			}
			report, err := s.ApplyInstallerSetup(p, false)
			if err != nil {
				t.Fatal(err)
			}
			admin, err := s.GetUserByUsername(p.Admin.Username)
			if err != nil {
				t.Fatal(err)
			}
			everyday, err := s.GetUserByUsername(p.Everyday.Username)
			if err != nil {
				t.Fatal(err)
			}
			expected := map[string][]string{admin.ID: {}, everyday.ID: {}}
			if mode != "ordinary-role" {
				expected[admin.ID] = []string{"owner:admin"}
			}
			if mode != "management-only" {
				expected[everyday.ID] = []string{"editor"}
			}
			for id, want := range expected {
				claims, err := s.UserAppClaims(id, p.Clients[0].ID)
				if err != nil || claims.LegacyRole || claims.GroupsClaim || !slices.Equal(claims.Roles, want) {
					t.Fatalf("claims %+v want %v error %v", claims, want, err)
				}
				allowed, err := s.ClientAccessAllowed(id, p.Clients[0].ID)
				if err != nil || allowed != (len(want) > 0) {
					t.Fatalf("access %v error %v", allowed, err)
				}
			}
			for _, check := range []bool{false, true} {
				resumed, err := s.ApplyInstallerSetup(p, check)
				if err != nil || len(resumed.Created) != 0 || len(resumed.Reused) != len(report.Created) {
					t.Fatalf("role resume %+v error %v", resumed, err)
				}
			}
			var appID string
			if err := s.db.QueryRow(`SELECT id FROM app_registry WHERE client_id=?`, p.Clients[0].ID).Scan(&appID); err != nil {
				t.Fatal(err)
			}
			if mode == "management-only" {
				if _, err := s.db.Exec(`UPDATE app_registry SET access_mode='all_active_users' WHERE id=?`, appID); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := s.db.Exec(`INSERT INTO app_role_user_assignments(role_id,user_id) SELECT id,? FROM app_roles WHERE app_id=? AND name='editor'`, admin.ID, appID); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.ApplyInstallerSetup(p, true); err == nil {
				t.Fatal("management policy or role mapping drift accepted")
			}
		})
	}
}

func TestInstallerRolesRollbackWithAuditFailure(t *testing.T) {
	s, close := setupTestStore(t)
	defer close()
	p := installerFixture()
	p.Clients[0].AdministratorRole = "admin"
	p.Clients[0].EverydayRole = "user"
	if _, err := s.db.Exec(`CREATE TRIGGER refuse_installer_role_audit BEFORE INSERT ON audit_events WHEN NEW.action='installer.role_created' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyInstallerSetup(p, false); err == nil {
		t.Fatal("role audit failure accepted")
	}
	for _, table := range []string{"installer_setup_resources", "app_roles", "app_role_user_assignments", "app_user_assignments"} {
		var count int
		if err := s.db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("partial %s: %d error %v", table, count, err)
		}
	}
}
func TestInstallerSetupAtomicAndIdempotent(t *testing.T) {
	s, close := setupTestStore(t)
	defer close()
	p := installerFixture()
	if _, err := s.ApplyInstallerSetup(p, true); err == nil {
		t.Fatal("check accepted missing setup")
	}
	r, err := s.ApplyInstallerSetup(p, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Created) != 3 {
		t.Fatalf("created: %+v", r)
	}
	var adminID, userID, hash string
	if err := s.db.QueryRow(`SELECT id FROM users WHERE username='owner-admin'`).Scan(&adminID); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT id FROM users WHERE username='owner'`).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ClientAccessAllowed(userID, "kydrive"); err != nil || !ok {
		t.Fatalf("everyday access %v: %v", ok, err)
	}
	if ok, err := s.ClientAccessAllowed(adminID, "kydrive"); err != nil || ok {
		t.Fatalf("admin ordinary access %v: %v", ok, err)
	}
	if _, err := s.db.Exec(`UPDATE users SET password_hash='rotated' WHERE id=?`, adminID); err != nil {
		t.Fatal(err)
	}
	p.Admin.PasswordHash = "replacement-must-not-write"
	for _, check := range []bool{false, true} {
		r, err = s.ApplyInstallerSetup(p, check)
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Created) != 0 || len(r.Reused) != 3 {
			t.Fatalf("rerun %+v", r)
		}
	}
	if err := s.db.QueryRow(`SELECT password_hash FROM users WHERE id=?`, adminID).Scan(&hash); err != nil || hash != "rotated" {
		t.Fatal("password changed", err)
	}
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM audit_events WHERE actor_username='kyquickstart'`).Scan(&count); err != nil || count != 4 {
		t.Fatalf("audit %d: %v", count, err)
	}
	if err := s.EvaluateAlerts(time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM alerts WHERE rule='privilege_change' AND key=?`, adminID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("administrator creation alert %d: %v", count, err)
	}

	p.ID = uuid.NewString()
	if _, err := s.ApplyInstallerSetup(p, false); err == nil {
		t.Fatal("foreign setup adopted resources")
	}
}
func TestInstallerSetupRollbackOnConflictOrAuditFailure(t *testing.T) {
	for _, cause := range []string{"account-conflict", "audit-failure"} {
		t.Run(cause, func(t *testing.T) {
			s, close := setupTestStore(t)
			defer close()
			p := installerFixture()
			if cause == "account-conflict" {
				createTestUserNamed(t, s, p.Everyday.Username)
			} else {
				if _, err := s.db.Exec(`CREATE TRIGGER refuse_installer_audit BEFORE INSERT ON audit_events WHEN NEW.actor_username='kyquickstart' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.ApplyInstallerSetup(p, false); err == nil {
				t.Fatal("accepted conflict")
			}
			var n int
			if err := s.db.QueryRow(`SELECT count(*) FROM users WHERE username=?`, p.Admin.Username).Scan(&n); err != nil || n != 0 {
				t.Fatalf("partial admin creation %d: %v", n, err)
			}
			if err := s.db.QueryRow(`SELECT count(*) FROM installer_setup_resources`).Scan(&n); err != nil || n != 0 {
				t.Fatalf("partial ownership %d: %v", n, err)
			}
		})
	}
}
func TestInstallerCheckRejectsAdministratorOrdinaryAccess(t *testing.T) {
	s, close := setupTestStore(t)
	defer close()
	p := installerFixture()
	if _, err := s.ApplyInstallerSetup(p, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO app_user_assignments(app_id,user_id) SELECT a.id,u.id FROM app_registry a,users u WHERE a.client_id='kydrive' AND u.username='owner-admin'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyInstallerSetup(p, true); err == nil {
		t.Fatal("accepted administrator ordinary workflow grant")
	}
}

func TestSetInstallerLaunchURL(t *testing.T) {
	s, close := setupTestStore(t)
	defer close()
	p := installerFixture()
	if _, err := s.ApplyInstallerSetup(p, false); err != nil {
		t.Fatal(err)
	}
	event := func() *AuditEvent {
		return &AuditEvent{ID: uuid.NewString(), Action: "admin.client_launcher_updated", TargetType: "client", Outcome: "success", CreatedAt: time.Now().UTC()}
	}
	if _, err := s.SetInstallerLaunchURL(uuid.NewString(), "kydrive", "https://drive.example.test/", event()); err != ErrNotFound {
		t.Fatal("another setup set the client's launch URL", err)
	}
	audits := auditCount(t, s)
	for _, want := range []bool{true, false} {
		if changed, err := s.SetInstallerLaunchURL(p.ID, "kydrive", "https://drive.example.test/", event()); err != nil || changed != want {
			t.Fatalf("changed %v: %v", changed, err)
		}
	}
	if c, _ := s.GetOAuthClientByID("kydrive"); c.LaunchURL != "https://drive.example.test/" || auditCount(t, s) != audits+1 {
		t.Fatalf("launch URL %q, audits %d", c.LaunchURL, auditCount(t, s)-audits)
	}
	// The installer's own setup still checks with a launch URL on its client.
	if _, err := s.ApplyInstallerSetup(p, true); err != nil {
		t.Fatal(err)
	}
}
