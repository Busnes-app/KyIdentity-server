package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Busnes-app/kyidentity-server/internal/auth"
	"github.com/Busnes-app/kyidentity-server/internal/config"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

func TestRestoreHelpUsesStableServiceIdentity(t *testing.T) {
	if help := restoreServiceHelp(); !strings.Contains(help, config.DefaultAppName) {
		t.Fatalf("restore help = %q, want %q", help, config.DefaultAppName)
	}
}

func testStore(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.NewTest(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// Leaving BOOTSTRAP_ADMIN_PASS in an .env file is normal. It must not silently revert the
// admin password to that value on every restart, undoing any rotation the admin performed.
func TestBootstrapDoesNotResetAnExistingAdminPassword(t *testing.T) {
	db := testStore(t)

	if _, err := ensureBootstrapAdmin(db, "admin", "", "first-run-password", "test"); err != nil {
		t.Fatalf("initial bootstrap failed: %v", err)
	}

	admin, err := db.GetUserByUsername("admin")
	if err != nil || admin == nil {
		t.Fatalf("bootstrap admin was not created: %v", err)
	}

	// The admin rotates their password, as they would after a scare.
	rotated, err := auth.HashPassword("rotated-password-99")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DefaultOrg().EditUser(admin.ID, nil, func(u *store.User) (bool, error) {
		u.PasswordHash = rotated
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}

	// A restart with the same environment variable still set.
	if _, err := ensureBootstrapAdmin(db, "admin", "", "first-run-password", "test"); err != nil {
		t.Fatalf("second bootstrap returned an error: %v", err)
	}

	after, err := db.GetUserByUsername("admin")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := auth.VerifyPassword("first-run-password", after.PasswordHash); ok {
		t.Error("restarting reverted the admin password to BOOTSTRAP_ADMIN_PASS")
	}
	if ok, _ := auth.VerifyPassword("rotated-password-99", after.PasswordHash); !ok {
		t.Error("the rotated password no longer works")
	}
}

// A failure to create the first administrator must not be swallowed; a server that starts
// with no way to log in is worse than one that refuses to start.
func TestBootstrapReportsFailure(t *testing.T) {
	db := testStore(t)

	if _, err := ensureBootstrapAdmin(db, "admin", "", "short", "test"); err == nil {
		t.Error("a password that violates the policy was accepted silently")
	}
	if u, _ := db.GetUserByUsername("admin"); u != nil {
		t.Error("an admin was created despite the failure")
	}
}

// A password in argv is readable through /proc by every local user and lands in shell
// history; bootstrap-admin takes it from stdin only.
func TestBootstrapRefusesArgvPassword(t *testing.T) {
	if _, err := parseBootstrap([]string{"-password", "a-good-first-password"}, strings.NewReader(""), false); err == nil {
		t.Fatal("a password on the command line was accepted")
	}
	req, err := parseBootstrap(nil, strings.NewReader("a good first password\nignored\n"), false)
	if err != nil || req.password != "a good first password" || req.generated {
		t.Fatalf("stdin password: %+v %v", req, err)
	}
	req, err = parseBootstrap(nil, strings.NewReader(""), false)
	if err != nil || !req.generated || len(req.password) < 16 {
		t.Fatalf("empty stdin should generate a password: %+v %v", req, err)
	}
}

func TestBootstrapHonoursEmailAndAudits(t *testing.T) {
	if _, err := parseBootstrap([]string{"-email", "Root <root@example.test>"}, strings.NewReader("pw\n"), false); err == nil {
		t.Fatal("a non-bare email address was accepted")
	}
	req, err := parseBootstrap([]string{"-username", "root", "-email", "root@example.test"}, strings.NewReader("a-good-first-password\n"), false)
	if err != nil {
		t.Fatal(err)
	}
	db := testStore(t)
	created, err := ensureBootstrapAdmin(db, req.username, req.email, req.password, "kyidentity-cli")
	if err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	u, err := db.GetUserByUsername("root")
	if err != nil || u == nil || u.Email != "root@example.test" {
		t.Fatalf("email not honoured: %+v %v", u, err)
	}
	events, _, err := db.DefaultOrg().SearchAuditEvents(store.AuditFilter{Action: "admin.user_created", Limit: 5})
	if err != nil || len(events) != 1 || events[0].TargetID != u.ID || !strings.Contains(events[0].DetailsJSON, `"role":"admin"`) {
		t.Fatalf("admin.user_created audit: %+v %v", events, err)
	}
}

// An existing account that is not an active administrator is not a successful bootstrap:
// nothing is promoted or re-enabled, and no password file names an account bootstrap did
// not create.
func TestBootstrapRefusesAnExistingNonAdmin(t *testing.T) {
	db := testStore(t)
	if err := db.DefaultOrg().CreateUser(&store.User{ID: "u1", Username: "admin", DisplayName: "A", Email: "a@test.invalid", PasswordHash: "x", Role: "user", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := bootstrapOnStart(db, "admin", "", dir, false); err == nil {
		t.Fatal("first start reported success over an existing ordinary user")
	}
	if _, err := os.Stat(filepath.Join(dir, "first-run-password.txt")); !os.IsNotExist(err) {
		t.Fatal("a password file was written for an account bootstrap did not create:", err)
	}
	if u, _ := db.GetUserByUsername("admin"); u == nil || u.Role != "user" || u.PasswordHash != "x" {
		t.Fatalf("the existing account was changed: %+v", u)
	}

	if err := db.DefaultOrg().CreateUser(&store.User{ID: "u2", Username: "old-admin", DisplayName: "B", Email: "b@test.invalid", PasswordHash: "x", Role: "admin", Status: "disabled"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureBootstrapAdmin(db, "old-admin", "", "a-good-first-password", "test"); err == nil {
		t.Fatal("a disabled administrator was reported as bootstrapped")
	}
}

func TestBootstrapCreatesAdminWhenNoneExists(t *testing.T) {
	db := testStore(t)

	if _, err := ensureBootstrapAdmin(db, "admin", "", "a-good-first-password", "test"); err != nil {
		t.Fatal(err)
	}
	admin, err := db.GetUserByUsername("admin")
	if err != nil || admin == nil {
		t.Fatalf("no admin created: %v", err)
	}
	if admin.Role != "admin" || admin.Status != "active" {
		t.Errorf("unexpected bootstrap admin: role=%s status=%s", admin.Role, admin.Status)
	}
	if ok, _ := auth.VerifyPassword("a-good-first-password", admin.PasswordHash); !ok {
		t.Error("the bootstrap password does not verify")
	}
	if !admin.PasswordChangeRequired {
		t.Error("the bootstrap admin is not required to replace its first password")
	}
}

// The first-run credentials file is a plaintext password on disk. Once it has been used it
// is only a liability.
func TestFirstRunPasswordFileIsRemovedAfterAdminLogsIn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "first-run-password.txt")
	if err := os.WriteFile(path, []byte("User: admin\nPassword: hunter2\n"), 0600); err != nil {
		t.Fatal(err)
	}

	db := testStore(t)
	if _, err := ensureBootstrapAdmin(db, "admin", "", "a-good-first-password", "test"); err != nil {
		t.Fatal(err)
	}
	admin, _ := db.GetUserByUsername("admin")

	// Once a session exists the admin has logged in and no longer needs the file.
	if err := db.CreateSession(&store.Session{
		ID: "s1", UserID: admin.ID, SessionTokenHash: "h", IPAddress: "1.1.1.1",
		UserAgent: "t", ExpiresAt: adminSessionExpiry(),
	}); err != nil {
		t.Fatal(err)
	}

	if err := clearFirstRunPasswordFile(db, dir); err != nil {
		t.Fatalf("clearFirstRunPasswordFile: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("the first-run password file survived after the admin logged in")
	}
}

// The emergency runbook bootstraps a second administrator while other users are signed
// in; their sessions must not delete the new administrator's generated password.
func TestFirstRunPasswordFileWaitsForTheNamedAccount(t *testing.T) {
	dir := t.TempDir()
	db := testStore(t)
	if _, err := ensureBootstrapAdmin(db, "admin", "", "a-good-first-password", "test"); err != nil {
		t.Fatal(err)
	}
	admin, _ := db.GetUserByUsername("admin")
	if err := db.CreateSession(&store.Session{ID: "s1", UserID: admin.ID, SessionTokenHash: "h", IPAddress: "1.1.1.1", UserAgent: "t", ExpiresAt: adminSessionExpiry()}); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureBootstrapAdmin(db, "rescue", "", "another-good-password", "test"); err != nil {
		t.Fatal(err)
	}
	path, err := writeFirstRunPassword(dir, "rescue", "another-good-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := clearFirstRunPasswordFile(db, dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("another user's session deleted the rescue administrator's password:", err)
	}
	rescue, _ := db.GetUserByUsername("rescue")
	if err := db.CreateSession(&store.Session{ID: "s2", UserID: rescue.ID, SessionTokenHash: "h2", IPAddress: "1.1.1.1", UserAgent: "t", ExpiresAt: adminSessionExpiry()}); err != nil {
		t.Fatal(err)
	}
	if err := clearFirstRunPasswordFile(db, dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("the file survived the named administrator's sign-in")
	}
}

func TestBootstrapSingleTenantUsesDefaultOrg(t *testing.T) {
	db := testStore(t)
	created, err := ensureBootstrapAdmin(db, "admin", "", "a-good-first-password", "test")
	if err != nil || !created {
		t.Fatalf("ensureBootstrapAdmin: created=%v err=%v", created, err)
	}
	admin, err := db.GetUserByUsername("admin")
	if err != nil || admin == nil {
		t.Fatalf("GetUserByUsername: %v %v", admin, err)
	}
	if admin.Org().String() != store.DefaultOrgID {
		t.Fatalf("single-tenant admin org = %s, want default org %s", admin.Org(), store.DefaultOrgID)
	}
	if staff, err := db.IsStaffOrg(admin.Org()); err != nil || staff {
		t.Fatalf("IsStaffOrg(default) = %v, %v; want false", staff, err)
	}
	orgs, err := db.Platform().FindOrgs("")
	if err != nil || len(orgs) != 0 {
		t.Fatalf("single-tenant bootstrap created staff orgs: %+v (%v)", orgs, err)
	}
}

func TestBootstrapMultiTenantCreatesAndReusesStaffOrg(t *testing.T) {
	db := testStore(t)
	if err := db.SetSetting(store.TenancySetting, "multi"); err != nil {
		t.Fatal(err)
	}

	if err := bootstrapOnStart(db, "admin", "a-good-first-password", t.TempDir(), false); err != nil {
		t.Fatalf("bootstrapOnStart: %v", err)
	}
	admin, err := db.GetUserByUsername("admin")
	if err != nil || admin == nil {
		t.Fatalf("GetUserByUsername(admin): %v %v", admin, err)
	}
	if admin.Org().String() == store.DefaultOrgID {
		t.Fatalf("multi-tenant bootstrap placed admin in default org %s", store.DefaultOrgID)
	}
	if staff, err := db.IsStaffOrg(admin.Org()); err != nil || !staff {
		t.Fatalf("IsStaffOrg(%s) = %v, %v; want true", admin.Org(), staff, err)
	}
	resolved, customer, err := db.StaffOrg(admin.Org().String())
	if err != nil || resolved != admin.Org() || customer {
		t.Fatalf("StaffOrg(%s) = (%s, %v, %v), want (%s, false, nil)", admin.Org(), resolved, customer, err, admin.Org())
	}
	events, _, err := db.Org(admin.Org()).SearchAuditEvents(store.AuditFilter{Action: "admin.user_created", Limit: 5})
	if err != nil || len(events) != 1 || events[0].TargetID != admin.ID {
		t.Fatalf("staff org audit events = %+v (%v), want 1 admin.user_created for %s", events, err, admin.ID)
	}

	// Re-running bootstrap for the same administrator is a no-op and keeps the password.
	created, err := ensureBootstrapAdmin(db, "admin", "", "another-good-password", "kyidentity-cli")
	if err != nil || created {
		t.Fatalf("second ensureBootstrapAdmin(admin): created=%v err=%v", created, err)
	}
	if ok, _ := auth.VerifyPassword("a-good-first-password", admin.PasswordHash); !ok {
		t.Fatal("initial password did not verify")
	}

	// Bootstrapping a second (rescue) administrator reuses the same staff org.
	created, err = ensureBootstrapAdmin(db, "rescue", "rescue@example.test", "another-good-password", "kyidentity-cli")
	if err != nil || !created {
		t.Fatalf("ensureBootstrapAdmin(rescue): created=%v err=%v", created, err)
	}
	rescue, err := db.GetUserByUsername("rescue")
	if err != nil || rescue == nil {
		t.Fatalf("GetUserByUsername(rescue): %v %v", rescue, err)
	}
	if rescue.Org() != admin.Org() {
		t.Fatalf("rescue admin org = %s, want staff org %s", rescue.Org(), admin.Org())
	}
	orgs, err := db.Platform().FindOrgs("")
	if err != nil || len(orgs) != 1 || orgs[0].ID != admin.Org().String() || orgs[0].Kind != "staff" {
		t.Fatalf("FindOrgs(\"\") = %+v (%v), want 1 staff org %s", orgs, err, admin.Org())
	}
}

func TestBootstrapMultiTenantRefusesAdminOutsideStaffOrg(t *testing.T) {
	db := testStore(t)
	if _, err := ensureBootstrapAdmin(db, "admin", "", "a-good-first-password", "test"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting(store.TenancySetting, "multi"); err != nil {
		t.Fatal(err)
	}
	_, err := ensureBootstrapAdmin(db, "admin", "", "another-good-password", "test")
	if err == nil || !strings.Contains(err.Error(), "outside the staff org") {
		t.Fatalf("ensureBootstrapAdmin in multi-tenant mode with default-org admin = %v, want outside-staff-org error", err)
	}
}

func TestConcurrentMultiTenantFirstStartsCreateOneStaffOrgAndAdmin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "multi-first-start.db")
	const replicas = 6
	stores := make([]*store.Store, replicas)
	for i := range replicas {
		s, err := store.NewTest(path)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		stores[i] = s
	}
	if err := stores[0].SetSetting(store.TenancySetting, "multi"); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	start := make(chan struct{})
	errs := make([]error, replicas)
	var wg sync.WaitGroup
	for i := range replicas {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = bootstrapOnStart(stores[i], "admin", "a-good-first-password", dir, false)
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("replica %d: bootstrapOnStart: %v", i, err)
		}
	}
	n, err := stores[0].Platform().CountAdmins()
	if err != nil || n != 1 {
		t.Fatalf("CountAdmins = %d (%v), want 1", n, err)
	}
	orgs, err := stores[0].Platform().FindOrgs("")
	if err != nil || len(orgs) != 1 || orgs[0].Kind != "staff" {
		t.Fatalf("FindOrgs(\"\") = %+v (%v), want 1 staff org", orgs, err)
	}
	admin, err := stores[0].GetUserByUsername("admin")
	if err != nil || admin == nil || admin.Org().String() != orgs[0].ID {
		t.Fatalf("admin = %+v (%v), want org %s", admin, err, orgs[0].ID)
	}
}

func TestFreshMultiTenantPostgresBootstrapsStaffOrg(t *testing.T) {
	multi := freshPostgresTenancy(t)
	s, err := openStore(multi)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	defer s.Close()

	if err := checkTenancy(multi, s); err != nil {
		t.Fatalf("checkTenancy: %v", err)
	}
	if err := bootstrapOnStart(s, "admin", "a-good-first-password", t.TempDir(), false); err != nil {
		t.Fatalf("bootstrapOnStart: %v", err)
	}
	admin, err := s.GetUserByUsername("admin")
	if err != nil || admin == nil {
		t.Fatalf("GetUserByUsername(admin): %v %v", admin, err)
	}
	if admin.Org().String() == store.DefaultOrgID {
		t.Fatalf("multi-tenant Postgres bootstrap placed admin in default org %s", store.DefaultOrgID)
	}
	if staff, err := s.IsStaffOrg(admin.Org()); err != nil || !staff {
		t.Fatalf("IsStaffOrg(%s) = %v, %v; want true", admin.Org(), staff, err)
	}
	orgs, err := s.Platform().FindOrgs("")
	if err != nil || len(orgs) != 1 || orgs[0].ID != admin.Org().String() || orgs[0].Kind != "staff" {
		t.Fatalf("FindOrgs(\"\") = %+v (%v), want 1 staff org %s", orgs, err, admin.Org())
	}
	policies, err := s.ListEnrollmentPolicies()
	if err != nil {
		t.Fatalf("ListEnrollmentPolicies: %v", err)
	}
	var pinned bool
	for _, p := range policies {
		if p.Scope == "administrators" && p.Required && strings.Join(p.AllowedMethods, ",") == "webauthn" && p.GraceSeconds == 0 {
			pinned = true
		}
	}
	if !pinned {
		t.Fatalf("administrators passkey policy was not pinned: %+v", policies)
	}
}

func TestFirstRunPasswordFileSurvivesUntilFirstLogin(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "first-run-password.txt")
	if err := os.WriteFile(path, []byte("User: admin\nPassword: hunter2\n"), 0600); err != nil {
		t.Fatal(err)
	}

	db := testStore(t)
	if err := clearFirstRunPasswordFile(db, dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Error("the credentials file was deleted before anyone could read it")
	}
}

func TestGeneratedPasswordIsHandedOverPrivately(t *testing.T) {
	dir := t.TempDir()
	path, err := writeFirstRunPassword(dir, "admin", "s3cret-generated")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Fatalf("mode = %o, want 600", mode)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "Password: s3cret-generated") {
		t.Fatalf("file lacks the password: %q", raw)
	}
}
