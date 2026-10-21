package main

import (
	"os"
	"path/filepath"
	"strings"
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
	db, err := store.New(filepath.Join(t.TempDir(), "test.db"))
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
	if _, err := db.EditUser(admin.ID, nil, func(u *store.User) (bool, error) {
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
	events, _, err := db.SearchAuditEvents(store.AuditFilter{Action: "admin.user_created", Limit: 5})
	if err != nil || len(events) != 1 || events[0].TargetID != u.ID || !strings.Contains(events[0].DetailsJSON, `"role":"admin"`) {
		t.Fatalf("admin.user_created audit: %+v %v", events, err)
	}
}

// An existing account that is not an active administrator is not a successful bootstrap:
// nothing is promoted or re-enabled, and no password file names an account bootstrap did
// not create.
func TestBootstrapRefusesAnExistingNonAdmin(t *testing.T) {
	db := testStore(t)
	if err := db.CreateUser(&store.User{ID: "u1", Username: "admin", DisplayName: "A", Email: "a@test.invalid", PasswordHash: "x", Role: "user", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := bootstrapOnStart(db, "admin", "", dir); err == nil {
		t.Fatal("first start reported success over an existing ordinary user")
	}
	if _, err := os.Stat(filepath.Join(dir, "first-run-password.txt")); !os.IsNotExist(err) {
		t.Fatal("a password file was written for an account bootstrap did not create:", err)
	}
	if u, _ := db.GetUserByUsername("admin"); u == nil || u.Role != "user" || u.PasswordHash != "x" {
		t.Fatalf("the existing account was changed: %+v", u)
	}

	if err := db.CreateUser(&store.User{ID: "u2", Username: "old-admin", DisplayName: "B", Email: "b@test.invalid", PasswordHash: "x", Role: "admin", Status: "disabled"}); err != nil {
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
