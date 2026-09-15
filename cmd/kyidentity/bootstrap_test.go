package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Busness-app/kyidentity-server/internal/auth"
	"github.com/Busness-app/kyidentity-server/internal/store"
)

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

	if err := ensureBootstrapAdmin(db, "admin", "first-run-password"); err != nil {
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
	if err := db.UpdateUserPassword(admin.ID, rotated); err != nil {
		t.Fatal(err)
	}

	// A restart with the same environment variable still set.
	if err := ensureBootstrapAdmin(db, "admin", "first-run-password"); err != nil {
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

	if err := ensureBootstrapAdmin(db, "admin", "short"); err == nil {
		t.Error("a password that violates the policy was accepted silently")
	}
	if u, _ := db.GetUserByUsername("admin"); u != nil {
		t.Error("an admin was created despite the failure")
	}
}

func TestBootstrapCreatesAdminWhenNoneExists(t *testing.T) {
	db := testStore(t)

	if err := ensureBootstrapAdmin(db, "admin", "a-good-first-password"); err != nil {
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
	if err := ensureBootstrapAdmin(db, "admin", "a-good-first-password"); err != nil {
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
