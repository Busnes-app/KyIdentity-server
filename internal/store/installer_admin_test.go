package store

import "testing"

// Issue #108: the credential export names the administrator the setup owns, found by
// ID. A username that has since moved to another account must never select that account.
func TestInstallerSetupAdministratorFollowsOwnership(t *testing.T) {
	s, close := setupTestStore(t)
	defer close()
	p := installerFixture()
	if _, err := s.ApplyInstallerSetup(p, false); err != nil {
		t.Fatal(err)
	}
	owned, err := s.GetUserByUsername(p.Admin.Username)
	if err != nil || owned == nil {
		t.Fatal(err)
	}
	if got, err := s.InstallerSetupAdministrator(p.ID); err != nil || got.ID != owned.ID {
		t.Fatalf("owned administrator: %+v %v", got, err)
	}
	if _, err := s.InstallerSetupAdministrator("00000000-0000-0000-0000-000000000000"); err == nil {
		t.Fatal("unknown setup named an administrator")
	}
	other := &User{ID: "other-admin", Username: "other-admin", DisplayName: "Other", Email: "other@example.test", PasswordHash: "x", Role: "admin", Status: "active"}
	if err := s.CreateUser(other); err != nil {
		t.Fatal(err)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := s.db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	// The owned username moves to another administrator.
	exec(`UPDATE users SET username='renamed' WHERE id=?`, owned.ID)
	exec(`UPDATE users SET username=? WHERE id=?`, p.Admin.Username, other.ID)
	if got, err := s.InstallerSetupAdministrator(p.ID); err == nil {
		t.Fatalf("moved username exported account %s", got.ID)
	}
	exec(`UPDATE users SET username='other-admin' WHERE id=?`, other.ID)
	exec(`UPDATE users SET username=? WHERE id=?`, p.Admin.Username, owned.ID)
	for name, change := range map[string]string{
		"disabled": `UPDATE users SET status='disabled' WHERE id=?`,
		"demoted":  `UPDATE users SET role='user' WHERE id=?`,
		"ended":    `UPDATE users SET ends_at=1 WHERE id=?`,
	} {
		exec(change, owned.ID)
		if _, err := s.InstallerSetupAdministrator(p.ID); err == nil {
			t.Fatalf("%s administrator exported", name)
		}
		exec(`UPDATE users SET status='active', role='admin', ends_at=NULL WHERE id=?`, owned.ID)
	}
	exec(`DELETE FROM users WHERE id=?`, owned.ID)
	if _, err := s.InstallerSetupAdministrator(p.ID); err == nil {
		t.Fatal("deleted administrator exported")
	}
}
