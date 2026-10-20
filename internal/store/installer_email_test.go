package store

import (
	"bytes"
	"testing"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
)

func auditActions(t *testing.T, s *Store, action string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM audit_events WHERE action=?`, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// The installer owns its identities and took their addresses from the owner's plan.
func TestInstallerAccountsHaveVerifiedEmail(t *testing.T) {
	s, close := setupTestStore(t)
	defer close()
	p := installerFixture()
	if _, err := s.ApplyInstallerSetup(p, false); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{p.Admin.Username, p.Everyday.Username} {
		if u, err := s.GetUserByUsername(name); err != nil || u.EmailVerifiedAt == nil {
			t.Fatalf("installer account %s unverified: %v", name, err)
		}
	}
	if other := createTestUser(t, s); other.EmailVerifiedAt != nil {
		t.Fatal("ordinary account created verified")
	}
	if n := auditActions(t, s, "installer.email_verified"); n != 0 {
		t.Fatalf("creation recorded %d backfill audits", n)
	}

	// A new address is unproven; a rerun refuses the drift instead of re-verifying it.
	everyday, _ := s.GetUserByUsername(p.Everyday.Username)
	everyday.Email = "elsewhere@example.test"
	if err := s.UpdateUserWithSyncEvents(everyday, false, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyInstallerSetup(p, false); err == nil {
		t.Fatal("rerun accepted a changed installer address")
	}
	if u, _ := s.GetUserByUsername(p.Everyday.Username); u.EmailVerifiedAt != nil {
		t.Fatal("address change kept verification")
	}
}

// Accounts applied before installer verification existed gain it on an ordinary rerun,
// never through inspection or an amendment.
func TestInstallerRerunVerifiesUnchangedAddress(t *testing.T) {
	s, close := setupTestStore(t)
	defer close()
	p := installerFixture()
	if _, err := s.ApplyInstallerSetup(p, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE users SET email_verified_at=NULL`); err != nil {
		t.Fatal(err)
	}
	unverified := func() int {
		var n int
		if err := s.db.QueryRow(`SELECT count(*) FROM users WHERE email_verified_at IS NULL`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if _, err := s.ApplyInstallerSetup(p, true); err != nil || unverified() != 2 {
		t.Fatalf("inspection changed verification: %v", err)
	}
	a := amendmentFixture(p.ID)
	a.Clients[0].Groups = nil
	if _, err := s.ApplyInstallerSetup(a, false); err != nil || unverified() != 2 {
		t.Fatalf("amendment changed verification: %v", err)
	}
	for range 2 {
		if _, err := s.ApplyInstallerSetup(p, false); err != nil {
			t.Fatal(err)
		}
	}
	if unverified() != 0 || auditActions(t, s, "installer.email_verified") != 2 {
		t.Fatalf("rerun left %d unverified with %d audits", unverified(), auditActions(t, s, "installer.email_verified"))
	}
}

func mailFixture(t *testing.T, password string) (InstallerSetup, []byte) {
	t.Helper()
	p := installerFixture()
	p.EncryptionKey = bytes.Repeat([]byte{'k'}, 32)
	p.Mail = &InstallerMail{Host: "mail.example.test", Contract: `{"host":"mail.example.test","port":587}`,
		Settings: []byte(`{"host":"mail.example.test","port":587,"password":"` + password + `"}`)}
	return p, p.Mail.Settings
}

func TestInstallerMailSettingsAreOwnedAndSealed(t *testing.T) {
	s, close := setupTestStore(t)
	defer close()
	p, plain := mailFixture(t, "relay-secret")
	if _, err := s.ApplyInstallerSetup(p, false); err != nil {
		t.Fatal(err)
	}
	sealed, err := s.GetSetting(MailSettingKey)
	if err != nil || bytes.Contains([]byte(sealed), []byte("relay-secret")) {
		t.Fatalf("mail setting missing or plaintext: %v", err)
	}
	if got, err := crypto.Open(p.EncryptionKey, SealMail, MailSettingKey, sealed); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("sealed mail settings %q %v", got, err)
	}
	var contract string
	if err := s.db.QueryRow(`SELECT contract FROM installer_setup_resources WHERE kind='mail' AND setup_id=?`, p.ID).Scan(&contract); err != nil || bytes.Contains([]byte(contract), []byte("relay-secret")) {
		t.Fatalf("mail ownership %q %v", contract, err)
	}
	if n := auditActions(t, s, "admin.mail_configured"); n != 1 {
		t.Fatalf("mail audits %d", n)
	}
	for _, check := range []bool{false, true} {
		r, err := s.ApplyInstallerSetup(p, check)
		if err != nil || len(r.Created) != 0 {
			t.Fatalf("mail resume %+v %v", r, err)
		}
	}
	changed, _ := mailFixture(t, "other-secret")
	changed.ID, changed.Clients = p.ID, p.Clients
	if _, err := s.ApplyInstallerSetup(changed, true); err == nil {
		t.Fatal("changed relay password accepted")
	}
	// Settings changed in the UI are drift, never overwritten.
	resealed, _ := crypto.Seal(p.EncryptionKey, SealMail, MailSettingKey, []byte(`{"host":"mail.example.test","port":587,"password":"ui"}`))
	if err := s.SetSetting(MailSettingKey, resealed); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyInstallerSetup(p, false); err == nil {
		t.Fatal("mail drift accepted")
	}
	if err := s.DeleteSetting(MailSettingKey); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyInstallerSetup(p, false); err == nil {
		t.Fatal("cleared owned mail settings were recreated")
	}
}

func TestInstallerMailRefusesForeignSettingsAndAmendments(t *testing.T) {
	s, close := setupTestStore(t)
	defer close()
	if err := s.SetSetting(MailSettingKey, "configured-in-ui"); err != nil {
		t.Fatal(err)
	}
	p, _ := mailFixture(t, "relay-secret")
	if _, err := s.ApplyInstallerSetup(p, false); err == nil {
		t.Fatal("foreign mail settings adopted")
	}
	if v, _ := s.GetSetting(MailSettingKey); v != "configured-in-ui" {
		t.Fatal("foreign mail settings overwritten")
	}
	if err := s.DeleteSetting(MailSettingKey); err != nil {
		t.Fatal(err)
	}
	p.Mail = nil
	if _, err := s.ApplyInstallerSetup(p, false); err != nil {
		t.Fatal(err)
	}
	a := amendmentFixture(p.ID)
	a.Clients[0].Groups = nil
	m, _ := mailFixture(t, "relay-secret")
	a.Mail, a.EncryptionKey = m.Mail, m.EncryptionKey
	if _, err := s.ApplyInstallerSetup(a, false); err == nil {
		t.Fatal("amendment configured mail")
	}
}
