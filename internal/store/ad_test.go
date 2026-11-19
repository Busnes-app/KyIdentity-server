package store

import (
	"crypto/ecdh"
	"errors"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/adpass"
	"github.com/google/uuid"
)

// adStoreFixture is a directory connector with an agent key, its app, and one assigned user.
func adStoreFixture(t *testing.T, s *Store, id string) (*ecdh.PrivateKey, string) {
	t.Helper()
	k, err := adpass.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ps := &PairedSystem{ID: id, Name: id, SystemType: "active_directory", CallbackURL: "ldaps://dc.example.test", HMACSecretEncrypted: "sealed", Status: "active"}
	if err := s.CreateADSystem(ps, &ADConnector{BindDN: "CN=b", BaseDN: "OU=K,DC=example,DC=test", CAPEM: "pem", AgentPublicKey: adpass.EncodePublicKey(k.PublicKey()), PasswordTTLMinutes: 1440}, nil); err != nil {
		t.Fatal(err)
	}
	var app string
	if err := s.db.QueryRow(`SELECT id FROM app_registry WHERE system_id=?`, id).Scan(&app); err != nil {
		t.Fatal(err)
	}
	return k, app
}

func queueAudits(t *testing.T, s *Store, action string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM audit_events WHERE action=?`, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func queuedAudit(systemID string, seq int64, superseded bool) *AuditEvent {
	return &AuditEvent{ID: uuid.NewString(), Action: "directory.password_queued", Outcome: "success", TargetType: "user"}
}

func TestDirectoryPasswordQueueSealsForManagedUsersOnly(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	k, app := adStoreFixture(t, s, "ad-1")
	managed, outsider := createTestUser(t, s), createTestUser(t, s)
	if err := s.SetAppAssignment(app, "users", managed.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if n, err := s.QueueDirectoryPassword(outsider.ID, outsider.PasswordHash, []byte("Outsider-pass-1"), queuedAudit); err != nil || n != 0 {
		t.Fatal("queued for a user the connector does not hold", n, err)
	}
	if n, err := s.QueueDirectoryPassword(managed.ID, "not-the-current-hash", []byte("Stale-pass-1"), queuedAudit); err != nil || n != 0 {
		t.Fatal("queued a password that is no longer current", n, err)
	}
	if n, err := s.QueueDirectoryPassword(managed.ID, managed.PasswordHash, []byte("First-pass-1"), queuedAudit); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	firstEntries, _ := s.PendingADPasswords("ad-1", time.Now(), 10)
	if n, err := s.QueueDirectoryPassword(managed.ID, managed.PasswordHash, []byte("Second-pass-2"), queuedAudit); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	entries, err := s.PendingADPasswords("ad-1", time.Now(), 10)
	if err != nil || len(entries) != 1 || entries[0].UserID != managed.ID {
		t.Fatal("a newer password did not supersede the older one", entries, err)
	}
	if entries[0].Seq <= firstEntries[0].Seq {
		t.Fatal("sequence did not advance", firstEntries[0].Seq, entries[0].Seq)
	}
	plain, err := adpass.Open(k, "ad-1", managed.ID, entries[0].Seq, entries[0].Ciphertext)
	if err != nil || string(plain) != "Second-pass-2" {
		t.Fatal("agent cannot open the newest entry", err)
	}
	if queueAudits(t, s, "directory.password_queued") != 2 {
		t.Fatal("each queued password is audited")
	}
	// The superseded ciphertext is gone: finishing it is refused.
	if err := s.FinishADPassword("ad-1", managed.ID, firstEntries[0].Seq, "applied", ""); !errors.Is(err, ErrNotFound) {
		t.Fatal("an acknowledgement for a superseded entry was accepted", err)
	}
	st, _ := s.ADPasswordStatuses("ad-1")
	if len(st) != 1 || st[0].State != "pending" {
		t.Fatalf("status %+v", st)
	}
	if err := s.FinishADPassword("ad-1", managed.ID, entries[0].Seq, "applied", ""); err != nil {
		t.Fatal(err)
	}
	if left, _ := s.PendingADPasswords("ad-1", time.Now(), 10); len(left) != 0 {
		t.Fatal("acknowledged entry still served")
	}
	var ct string
	if err := s.db.QueryRow(`SELECT ciphertext FROM ad_passwords WHERE system_id='ad-1' AND user_id=?`, managed.ID).Scan(&ct); err != nil || ct != "" {
		t.Fatal("acknowledged ciphertext kept", err)
	}
	if st, _ := s.ADPasswordStatuses("ad-1"); st[0].State != "current" || queueAudits(t, s, "directory.password_delivered") != 1 {
		t.Fatalf("status after delivery %+v", st)
	}
	if err := s.FinishADPassword("ad-1", managed.ID, entries[0].Seq, "applied", ""); !errors.Is(err, ErrNotFound) {
		t.Fatal("an entry was finished twice", err)
	}
	// A password set since the last delivery shows the directory copy as stale.
	if _, err := s.db.Exec(`UPDATE users SET password_hash='changed-without-queue' WHERE id=?`, managed.ID); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.ADPasswordStatuses("ad-1"); st[0].State != "stale" {
		t.Fatalf("status after an unqueued change %+v", st)
	}
}

func TestDirectoryPasswordQueueExpiresAndRejects(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	_, app := adStoreFixture(t, s, "ad-1")
	u := createTestUser(t, s)
	if err := s.SetAppAssignment(app, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.ADPasswordStatuses("ad-1"); st[0].State != "missing" {
		t.Fatalf("a user with no delivered password: %+v", st)
	}
	if _, err := s.QueueDirectoryPassword(u.ID, u.PasswordHash, []byte("Expiring-pass-1"), queuedAudit); err != nil {
		t.Fatal(err)
	}
	if n, err := s.ExpireADPasswords(time.Now()); err != nil || n != 0 {
		t.Fatal("a fresh entry expired", n, err)
	}
	if n, err := s.ExpireADPasswords(time.Now().Add(24*time.Hour + time.Minute)); err != nil || n != 1 {
		t.Fatal("entry outlived its lifetime", n, err)
	}
	if left, _ := s.PendingADPasswords("ad-1", time.Now(), 10); len(left) != 0 || queueAudits(t, s, "directory.password_expired") != 1 {
		t.Fatal("expired entry still served or not audited")
	}
	if st, _ := s.ADPasswordStatuses("ad-1"); st[0].State != "missing" {
		t.Fatalf("status after expiry %+v", st)
	}

	// An admin-lowered lifetime applies to the next entry.
	c, _ := s.ADConnector("ad-1")
	c.PasswordTTLMinutes = 10
	if err := s.ConfigureADSystem("ad-1", "ldaps://dc.example.test", "", c, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.QueueDirectoryPassword(u.ID, u.PasswordHash, []byte("Short-lived-1"), queuedAudit); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.ExpireADPasswords(time.Now().Add(11 * time.Minute)); n != 1 {
		t.Fatal("lowered lifetime not applied")
	}

	if _, err := s.QueueDirectoryPassword(u.ID, u.PasswordHash, []byte("Too-simple"), queuedAudit); err != nil {
		t.Fatal(err)
	}
	e, _ := s.PendingADPasswords("ad-1", time.Now(), 10)
	if err := s.FinishADPassword("ad-1", u.ID, e[0].Seq, "rejected", "made up"); err == nil {
		t.Fatal("unknown reason accepted")
	}
	if err := s.FinishADPassword("ad-1", u.ID, e[0].Seq, "retry", "user_not_found"); err != nil {
		t.Fatal(err)
	}
	if left, _ := s.PendingADPasswords("ad-1", time.Now(), 10); len(left) != 1 {
		t.Fatal("a retry dropped the entry")
	}
	if err := s.FinishADPassword("ad-1", u.ID, e[0].Seq, "rejected", "password_policy"); err != nil {
		t.Fatal(err)
	}
	st, _ := s.ADPasswordStatuses("ad-1")
	if st[0].State != "rejected" || st[0].LastError != "password_policy" || queueAudits(t, s, "directory.password_rejected") != 1 {
		t.Fatalf("rejection not visible %+v", st)
	}
}

func TestDirectoryAgentTokensAndKeysAreScopedToOneConnector(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	_, app1 := adStoreFixture(t, s, "ad-1")
	_, _ = adStoreFixture(t, s, "ad-2")
	u := createTestUser(t, s)
	if err := s.SetAppAssignment(app1, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetADAgentToken("ad-1", "kyad_one", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetADAgentToken("ad-2", "kyad_two", nil); err != nil {
		t.Fatal(err)
	}
	for token, want := range map[string]string{"kyad_one": "ad-1", "kyad_two": "ad-2"} {
		if got, err := s.ADSystemForAgentToken(token); err != nil || got != want {
			t.Fatal(token, got, err)
		}
	}
	for _, bad := range []string{"", "kyad_three", HashAgentToken("kyad_one")} {
		if _, err := s.ADSystemForAgentToken(bad); !errors.Is(err, ErrNotFound) {
			t.Fatalf("token %q accepted: %v", bad, err)
		}
	}
	var stored string
	if err := s.db.QueryRow(`SELECT agent_token_hash FROM ad_connectors WHERE system_id='ad-1'`).Scan(&stored); err != nil || stored == "kyad_one" {
		t.Fatal("agent token stored in the clear")
	}
	if _, err := s.QueueDirectoryPassword(u.ID, u.PasswordHash, []byte("Scoped-pass-1"), queuedAudit); err != nil {
		t.Fatal(err)
	}
	if e, _ := s.PendingADPasswords("ad-2", time.Now(), 10); len(e) != 0 {
		t.Fatal("another connector's queue holds the entry")
	}
	e, _ := s.PendingADPasswords("ad-1", time.Now(), 10)
	if err := s.FinishADPassword("ad-2", u.ID, e[0].Seq, "applied", ""); !errors.Is(err, ErrNotFound) {
		t.Fatal("another connector acknowledged the entry", err)
	}
	// Replacing the token ends the old one; a new agent key drops undeliverable ciphertext.
	if err := s.SetADAgentToken("ad-1", "kyad_new", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ADSystemForAgentToken("kyad_one"); !errors.Is(err, ErrNotFound) {
		t.Fatal("replaced token still works")
	}
	k2, _ := adpass.GenerateKey()
	c, _ := s.ADConnector("ad-1")
	c.AgentPublicKey = adpass.EncodePublicKey(k2.PublicKey())
	if err := s.ConfigureADSystem("ad-1", "ldaps://dc.example.test", "", c, nil); err != nil {
		t.Fatal(err)
	}
	if e, _ := s.PendingADPasswords("ad-1", time.Now(), 10); len(e) != 0 {
		t.Fatal("ciphertext for the old key kept")
	}
	// A disabled connector's token stops working.
	if _, err := s.db.Exec(`UPDATE paired_systems SET status='disabled' WHERE id='ad-1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ADSystemForAgentToken("kyad_new"); !errors.Is(err, ErrNotFound) {
		t.Fatal("disabled connector's token accepted")
	}
}
