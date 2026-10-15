package store

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
)

// legacyStore holds one legacy secret of every sealed kind, as a pre-v2 database or an
// old backup capsule does: TOTP for u1, connector sys1, and mail settings.
func legacyStore(t *testing.T, key []byte) *Store {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "sealed.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	legacy := func(plain string) string {
		c, err := crypto.EncryptAESGCM(key, []byte(plain))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	for _, id := range []string{"u1", "u2"} {
		if err := s.CreateUser(&User{ID: id, Username: id, DisplayName: id, Email: id + "@example.test", PasswordHash: "h", Role: "user", Status: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetMFAMethod(&MFAMethod{ID: "m1", UserID: "u1", MethodType: "totp", EncryptedSecret: legacy("totp-u1")}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetMFAMethod(&MFAMethod{ID: "m2", UserID: "u1", MethodType: "push"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePairedSystem(&PairedSystem{ID: "sys1", Name: "sys1", SystemType: "scim", CallbackURL: "https://a.example.test", HMACSecretEncrypted: legacy("token-sys1"), Status: "active"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSetting(MailSettingKey, legacy(`{"host":"smtp"}`)); err != nil {
		t.Fatal(err)
	}
	return s
}

func sealedSnapshot(t *testing.T, s *Store) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, c := range sealedColumns {
		var v string
		if err := s.db.QueryRow(`SELECT ` + c.column + ` FROM ` + c.table + ` WHERE ` + c.where + ` AND COALESCE(` + c.column + `, '') != ''`).Scan(&v); err != nil {
			t.Fatal(c.table, err)
		}
		out[c.purpose] = v
	}
	return out
}

func TestSealLegacySecretsMigratesOnceAndRefusesLaterLegacy(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)
	s := legacyStore(t, key)
	if err := s.SealLegacySecrets(key); err != nil {
		t.Fatal(err)
	}
	first := sealedSnapshot(t, s)
	for purpose, want := range map[string][2]string{SealTOTP: {"u1", "totp-u1"}, SealConnector: {"sys1", "token-sys1"}, SealMail: {MailSettingKey, `{"host":"smtp"}`}} {
		got, err := crypto.Open(key, purpose, want[0], first[purpose])
		if err != nil || string(got) != want[1] {
			t.Fatalf("%s after migration: %q %v", purpose, got, err)
		}
	}
	var push string
	if err := s.db.QueryRow(`SELECT COALESCE(encrypted_secret, '') FROM mfa_methods WHERE id = 'm2'`).Scan(&push); err != nil || push != "" {
		t.Fatalf("push method gained a secret: %q %v", push, err)
	}

	// Idempotent: a rerun changes nothing.
	if err := s.SealLegacySecrets(key); err != nil {
		t.Fatal(err)
	}
	for purpose, v := range sealedSnapshot(t, s) {
		if v != first[purpose] {
			t.Fatalf("%s rewritten by a rerun", purpose)
		}
	}

	// A legacy blob planted after migration is neither migrated nor opened, so u1's
	// legacy TOTP copied onto u2 cannot become u2's sealed secret.
	planted, _ := crypto.EncryptAESGCM(key, []byte("totp-u1"))
	if err := s.SetMFAMethod(&MFAMethod{ID: "m3", UserID: "u2", MethodType: "totp", EncryptedSecret: planted}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SealLegacySecrets(key); err != nil {
		t.Fatal(err)
	}
	m, err := s.GetMFAMethod("u2", "totp")
	if err != nil || m.EncryptedSecret != planted {
		t.Fatalf("planted legacy blob was migrated: %v", err)
	}
	if _, err := crypto.Open(key, SealTOTP, "u2", m.EncryptedSecret); !errors.Is(err, crypto.ErrLegacyCiphertext) {
		t.Fatalf("planted legacy blob opened: %v", err)
	}
}

// A legacy secret that does not decrypt (wrong key, damaged row) aborts the whole
// migration: nothing is rewritten and the database is not marked, so a corrected key
// can still migrate it.
func TestSealLegacySecretsFailsClosedOnUndecryptableRow(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)
	s := legacyStore(t, key)
	before := sealedSnapshot(t, s)
	if err := s.SealLegacySecrets(bytes.Repeat([]byte{4}, 32)); err == nil {
		t.Fatal("migration under the wrong key succeeded")
	}
	for purpose, v := range sealedSnapshot(t, s) {
		if v != before[purpose] {
			t.Fatalf("%s rewritten by a failed migration", purpose)
		}
	}
	if _, err := s.GetSetting(SealedSecretsSetting); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed migration marked the database: %v", err)
	}
	if err := s.SealLegacySecrets(key); err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.Open(key, SealConnector, "sys1", sealedSnapshot(t, s)[SealConnector]); err != nil {
		t.Fatal(err)
	}
}
