package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	kymail "github.com/Busnes-app/kyidentity-server/internal/mail"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// The bundle's relay lands where every sender reads it, with the password from the
// protected file, and never appears in the report.
func TestSetupConfiguresMailRelayFromProtectedFile(t *testing.T) {
	b, _, db := stageFixture(t)
	data := os.Getenv("KYIDENTITY_DATA_DIR")
	files := map[string]string{"admin": "administrator-secret-123", "everyday": "everyday-secret-456", "oidc": strings.Repeat("q", 48), "webhook": strings.Repeat("w", 48), "smtp": "relay-password-789"}
	for name, value := range files {
		if err := os.WriteFile(filepath.Join(data, name), []byte(value+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	b.Admin.PasswordFile, b.Everyday.PasswordFile = filepath.Join(data, "admin"), filepath.Join(data, "everyday")
	b.Clients[0].SecretFile, b.Clients[0].SuiteWebhook.SigningSecretFile = filepath.Join(data, "oidc"), filepath.Join(data, "webhook")
	b.Mail = &setupMail{Host: "mailpit", Port: 1025, Security: "starttls", From: "KyIdentity <id@example.test>", Username: "kyidentity", PasswordFile: filepath.Join(data, "smtp")}
	raw, _ := json.Marshal(b)
	file := filepath.Join(data, "bundle.json")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	for _, args := range [][]string{{"--file", file, "--db", db}, {"--file", file, "--db", db, "--check"}} {
		out.Reset()
		if err := runSetup(args, &out); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out.String(), "relay-password") || !strings.Contains(out.String(), `"kind":"mail"`) {
			t.Fatalf("mail report %s", out.String())
		}
	}
	s, err := store.OpenInstallerStore(db, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := kymail.Load(s, bytes.Repeat([]byte{'k'}, 32))
	want := kymail.Settings{Host: "mailpit", Port: 1025, Security: "starttls", From: "KyIdentity <id@example.test>", Username: "kyidentity", Password: "relay-password-789"}
	if err != nil || got == nil || *got != want {
		t.Fatalf("loaded mail settings %+v %v", got, err)
	}
	// The relay credential is sent to the relay, so it may not be a setup credential.
	b.Mail.PasswordFile = b.Admin.PasswordFile
	if _, err := prepareSetup(mustSetupJSON(t, b)); err == nil {
		t.Fatal("account password accepted as relay password")
	}
	out.Reset()
	if err := runSetupInput([]string{"--capabilities"}, nil, &out); err != nil || !strings.Contains(out.String(), `"mail-relay"`) || !strings.Contains(out.String(), `"installer-verified-email"`) {
		t.Fatalf("capabilities %s %v", out.String(), err)
	}
}

func mustSetupJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSetupMailMetadataRefusesUnsafeRelays(t *testing.T) {
	b, _, _ := stageFixture(t)
	b.Admin.PasswordFile, b.Everyday.PasswordFile, b.Clients[0].SecretFile, b.Clients[0].SuiteWebhook.SigningSecretFile = "/a", "/b", "/c", "/d"
	ok := setupMail{Host: "smtp.example.test", Port: 587, Security: "starttls", From: "id@example.test", Username: "u", PasswordFile: "/run/smtp"}
	b.Mail = &ok
	if _, _, err := setupMetadata(mustSetupJSON(t, b)); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*setupMail){
		"plaintext":              func(m *setupMail) { m.Security = "none" },
		"no host":                func(m *setupMail) { m.Host = "" },
		"padded host":            func(m *setupMail) { m.Host = " smtp.example.test" },
		"control host":           func(m *setupMail) { m.Host = "smtp\x00.example.test" },
		"port":                   func(m *setupMail) { m.Port = 0 },
		"sender":                 func(m *setupMail) { m.From = "not an address" },
		"header injection":       func(m *setupMail) { m.From = "id@example.test\r\nBcc: x@example.test" },
		"username, no password":  func(m *setupMail) { m.PasswordFile = "" },
		"password, no username":  func(m *setupMail) { m.Username = "" },
		"relative password file": func(m *setupMail) { m.PasswordFile = "smtp" },
	} {
		m := ok
		edit(&m)
		b.Mail = &m
		if _, _, err := setupMetadata(mustSetupJSON(t, b)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	anonymous := setupMail{Host: "smtp.example.test", Port: 465, Security: "tls", From: "id@example.test"}
	b.Mail = &anonymous
	if _, _, err := setupMetadata(mustSetupJSON(t, b)); err != nil {
		t.Fatalf("unauthenticated relay refused: %v", err)
	}
	amendment := setupBundle{Schema: "kyidentity.setup/1", ID: "6f1b2b44-5b4f-4d43-9d4e-1f2d8c0a9e31", Extends: b.ID, Clients: b.Clients, Mail: &anonymous}
	if _, _, err := setupMetadata(mustSetupJSON(t, amendment)); err == nil {
		t.Fatal("amendment declared mail")
	}
}

// A relay password may be human-chosen: nothing derived from it enters the preparation
// receipt or the native record, so a leaked receipt allows no offline guessing. Apply
// still refuses a changed password through the sealed relay settings.
func TestSetupPreparationRecordsNothingDerivedFromMailPassword(t *testing.T) {
	b, file, db := stageFixture(t)
	password := filepath.Join(os.Getenv("KYIDENTITY_DATA_DIR"), "smtp.password")
	b.Mail = &setupMail{Host: "mailpit", Port: 1025, Security: "starttls", From: "id@example.test", Username: "kyidentity", PasswordFile: password}
	if _, err := stageCommand(t, b, file, db, false); err == nil {
		t.Fatal("preparation accepted a missing relay password file")
	}
	if err := os.WriteFile(password, []byte("relay-password-789\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := stageCommand(t, b, file, db, false); err != nil {
		t.Fatal(err)
	}
	receipt, err := os.ReadFile(filepath.Join(filepath.Dir(file), "credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	var sealed struct{ Credentials map[string]string }
	if err := json.Unmarshal(receipt, &sealed); err != nil {
		t.Fatal(err)
	}
	if _, found := sealed.Credentials[password]; found {
		t.Fatalf("receipt records the relay password file: %s", receipt)
	}
	for _, secret := range []string{"relay-password-789", "relay-password-789\n"} {
		sum := sha256.Sum256([]byte(secret))
		if bytes.Contains(receipt, []byte(secret)) || bytes.Contains(receipt, []byte(hex.EncodeToString(sum[:]))) {
			t.Fatalf("receipt holds a value derived from the relay password: %s", receipt)
		}
	}
	var out bytes.Buffer
	if err := runSetup([]string{"--file", file, "--db", db}, &out); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(password, []byte("rotated-password-000"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := stageCommand(t, b, file, db, true); err != nil {
		t.Fatalf("preparation check depends on the relay password: %v", err)
	}
	if err := runSetup([]string{"--file", file, "--db", db, "--check"}, &out); err == nil {
		t.Fatal("changed relay password accepted")
	}
	if err := externalCredentialAllowed(filepath.Join(filepath.Dir(file), "smtp.password"), nil, "mail password"); err == nil {
		t.Fatal("relay password inside a preparation directory accepted")
	}
}
