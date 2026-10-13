package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busnes-app/kyidentity-server/internal/auth"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

func TestSetupCommandProtectsSecretsAndChecksRealDatabase(t *testing.T) {
	for _, protocol := range []string{"scim", "suite_webhook"} {
		t.Run(protocol, func(t *testing.T) { testSetupProtectedConnector(t, protocol) })
	}
}

func testSetupProtectedConnector(t *testing.T, protocol string) {
	dir := t.TempDir()
	db := filepath.Join(dir, "identity.db")
	s, err := store.New(db)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	admin := filepath.Join(dir, "admin")
	user := filepath.Join(dir, "everyday")
	secret := filepath.Join(dir, "oidc")
	token := filepath.Join(dir, "scim")
	t.Setenv("KYIDENTITY_DATA_DIR", dir)
	t.Setenv("KYIDENTITY_ENCRYPTION_KEY", "")
	for path, value := range map[string]string{admin: "administrator-secret-123", user: "everyday-secret-456", secret: strings.Repeat("q", 48), token: strings.Repeat("s", 48), filepath.Join(dir, "encryption.key"): strings.Repeat("k", 32)} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	b := setupBundle{Schema: "kyidentity.setup/1", ID: uuid.NewString(), Admin: setupAccount{"owner-admin", "admin@example.test", admin}, Everyday: setupAccount{"owner", "owner@example.test", user}, Clients: []setupClient{{ID: "drive", Name: "Drive", SecretFile: secret, RedirectURIs: []string{"https://drive.example.test/callback"}, AdministratorRole: "admin", EverydayRole: "user", SCIM: &setupSCIM{URL: "https://bridge.test/scim/v2/drive", TokenFile: token}}}}
	if protocol == "suite_webhook" {
		b.Clients[0].SCIM = nil
		b.Clients[0].SuiteWebhook = &setupSuiteWebhook{URL: "https://notes.test/api/v1/sync/events", SigningSecretFile: token}
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runSetup([]string{"--file", file, "--db", db, "--check"}, &out); err == nil {
		t.Fatal("check passed unconfigured")
	}
	for _, args := range [][]string{{"--file", file, "--db", db}, {"--file", file, "--db", db, "--check"}} {
		out.Reset()
		if err := runSetup(args, &out); err != nil {
			t.Fatal(err)
		}
		for _, credential := range []string{"administrator-secret-123", "everyday-secret-456", strings.Repeat("q", 48), strings.Repeat("s", 48), strings.Repeat("k", 32), "argon2id"} {
			if strings.Contains(out.String(), credential) {
				t.Fatal("report leaked credentials")
			}
		}
	}
	s, err = store.New(db)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	u, err := s.GetUserByUsername("owner-admin")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := auth.VerifyPassword("administrator-secret-123", u.PasswordHash); err != nil || !ok {
		t.Fatal("cannot authenticate created owner", err)
	}
	claims, err := s.UserAppClaims(u.ID, "drive")
	if err != nil || claims.LegacyRole || len(claims.Roles) != 1 || claims.Roles[0] != "admin" {
		t.Fatal("configured owner app role missing", err)
	}
	if protocol == "suite_webhook" {
		if err := os.Chmod(token, 0644); err != nil {
			t.Fatal(err)
		}
		out.Reset()
		if err := runSetup([]string{"--file", file, "--db", db, "--check"}, &out); err == nil || out.Len() != 0 {
			t.Fatal("shared signing secret accepted or reported")
		}
		if err := os.Chmod(token, 0600); err != nil {
			t.Fatal(err)
		}
		for _, invalid := range []string{strings.Repeat("s", 31), strings.Repeat("s", 1025), strings.Repeat("s", 32) + " embedded space", strings.Repeat("s", 32) + "\x00"} {
			if err := os.WriteFile(token, []byte(invalid), 0600); err != nil {
				t.Fatal(err)
			}
			out.Reset()
			if err := runSetup([]string{"--file", file, "--db", db, "--check"}, &out); err == nil || out.Len() != 0 {
				t.Fatal("invalid signing secret accepted or reported")
			}
		}
		if err := os.WriteFile(token, []byte(strings.Repeat("s", 48)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(admin, 0644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runSetup([]string{"--file", file, "--db", db}, &out); err == nil || out.Len() != 0 {
		t.Fatal("accepted shared credential file")
	}
}

func TestSetupSCIMBoundaryAndExistingKeyOnly(t *testing.T) {
	for _, endpoint := range []string{"http://bridge.test/scim/v2", "https://secret@bridge.test/scim/v2", "https://bridge.test/scim/v2?", "https://bridge.test/scim/v2#", "https://bridge.test/scim/v2?token=do-not-echo"} {
		b := setupBundle{Schema: "kyidentity.setup/1", ID: uuid.NewString(), Admin: setupAccount{"owner-admin", "admin@example.test", "/missing"}, Everyday: setupAccount{"owner", "owner@example.test", "/missing"}, Clients: []setupClient{{ID: "drive", Name: "Drive", SecretFile: "/missing", RedirectURIs: []string{"https://drive.test/callback"}, SCIM: &setupSCIM{URL: endpoint, TokenFile: "/missing"}}}}
		raw, _ := json.Marshal(b)
		if _, err := prepareSetup(raw); err == nil || !strings.Contains(err.Error(), "SCIM") || strings.Contains(err.Error(), "do-not-echo") {
			t.Fatal("SCIM boundary failed before credentials", err)
		}
	}
	dir := t.TempDir()
	t.Setenv("KYIDENTITY_DATA_DIR", dir)
	t.Setenv("KYIDENTITY_ENCRYPTION_KEY", "")
	if _, err := existingSetupEncryptionKey(); err == nil {
		t.Fatal("accepted missing key")
	}
	if _, err := os.Stat(filepath.Join(dir, "encryption.key")); !os.IsNotExist(err) {
		t.Fatal("generated key during inspection")
	}
	t.Setenv("KYIDENTITY_ENCRYPTION_KEY", strings.Repeat("ab", 32))
	if key, err := existingSetupEncryptionKey(); err != nil || len(key) != 32 {
		t.Fatal("existing environment key", err)
	}
	t.Setenv("KYIDENTITY_ENCRYPTION_KEY", "do-not-echo")
	if _, err := existingSetupEncryptionKey(); err == nil || strings.Contains(err.Error(), "do-not-echo") {
		t.Fatal("invalid key accepted or echoed", err)
	}
}

func TestSetupRoleValidationBeforeCredentialReads(t *testing.T) {
	for _, roles := range [][2]string{{"admin", "ADMIN"}, {"bad role", "user"}, {"admin", "bad\nrole"}, {strings.Repeat("x", 65), "user"}} {
		b := setupBundle{Schema: "kyidentity.setup/1", ID: uuid.NewString(), Admin: setupAccount{"owner-admin", "admin@example.test", "/missing"}, Everyday: setupAccount{"owner", "owner@example.test", "/missing"}, Clients: []setupClient{{ID: "drive", Name: "Drive", SecretFile: "/missing", RedirectURIs: []string{"https://drive.example.test/callback"}, AdministratorRole: roles[0], EverydayRole: roles[1]}}}
		raw, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := prepareSetup(raw); err == nil || !strings.Contains(err.Error(), "roles") {
			t.Fatal("roles were not rejected before credentials", err)
		}
	}
}
func TestSetupFileAndBundleBoundary(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "secret")
	if err := os.WriteFile(real, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, dir, "relative"} {
		if _, err := readSetupFile(path, 64); err == nil {
			t.Fatalf("accepted %s", path)
		}
	}
	for _, raw := range []string{`{"schema":"kyidentity.setup/1","password":"do-not-echo"}`, `{} {}`, `{"schema":"other"}`} {
		if _, err := prepareSetup([]byte(raw)); err == nil || strings.Contains(err.Error(), "do-not-echo") {
			t.Fatal("invalid bundle accepted or echoed")
		}
	}
	if setupURI("http://drive.test/callback") || setupURI("https://secret@drive.test/callback") || setupURI("https://drive.test/callback#fragment") || !setupURI("https://drive.test/callback") {
		t.Fatal("URI boundary")
	}
	var out bytes.Buffer
	if err := runSetup([]string{"--capabilities"}, &out); err != nil || !strings.Contains(out.String(), "assigned-only") {
		t.Fatal("capabilities", err)
	}
	if !strings.Contains(out.String(), "suite-webhook-connectors") {
		t.Fatal("missing signed suite capability")
	}
}

func TestSetupSuiteWebhookBoundaryBeforeCredentials(t *testing.T) {
	for _, endpoint := range []string{"http://notes.test/sync/events", "https://secret@notes.test/sync/events", "https://notes.test/sync/events?", "https://notes.test/sync/events#", "https://notes.test/sync/events?secret=do-not-echo"} {
		b := setupBundle{Schema: "kyidentity.setup/1", ID: uuid.NewString(), Admin: setupAccount{"owner-admin", "admin@example.test", "/missing"}, Everyday: setupAccount{"owner", "owner@example.test", "/missing"}, Clients: []setupClient{{ID: "notes", Name: "Notes", SecretFile: "/missing", RedirectURIs: []string{"https://notes.test/callback"}, SuiteWebhook: &setupSuiteWebhook{URL: endpoint, SigningSecretFile: "/missing"}}}}
		raw, _ := json.Marshal(b)
		if _, err := prepareSetup(raw); err == nil || !strings.Contains(err.Error(), "suite webhook") || strings.Contains(err.Error(), "do-not-echo") {
			t.Fatal("suite endpoint boundary", err)
		}
	}
	b := setupBundle{Schema: "kyidentity.setup/1", ID: uuid.NewString(), Admin: setupAccount{"owner-admin", "admin@example.test", "/missing"}, Everyday: setupAccount{"owner", "owner@example.test", "/missing"}, Clients: []setupClient{{ID: "notes", Name: "Notes", SecretFile: "/missing", RedirectURIs: []string{"https://notes.test/callback"}, SCIM: &setupSCIM{URL: "https://notes.test/scim/v2", TokenFile: "/missing"}, SuiteWebhook: &setupSuiteWebhook{URL: "https://notes.test/sync/events", SigningSecretFile: "/missing"}}}}
	raw, _ := json.Marshal(b)
	if _, err := prepareSetup(raw); err == nil || !strings.Contains(err.Error(), "one SCIM or signed suite") {
		t.Fatal("accepted two connector protocols", err)
	}
	b.Clients[0].SCIM = nil
	b.Clients[0].SuiteWebhook.SigningSecretFile = "relative"
	raw, _ = json.Marshal(b)
	if _, err := prepareSetup(raw); err == nil || !strings.Contains(err.Error(), "suite webhook") {
		t.Fatal("accepted relative signing secret", err)
	}
}
