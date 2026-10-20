package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busnes-app/kyidentity-server/internal/auth"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

func stageFixture(t *testing.T) (setupBundle, string, string) {
	t.Helper()
	data := t.TempDir()
	t.Setenv("KYIDENTITY_DATA_DIR", data)
	t.Setenv("KYIDENTITY_ENCRYPTION_KEY", "")
	db := filepath.Join(data, "identity.db")
	s, err := store.New(db)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	b := setupBundle{Schema: "kyidentity.setup/1", ID: uuid.NewString(), Admin: setupAccount{Username: "owner-admin", Email: "admin@example.test"}, Everyday: setupAccount{Username: "owner", Email: "owner@example.test"}, Clients: []setupClient{{ID: "notes", Name: "KyNotes", RedirectURIs: []string{"https://notes.example.test/api/v1/auth/oidc/callback"}, AdministratorRole: "admin", EverydayRole: "user", SuiteWebhook: &setupSuiteWebhook{URL: "https://notes.example.test/api/v1/sync/events"}}}}
	if err := os.WriteFile(filepath.Join(data, "encryption.key"), bytes.Repeat([]byte{'k'}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	return b, filepath.Join(data, "installer", b.ID, "setup.json"), db
}

func stageCommand(t *testing.T, b setupBundle, file, db string, check bool) (string, error) {
	t.Helper()
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"--stage", "--file", file, "--db", db}
	if check {
		args = append(args, "--check")
	}
	var out bytes.Buffer
	err = runSetupInput(args, bytes.NewReader(raw), &out)
	if err != nil && out.Len() != 0 {
		t.Fatal("rejected preparation wrote output")
	}
	return out.String(), err
}

func TestSetupPreparationNativeApplyResumeAndCredentialLoss(t *testing.T) {
	b, file, db := stageFixture(t)
	if _, err := stageCommand(t, b, file, db, true); err == nil {
		t.Fatal("check accepted absent preparation")
	}
	if _, err := os.Stat(filepath.Dir(filepath.Dir(file))); !os.IsNotExist(err) {
		t.Fatal("check created installer directory")
	}
	if err := os.Chmod(os.Getenv("KYIDENTITY_DATA_DIR"), 0755); err != nil {
		t.Fatal(err)
	}
	report, err := stageCommand(t, b, file, db, false)
	if err != nil || !strings.Contains(report, `"created"`) {
		t.Fatal("native preparation failed", err)
	}
	raw, err := readSetupFile(file, setupBundleLimit)
	if err != nil {
		t.Fatal(err)
	}
	var prepared setupBundle
	if json.Unmarshal(raw, &prepared) != nil {
		t.Fatal("invalid native bundle")
	}
	password, err := readSetupFile(prepared.Admin.PasswordFile, 43)
	if err != nil {
		t.Fatal(err)
	}
	clientSecret, err := readSetupFile(prepared.Clients[0].SecretFile, 43)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(password, clientSecret) || strings.Contains(report, string(password)) || strings.Contains(report, string(clientSecret)) {
		t.Fatal("credentials reused or disclosed")
	}
	for _, check := range []bool{true, false} {
		report, err := stageCommand(t, b, file, db, check)
		if err != nil || !strings.Contains(report, `"present"`) {
			t.Fatal("preparation resume failed", err)
		}
	}
	var out bytes.Buffer
	if err := runSetup([]string{"--file", file, "--db", db}, &out); err != nil {
		t.Fatal(err)
	}
	if err := runSetup([]string{"--file", file, "--db", db, "--check"}, &out); err != nil {
		t.Fatal(err)
	}
	s, err := store.OpenInstallerStore(db, true)
	if err != nil {
		t.Fatal(err)
	}
	user, err := s.GetUserByUsername(b.Admin.Username)
	s.Close()
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := auth.VerifyPassword(string(password), user.PasswordHash); err != nil || !ok {
		t.Fatal("generated owner password did not authenticate", err)
	}
	retained, _ := os.ReadFile(file)
	b.Clients[0].Name = "Changed"
	if _, err := stageCommand(t, b, file, db, false); err == nil {
		t.Fatal("changed intent accepted")
	}
	after, _ := os.ReadFile(file)
	if !bytes.Equal(retained, after) {
		t.Fatal("changed intent replaced native bundle")
	}
	b.Clients[0].Name = "KyNotes"
	if err := os.Remove(prepared.Admin.PasswordFile); err != nil {
		t.Fatal(err)
	}
	for _, check := range []bool{true, false} {
		if _, err := stageCommand(t, b, file, db, check); err == nil {
			t.Fatal("lost credential regenerated or accepted")
		}
	}
	if _, err := os.Stat(prepared.Admin.PasswordFile); !os.IsNotExist(err) {
		t.Fatal("missing credential replaced")
	}
	if err := os.WriteFile(prepared.Admin.PasswordFile, password, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(prepared.Clients[0].SecretFile, bytes.Repeat([]byte{'x'}, 43), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := stageCommand(t, b, file, db, false); err == nil {
		t.Fatal("changed credential accepted")
	}
	out.Reset()
	if err := runSetup([]string{"--file", file, "--db", db}, &out); err == nil || out.Len() != 0 {
		t.Fatal("ordinary apply bypassed preparation receipt")
	}
	if err := os.WriteFile(prepared.Clients[0].SecretFile, clientSecret, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(filepath.Dir(file), "credentials.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := stageCommand(t, b, file, db, false); err == nil {
		t.Fatal("lost receipt accepted after apply")
	}
}

func TestSetupPreparationBoundariesBeforeWrites(t *testing.T) {
	for _, kind := range []string{"unknown", "large", "account", "path", "key", "foreign", "symlink", "scim"} {
		t.Run(kind, func(t *testing.T) {
			b, file, db := stageFixture(t)
			switch kind {
			case "account":
				b.Everyday.Username = b.Admin.Username
			case "path":
				b.Admin.PasswordFile = "/outside/password"
			case "key":
				if err := os.Remove(filepath.Join(os.Getenv("KYIDENTITY_DATA_DIR"), "encryption.key")); err != nil {
					t.Fatal(err)
				}
			case "scim":
				b.Clients[0].SuiteWebhook = nil
				b.Clients[0].SCIM = &setupSCIM{URL: "https://bridge.example.test/scim/v2/notes", TokenFile: filepath.Join(os.Getenv("KYIDENTITY_DATA_DIR"), "not-issued")}
			case "foreign":
				if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(filepath.Dir(file), "foreign"), []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(t.TempDir(), filepath.Dir(filepath.Dir(file))); err != nil {
					t.Fatal(err)
				}
			}
			raw, _ := json.Marshal(b)
			if kind == "unknown" {
				raw = append(raw[:len(raw)-1], []byte(`,"password":"do-not-log"}`)...)
			}
			if kind == "large" {
				raw = bytes.Repeat([]byte{'x'}, setupBundleLimit+1)
			}
			var out bytes.Buffer
			err := runSetupInput([]string{"--stage", "--file", file, "--db", db}, bytes.NewReader(raw), &out)
			if err == nil || out.Len() != 0 || strings.Contains(err.Error(), "do-not-log") {
				t.Fatal("preparation boundary accepted or disclosed input")
			}
			if _, err := os.Stat(file); !os.IsNotExist(err) {
				t.Fatal("invalid intent published a bundle")
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(file), "admin.password")); !os.IsNotExist(err) {
				t.Fatal("invalid intent generated credential")
			}
		})
	}
}

func TestSetupPreparationInterruptedPublicationKeepsCredentials(t *testing.T) {
	b, file, db := stageFixture(t)
	scope := filepath.Dir(file)
	if err := os.MkdirAll(scope, 0700); err != nil {
		t.Fatal(err)
	}
	prepared := b
	prepared.Admin.PasswordFile = filepath.Join(scope, "admin.password")
	prepared.Everyday.PasswordFile = filepath.Join(scope, "everyday.password")
	prepared.Clients = append([]setupClient{}, b.Clients...)
	connector := *prepared.Clients[0].SuiteWebhook
	prepared.Clients[0].SuiteWebhook = &connector
	prepared.Clients[0].SecretFile = filepath.Join(scope, "client-notes.secret")
	prepared.Clients[0].SuiteWebhook.SigningSecretFile = filepath.Join(scope, "client-notes.webhook")
	intent, _ := json.Marshal(prepared)
	if err := os.WriteFile(filepath.Join(scope, "intent.json"), intent, 0600); err != nil {
		t.Fatal(err)
	}
	password := []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{'p'}, 32)))
	if err := os.WriteFile(prepared.Admin.PasswordFile, password, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := stageCommand(t, b, file, db, false); err != nil {
		t.Fatal("partial preparation could not resume", err)
	}
	after, _ := os.ReadFile(prepared.Admin.PasswordFile)
	if !bytes.Equal(password, after) {
		t.Fatal("partial resume replaced retained password")
	}
	if _, err := stageCommand(t, b, file, db, true); err != nil {
		t.Fatal(err)
	}
}

func TestSetupPreparationDestinationTokenAndExistingNativeOwnership(t *testing.T) {
	t.Run("destination-token", func(t *testing.T) {
		b, file, db := stageFixture(t)
		token := filepath.Join(os.Getenv("KYIDENTITY_DATA_DIR"), "destination.token")
		issued := bytes.Repeat([]byte{'t'}, 48)
		if err := os.WriteFile(token, issued, 0600); err != nil {
			t.Fatal(err)
		}
		b.Clients[0].SuiteWebhook = nil
		b.Clients[0].SCIM = &setupSCIM{URL: "https://bridge.example.test/scim/v2/notes", TokenFile: token}
		if _, err := stageCommand(t, b, file, db, false); err != nil {
			t.Fatal(err)
		}
		retained, _ := os.ReadFile(token)
		if !bytes.Equal(issued, retained) {
			t.Fatal("destination-issued token replaced")
		}
		if err := os.WriteFile(token, bytes.Repeat([]byte{'r'}, 48), 0600); err != nil {
			t.Fatal(err)
		}
		for _, check := range []bool{true, false} {
			if _, err := stageCommand(t, b, file, db, check); err == nil {
				t.Fatal("changed destination token accepted")
			}
		}
		if err := os.WriteFile(token, issued, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := stageCommand(t, b, file, db, true); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("already-applied-without-preparation", func(t *testing.T) {
		b, file, db := stageFixture(t)
		original := b
		data := os.Getenv("KYIDENTITY_DATA_DIR")
		b.Admin.PasswordFile = filepath.Join(data, "manual-admin")
		b.Everyday.PasswordFile = filepath.Join(data, "manual-everyday")
		// Copy nested client/connector metadata before setting manual credential paths.
		b.Clients = append([]setupClient{}, b.Clients...)
		connector := *b.Clients[0].SuiteWebhook
		b.Clients[0].SuiteWebhook = &connector
		b.Clients[0].SecretFile = filepath.Join(data, "manual-client")
		b.Clients[0].SuiteWebhook.SigningSecretFile = filepath.Join(data, "manual-webhook")
		for _, path := range []string{b.Admin.PasswordFile, b.Everyday.PasswordFile, b.Clients[0].SecretFile, b.Clients[0].SuiteWebhook.SigningSecretFile} {
			if err := os.WriteFile(path, bytes.Repeat([]byte{'m'}, 48), 0600); err != nil {
				t.Fatal(err)
			}
		}
		raw, _ := json.Marshal(b)
		manual := filepath.Join(data, "manual.json")
		if err := os.WriteFile(manual, raw, 0600); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := runSetup([]string{"--file", manual, "--db", db}, &out); err != nil {
			t.Fatal(err)
		}
		if _, err := stageCommand(t, original, file, db, false); err == nil {
			t.Fatal("already applied native setup minted new credentials")
		}
		if _, err := os.Stat(filepath.Dir(filepath.Dir(file))); !os.IsNotExist(err) {
			t.Fatal("already applied native setup created preparation directory")
		}
	})
}

func TestSetupPreparationLostCompletionFilesBeforeApplication(t *testing.T) {
	b, file, db := stageFixture(t)
	if _, err := stageCommand(t, b, file, db, false); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"admin.password", "credentials.json", "setup.json"} {
		if err := os.Remove(filepath.Join(filepath.Dir(file), name)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := stageCommand(t, b, file, db, false); err == nil {
		t.Fatal("lost completion markers authorized replacement credentials")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(file), "admin.password")); !os.IsNotExist(err) {
		t.Fatal("prepared password regenerated before account application")
	}
}

func TestSetupPublicClientAndBackchannel(t *testing.T) {
	b, file, db := stageFixture(t)
	b.Clients[0].ClientType = "public"
	b.Clients[0].BackchannelLogoutURI = "https://notes.example.test/logout"
	if _, err := stageCommand(t, b, file, db, false); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var staged setupBundle
	if err := json.Unmarshal(raw, &staged); err != nil {
		t.Fatal(err)
	}
	if staged.Clients[0].SecretFile != "" {
		t.Fatal("public client got a secret")
	}
	var out bytes.Buffer
	if err := runSetup([]string{"--file", file, "--db", db}, &out); err != nil {
		t.Fatal(err)
	}
	if err := runSetup([]string{"--file", file, "--db", db, "--check"}, &out); err != nil {
		t.Fatal(err)
	}
	s, err := store.OpenInstallerStore(db, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := s.GetOAuthClientByID("notes")
	if err != nil {
		t.Fatal(err)
	}
	if c.ClientType != "public" || c.ClientSecretHash != "" || c.BackchannelLogoutURI != b.Clients[0].BackchannelLogoutURI {
		t.Fatalf("wrong client: %#v", c)
	}
	if err := runSetup([]string{"--file", file, "--db", db, "--export-client", "notes"}, &out); err == nil {
		t.Fatal("exported public client")
	}
	c.BackchannelLogoutURI = "https://notes.example.test/changed"
	if err := s.UpdateOAuthClient(c); err != nil {
		t.Fatal(err)
	}
	if err := runSetup([]string{"--file", file, "--db", db, "--check"}, &out); err == nil {
		t.Fatal("accepted back-channel logout drift")
	}
}
