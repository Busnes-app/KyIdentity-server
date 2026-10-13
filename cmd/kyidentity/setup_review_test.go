package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// A crash inside keyfile.Store leaves a private temp file; the rerun must resume.
func TestSetupStageResumesAfterInterruptedIntent(t *testing.T) {
	b, file, db := stageFixture(t)
	scope := filepath.Dir(file)
	if err := os.MkdirAll(scope, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(scope), 0700); err != nil {
		t.Fatal(err)
	}
	stray := filepath.Join(scope, ".keyfile-123.tmp")
	if err := os.WriteFile(stray, []byte("{partial"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := stageCommand(t, b, file, db, false); err != nil {
		t.Fatal("interrupted preparation did not resume:", err)
	}
	if _, err := os.Stat(stray); !os.IsNotExist(err) {
		t.Fatal("stray temp file retained")
	}
	if _, err := stageCommand(t, b, file, db, true); err != nil {
		t.Fatal(err)
	}
}

// A SCIM token is sent to the connector URL, so it can never be a setup credential
// or product secret, including another setup's generated password.
func TestSetupSCIMTokenRefusesSetupCredentials(t *testing.T) {
	a, fileA, db := stageFixture(t)
	if _, err := stageCommand(t, a, fileA, db, false); err != nil {
		t.Fatal(err)
	}
	data := os.Getenv("KYIDENTITY_DATA_DIR")
	for name, token := range map[string]string{
		"other-setup-password": filepath.Join(filepath.Dir(fileA), "admin.password"),
		"encryption-key":       filepath.Join(data, "encryption.key"),
	} {
		t.Run(name, func(t *testing.T) {
			b := setupBundle{Schema: "kyidentity.setup/1", ID: uuid.NewString(),
				Admin:    setupAccount{Username: "b-admin", Email: "b-admin@example.test"},
				Everyday: setupAccount{Username: "b-user", Email: "b-user@example.test"},
				Clients: []setupClient{{ID: "wiki", Name: "Wiki", RedirectURIs: []string{"https://wiki.example.test/cb"},
					SCIM: &setupSCIM{URL: "https://bridge.example.test/scim/v2", TokenFile: token}}}}
			fileB := filepath.Join(data, "installer", b.ID, "setup.json")
			if _, err := stageCommand(t, b, fileB, db, false); err == nil || !strings.Contains(err.Error(), "SCIM token") {
				t.Fatal("stage accepted a setup credential as SCIM token:", err)
			}
			// Ordinary apply with explicit credential files enforces the same boundary.
			b.Admin.PasswordFile = filepath.Join(data, "b-admin.password")
			b.Everyday.PasswordFile = filepath.Join(data, "b-user.password")
			b.Clients[0].SecretFile = filepath.Join(data, "wiki.secret")
			for _, f := range []string{b.Admin.PasswordFile, b.Everyday.PasswordFile, b.Clients[0].SecretFile} {
				if err := os.WriteFile(f, bytes.Repeat([]byte{'p'}, 48), 0600); err != nil {
					t.Fatal(err)
				}
			}
			raw, _ := json.Marshal(b)
			bundle := filepath.Join(data, "bundle-"+name+".json")
			if err := os.WriteFile(bundle, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if err := runSetup([]string{"--file", bundle, "--db", db}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "SCIM token") {
				t.Fatal("apply accepted a setup credential as SCIM token:", err)
			}
		})
	}
	t.Run("own-password", func(t *testing.T) {
		if err := scimTokenAllowed(filepath.Join(data, "pw"), []string{filepath.Join(data, "pw")}); err == nil {
			t.Fatal("bundle credential accepted as SCIM token")
		}
		if err := scimTokenAllowed(filepath.Join(data, "destination.token"), []string{filepath.Join(data, "pw")}); err != nil {
			t.Fatal("destination-issued token refused:", err)
		}
	})
}
