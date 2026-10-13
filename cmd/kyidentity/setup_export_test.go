package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"os"
	"testing"

	"github.com/Busnes-app/kyidentity-server/internal/store"
)

func TestSetupClientExportScopeAndReadOnly(t *testing.T) {
	b, file, db := stageFixture(t)
	t.Setenv("KYIDENTITY_ISSUER_URL", "https://identity.example.test/")
	b.Clients[0].AdministratorRole = "kynotes.admin"
	b.Clients[0].EverydayRole = "kynotes.user"
	b.Clients = append(b.Clients, setupClient{ID: "drive", Name: "KyDrive", RedirectURIs: []string{"https://drive.example.test/callback"}})
	if _, err := stageCommand(t, b, file, db, false); err != nil {
		t.Fatal(err)
	}
	args := []string{"--file", file, "--db", db, "--export-client", "notes"}
	var out bytes.Buffer
	if err := runSetup(args, &out); err == nil || out.Len() != 0 {
		t.Fatal("export accepted unapplied preparation")
	}
	if err := runSetup([]string{"--file", file, "--db", db}, &out); err != nil {
		t.Fatal(err)
	}
	raw, err := readSetupFile(file, setupBundleLimit)
	if err != nil {
		t.Fatal(err)
	}
	var prepared setupBundle
	if err := json.Unmarshal(raw, &prepared); err != nil {
		t.Fatal(err)
	}
	s, err := store.OpenInstallerStore(db, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	before, count, err := s.ListAuditEvents(100, 0)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := s.GetUserByUsername(b.Admin.Username)
	if err != nil {
		t.Fatal(err)
	}
	var retained []byte
	for i := 0; i < 2; i++ {
		out.Reset()
		if err := runSetup(args, &out); err != nil {
			t.Fatal(err)
		}
		var frame clientCredentials
		if err := json.Unmarshal(out.Bytes(), &frame); err != nil {
			t.Fatal("invalid private frame")
		}
		client, _ := readSetupFile(prepared.Clients[0].SecretFile, 43)
		directory, _ := readSetupFile(prepared.Clients[0].SuiteWebhook.SigningSecretFile, 43)
		if frame.Schema != "kyidentity.client-credentials/1" || frame.SetupID != b.ID || frame.IssuerURL != "https://identity.example.test" || frame.ClientID != "notes" || frame.ClientSecret != string(client) || frame.DirectorySecret != string(directory) || frame.DirectoryURL != b.Clients[0].SuiteWebhook.URL || len(frame.RedirectURIs) != 1 || frame.RedirectURIs[0] != b.Clients[0].RedirectURIs[0] || frame.Administrator.Subject != owner.ID || frame.Administrator.Username != owner.Username || frame.Administrator.Role != "kynotes.admin" {
			t.Fatal("export did not bind exact owned client credentials and administrator")
		}
		for _, forbidden := range []string{prepared.Admin.PasswordFile, prepared.Everyday.PasswordFile, prepared.Clients[1].SecretFile} {
			secret, err := readSetupFile(forbidden, 43)
			if err != nil || bytes.Contains(out.Bytes(), secret) || bytes.Contains(out.Bytes(), []byte(forbidden)) {
				t.Fatal("export disclosed unselected credential or protected file path")
			}
		}
		if i == 1 && !bytes.Equal(retained, out.Bytes()) {
			t.Fatal("export changed credentials on resume")
		}
		retained = append([]byte(nil), out.Bytes()...)
	}
	after, afterCount, err := s.ListAuditEvents(100, 0)
	beforeJSON, _ := json.Marshal(before)
	afterJSON, _ := json.Marshal(after)
	if err != nil || count != afterCount || !bytes.Equal(beforeJSON, afterJSON) {
		t.Fatal("read-only export changed native audits")
	}
	for _, extra := range [][]string{{"--stage"}, {"--check"}, {"--capabilities"}} {
		out.Reset()
		if err := runSetup(append(append([]string(nil), args...), extra...), &out); err == nil || out.Len() != 0 {
			t.Fatal("combined export mode accepted")
		}
	}
	for _, client := range []string{"other", "Notes", "../notes", "notes\n"} {
		out.Reset()
		if err := runSetup([]string{"--file", file, "--db", db, "--export-client", client}, &out); err == nil || out.Len() != 0 {
			t.Fatal("export accepted foreign or invalid client")
		}
	}
	for _, issuer := range []string{"", "http://identity.example.test", "https://user@identity.example.test", "https://identity.example.test?", "https://identity.example.test#"} {
		t.Setenv("KYIDENTITY_ISSUER_URL", issuer)
		out.Reset()
		if err := runSetup(args, &out); err == nil || out.Len() != 0 {
			t.Fatal("export accepted unsafe issuer")
		}
	}
	t.Setenv("KYIDENTITY_ISSUER_URL", "https://identity.example.test")
	password, _ := readSetupFile(prepared.Admin.PasswordFile, 43)
	if err := os.Remove(prepared.Admin.PasswordFile); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runSetup(args, &out); err == nil || out.Len() != 0 {
		t.Fatal("export accepted missing preparation credential")
	}
	if err := os.WriteFile(prepared.Admin.PasswordFile, password, 0600); err != nil {
		t.Fatal(err)
	}
	writable, err := sql.Open("sqlite", db)
	if err != nil {
		t.Fatal(err)
	}
	defer writable.Close()
	if _, err := writable.Exec("UPDATE oauth_clients SET client_secret_hash='changed' WHERE id='notes'"); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runSetup(args, &out); err == nil || out.Len() != 0 {
		t.Fatal("export accepted native credential drift")
	}
}
