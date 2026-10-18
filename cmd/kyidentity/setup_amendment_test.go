package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// amendmentFixture applies a prepared parent and returns an amendment adding one client.
func amendmentFixture(t *testing.T) (parent, amendment setupBundle, parentFile, file, db string) {
	t.Helper()
	parent, parentFile, db = stageFixture(t)
	t.Setenv("KYIDENTITY_ISSUER_URL", "https://identity.example.test")
	if _, err := stageCommand(t, parent, parentFile, db, false); err != nil {
		t.Fatal(err)
	}
	if err := runSetup([]string{"--file", parentFile, "--db", db}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	amendment = setupBundle{Schema: "kyidentity.setup/1", ID: uuid.NewString(), Extends: parent.ID, Clients: []setupClient{{ID: "recovery", Name: "KyRecovery",
		RedirectURIs: []string{"https://recovery.example.test/callback"}, AdministratorRole: "admin", SuiteWebhook: &setupSuiteWebhook{URL: "https://recovery.example.test/sync"}}}}
	file = filepath.Join(os.Getenv("KYIDENTITY_DATA_DIR"), "installer", amendment.ID, "setup.json")
	return
}

func exportFrame(t *testing.T, file, db, client string) (clientCredentials, error) {
	t.Helper()
	var out bytes.Buffer
	err := runSetup([]string{"--file", file, "--db", db, "--export-client", client}, &out)
	var frame clientCredentials
	if err == nil && json.Unmarshal(out.Bytes(), &frame) != nil {
		t.Fatal("invalid private frame")
	}
	if err != nil && out.Len() != 0 {
		t.Fatal("refused export wrote output")
	}
	return frame, err
}

func TestSetupAmendmentAddsClientAndScopesExport(t *testing.T) {
	parent, a, parentFile, file, db := amendmentFixture(t)
	if _, err := stageCommand(t, a, file, db, false); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Dir(file))
	names := []string{}
	for _, e := range entries {
		names = append(names, e.Name())
		info, _ := e.Info()
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode %v", e.Name(), info.Mode())
		}
	}
	if strings.Join(names, ",") != "client-recovery.secret,client-recovery.webhook,credentials.json,intent.json,setup.json" {
		t.Fatalf("amendment preparation files %v", names)
	}
	if raw, _ := os.ReadFile(file); bytes.Contains(raw, []byte(`"admin":`)) || bytes.Contains(raw, []byte(`"everyday":`)) || !bytes.Contains(raw, []byte(`"extends":"`+parent.ID+`"`)) {
		t.Fatalf("amendment bundle %s", raw)
	}
	if _, err := exportFrame(t, file, db, "recovery"); err == nil {
		t.Fatal("export accepted an unapplied amendment")
	}
	var report bytes.Buffer
	if err := runSetup([]string{"--file", file, "--db", db}, &report); err != nil {
		t.Fatal(err)
	}
	var r store.InstallerReport
	if json.Unmarshal(report.Bytes(), &r) != nil || len(r.Created) != 3 || r.Created[0].Kind != "role" || r.Created[1].Kind != "connector" || r.Created[2].Kind != "client" {
		t.Fatalf("amendment report %s", report.Bytes())
	}
	s, err := store.OpenInstallerStore(db, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, audits, _ := s.ListAuditEvents(1, 0)
	owner, _ := s.GetUserByUsername(parent.Admin.Username)
	frame, err := exportFrame(t, file, db, "recovery")
	secret, _ := readSetupFile(filepath.Join(filepath.Dir(file), "client-recovery.secret"), 43)
	if err != nil || frame.SetupID != a.ID || frame.ClientID != "recovery" || frame.ClientSecret != string(secret) || frame.DirectoryURL != a.Clients[0].SuiteWebhook.URL ||
		frame.Administrator.Subject != owner.ID || frame.Administrator.Username != parent.Admin.Username || frame.Administrator.Role != "admin" {
		t.Fatalf("amendment export %+v %v", frame, err)
	}
	// Each prepared path exports only its own clients.
	if _, err := exportFrame(t, file, db, "notes"); err == nil {
		t.Fatal("amendment exported its parent's client")
	}
	if _, err := exportFrame(t, parentFile, db, "recovery"); err == nil {
		t.Fatal("parent exported the amendment's client")
	}
	if _, err := exportFrame(t, parentFile, db, "notes"); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"--file", file}, {"--file", file, "--check"}, {"--file", parentFile, "--check"}, {"--file", parentFile}} {
		report.Reset()
		if err := runSetup(append(args, "--db", db), &report); err != nil || json.Unmarshal(report.Bytes(), &r) != nil || len(r.Created) != 0 {
			t.Fatalf("rerun %v: %s %v", args, report.Bytes(), err)
		}
	}
	if _, after, _ := s.ListAuditEvents(1, 0); after != audits {
		t.Fatal("rerun or export wrote audits")
	}
	for _, check := range []bool{true, false} {
		if status, err := stageCommand(t, a, file, db, check); err != nil || !strings.Contains(status, `"present"`) {
			t.Fatal("amendment preparation resume", err)
		}
	}
	a.Clients[0].Name = "Changed"
	if _, err := stageCommand(t, a, file, db, false); err == nil {
		t.Fatal("changed amendment intent accepted")
	}
}

func TestSetupAmendmentRefusals(t *testing.T) {
	for _, kind := range []string{"missing-parent", "account-block", "groups-block", "admin-disabled", "admin-renamed", "parent-client", "foreign-client"} {
		t.Run(kind, func(t *testing.T) {
			parent, a, _, file, db := amendmentFixture(t)
			exec := func(q string) {
				w, err := sql.Open("sqlite", db)
				if err != nil {
					t.Fatal(err)
				}
				defer w.Close()
				if _, err := w.Exec(q); err != nil {
					t.Fatal(err)
				}
			}
			staged := true
			switch kind {
			case "missing-parent":
				a.Extends, staged = uuid.NewString(), false
			case "account-block":
				a.Admin, staged = setupAccount{Username: "intruder", Email: "intruder@example.test"}, false
			case "groups-block":
				a.Groups, staged = []setupGroup{{Name: "Suite users", Members: []string{}}}, false
			case "admin-disabled":
				exec(`UPDATE users SET status='disabled' WHERE username='` + parent.Admin.Username + `'`)
			case "admin-renamed":
				exec(`UPDATE users SET username='renamed' WHERE username='` + parent.Admin.Username + `'`)
			case "parent-client":
				a.Clients[0].ID = parent.Clients[0].ID
			case "foreign-client":
				exec(`INSERT INTO oauth_clients(id,client_name,client_type,client_secret_hash,redirect_uris_json,allowed_scopes_json,enabled,created_at,post_logout_redirect_uris_json) VALUES('recovery','Foreign','confidential','x','[]','["openid"]',1,CURRENT_TIMESTAMP,'[]')`)
			}
			_, err := stageCommand(t, a, file, db, false)
			if !staged {
				if err == nil {
					t.Fatal("amendment preparation accepted")
				}
				if _, err := os.Stat(filepath.Dir(file)); !os.IsNotExist(err) {
					t.Fatal("refused amendment created a preparation directory")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			for _, args := range [][]string{{"--check"}, {}} {
				if err := runSetup(append([]string{"--file", file, "--db", db}, args...), &out); err == nil || out.Len() != 0 {
					t.Fatalf("amendment %v accepted", args)
				}
			}
			r, err := sql.Open("sqlite", db)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			var owned, foreign, clients int
			if err := r.QueryRow(`SELECT (SELECT count(*) FROM installer_setup_resources WHERE setup_id=? AND kind<>'preparation'), (SELECT count(*) FROM oauth_clients WHERE client_name='Foreign'), (SELECT count(*) FROM oauth_clients)`, a.ID).Scan(&owned, &foreign, &clients); err != nil {
				t.Fatal(err)
			}
			if owned != 0 || clients != 1+foreign {
				t.Fatalf("refused amendment left %d owned rows and %d clients", owned, clients)
			}
		})
	}
}

// Retained intent is compared byte for byte, so a base bundle must encode as before amendments.
func TestSetupBaseBundleEncodingUnchanged(t *testing.T) {
	b := setupBundle{Schema: "kyidentity.setup/1", ID: "271333e2-c221-4601-b249-563b3d828530", Admin: setupAccount{"a", "a@x.test", "/p/a"}, Everyday: setupAccount{"e", "e@x.test", "/p/e"}, Clients: []setupClient{{ID: "c", Name: "C", SecretFile: "/p/c", RedirectURIs: []string{"https://c.test/cb"}}}}
	raw, _ := json.Marshal(b)
	want := `{"schema":"kyidentity.setup/1","setupId":"271333e2-c221-4601-b249-563b3d828530","admin":{"username":"a","email":"a@x.test","passwordFile":"/p/a"},"everyday":{"username":"e","email":"e@x.test","passwordFile":"/p/e"},"clients":[{"id":"c","name":"C","secretFile":"/p/c","redirectUris":["https://c.test/cb"],"postLogoutUris":null}]}`
	if string(raw) != want {
		t.Fatalf("base bundle encoding changed:\n%s", raw)
	}
}
