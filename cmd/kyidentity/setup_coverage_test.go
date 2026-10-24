package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// metadataBundle is a valid bundle whose credential files do not exist, so any error it
// produces comes from metadata validation before a credential is read.
func metadataBundle() setupBundle {
	return setupBundle{Schema: "kyidentity.setup/1", ID: uuid.NewString(),
		Admin:    setupAccount{"owner-admin", "admin@example.test", "/missing"},
		Everyday: setupAccount{"owner", "owner@example.test", "/missing"},
		Groups:   []setupGroup{{Name: "Staff", Members: []string{"owner"}}},
		Clients: []setupClient{{ID: "drive", Name: "Drive", SecretFile: "/missing", RedirectURIs: []string{"https://drive.example.test/callback"},
			AdministratorRole: "admin", EverydayRole: "user", Groups: []string{"Staff"}}}}
}

// Malformed identities, duplicate clients and unsafe redirects are refused by metadata
// validation, before any credential file is opened.
func TestSetupMetadataRefusalsBeforeCredentials(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*setupBundle)
		want   string
	}{
		{"uppercase setup id", func(b *setupBundle) { b.ID = strings.ToUpper(b.ID) }, "setupId must be a canonical UUID"},
		{"extends itself", func(b *setupBundle) { b.Extends = b.ID }, "extends must be another setup's canonical UUID"},
		{"extends non-uuid", func(b *setupBundle) { b.Extends = "parent" }, "extends must be another setup's canonical UUID"},
		{"amendment with accounts", func(b *setupBundle) { b.Extends = uuid.NewString() }, "an amendment declares clients only"},
		{"bad username", func(b *setupBundle) { b.Admin.Username = "../root" }, "invalid setup account name or email"},
		{"display-name email", func(b *setupBundle) { b.Everyday.Email = "Owner <owner@example.test>" }, "invalid setup account name or email"},
		{"too many clients", func(b *setupBundle) {
			for i := 0; i < 33; i++ {
				b.Clients = append(b.Clients, setupClient{ID: fmt.Sprintf("c%d", i)})
			}
		}, "unsupported setup schema or client count"},
		{"duplicate group", func(b *setupBundle) { b.Groups = append(b.Groups, setupGroup{Name: "staff"}) }, "invalid group, duplicate name"},
		{"client repeats a group", func(b *setupBundle) { b.Clients[0].Groups = []string{"Staff", "Staff"} }, "distinct bundle-owned group"},
		{"client names an unknown group", func(b *setupBundle) { b.Clients[0].Groups = []string{"Other"} }, "distinct bundle-owned group"},
		{"management-only client grants groups", func(b *setupBundle) { b.Clients[0].EverydayRole = "" }, "management-only clients"},
		{"scim groups without groups", func(b *setupBundle) {
			b.Clients[0].Groups = nil
			b.Clients[0].SCIM = &setupSCIM{URL: "https://bridge.example.test/scim/v2", TokenFile: "/missing", Groups: true}
		}, "SCIM group delivery requires assigned bundle groups"},
		{"duplicate client id", func(b *setupBundle) {
			c := b.Clients[0]
			c.ID = "DRIVE"
			b.Clients = append(b.Clients, c)
		}, "invalid or duplicate setup client"},
		{"no redirect", func(b *setupBundle) { b.Clients[0].RedirectURIs = nil }, "invalid or duplicate setup client"},
		{"http redirect", func(b *setupBundle) { b.Clients[0].RedirectURIs = []string{"http://drive.example.test/callback"} }, "setup redirects require HTTPS"},
		{"logout fragment", func(b *setupBundle) { b.Clients[0].PostLogoutURIs = []string{"https://drive.example.test/#x"} }, "setup redirects require HTTPS"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := metadataBundle()
			c.mutate(&b)
			if _, err := prepareSetup(mustSetupJSON(t, b)); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
	// The base bundle passes metadata validation and fails only on its missing credentials.
	if _, err := prepareSetup(mustSetupJSON(t, metadataBundle())); err == nil || !strings.Contains(err.Error(), "protected setup") {
		t.Fatalf("valid metadata: %v", err)
	}
}

// credentialFixture writes a complete set of protected credential files and returns a
// bundle using them, with a SCIM connector, an encryption key and a mail relay.
func credentialFixture(t *testing.T) (setupBundle, string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("KYIDENTITY_DATA_DIR", dir)
	t.Setenv("KYIDENTITY_ENCRYPTION_KEY", "")
	t.Setenv("KYIDENTITY_DB_PATH", "")
	for name, value := range map[string]string{"admin": "administrator-secret-123", "everyday": "everyday-secret-456", "oidc": strings.Repeat("q", 48),
		"scim": strings.Repeat("s", 48), "smtp": "relay-password", "encryption.key": strings.Repeat("k", 32)} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	b := setupBundle{Schema: "kyidentity.setup/1", ID: uuid.NewString(),
		Admin:    setupAccount{"owner-admin", "admin@example.test", filepath.Join(dir, "admin")},
		Everyday: setupAccount{"owner", "owner@example.test", filepath.Join(dir, "everyday")},
		Clients: []setupClient{{ID: "drive", Name: "Drive", SecretFile: filepath.Join(dir, "oidc"), RedirectURIs: []string{"https://drive.example.test/callback"},
			SCIM: &setupSCIM{URL: "https://bridge.example.test/scim/v2", TokenFile: filepath.Join(dir, "scim")}}},
		Mail: &setupMail{Host: "smtp.example.test", Port: 587, Security: "starttls", From: "id@example.test", Username: "relay", PasswordFile: filepath.Join(dir, "smtp")}}
	return b, dir
}

// Every credential is read and checked before anything is applied: a weak or malformed
// password, secret or token, or a missing deployment key, refuses the whole bundle.
func TestPrepareSetupRefusesUnusableCredentials(t *testing.T) {
	b, _ := credentialFixture(t)
	if p, err := prepareSetup(mustSetupJSON(t, b)); err != nil || p.Mail == nil || p.Clients[0].SCIM == nil || len(p.EncryptionKey) != 32 {
		t.Fatalf("valid fixture: %+v %v", p, err)
	}
	cases := []struct {
		name  string
		file  string
		value string
		want  string
	}{
		{"password with carriage return", "admin", "administrator\rsecret-123", "invalid password file"},
		{"short password", "everyday", "short", "password must contain 12 to 1024 bytes"},
		{"short client secret", "oidc", "too-short", "client secret requires at least 32 bytes"},
		{"scim token with space", "scim", strings.Repeat("s", 40) + " x", "SCIM token requires 32 to 8192"},
		{"empty relay password", "smtp", "\n", "mail password requires 1 to 1024 bytes"},
		{"short encryption key", "encryption.key", "short", "existing protected encryption key is unavailable"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, dir := credentialFixture(t)
			if err := os.WriteFile(filepath.Join(dir, c.file), []byte(c.value), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := prepareSetup(mustSetupJSON(t, b)); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
	for _, missing := range []string{"oidc", "scim", "smtp"} {
		t.Run("missing "+missing, func(t *testing.T) {
			b, dir := credentialFixture(t)
			if err := os.Remove(filepath.Join(dir, missing)); err != nil {
				t.Fatal(err)
			}
			if _, err := prepareSetup(mustSetupJSON(t, b)); err == nil || !strings.Contains(err.Error(), "cannot open protected setup file") {
				t.Fatalf("missing %s: %v", missing, err)
			}
		})
	}
	// Without a relay, the SCIM connector and then a suite webhook still need the
	// existing key, and neither may cause one to be generated.
	for _, connector := range []string{"scim", "webhook"} {
		t.Run("no key for "+connector, func(t *testing.T) {
			b, dir := credentialFixture(t)
			b.Mail = nil
			if connector == "webhook" {
				b.Clients[0].SCIM = nil
				b.Clients[0].SuiteWebhook = &setupSuiteWebhook{URL: "https://notes.example.test/sync", SigningSecretFile: filepath.Join(dir, "scim")}
			}
			if err := os.Remove(filepath.Join(dir, "encryption.key")); err != nil {
				t.Fatal(err)
			}
			if _, err := prepareSetup(mustSetupJSON(t, b)); err == nil || !strings.Contains(err.Error(), "encryption key") {
				t.Fatalf("connector without key: %v", err)
			}
			if _, err := os.Stat(filepath.Join(dir, "encryption.key")); !os.IsNotExist(err) {
				t.Fatal("setup generated an encryption key:", err)
			}
		})
	}
	// A path that is absolute but not clean is refused before it is opened.
	if _, err := readSetupFile(b.Admin.PasswordFile+"/../admin", 64); err == nil || !strings.Contains(err.Error(), "clean absolute") {
		t.Fatalf("unclean path: %v", err)
	}
}

// With KYIDENTITY_DATA_DIR unset the key is read from ./data, as the product does.
func TestExistingSetupEncryptionKeyDefaultsToDataDirectory(t *testing.T) {
	t.Setenv("KYIDENTITY_ENCRYPTION_KEY", "")
	t.Setenv("KYIDENTITY_DATA_DIR", "")
	cwd := t.TempDir()
	t.Chdir(cwd)
	if err := os.Mkdir("data", 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := existingSetupEncryptionKey(); err == nil {
		t.Fatal("a missing ./data key was accepted")
	}
	want := bytes.Repeat([]byte{'z'}, 32)
	if err := os.WriteFile(filepath.Join("data", "encryption.key"), want, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := existingSetupEncryptionKey(); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("key = %q, %v", got, err)
	}
	if got := setupDatabasePath(""); got != filepath.Join("data", "kyidentity.db") {
		t.Fatalf("default database path = %q", got)
	}
}

// apply-setup refuses stray arguments, unreadable input and anything that is not an
// initialized database, and prints nothing when it refuses.
func TestRunSetupInputRefusals(t *testing.T) {
	b, dir := credentialFixture(t)
	file := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(file, mustSetupJSON(t, b), 0600); err != nil {
		t.Fatal(err)
	}
	notDB := filepath.Join(dir, "not.db")
	if err := os.WriteFile(notDB, []byte("this is not sqlite, it is long enough to be read as a header"), 0600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		args     []string
		failRead bool
		want     string
	}{
		{"positional argument", []string{"--file", file, "extra"}, false, "invalid apply-setup arguments"},
		{"capabilities with file", []string{"--capabilities", "--file", file}, false, "capabilities cannot be combined"},
		{"unreadable stage input", []string{"--stage", "--file", file}, true, "cannot read bounded preparation metadata"},
		{"missing bundle", []string{"--file", filepath.Join(dir, "absent.json")}, false, "cannot open protected setup file"},
		{"missing database", []string{"--file", file, "--db", filepath.Join(dir, "absent.db")}, false, "requires an initialized KyIdentity database"},
		{"database is a directory", []string{"--file", file, "--db", dir}, false, "requires an initialized KyIdentity database"},
		{"not a database", []string{"--file", file, "--db", notDB}, false, "setup refused"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			var err error
			if c.failRead {
				err = runSetupInput(c.args, iotest.ErrReader(os.ErrClosed), &out)
			} else {
				err = runSetupInput(c.args, strings.NewReader(""), &out)
			}
			if err == nil || !strings.Contains(err.Error(), c.want) || out.Len() != 0 {
				t.Fatalf("err = %v (output %q), want %q", err, out.String(), c.want)
			}
		})
	}
}

// stageSetup refuses metadata that would put generated credentials anywhere but the
// setup-owned directory, and destination credentials that are unusable, before writing.
func TestStageSetupRefusalsBeforeWrites(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(b *setupBundle, file *string, data string)
		want   string
	}{
		{"uppercase setup id", func(b *setupBundle, _ *string, _ string) { b.ID = strings.ToUpper(b.ID) }, "setupId must be a canonical UUID"},
		{"foreign file", func(_ *setupBundle, file *string, data string) { *file = filepath.Join(data, "setup.json") }, "product-owned setup UUID directory"},
		{"bad client id", func(b *setupBundle, _ *string, _ string) { b.Clients[0].ID = "../notes" }, "invalid preparation client identifier"},
		{"client secret elsewhere", func(b *setupBundle, _ *string, data string) { b.Clients[0].SecretFile = filepath.Join(data, "secret") }, "generated credential paths must match"},
		{"webhook secret elsewhere", func(b *setupBundle, _ *string, data string) {
			b.Clients[0].SuiteWebhook.SigningSecretFile = filepath.Join(data, "webhook")
		}, "generated credential paths must match"},
		{"wrong schema", func(b *setupBundle, _ *string, _ string) { b.Schema = "kyidentity.setup/2" }, "unsupported setup schema"},
		{"short scim token", func(b *setupBundle, _ *string, data string) {
			token := filepath.Join(data, "scim-token")
			if err := os.WriteFile(token, []byte("short"), 0600); err != nil {
				t.Fatal(err)
			}
			b.Clients[0].SuiteWebhook = nil
			b.Clients[0].SCIM = &setupSCIM{URL: "https://bridge.example.test/scim/v2", TokenFile: token}
		}, "invalid destination-issued SCIM token"},
		{"relay password is the product key", func(b *setupBundle, _ *string, data string) {
			b.Mail = &setupMail{Host: "smtp.example.test", Port: 587, Security: "starttls", From: "id@example.test", Username: "relay", PasswordFile: filepath.Join(data, "encryption.key")}
		}, "mail password must be a destination-issued protected file"},
		{"relay password missing", func(b *setupBundle, _ *string, data string) {
			b.Mail = &setupMail{Host: "smtp.example.test", Port: 587, Security: "starttls", From: "id@example.test", Username: "relay", PasswordFile: filepath.Join(data, "absent")}
		}, "destination-issued mail password is unavailable"},
		{"shared data directory", func(b *setupBundle, _ *string, data string) {
			// No connector, so the refusal comes from the directory check, not the key read.
			b.Clients[0].SuiteWebhook = nil
			if err := os.Chmod(data, 0777); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(data, 0700) })
		}, "owned protected product data directory"},
		{"amendment without applied parent", func(b *setupBundle, _ *string, _ string) {
			b.Extends, b.Admin, b.Everyday = uuid.NewString(), setupAccount{}, setupAccount{}
		}, "amendment requires its applied parent setup"},
		{"shared installer directory", func(_ *setupBundle, _ *string, data string) {
			if err := os.Mkdir(filepath.Join(data, "installer"), 0755); err != nil {
				t.Fatal(err)
			}
		}, "preparation directory is missing, shared or unsafe"},
		{"crowded preparation directory", func(b *setupBundle, file *string, _ string) {
			scope := filepath.Dir(*file)
			if err := os.MkdirAll(scope, 0700); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 16; i++ {
				if err := os.WriteFile(filepath.Join(scope, fmt.Sprintf(".keyfile-%d.tmp", i)), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
		}, "unclaimed preparation directory is not empty"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, file, db := stageFixture(t)
			data := os.Getenv("KYIDENTITY_DATA_DIR")
			c.mutate(&b, &file, data)
			raw, err := json.Marshal(b)
			if err != nil {
				t.Fatal(err)
			}
			status, err := stageSetup(file, db, raw, false)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("status %q err = %v, want %q", status, err, c.want)
			}
			if _, err := os.Stat(file); !os.IsNotExist(err) {
				t.Fatal("a refused preparation published its bundle")
			}
		})
	}
}

// Preparation never creates a database: a missing or unreadable one is refused before
// any directory or credential is created.
func TestStageSetupRequiresAnInitializedDatabase(t *testing.T) {
	b, file, _ := stageFixture(t)
	data := os.Getenv("KYIDENTITY_DATA_DIR")
	raw := mustSetupJSON(t, b)
	missing := filepath.Join(data, "absent.db")
	if _, err := stageSetup(file, missing, raw, false); err == nil || !strings.Contains(err.Error(), "cannot inspect native setup ownership") {
		t.Fatalf("missing database: %v", err)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("preparation created a database:", err)
	}
	if _, err := os.Stat(filepath.Join(data, "installer")); !os.IsNotExist(err) {
		t.Fatal("preparation created its directory against a missing database:", err)
	}
}

// The default database is $KYIDENTITY_DB_PATH, then data/kyidentity.db, falling back to a
// legacy kysignon.db only when the current one is absent.
func TestSetupDatabasePathResolution(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KYIDENTITY_DATA_DIR", dir)
	t.Setenv("KYIDENTITY_DB_PATH", "/explicit/identity.db")
	if got := setupDatabasePath(""); got != "/explicit/identity.db" {
		t.Fatalf("KYIDENTITY_DB_PATH ignored: %q", got)
	}
	if got := setupDatabasePath("/flag.db"); got != "/flag.db" {
		t.Fatalf("--db ignored: %q", got)
	}
	t.Setenv("KYIDENTITY_DB_PATH", "")
	if got := setupDatabasePath(""); got != filepath.Join(dir, "kyidentity.db") {
		t.Fatalf("fresh default: %q", got)
	}
	legacy := filepath.Join(dir, "kysignon.db")
	if err := os.WriteFile(legacy, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if got := setupDatabasePath(""); got != legacy {
		t.Fatalf("legacy database not reused: %q", got)
	}
	s, err := store.New(filepath.Join(dir, "kyidentity.db"))
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if got := setupDatabasePath(""); got != filepath.Join(dir, "kyidentity.db") {
		t.Fatalf("current database not preferred over legacy: %q", got)
	}
}
