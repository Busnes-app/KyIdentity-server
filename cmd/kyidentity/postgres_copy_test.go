package main

import (
	"bytes"
	"crypto/sha256"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/recoverykey"
	"github.com/Busnes-app/kyidentity-server/internal/config"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// onSQLite makes store.New open SQLite files for the rest of the test, so a Postgres run
// can make the SQLite install a migration or a capsule starts from; it returns the test
// database URL for switching back.
func onSQLite(t *testing.T) string {
	t.Helper()
	pg := os.Getenv("KYIDENTITY_TEST_DATABASE_URL")
	if pg == "" {
		t.Skip("needs KYIDENTITY_TEST_DATABASE_URL")
	}
	t.Setenv("KYIDENTITY_TEST_DATABASE_URL", "")
	return pg
}

func fileHash(t *testing.T, path string) [32]byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(b)
}

// noCredentials fails if the URL's user information (user and password) is in text.
func noCredentials(t *testing.T, rawURL, text string) {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text, u.User.String()+"@") {
		t.Fatalf("the URL's credentials reached the output: %s", text)
	}
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// migrate-to-postgres copies a stopped SQLite install into Postgres, never touching the
// file, and a server opened on the result signs the same administrator in.
func TestMigrateToPostgres(t *testing.T) {
	pgTest := onSQLite(t)
	cfg, _ := commandInstance(t, false)
	lite, err := store.New(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := lite.GetUserByUsername("admin")
	if err != nil || admin == nil {
		t.Fatal(admin, err)
	}
	lite.Close()
	before, beforeDir := fileHash(t, cfg.DBPath), dirNames(t, filepath.Dir(cfg.DBPath))
	t.Setenv("KYIDENTITY_TEST_DATABASE_URL", pgTest)

	var stdout, stderr bytes.Buffer
	if err := migrateToPostgres([]string{"-from", cfg.DBPath}, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "KYIDENTITY_DATABASE_URL") {
		t.Fatalf("without a database URL: %v", err)
	}
	dbURL, err := store.PostgresURLForTest(filepath.Join(t.TempDir(), "pg"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("KYIDENTITY_DATABASE_URL", dbURL)
	logged := captureLog(t, func() {
		if err = migrateToPostgres([]string{"-from", cfg.DBPath}, &stdout, &stderr); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(stdout.String(), "every table's row count matches") || !strings.Contains(stdout.String(), "users") {
		t.Fatalf("output: %s", stdout.String())
	}
	if fileHash(t, cfg.DBPath) != before || strings.Join(dirNames(t, filepath.Dir(cfg.DBPath)), ",") != strings.Join(beforeDir, ",") {
		t.Fatal("the migration changed the source file or its directory")
	}
	noCredentials(t, dbURL, stdout.String()+stderr.String()+logged)

	// The server's own open path on the result: the administrator signs in with the same hash.
	serverCfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	pg, err := openStore(serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	if !pg.Postgres() {
		t.Fatal("openStore did not open Postgres")
	}
	got, err := pg.GetUserByUsername("ADMIN")
	if err != nil || got == nil || got.ID != admin.ID || got.PasswordHash != admin.PasswordHash {
		t.Fatalf("administrator on Postgres: %+v %v", got, err)
	}

	// Once a server has run on it, a second migration is refused.
	if err := migrateToPostgres([]string{"-from", cfg.DBPath}, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("a migration into a used database: %v", err)
	}
}

// Neither a connection failure nor an unparsable URL repeats the password.
func TestMigrateToPostgresNeverPrintsThePassword(t *testing.T) {
	pgTest := onSQLite(t)
	cfg, _ := commandInstance(t, false)
	t.Setenv("KYIDENTITY_TEST_DATABASE_URL", pgTest)
	const secret = "Zq9-unmistakable-pa55word"
	u, err := url.Parse(pgTest)
	if err != nil {
		t.Fatal(err)
	}
	// A missing database fails to connect under any authentication method, trust included.
	u.User = url.UserPassword("postgres", secret)
	u.Path = "/kt_no_such_database"
	for _, bad := range []string{u.String(), "postgres://postgres:" + secret + "@:port/x"} {
		t.Setenv("KYIDENTITY_DATABASE_URL", bad)
		var stdout, stderr bytes.Buffer
		var err error
		logged := captureLog(t, func() { err = migrateToPostgres([]string{"-from", cfg.DBPath}, &stdout, &stderr) })
		if err == nil {
			t.Fatal("a missing database connected")
		}
		if all := err.Error() + stdout.String() + stderr.String() + logged; strings.Contains(all, secret) {
			t.Fatalf("the password reached the output: %s", all)
		}
	}
}

// restore with the database URL set puts the keys in -to and the capsule's database into
// Postgres with the restored state applied, from a capsule made on either backend; a
// database with rows is replaced only with -replace-database.
func TestRestoreIntoPostgres(t *testing.T) {
	for _, origin := range []string{"sqlite", "postgres"} {
		t.Run(origin, func(t *testing.T) {
			pgTest := onSQLite(t)
			if origin == "postgres" {
				t.Setenv("KYIDENTITY_TEST_DATABASE_URL", pgTest)
			}
			cfg, priv := commandInstance(t, true)
			s, err := store.New(cfg.DBPath)
			if err != nil {
				t.Fatal(err)
			}
			admin, err := s.GetUserByUsername("admin")
			if err != nil {
				t.Fatal(err)
			}
			if err := s.CreateSession(&store.Session{ID: "s1", UserID: admin.ID, SessionTokenHash: "from-the-capsule", ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
			if err := s.SetSetting("backup_interval_sec", "3600"); err != nil {
				t.Fatal(err)
			}
			if err := s.CreatePairedSystem(&store.PairedSystem{ID: "hr", Name: "hr", SystemType: "scim", CallbackURL: "https://example.com/scim", Status: "active"}, nil); err != nil {
				t.Fatal(err)
			}
			s.Close()
			capPath := filepath.Join(t.TempDir(), "c.kycap")
			captureLog(t, func() { runExportCapsule(capPath) })
			raw, err := os.ReadFile(capPath)
			if err != nil {
				t.Fatal(err)
			}
			split, err := recoverykey.Split(priv, 2, 3)
			if err != nil {
				t.Fatal(err)
			}
			shares := split[0].String() + "\n" + split[1].String() + "\n"

			t.Setenv("KYIDENTITY_TEST_DATABASE_URL", pgTest)
			dbURL, err := store.PostgresURLForTest(filepath.Join(t.TempDir(), "pg"))
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("KYIDENTITY_DATABASE_URL", dbURL)
			run := func(target string, extra ...string) (string, error) {
				var stdout, stderr bytes.Buffer
				err := restoreCommand(append([]string{"-capsule", capPath, "-to", target, "-expect-digest", sha256Hex(raw)}, extra...), strings.NewReader(shares), &stdout, &stderr, false)
				return stdout.String() + stderr.String(), err
			}
			target := filepath.Join(t.TempDir(), "restored")
			out, err := run(target)
			if err != nil {
				t.Fatal(err, out)
			}
			noCredentials(t, dbURL, out)
			for _, key := range []string{"jwt_rs256.key", "encryption.key", "secret.key"} {
				if _, err := os.Stat(filepath.Join(target, "data", key)); err != nil {
					t.Fatalf("key %s was not restored: %v", key, err)
				}
			}
			for _, gone := range []string{"kyidentity.db", restoreMarkerName} {
				if _, err := os.Stat(filepath.Join(target, "data", gone)); !os.IsNotExist(err) {
					t.Fatalf("%s is left in the restored directory: %v", gone, err)
				}
			}

			pg, err := store.NewPostgres(dbURL)
			if err != nil {
				t.Fatal(err)
			}
			defer pg.Close()
			got, err := pg.GetUserByUsername("Admin")
			if err != nil || got == nil || got.PasswordHash != admin.PasswordHash {
				t.Fatalf("restored administrator: %+v %v", got, err)
			}
			if sess, err := pg.GetSessionByTokenHash("from-the-capsule", time.Hour); err == nil && sess != nil {
				t.Fatal("a login from the capsule survived the restore")
			}
			if v, err := pg.GetSetting("backup_interval_sec"); err != nil || v != "0" {
				t.Fatalf("scheduled deposits after the restore: %q %v", v, err)
			}
			if sys, err := pg.GetPairedSystemByID("hr"); err != nil || sys == nil || !sys.ProvisioningHold {
				t.Fatalf("connector not held: %+v %v", sys, err)
			}
			events, _, err := pg.SearchAuditEvents(store.AuditFilter{Action: "system.restored", Limit: 5})
			if err != nil || len(events) != 1 || !strings.Contains(events[0].DetailsJSON, `"authenticated":true`) || !strings.Contains(events[0].DetailsJSON, "credentialsInvalidated") {
				t.Fatalf("restore audit: %+v %v", events, err)
			}

			// Again, onto the rows the first restore left: refused, then replaced.
			if out, err := run(filepath.Join(t.TempDir(), "again")); err == nil || !strings.Contains(err.Error(), "not empty") {
				t.Fatalf("a restore over rows: %v %s", err, out)
			}
			if out, err := run(filepath.Join(t.TempDir(), "replace"), "-replace-database"); err != nil {
				t.Fatal(err, out)
			}
			events, _, err = pg.SearchAuditEvents(store.AuditFilter{Action: "system.restored", Limit: 5})
			if err != nil || len(events) != 1 {
				t.Fatalf("after a replace the database holds the capsule's rows and one restore: %d %v", len(events), err)
			}
		})
	}
}

// -replace-database means nothing to a restore into SQLite and is refused there.
func TestReplaceDatabaseNeedsPostgres(t *testing.T) {
	t.Setenv("KYIDENTITY_DATABASE_URL", "")
	t.Setenv("KYIDENTITY_DATABASE_URL_FILE", "")
	capPath, digest, shares := restoreCase(t, config.DefaultAppName, "data/kyidentity.db")
	target := filepath.Join(t.TempDir(), "restored")
	err := restoreCommand([]string{"-capsule", capPath, "-to", target, "-expect-digest", digest, "-replace-database"}, strings.NewReader(shares), &bytes.Buffer{}, &bytes.Buffer{}, false)
	if err == nil || !strings.Contains(err.Error(), "only to a restore into Postgres") {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("the refused restore wrote the target:", err)
	}
}
