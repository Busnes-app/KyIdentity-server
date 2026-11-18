package main

import (
	"bytes"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Busnes-app/ky-primitives/recoverykey"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// stoppedInstall is a SQLite install whose server has stopped, at <work>/data/kyidentity.db.
func stoppedInstall(t *testing.T) (work, db string) {
	t.Helper()
	cfg, _ := commandInstance(t, false)
	work = t.TempDir()
	db = filepath.Join(work, "data", "kyidentity.db")
	if err := os.MkdirAll(filepath.Dir(db), 0o700); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(db, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return work, db
}

// migrate-to-postgres reads the same file whichever way -from names it, and a relative
// KYIDENTITY_DATABASE_URL_FILE; it never writes beside the file and refuses a second run.
func TestMigrateToPostgresResolvesItsPaths(t *testing.T) {
	pgTest := onSQLite(t)
	work, db := stoppedInstall(t)
	if err := os.MkdirAll(filepath.Join(work, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(work, "elsewhere"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KYIDENTITY_TEST_DATABASE_URL", pgTest)
	for _, c := range []struct{ name, cwd, from string }{
		{"relative", work, "data/kyidentity.db"},
		{"dot-dot from another directory", filepath.Join(work, "elsewhere"), "../x/../data/kyidentity.db"},
		{"absolute", t.TempDir(), db},
	} {
		t.Run(c.name, func(t *testing.T) {
			url, err := store.PostgresURLForTest(filepath.Join(t.TempDir(), "pg"))
			if err != nil {
				t.Fatal(err)
			}
			t.Chdir(c.cwd)
			if c.name == "relative" {
				if err := os.WriteFile("database-url", []byte(url), 0o600); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Remove(filepath.Join(c.cwd, "database-url")) })
				t.Setenv("KYIDENTITY_DATABASE_URL", "")
				t.Setenv("KYIDENTITY_DATABASE_URL_FILE", "database-url")
			} else {
				t.Setenv("KYIDENTITY_DATABASE_URL_FILE", "")
				t.Setenv("KYIDENTITY_DATABASE_URL", url)
			}
			sum, files := fileHash(t, db), dirNames(t, filepath.Dir(db))
			var stdout, stderr bytes.Buffer
			if err := migrateToPostgres([]string{"-from", c.from}, &stdout, &stderr); err != nil {
				t.Fatal(err, stderr.String())
			}
			if fileHash(t, db) != sum || !slices.Equal(dirNames(t, filepath.Dir(db)), files) {
				t.Fatal("the migration changed the source or created files beside it")
			}
			counts, err := store.PostgresRowCounts(url)
			if err != nil {
				t.Fatal(err)
			}
			if err := migrateToPostgres([]string{"-from", c.from}, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "not empty") {
				t.Fatalf("a second migration into the populated database: %v", err)
			}
			if again, err := store.PostgresRowCounts(url); err != nil || !maps.Equal(again, counts) {
				t.Fatalf("the refused migration changed the counts: %v", err)
			}
			if fileHash(t, db) != sum || !slices.Equal(dirNames(t, filepath.Dir(db)), files) {
				t.Fatal("the refused migration changed the source or created files beside it")
			}
		})
	}
}

// restore -to a relative directory into PostgreSQL works from wherever it is run, leaves the
// capsule unchanged and leaves no SQLite log behind.
func TestRestoreIntoPostgresTakesARelativeTarget(t *testing.T) {
	pgTest := onSQLite(t)
	_, priv := commandInstance(t, true)
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
	t.Setenv("KYIDENTITY_TEST_DATABASE_URL", pgTest)
	url, err := store.PostgresURLForTest(filepath.Join(t.TempDir(), "pg"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("KYIDENTITY_DATABASE_URL", url)
	work := t.TempDir()
	t.Chdir(work)
	sum := fileHash(t, capPath)
	var stdout, stderr bytes.Buffer
	shares := split[0].String() + "\n" + split[1].String() + "\n"
	if err := restoreCommand([]string{"-capsule", capPath, "-to", "restored", "-expect-digest", sha256Hex(raw)}, strings.NewReader(shares), &stdout, &stderr, false); err != nil {
		t.Fatal(err, stdout.String(), stderr.String())
	}
	if fileHash(t, capPath) != sum {
		t.Fatal("the restore changed the capsule")
	}
	for _, name := range dirNames(t, filepath.Join(work, "restored", "data")) {
		if strings.HasPrefix(name, "kyidentity.db") {
			t.Fatalf("the restore left %s in the target", name)
		}
	}
	if _, err := os.Stat(filepath.Join(work, "restored", "data", "jwt_rs256.key")); err != nil {
		t.Fatal("the keys were not restored into the relative target:", err)
	}
	if counts, err := store.PostgresRowCounts(url); err != nil || counts["users"] == 0 {
		t.Fatalf("the restored database: %v %v", counts, err)
	}
}
