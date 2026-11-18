package store

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/config"
)

// A restore keeps the record of device assertions already spent: an assertion spent before
// the capsule was taken must still be refused within its lifetime. Only expired rows go,
// as does the replica fingerprint; every other cleared table is still emptied.
func TestRestoreKeepsUnexpiredReplayHistory(t *testing.T) {
	s, cleanup := restoreFixture(t)
	defer cleanup()
	now := time.Now().UTC()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO device_signon_jtis(jti,expires_at) VALUES('spent',?)`, []any{now.Add(4 * time.Minute)}},
		{`INSERT INTO device_signon_jtis(jti,expires_at) VALUES('old',?)`, []any{now.Add(-time.Minute)}},
		{`INSERT INTO system_settings(key,value,updated_at) VALUES(?,'{}',CURRENT_TIMESTAMP)`, []any{config.ReplicaConfigSetting}},
	} {
		if _, err := s.db.Exec(q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.ApplyRestoredState(now, nil); err != nil {
		t.Fatal(err)
	}
	for _, table := range restoredCleared {
		if n := countRows(t, s, `SELECT COUNT(*) FROM `+table); n != 0 {
			t.Errorf("%s survived the restore with %d row(s)", table, n)
		}
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM device_signon_jtis WHERE jti='old'`); n != 0 {
		t.Error("an expired replay record survived the restore")
	}
	if ok, err := s.ConsumeDeviceSignOnJTI("spent", now.Add(4*time.Minute)); err != nil || ok {
		t.Fatalf("an assertion spent before the restore was accepted again: %v %v", ok, err)
	}
	if _, err := s.GetSetting(config.ReplicaConfigSetting); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the replica fingerprint survived the restore: %v", err)
	}
}

// The PostgreSQL restore (ImportSQLite with Replace and Restored) keeps the same history.
func TestPostgresRestoreKeepsUnexpiredReplayHistory(t *testing.T) {
	requirePostgres(t)
	dir := t.TempDir()
	src := liteFixture(t, filepath.Join(dir, "capsule.db"))
	now := time.Now().UTC()
	db, err := sql.Open("sqlite", src)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO device_signon_jtis(jti,expires_at) VALUES('spent',?)`, []any{now.Add(4 * time.Minute)}},
		{`INSERT INTO device_signon_jtis(jti,expires_at) VALUES('old',?)`, []any{now.Add(-time.Minute)}},
		{`INSERT OR REPLACE INTO system_settings(key,value,updated_at) VALUES(?,'{}',CURRENT_TIMESTAMP)`, []any{config.ReplicaConfigSetting}},
	} {
		if _, err := db.Exec(q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	url := testURL(t, filepath.Join(dir, "pg"))
	if _, err := ImportSQLite(url, src, ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	event := &AuditEvent{ID: "restored", Action: "system.restored", Outcome: "success", CreatedAt: now}
	if _, err := ImportSQLite(url, src, ImportOptions{Replace: true, Restored: event}); err != nil {
		t.Fatal(err)
	}
	pg := testPostgres(t, filepath.Join(dir, "pg"))
	for _, table := range restoredCleared {
		if n := countRows(t, pg, `SELECT COUNT(*) FROM `+table); n != 0 {
			t.Errorf("%s survived the restore with %d row(s)", table, n)
		}
	}
	if n := countRows(t, pg, `SELECT COUNT(*) FROM device_signon_jtis WHERE jti='old'`); n != 0 {
		t.Error("an expired replay record survived the restore")
	}
	if ok, err := pg.ConsumeDeviceSignOnJTI("spent", now.Add(4*time.Minute)); err != nil || ok {
		t.Fatalf("an assertion spent before the restore was accepted again: %v %v", ok, err)
	}
	if _, err := pg.GetSetting(config.ReplicaConfigSetting); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the replica fingerprint survived the restore: %v", err)
	}
}

// Every identity column, read from the catalog, continues past the largest value imported,
// after an import and after a restore that replaces the rows. A table with an identity and
// no fixture row proves nothing, so it fails the test: copyFixture must give it a row.
func TestEveryIdentityContinuesPastImportedRows(t *testing.T) {
	requirePostgres(t)
	dir := t.TempDir()
	src := liteFixture(t, filepath.Join(dir, "src.db"))
	// immutable: an open reader must not leave a log beside the file the import reads.
	lite, err := sql.Open("sqlite", "file:"+src+"?mode=ro&immutable=1")
	if err != nil {
		t.Fatal(err)
	}
	defer lite.Close()
	url := testURL(t, filepath.Join(dir, "pg"))
	if _, err := ImportSQLite(url, src, ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	pg := testPostgres(t, filepath.Join(dir, "pg"))
	check := func(stage string) {
		t.Helper()
		rows, err := pg.db.Query(`SELECT c.relname, a.attname FROM pg_attribute a
 JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE a.attidentity<>'' AND c.relkind='r' AND n.nspname=current_schema() ORDER BY 1, 2`)
		if err != nil {
			t.Fatal(err)
		}
		var cols [][2]string
		for rows.Next() {
			var table, col string
			if err := rows.Scan(&table, &col); err != nil {
				t.Fatal(err)
			}
			cols = append(cols, [2]string{table, col})
		}
		rows.Close()
		if len(cols) == 0 {
			t.Fatal("no identity columns found in the catalog")
		}
		for _, c := range cols {
			var largest int64
			if err := lite.QueryRow(`SELECT COALESCE(MAX(` + quoteIdent(c[1]) + `), 0) FROM ` + quoteIdent(c[0])).Scan(&largest); err != nil {
				t.Fatal(err)
			}
			if largest == 0 {
				t.Errorf("%s.%s is an identity with no fixture row: add one to copyFixture", c[0], c[1])
				continue
			}
			var next int64
			if err := pg.db.QueryRow(`SELECT nextval(pg_get_serial_sequence(?, ?))`, c[0], c[1]).Scan(&next); err != nil {
				t.Fatal(err)
			}
			if next <= largest {
				t.Errorf("%s: %s.%s would next be %d, not above the imported %d", stage, c[0], c[1], next, largest)
			}
		}
	}
	check("after import")
	event := &AuditEvent{ID: "restored", Action: "system.restored", Outcome: "success", CreatedAt: time.Now().UTC()}
	if _, err := ImportSQLite(url, src, ImportOptions{Replace: true, Restored: event}); err != nil {
		t.Fatal(err)
	}
	check("after a restore with Replace")
}

// A source that fails SQLite's own checks is refused before anything is copied.
func TestImportRefusesASourceThatFailsItsChecks(t *testing.T) {
	requirePostgres(t)
	dir := t.TempDir()
	src := liteFixture(t, filepath.Join(dir, "src.db"))

	orphan := withOrphan(t, src, filepath.Join(dir, "orphan.db"))
	url := testURL(t, filepath.Join(dir, "pg-orphan"))
	if _, err := ImportSQLite(url, orphan, ImportOptions{}); err == nil || !strings.Contains(err.Error(), "foreign key check failed") {
		t.Fatalf("a source with an orphan row: %v", err)
	}
	if n := schemaObjects(t, url); n != 0 {
		t.Fatalf("a refused source left %d relations", n)
	}

	// An index that no longer matches its table: integrity_check, not the foreign keys.
	corrupt := filepath.Join(dir, "corrupt.db")
	if err := copyFile(src, corrupt); err != nil {
		t.Fatal(err)
	}
	rawSQLite(t, corrupt, `CREATE TABLE probe(a TEXT, b TEXT)`, `CREATE INDEX probe_a ON probe(a)`,
		`INSERT INTO probe VALUES('x','y')`, `PRAGMA writable_schema=ON`,
		`UPDATE sqlite_schema SET sql='CREATE INDEX probe_a ON probe(b)' WHERE name='probe_a'`)
	url = testURL(t, filepath.Join(dir, "pg-corrupt"))
	if _, err := ImportSQLite(url, corrupt, ImportOptions{}); err == nil || !strings.Contains(err.Error(), "integrity check failed") {
		t.Fatalf("a source failing integrity_check: %v", err)
	}
	if n := schemaObjects(t, url); n != 0 {
		t.Fatalf("a refused source left %d relations", n)
	}
}

// A source written to, or opened by a server, while it is copied is caught before commit:
// the import rolls back and the target stays empty.
func TestImportRefusesASourceThatChanges(t *testing.T) {
	requirePostgres(t)
	for name, change := range map[string]func(t *testing.T, path string){
		"written": func(t *testing.T, path string) {
			rawSQLite(t, path, `INSERT INTO system_settings(key,value,updated_at) VALUES('late','1',CURRENT_TIMESTAMP)`)
		},
		"gained a log": func(t *testing.T, path string) {
			if err := os.WriteFile(path+"-wal", nil, 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			src := liteFixture(t, filepath.Join(dir, "src.db"))
			beforeImportCommit = func() { change(t, src) }
			defer func() { beforeImportCommit = func() {} }()
			url := testURL(t, filepath.Join(dir, "pg"))
			_, err := ImportSQLite(url, src, ImportOptions{})
			if err == nil || !strings.Contains(err.Error(), src) {
				t.Fatalf("a source that %s during the copy: %v", name, err)
			}
			if n := schemaObjects(t, url); n != 0 {
				t.Fatalf("the refused import left %d relations", n)
			}
		})
	}
}
