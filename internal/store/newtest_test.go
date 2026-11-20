package store

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

// A NewTest copy is the database a fresh New migrates, statement for statement.
func TestNewTestMatchesAFreshMigration(t *testing.T) {
	SkipOnPostgres(t, "NewTest is New on Postgres")
	dir := t.TempDir()
	fresh, copied := filepath.Join(dir, "fresh.db"), filepath.Join(dir, "copied.db")
	openAndClose(t, fresh)
	s, err := NewTest(copied)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if got, want := schemaSQL(t, copied), schemaSQL(t, fresh); got != want {
		t.Fatalf("NewTest schema differs from a fresh migration:\n got %s\nwant %s", got, want)
	}
	if got, want := schemaVersions(t, copied), schemaVersions(t, fresh); got != want {
		t.Fatalf("NewTest schema_migrations = %q, fresh = %q", got, want)
	}
}

func schemaSQL(t *testing.T, path string) string {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT type || ' ' || name || ' ' || COALESCE(sql, '') FROM sqlite_master ORDER BY type, name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		out = append(out, line)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return strings.Join(out, "\n")
}
