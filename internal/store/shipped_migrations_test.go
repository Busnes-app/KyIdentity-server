package store

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

var updateShipped = flag.Bool("update-shipped", false, "write testdata/shipped-migrations.txt from this build; run it only on origin/master")

const shippedMigrationsFile = "testdata/shipped-migrations.txt"

// schemaText is the database's schema as text: SQLite's stored DDL, or Postgres's
// columns, constraints, indexes, views, trigger definitions and function bodies.
func schemaText(t *testing.T, s *Store) string {
	t.Helper()
	qs := []string{`SELECT type||' '||name||' '||coalesce(sql,'') FROM sqlite_schema WHERE name<>'sqlite_sequence' ORDER BY type,name`}
	if s.postgres {
		in := `IN (SELECT oid FROM pg_class WHERE relnamespace=current_schema()::regnamespace)`
		qs = []string{
			`SELECT table_name||' '||column_name||' '||data_type||' '||is_nullable||' '||coalesce(column_default,'') FROM information_schema.columns WHERE table_schema=current_schema() ORDER BY 1`,
			// PostgreSQL 18 also lists NOT NULL here (contype n); is_nullable above has it.
			`SELECT conrelid::regclass::text||' '||conname||' '||pg_get_constraintdef(oid) FROM pg_constraint WHERE contype<>'n' AND conrelid ` + in + ` ORDER BY 1`,
			`SELECT indexdef FROM pg_indexes WHERE schemaname=current_schema() ORDER BY 1`,
			`SELECT viewname||' '||definition FROM pg_views WHERE schemaname=current_schema() ORDER BY 1`,
			`SELECT tgname||' '||pg_get_triggerdef(oid) FROM pg_trigger WHERE NOT tgisinternal AND tgrelid ` + in + ` ORDER BY 1`,
			`SELECT proname||' '||prosrc FROM pg_proc WHERE pronamespace=current_schema()::regnamespace ORDER BY 1`,
		}
	}
	var b strings.Builder
	for _, q := range qs {
		rows, err := s.db.Query(q)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				t.Fatal(err)
			}
			if !s.postgres && strings.HasPrefix(line, "table ") {
				line = sortedTableSQL(line)
			}
			b.WriteString(line + "\n")
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
	}
	var schema string
	if s.postgres {
		if err := s.db.QueryRow(`SELECT current_schema()`).Scan(&schema); err != nil {
			t.Fatal(err)
		}
		return strings.ReplaceAll(b.String(), schema+".", "")
	}
	return b.String()
}

// sortedTableSQL sorts a CREATE TABLE's top-level elements: migrateLegacy adds columns in
// map order, so their order in the stored DDL is not the schema's.
func sortedTableSQL(def string) string {
	open, end := strings.IndexByte(def, '('), strings.LastIndexByte(def, ')')
	if open < 0 || end < open {
		return def
	}
	var parts []string
	depth, quoted, start := 0, false, open+1
	for i := open + 1; i < end; i++ {
		switch c := def[i]; {
		case c == '\'':
			quoted = !quoted
		case quoted:
		case c == '(':
			depth++
		case c == ')':
			depth--
		case c == ',' && depth == 0:
			parts = append(parts, strings.TrimSpace(def[start:i]))
			start = i + 1
		}
	}
	parts = append(parts, strings.TrimSpace(def[start:end]))
	slices.Sort(parts)
	return def[:open+1] + strings.Join(parts, ", ") + def[end:]
}

// Shipped migrations are append only (migrations.go). Each line of shippedMigrationsFile
// is the hash of the schema after one shipped version on one backend, as origin/master
// built it; every build must build the same. A version not listed has not shipped.
// After a version merges, append its line (the failure log of this test prints it).
func TestShippedMigrationsUnchanged(t *testing.T) {
	backend := "sqlite"
	if testDatabaseURL() != "" {
		backend = "postgres"
	}
	want := map[int]string{}
	if data, err := os.ReadFile(shippedMigrationsFile); err == nil && !*updateShipped {
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			f := strings.Fields(line)
			if len(f) != 3 {
				t.Fatalf("bad line %q", line)
			}
			if f[0] == backend {
				v, err := strconv.Atoi(f[1])
				if err != nil {
					t.Fatal(err)
				}
				want[v] = f[2]
			}
		}
	} else if !*updateShipped {
		t.Fatal(err)
	}
	if !*updateShipped && len(want) == 0 {
		t.Fatalf("%s lists no %s versions", shippedMigrationsFile, backend)
	}
	saved := migrations
	t.Cleanup(func() { migrations = saved })
	path := filepath.Join(t.TempDir(), "shipped.db")
	var out strings.Builder
	for i, m := range saved {
		migrations = saved[:i+1]
		s, err := New(path)
		if err != nil {
			t.Fatalf("version %d: %v", m.version, err)
		}
		got := fmt.Sprintf("%x", sha256.Sum256([]byte(schemaText(t, s))))
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&out, "%s %d %s\n", backend, m.version, got)
		switch h, ok := want[m.version]; {
		case *updateShipped:
		case !ok:
			t.Logf("version %d %s is not listed as shipped: %s %d %s", m.version, m.name, backend, m.version, got)
		case h != got:
			t.Fatalf("version %d %s builds a different %s schema from the one it shipped: restore it and change a later version instead", m.version, m.name, backend)
		}
		delete(want, m.version)
	}
	for v := range want {
		t.Errorf("shipped version %d is gone", v)
	}
	if *updateShipped {
		f, err := os.OpenFile(shippedMigrationsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := f.WriteString(out.String()); err != nil {
			t.Fatal(err)
		}
	}
}
