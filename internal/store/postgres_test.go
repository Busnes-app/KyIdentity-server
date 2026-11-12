package store

import (
	"database/sql"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func requirePostgres(t *testing.T) {
	t.Helper()
	if !OnPostgresTest() {
		t.Skip("needs KYIDENTITY_TEST_DATABASE_URL")
	}
}

// columnSets maps each table to its sorted column names.
func columnSets(t *testing.T, db *sql.DB, q string) map[string][]string {
	t.Helper()
	rows, err := db.Query(q)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var table, column string
		if err := rows.Scan(&table, &column); err != nil {
			t.Fatal(err)
		}
		out[table] = append(out[table], column)
	}
	for _, cols := range out {
		slices.Sort(cols)
	}
	return out
}

// The two backends' schemas name the same tables and columns. The only exceptions are
// SQLite's own sqlite_sequence and the identity column Postgres needs where the SQL orders
// by SQLite's implicit rowid. A migration that changes one schema and not the other fails here.
func TestBackendsHaveTheSameColumns(t *testing.T) {
	requirePostgres(t)
	lite, err := newSQLite(filepath.Join(t.TempDir(), "sqlite.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer lite.Close()
	pg, cleanup := setupTestStore(t)
	defer cleanup()
	want := columnSets(t, lite.db, `SELECT m.name, p.name FROM sqlite_master m, pragma_table_info(m.name) p WHERE m.type='table' AND m.name<>'sqlite_sequence'`)
	got := columnSets(t, pg.db, `SELECT c.table_name, c.column_name FROM information_schema.columns c JOIN information_schema.tables t USING (table_schema, table_name)
 WHERE c.table_schema=current_schema() AND t.table_type='BASE TABLE' AND NOT (c.table_name='account_sync_events' AND c.column_name='rowid')`)
	if len(want) < 50 {
		t.Fatalf("only %d SQLite tables read", len(want))
	}
	for table, cols := range want {
		if !slices.Equal(got[table], cols) {
			t.Errorf("table %s: SQLite has %v, Postgres has %v", table, cols, got[table])
		}
	}
	for table := range got {
		if _, ok := want[table]; !ok {
			t.Errorf("table %s exists only on Postgres", table)
		}
	}
	// Views and triggers by name, too.
	liteObjects := columnSets(t, lite.db, `SELECT type, name FROM sqlite_master WHERE type IN ('view','trigger')`)
	pgObjects := columnSets(t, pg.db, `SELECT 'view', table_name FROM information_schema.views WHERE table_schema=current_schema()
 UNION ALL SELECT 'trigger', tgname FROM pg_trigger g JOIN pg_class c ON c.oid=g.tgrelid WHERE c.relnamespace=current_schema()::regnamespace AND NOT g.tgisinternal`)
	for _, kind := range []string{"view", "trigger"} {
		if !slices.Equal(liteObjects[kind], pgObjects[kind]) {
			t.Errorf("%ss: SQLite has %v, Postgres has %v", kind, liteObjects[kind], pgObjects[kind])
		}
	}
}

// A database whose collation folds or orders text differently from SQLite is refused at
// startup, before any schema is written.
func TestPostgresRefusesANonCLocaleDatabase(t *testing.T) {
	requirePostgres(t)
	admin, err := sql.Open("pgx", testDatabaseURL()) // plain pgx: CREATE DATABASE cannot run in the writer transaction
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	_, _ = admin.Exec(`DROP DATABASE IF EXISTS kt_icu_locale`)
	if _, err := admin.Exec(`CREATE DATABASE kt_icu_locale TEMPLATE template0 ENCODING 'UTF8' LOCALE_PROVIDER icu ICU_LOCALE 'en-US' LOCALE 'C'`); err != nil {
		t.Skipf("cannot create an ICU database here: %v", err)
	}
	defer func() { _, _ = admin.Exec(`DROP DATABASE IF EXISTS kt_icu_locale WITH (FORCE)`) }()
	u, err := url.Parse(testDatabaseURL())
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/kt_icu_locale"
	s, err := NewPostgres(u.String())
	if err == nil {
		s.Close()
		t.Fatal("a database with ICU en-US collation was accepted")
	}
	if !strings.Contains(err.Error(), "C locale") {
		t.Fatalf("refusal does not name the requirement: %v", err)
	}
	probe, err := sql.Open("kypg", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	var tables int
	if err := probe.QueryRow(`SELECT count(*) FROM information_schema.tables WHERE table_schema='public'`).Scan(&tables); err != nil || tables != 0 {
		t.Fatalf("a refused start left %d tables: %v", tables, err)
	}
}
