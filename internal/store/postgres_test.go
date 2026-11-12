package store

import (
	"database/sql"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

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

// unixepoch() is whole seconds rounded down on both backends, never up: an expiry stored
// as unix seconds must not fire before its second has begun.
func TestUnixepochTruncates(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	for range 40 {
		before := time.Now().Unix()
		var got int64
		if err := s.db.QueryRow(`SELECT unixepoch()`).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if after := time.Now().Unix(); got < before || got > after {
			t.Fatalf("unixepoch() = %d outside [%d, %d]", got, before, after)
		}
		time.Sleep(13 * time.Millisecond)
	}
}

// The database URL carries a password: no error from opening it may repeat it.
func TestPostgresErrorsNeverRepeatThePassword(t *testing.T) {
	requirePostgres(t)
	const secret = "not-the-password-7f3a9c"
	u, err := url.Parse(testDatabaseURL())
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(u.User.Username(), secret)
	q := u.Query()
	q.Set("sslmode", "disable")
	u.RawQuery = q.Encode()
	for _, raw := range []string{u.String(), strings.Replace(u.String(), "@", ":bad-port@", 1), "postgres://user:" + secret + "@[bad/db"} {
		s, err := NewPostgres(raw)
		if err == nil { // a server that trusts every connection ignores the password
			s.Close()
			continue
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error repeats the password: %v", err)
		}
	}
}

// The two schemas enforce the same uniqueness and the same foreign keys: a unique index or
// a cascade present on one backend only would change who can sign in or what a delete removes.
// Primary keys are left out (SQLite lists none for a rowid key), and so is the identity
// column standing in for SQLite's rowid.
func TestBackendsHaveTheSameUniqueIndexesAndForeignKeys(t *testing.T) {
	requirePostgres(t)
	lite, err := newSQLite(filepath.Join(t.TempDir(), "sqlite.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer lite.Close()
	pg, cleanup := setupTestStore(t)
	defer cleanup()
	for what, q := range map[string][2]string{
		"unique indexes": {
			`SELECT m.name, (SELECT group_concat(COALESCE(i.name,'<expr>')) FROM pragma_index_info(l.name) i) || CASE WHEN l.partial THEN ' partial' ELSE '' END
 FROM sqlite_master m, pragma_index_list(m.name) l WHERE m.type='table' AND l."unique" AND l.origin<>'pk'`,
			`SELECT c.relname, (SELECT string_agg(COALESCE(a.attname,'<expr>'), ',' ORDER BY k.ord) FROM unnest(i.indkey::int2[]) WITH ORDINALITY k(num, ord)
  LEFT JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.num AND k.num>0) || CASE WHEN i.indpred IS NOT NULL THEN ' partial' ELSE '' END
 FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace=current_schema()::regnamespace AND i.indisunique AND NOT i.indisprimary
 AND NOT (c.relname='account_sync_events' AND pg_get_indexdef(i.indexrelid) ILIKE '%(rowid)')`,
		},
		"foreign keys": {
			`SELECT m.name, f."from" || ' -> ' || f."table" || ' ' || f.on_delete FROM sqlite_master m, pragma_foreign_key_list(m.name) f WHERE m.type='table'`,
			`SELECT c.relname, a.attname || ' -> ' || r.relname || ' ' || CASE k.confdeltype WHEN 'c' THEN 'CASCADE' WHEN 'n' THEN 'SET NULL' WHEN 'r' THEN 'RESTRICT' WHEN 'd' THEN 'SET DEFAULT' ELSE 'NO ACTION' END
 FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_class r ON r.oid=k.confrelid CROSS JOIN LATERAL unnest(k.conkey) num JOIN pg_attribute a ON a.attrelid=k.conrelid AND a.attnum=num
 WHERE k.contype='f' AND c.relnamespace=current_schema()::regnamespace`,
		},
	} {
		want, got := columnSets(t, lite.db, q[0]), columnSets(t, pg.db, q[1])
		if len(want) < 10 {
			t.Fatalf("%s: only %d SQLite tables read", what, len(want))
		}
		for table := range got {
			if _, ok := want[table]; !ok {
				want[table] = nil
			}
		}
		for table, w := range want {
			if !slices.Equal(got[table], w) {
				t.Errorf("%s of %s:\n  SQLite   %q\n  Postgres %q", what, table, w, got[table])
			}
		}
	}
}

// Lookups fold ASCII case and nothing else, on both backends: "ALICE" signs in as alice,
// "ÉMILE" is not émile, and a list sorts the same way.
func TestNameLookupsFoldASCIICaseOnly(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	for _, name := range []string{"alice", "Zed", "émile", "bob"} {
		u := &User{ID: "id-" + name, Username: name, DisplayName: name, Email: name + "@Example.com", PasswordHash: "x", Role: "user", Status: "active"}
		if err := s.CreateUser(u); err != nil {
			t.Fatal(err)
		}
	}
	if u, err := s.GetUserByUsername("ALICE"); err != nil || u == nil || u.Username != "alice" {
		t.Fatalf("ALICE did not find alice: %v", err)
	}
	if u, err := s.GetUserByEmail("ZED@example.COM"); err != nil || u == nil || u.Username != "Zed" {
		t.Fatalf("ZED@example.COM did not find Zed: %v", err)
	}
	if u, err := s.GetUserByUsername("ÉMILE"); err != nil || u != nil {
		t.Fatal("ÉMILE found émile: only ASCII letters may fold")
	}
	if u, err := s.GetUserByEmail("ÉMILE@example.com"); err != nil || u != nil {
		t.Fatal("ÉMILE@example.com found émile's address")
	}
	rows, err := s.db.Query(`SELECT username FROM users ORDER BY username`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var order []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		order = append(order, name)
	}
	if want := []string{"alice", "bob", "Zed", "émile"}; !slices.Equal(order, want) {
		t.Fatalf("usernames sort as %q, want %q", order, want)
	}
}

// The single writer only works at READ COMMITTED: the lock is taken after BEGIN, and a
// snapshot taken before it would hide what the previous holder committed. A server or
// URL that defaults to another level must not change that.
func TestWriteTransactionsAreReadCommitted(t *testing.T) {
	requirePostgres(t)
	u, err := url.Parse(testDatabaseURL())
	if err != nil {
		t.Fatal(err)
	}
	u.RawQuery += "&default_transaction_isolation=repeatable%20read"
	db, err := sql.Open("kypg", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var level string
	if err := tx.QueryRow(`SHOW transaction_isolation`).Scan(&level); err != nil || level != "read committed" {
		t.Fatalf("a write transaction runs at %q (%v), want read committed", level, err)
	}
}
