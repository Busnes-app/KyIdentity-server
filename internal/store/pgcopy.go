package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Busnes-app/kyidentity-server/internal/store/pgdialect"
)

// The table-by-table copy between the two backends. SnapshotTo on Postgres exports into a
// fresh SQLite file, so a capsule has the same members on both backends; ImportSQLite loads
// such a file into Postgres (migrate-to-postgres, restore). Tables, columns, types and
// foreign keys are read from the catalogs and both sides must agree exactly. Each side
// keeps its own schema_migrations rows; their versions must be equal.

// copyColumn is a column and its type on one side: the SQLite declared type, or the
// Postgres type name.
type copyColumn struct{ name, typ string }

type copyTable struct {
	cols     []copyColumn // by name
	refs     []string     // tables its foreign keys reference
	identity []string     // Postgres identity columns
	rowid    bool         // SQLite: an ordinary rowid table
}

type catalog map[string]*copyTable

type querier interface {
	Query(query string, args ...any) (*sql.Rows, error)
}

func quoteIdent(name string) string { return `"` + strings.ReplaceAll(name, `"`, `""`) + `"` }

func (c catalog) table(name string) *copyTable {
	if c[name] == nil {
		c[name] = &copyTable{}
	}
	return c[name]
}

// readPairs runs a query returning (table, value) rows.
func readPairs(q querier, query string, each func(table, value string, rest []any) error, rest ...any) error {
	rows, err := q.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var table, value string
		if err := rows.Scan(append([]any{&table, &value}, rest...)...); err != nil {
			return err
		}
		if err := each(table, value, rest); err != nil {
			return err
		}
	}
	return rows.Err()
}

func sqliteCatalog(q querier) (catalog, error) {
	c := catalog{}
	var typ string
	if err := readPairs(q, `SELECT m.name, p.name, p.type FROM sqlite_master m, pragma_table_info(m.name) p
 WHERE m.type='table' AND m.name NOT LIKE 'sqlite\_%' ESCAPE '\' ORDER BY m.name, p.name`, func(table, col string, _ []any) error {
		t := c.table(table)
		t.cols = append(t.cols, copyColumn{col, typ})
		return nil
	}, &typ); err != nil {
		return nil, fmt.Errorf("reading the SQLite catalog: %w", err)
	}
	var wr int
	if err := readPairs(q, `SELECT name, type, wr FROM pragma_table_list WHERE schema='main'`, func(table, kind string, _ []any) error {
		if t := c[table]; t != nil && kind == "table" && wr == 0 {
			t.rowid = true
		}
		return nil
	}, &wr); err != nil {
		return nil, fmt.Errorf("reading the SQLite catalog: %w", err)
	}
	if err := readPairs(q, `SELECT DISTINCT m.name, f."table" FROM sqlite_master m, pragma_foreign_key_list(m.name) f
 WHERE m.type='table' AND m.name NOT LIKE 'sqlite\_%' ESCAPE '\'`, func(table, ref string, _ []any) error {
		c.table(table).refs = append(c.table(table).refs, ref)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("reading the SQLite foreign keys: %w", err)
	}
	return c, nil
}

func pgCatalog(q querier) (catalog, error) {
	c := catalog{}
	var typ string
	var identity bool
	if err := readPairs(q, `SELECT c.relname, a.attname, t.typname, a.attidentity<>'' FROM pg_class c
 JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped JOIN pg_type t ON t.oid=a.atttypid
 WHERE c.relnamespace=current_schema()::regnamespace AND c.relkind='r' ORDER BY 1, 2`, func(table, col string, _ []any) error {
		t := c.table(table)
		t.cols = append(t.cols, copyColumn{col, typ})
		if identity {
			t.identity = append(t.identity, col)
		}
		return nil
	}, &typ, &identity); err != nil {
		return nil, fmt.Errorf("reading the Postgres catalog: %w", err)
	}
	if err := readPairs(q, `SELECT DISTINCT c.relname, r.relname FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid
 JOIN pg_class r ON r.oid=k.confrelid WHERE k.contype='f' AND c.relnamespace=current_schema()::regnamespace`, func(table, ref string, _ []any) error {
		c.table(table).refs = append(c.table(table).refs, ref)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("reading the Postgres foreign keys: %w", err)
	}
	return c, nil
}

func colNames(cols []copyColumn) []string {
	out := make([]string, len(cols))
	for i, c := range cols {
		out[i] = c.name
	}
	return out
}

// matchCatalogs refuses unless both sides have the same tables with the same columns.
// The Postgres identity column rowid stands for SQLite's implicit rowid, which is then
// added to the SQLite table so the copy carries it.
func matchCatalogs(lite, pg catalog) error {
	var problems []string
	for _, name := range slices.Sorted(maps.Keys(pg)) {
		l := lite[name]
		if l == nil {
			problems = append(problems, "table "+name+" exists only on Postgres")
			continue
		}
		p := pg[name]
		if slices.Contains(p.identity, "rowid") && !slices.Contains(colNames(l.cols), "rowid") && l.rowid {
			l.cols = append(l.cols, copyColumn{"rowid", "INTEGER"})
			slices.SortFunc(l.cols, func(a, b copyColumn) int { return strings.Compare(a.name, b.name) })
		}
		if lc, pc := colNames(l.cols), colNames(p.cols); !slices.Equal(lc, pc) {
			problems = append(problems, fmt.Sprintf("table %s has columns %v on SQLite and %v on Postgres", name, lc, pc))
		}
	}
	for _, name := range slices.Sorted(maps.Keys(lite)) {
		if pg[name] == nil {
			problems = append(problems, "table "+name+" exists only on SQLite")
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("the SQLite and Postgres schemas differ: %s", strings.Join(problems, "; "))
	}
	return nil
}

// fkOrder lists the tables so that every table comes after the tables it references.
func fkOrder(c catalog) ([]string, error) {
	var order []string
	done := map[string]bool{}
	names := slices.Sorted(maps.Keys(c))
	for len(order) < len(names) {
		before := len(order)
		for _, name := range names {
			if done[name] {
				continue
			}
			ready := true
			for _, ref := range c[name].refs {
				if c[ref] == nil {
					return nil, fmt.Errorf("table %s references %s, which does not exist", name, ref)
				}
				ready = ready && done[ref]
			}
			if ready {
				done[name] = true
				order = append(order, name)
			}
		}
		if len(order) == before {
			var left []string
			for _, name := range names {
				if !done[name] {
					left = append(left, name)
				}
			}
			return nil, fmt.Errorf("the foreign keys among %v form a cycle; refusing to guess an insert order", left)
		}
	}
	return order, nil
}

// knownVersions are the schema versions this binary creates.
func knownVersions() []int {
	v := []int{1}
	for _, m := range migrations {
		v = append(v, m.version)
	}
	return v
}

func readVersions(q querier) ([]int, error) {
	rows, err := q.Query(`SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// toSQLite converts a value read from Postgres for a SQLite column declared decl. Times are
// bound as time.Time, which the driver writes exactly as the store's own writes are.
func toSQLite(v any, decl string) (any, error) {
	if v == nil {
		return nil, nil
	}
	switch d := strings.ToUpper(decl); {
	case d == "DATETIME" || d == "TIMESTAMP":
		if t, ok := v.(time.Time); ok {
			return t.UTC(), nil
		}
	case d == "BOOLEAN" || strings.Contains(d, "INT"):
		// A boolean is 0 or 1 in either: some SQLite booleans are declared INTEGER.
		if b, ok := v.(bool); ok {
			if b {
				return int64(1), nil
			}
			return int64(0), nil
		}
		if n, ok := v.(int64); ok && d != "BOOLEAN" {
			return n, nil
		}
	case d == "TEXT":
		if s, ok := v.(string); ok {
			return s, nil
		}
	case d == "BLOB":
		if b, ok := v.([]byte); ok {
			return append([]byte{}, b...), nil // never nil: that would be NULL
		}
	default:
		return nil, fmt.Errorf("no mapping for SQLite type %q", decl)
	}
	return nil, fmt.Errorf("a %T value does not convert to SQLite %s", v, decl)
}

// toPostgres converts a value read from SQLite for a Postgres column of type typ.
func toPostgres(v any, typ string) (any, error) {
	if v == nil {
		return nil, nil
	}
	switch typ {
	case "bool":
		if n, ok := v.(int64); ok && (n == 0 || n == 1) {
			return n == 1, nil
		}
	case "int8":
		if n, ok := v.(int64); ok {
			return n, nil
		}
	case "text", "citext":
		s, ok := v.(string)
		if b, isBytes := v.([]byte); isBytes {
			s, ok = string(b), true
		}
		if ok && utf8.ValidString(s) && !strings.ContainsRune(s, 0) {
			return s, nil
		}
	case "timestamptz":
		if t, ok := v.(time.Time); ok {
			return t.UTC(), nil
		}
	case "bytea":
		if b, ok := v.([]byte); ok {
			return append([]byte{}, b...), nil
		}
	default:
		return nil, fmt.Errorf("no mapping for Postgres type %s", typ)
	}
	return nil, fmt.Errorf("a %T value does not convert to Postgres %s", v, typ)
}

// copyTableRows copies every row of one table, in rowid order where it has one. The
// error names the table and column of a value that does not convert, never the value.
func copyTableRows(src querier, dst *sql.Tx, name string, cols []copyColumn, convert func(any, string) (any, error)) (int64, error) {
	quoted := make([]string, len(cols))
	for i, c := range cols {
		quoted[i] = quoteIdent(c.name)
	}
	list := strings.Join(quoted, ", ")
	sel := "SELECT " + list + " FROM " + quoteIdent(name)
	if slices.Contains(colNames(cols), "rowid") {
		sel += ` ORDER BY "rowid"`
	}
	rows, err := src.Query(sel)
	if err != nil {
		return 0, fmt.Errorf("reading %s: %w", name, err)
	}
	defer rows.Close()
	ins, err := dst.Prepare("INSERT INTO " + quoteIdent(name) + " (" + list + ") VALUES (" + strings.TrimSuffix(strings.Repeat("?, ", len(cols)), ", ") + ")")
	if err != nil {
		return 0, fmt.Errorf("writing %s: %w", name, err)
	}
	defer ins.Close()
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	var n int64
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return n, fmt.Errorf("reading %s: %w", name, err)
		}
		for i, c := range cols {
			if vals[i], err = convert(vals[i], c.typ); err != nil {
				return n, fmt.Errorf("table %s column %s: %w", name, c.name, err)
			}
		}
		if _, err := ins.Exec(vals...); err != nil {
			return n, fmt.Errorf("writing %s: %w", name, err)
		}
		n++
	}
	if err := rows.Err(); err != nil {
		return n, fmt.Errorf("reading %s: %w", name, err)
	}
	return n, nil
}

// exportToSQLite is SnapshotTo on Postgres: a fresh SQLite database at dest with the
// current SQLite schema, filled from one REPEATABLE READ READ ONLY transaction, so the
// file is one point in time and needs no writer lock. dest is created 0600; on any error
// it is removed.
func (s *Store) exportToSQLite(dest string) (err error) {
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("creating the snapshot: %w", err)
	}
	_ = f.Close()
	defer func() {
		if err != nil {
			for _, p := range []string{dest, dest + "-wal", dest + "-shm", dest + "-journal"} {
				_ = os.Remove(p)
			}
			err = fmt.Errorf("database snapshot failed: %w", err)
		}
	}()
	fresh, err := newSQLite(dest)
	if err != nil {
		return err
	}
	if err := fresh.Close(); err != nil {
		return err
	}
	lite, err := sql.Open("sqlite", dest+"?_pragma=foreign_keys(0)&_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer lite.Close()
	lite.SetMaxOpenConns(1) // the pragmas below hold for one connection

	src, err := s.rdb.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return err
	}
	defer src.Rollback()
	pg, err := pgCatalog(src)
	if err != nil {
		return err
	}
	cat, err := sqliteCatalog(lite)
	if err != nil {
		return err
	}
	if err := matchCatalogs(cat, pg); err != nil {
		return err
	}
	order, err := fkOrder(cat)
	if err != nil {
		return err
	}
	if err := sameVersions(src, lite); err != nil {
		return err
	}
	type trigger struct{ name, sql string }
	var triggers []trigger
	var body string
	if err := readPairs(lite, `SELECT 'trigger', name, sql FROM sqlite_master WHERE type='trigger' ORDER BY name`, func(_, name string, _ []any) error {
		triggers = append(triggers, trigger{name, body})
		return nil
	}, &body); err != nil {
		return err
	}
	tx, err := lite.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, t := range triggers {
		if _, err := tx.Exec(`DROP TRIGGER ` + quoteIdent(t.name)); err != nil {
			return err
		}
	}
	for _, name := range order {
		if name == "schema_migrations" {
			continue
		}
		if _, err := tx.Exec(`DELETE FROM ` + quoteIdent(name)); err != nil {
			return err
		}
		if _, err := copyTableRows(src, tx, name, cat[name].cols, toSQLite); err != nil {
			return err
		}
	}
	for _, t := range triggers {
		if _, err := tx.Exec(t.sql); err != nil {
			return fmt.Errorf("recreating trigger %s: %w", t.name, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if err := sqliteChecks(lite); err != nil {
		return err
	}
	// Rollback journal, as VACUUM INTO writes: the file alone is the whole database.
	_, err = lite.Exec(`PRAGMA journal_mode=DELETE`)
	return err
}

// sameVersions refuses two databases at different schema versions.
func sameVersions(a, b querier) error {
	va, err := readVersions(a)
	if err != nil {
		return err
	}
	vb, err := readVersions(b)
	if err != nil {
		return err
	}
	if !slices.Equal(va, vb) {
		return fmt.Errorf("schema versions differ: %v and %v", va, vb)
	}
	return nil
}

// sqliteChecks fails on any foreign key violation or integrity problem.
func sqliteChecks(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		return err
	}
	if rows.Next() {
		var table string
		var rowid sql.NullInt64
		var parent string
		var fk int
		_ = rows.Scan(&table, &rowid, &parent, &fk)
		rows.Close()
		return fmt.Errorf("foreign key check failed: a row of %s references a missing %s row", table, parent)
	}
	rows.Close()
	var ok string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&ok); err != nil {
		return err
	}
	if ok != "ok" {
		return fmt.Errorf("integrity check failed: %s", ok)
	}
	return nil
}

// ImportOptions control ImportSQLite.
type ImportOptions struct {
	// Replace empties every table in the same transaction before the copy; without it a
	// database holding any row is refused.
	Replace bool
	// Restored, when set, applies the restored state (ApplyRestoredState) in the same
	// transaction and records this system.restored row with its counts.
	Restored *AuditEvent
}

// ImportResult is what one import copied.
type ImportResult struct {
	Rows    map[string]int64 // rows read from the file, per table
	Restore RestoreReport    // when ImportOptions.Restored was set
}

// ImportSQLite copies the SQLite database at srcPath into the Postgres database at rawURL,
// in one transaction under the writer lock and the migration lock: it creates the schema
// if absent, refuses a database holding rows (unless Replace), copies every table in
// foreign key order with user triggers disabled, moves each identity past its largest
// value and commits. A failure leaves Postgres as it was. The file is never written: a
// file from before schema versions is brought up to date on a private copy.
func ImportSQLite(rawURL, srcPath string, opt ImportOptions) (ImportResult, error) {
	return importSQLite(rawURL, "", srcPath, opt)
}

func importSQLite(rawURL, searchPath, srcPath string, opt ImportOptions) (res ImportResult, err error) {
	src, done, err := openImportSource(srcPath)
	if err != nil {
		return res, err
	}
	defer done()
	s, _, err := connectPostgres(rawURL, searchPath, false)
	if err != nil {
		return res, err
	}
	defer s.db.Close()
	err = s.withPostgresMigrationLock(func() error {
		var err error
		res, err = s.importTx(src, opt)
		return err
	})
	return res, err
}

// openImportSource opens the file read-only after checking its schema version. A file
// from before versions is first opened once by the normal SQLite path, on a copy.
func openImportSource(path string) (*sql.DB, func(), error) {
	if _, err := os.Stat(path); err != nil {
		return nil, nil, err
	}
	if _, err := os.Stat(path + "-wal"); err == nil {
		return nil, nil, fmt.Errorf("%s has a write-ahead log beside it: stop the server that uses it (a clean stop folds the log into the file) and try again", path)
	}
	// immutable: read the file alone and create nothing beside it (mode=ro alone leaves a
	// -wal and -shm next to a WAL-mode file). A log beside it is refused above.
	open := func(p string) (*sql.DB, error) {
		db, err := sql.Open("sqlite", "file:"+strings.NewReplacer("%", "%25", "?", "%3f", "#", "%23").Replace(p)+"?mode=ro&immutable=1")
		if err != nil {
			return nil, err
		}
		db.SetMaxOpenConns(1)
		return db, nil
	}
	db, err := open(path)
	if err != nil {
		return nil, nil, err
	}
	versions, err := readVersions(db)
	if err == nil && slices.Contains(versions, 1) {
		if !slices.Equal(versions, knownVersions()) {
			_ = db.Close()
			return nil, nil, fmt.Errorf("the SQLite file is at schema versions %v but this binary knows %v: open it with the matching release first", versions, knownVersions())
		}
		return db, func() { _ = db.Close() }, nil
	}
	_ = db.Close()
	if err != nil && !strings.Contains(err.Error(), "no such table") {
		return nil, nil, fmt.Errorf("reading the schema version of %s: %w", path, err)
	}
	// Unversioned: an install from before schema versions. Bring a copy up to date.
	dir, err := os.MkdirTemp("", "kyidentity-import-") // mode 0700
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	copyPath := filepath.Join(dir, "legacy.db")
	if err := copyFile(path, copyPath); err != nil {
		cleanup()
		return nil, nil, err
	}
	legacy, err := newSQLite(copyPath)
	if err == nil {
		err = legacy.Close()
	}
	if err == nil {
		db, err = open(copyPath)
	}
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("bringing a copy of the unversioned file %s up to date: %w", path, err)
	}
	return db, func() { _ = db.Close(); cleanup() }, nil
}

func copyFile(from, to string) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func (s *Store) importTx(lite *sql.DB, opt ImportOptions) (ImportResult, error) {
	res := ImportResult{Rows: map[string]int64{}}
	src, err := lite.Begin()
	if err != nil {
		return res, err
	}
	defer src.Rollback()
	tx, err := s.db.Begin()
	if err != nil {
		return res, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`CREATE EXTENSION IF NOT EXISTS citext`); err != nil {
		return res, fmt.Errorf("creating the citext extension: %w", err)
	}
	if err := checkPostgresCollation(tx); err != nil {
		return res, err
	}
	var initialized bool
	if err := tx.QueryRow(`SELECT to_regclass('schema_migrations') IS NOT NULL`).Scan(&initialized); err != nil {
		return res, err
	}
	if !initialized {
		if err := createPostgresSchemaTx(tx); err != nil {
			return res, fmt.Errorf("creating the Postgres schema: %w", err)
		}
	}
	pg, err := pgCatalog(tx)
	if err != nil {
		return res, err
	}
	cat, err := sqliteCatalog(src)
	if err != nil {
		return res, err
	}
	if err := matchCatalogs(cat, pg); err != nil {
		return res, err
	}
	if err := sameVersions(src, tx); err != nil {
		return res, fmt.Errorf("the file and the Postgres database: %w", err)
	}
	order, err := fkOrder(pg)
	if err != nil {
		return res, err
	}
	var data []string // every table but schema_migrations, which each side keeps
	for _, name := range order {
		if name != "schema_migrations" {
			data = append(data, name)
		}
	}
	quoted := make([]string, len(data))
	for i, name := range data {
		quoted[i] = quoteIdent(name)
	}
	if opt.Replace || !initialized {
		// A schema created above holds only its seed rows, which the file's replace. TRUNCATE
		// fires no row trigger and is undone with the transaction.
		if _, err := tx.Exec(`TRUNCATE ` + strings.Join(quoted, ", ")); err != nil {
			return res, err
		}
	} else {
		var held []string
		for _, name := range data {
			var has bool
			if err := tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM ` + quoteIdent(name) + `)`).Scan(&has); err != nil {
				return res, err
			}
			if has {
				held = append(held, name)
			}
		}
		if len(held) > 0 {
			return res, fmt.Errorf("the Postgres database is not empty (rows in %s); refusing to copy over it", strings.Join(held, ", "))
		}
	}
	for _, q := range quoted {
		if _, err := tx.Exec(`ALTER TABLE ` + q + ` DISABLE TRIGGER USER`); err != nil {
			return res, err
		}
	}
	for _, name := range data {
		n, err := copyTableRows(src, tx, name, pg[name].cols, toPostgres)
		if err != nil {
			return res, err
		}
		res.Rows[name] = n
	}
	versions, err := readVersions(src)
	if err != nil {
		return res, err
	}
	res.Rows["schema_migrations"] = int64(len(versions))
	// ALTER ... RESTART is transactional, unlike setval.
	for _, name := range data {
		for _, col := range pg[name].identity {
			var next int64
			if err := tx.QueryRow(`SELECT COALESCE(MAX(` + quoteIdent(col) + `), 0) + 1 FROM ` + quoteIdent(name)).Scan(&next); err != nil {
				return res, err
			}
			if _, err := tx.Exec(fmt.Sprintf(`ALTER TABLE %s ALTER COLUMN %s RESTART WITH %d`, quoteIdent(name), quoteIdent(col), next)); err != nil {
				return res, err
			}
		}
	}
	for _, q := range quoted {
		if _, err := tx.Exec(`ALTER TABLE ` + q + ` ENABLE TRIGGER USER`); err != nil {
			return res, err
		}
	}
	if opt.Restored != nil {
		if res.Restore, err = s.applyRestoredStateTx(tx, time.Now().UTC(), opt.Restored); err != nil {
			return res, err
		}
		if err := recordAuditTx(tx, opt.Restored); err != nil {
			return res, err
		}
	}
	return res, tx.Commit()
}

// PostgresRowCounts counts the rows of every table of the Postgres database at rawURL, for
// checking an import after it committed.
func PostgresRowCounts(rawURL string) (map[string]int64, error) {
	s, _, err := connectPostgres(rawURL, "", true)
	if err != nil {
		return nil, err
	}
	defer s.db.Close()
	tx, err := s.db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	pg, err := pgCatalog(tx)
	if err != nil {
		return nil, err
	}
	if len(pg) == 0 {
		return nil, errors.New("the Postgres database at " + pgdialect.Describe(rawURL) + " has no tables")
	}
	out := map[string]int64{}
	for name := range pg {
		var n int64
		if err := tx.QueryRow(`SELECT COUNT(*) FROM ` + quoteIdent(name)).Scan(&n); err != nil {
			return nil, err
		}
		out[name] = n
	}
	return out, nil
}
