package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store/pgdialect"
	"github.com/jackc/pgx/v5/pgconn"
	"modernc.org/sqlite"
)

// ErrNotOnPostgres marks a production path that is not supported on Postgres yet. Every
// such path returns it, naming itself, rather than doing nothing.
var ErrNotOnPostgres = errors.New("not supported on Postgres yet")

func notOnPostgres(what string) error { return fmt.Errorf("%s: %w", what, ErrNotOnPostgres) }

// Postgres reports whether this store runs on Postgres.
func (s *Store) Postgres() bool { return s.postgres }

// NewPostgres opens the shared Postgres database at rawURL and brings its schema to the
// version this code knows. Logs and errors name only the host and the database.
func NewPostgres(rawURL string) (*Store, error) {
	return openPostgres(rawURL, "", true, false)
}

// openPostgres opens the pools; migrate brings the schema up to date, otherwise the schema
// must exist already. readOnly makes both pools read-only sessions (OpenInstallerStore's
// inspection mode): every write is refused by the server, as SQLite's mode=ro does.
func openPostgres(rawURL, searchPath string, migrate, readOnly bool) (*Store, error) {
	where := pgdialect.Describe(rawURL)
	if searchPath != "" {
		rawURL = withSearchPath(rawURL, searchPath)
	}
	write, err := pgdialect.NewConnector(rawURL, readOnly)
	if err != nil {
		return nil, err
	}
	read, err := pgdialect.NewConnector(rawURL, true)
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(write)
	for _, p := range []*sql.DB{db} {
		p.SetMaxOpenConns(runtime.NumCPU() + 4)
		p.SetMaxIdleConns(4)
		p.SetConnMaxLifetime(5 * time.Minute)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("connecting to Postgres at %s: %w", where, err)
	}
	_, migrationKey := pgdialect.LockKeys(searchPath)
	s := &Store{db: db, rdb: db, postgres: true, migrationKey: migrationKey}
	if migrate {
		if err := s.withMigrationLease(func() error {
			if _, err := s.db.Exec(`CREATE EXTENSION IF NOT EXISTS citext`); err != nil {
				return fmt.Errorf("creating the citext extension: %w", err)
			}
			if err := s.checkPostgresCollation(); err != nil {
				return err
			}
			return s.migrate()
		}); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("schema creation failed on %s: %w", where, err)
		}
	} else {
		var initialized bool
		if err := db.QueryRow(`SELECT to_regclass('schema_migrations') IS NOT NULL`).Scan(&initialized); err != nil || !initialized {
			_ = db.Close()
			return nil, fmt.Errorf("the Postgres database at %s is not initialized (err %v)", where, err)
		}
	}
	s.rdb = sql.OpenDB(read)
	s.rdb.SetMaxOpenConns(runtime.NumCPU() + 4)
	s.rdb.SetMaxIdleConns(4)
	s.rdb.SetConnMaxLifetime(5 * time.Minute)
	log.Printf("database: Postgres at %s", where)
	return s, nil
}

// checkPostgresCollation refuses a database whose text rules differ from SQLite's: NOCASE
// and lower() fold ASCII letters only and compare bytes otherwise, which on Postgres needs
// the C locale (LC_COLLATE and LC_CTYPE) and citext for the case-insensitive columns.
func (s *Store) checkPostgresCollation() error {
	var utf8, lowerASCII, citextKeepsAccents, citextFoldsASCII, bytewise bool
	err := s.db.QueryRow(`SELECT current_setting('server_encoding')='UTF8', lower('É')='É', 'É'::citext<>'é'::citext, 'A'::citext='a'::citext, 'B'<'a'`).
		Scan(&utf8, &lowerASCII, &citextKeepsAccents, &citextFoldsASCII, &bytewise)
	if err != nil {
		return fmt.Errorf("checking the database collation: %w", err)
	}
	if !utf8 || !lowerASCII || !citextKeepsAccents || !citextFoldsASCII || !bytewise {
		return errors.New("the Postgres database must use encoding UTF8 with the C locale (LC_COLLATE and LC_CTYPE C), so names compare exactly as on SQLite; create it with CREATE DATABASE ... ENCODING 'UTF8' LOCALE 'C' TEMPLATE template0")
	}
	return nil
}

// withPostgresMigrationLock is withMigrationLease on Postgres: a session advisory lock held
// on one pinned connection, so a holder that dies releases it with its connection.
func (s *Store) withPostgresMigrationLock(fn func() error) error {
	ctx := context.Background()
	c, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	for waited := false; ; time.Sleep(50 * time.Millisecond) {
		var ok bool
		if err := c.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(?)`, s.migrationKey).Scan(&ok); err != nil {
			return err
		}
		if ok {
			break
		}
		if !waited {
			waited = true
			log.Printf("database: another process is migrating; waiting for it")
		}
	}
	defer func() { _, _ = c.ExecContext(ctx, `SELECT pg_advisory_unlock(?)`, s.migrationKey) }()
	return fn()
}

func withSearchPath(rawURL, searchPath string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL // NewConnector reports it
	}
	q := u.Query()
	q.Set("search_path", searchPath)
	u.RawQuery = q.Encode()
	return u.String()
}

// rowTime is now for a row whose time is also handed back to the caller as a version (the
// SCIM ETag is updated_at in nanoseconds). Postgres keeps microseconds, so the value is
// truncated to them on both backends and the caller's copy equals what a later read sees.
func rowTime() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }

// isUniqueViolation and isForeignKeyViolation classify a constraint error on either backend.
func isUniqueViolation(err error) bool {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code == "23505"
	}
	var lite *sqlite.Error
	return errors.As(err, &lite) && lite.Code() == 2067 || err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

func isForeignKeyViolation(err error) bool {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code == "23503"
	}
	var lite *sqlite.Error
	return errors.As(err, &lite) && lite.Code() == 787
}

// Tests run on Postgres when KYIDENTITY_TEST_DATABASE_URL is set: New(path) then opens a
// schema named after path, so two New calls on one path share it, as two handles on one
// file share the file, and different tests are isolated.
func testDatabaseURL() string {
	if !testing.Testing() {
		return ""
	}
	return os.Getenv("KYIDENTITY_TEST_DATABASE_URL")
}

// OnPostgresTest reports whether this test binary runs its stores on Postgres; tests about
// SQLite itself skip with it.
func OnPostgresTest() bool { return testDatabaseURL() != "" }

var testSetup = sync.OnceValue(func() error {
	db, err := sql.Open("kypg", testDatabaseURL())
	if err != nil {
		return err
	}
	defer db.Close()
	// citext lives in public, shared by every test schema, so dropping one keeps it. The
	// statement runs under the default writer lock: one process at a time.
	if _, err := db.Exec(`CREATE EXTENSION IF NOT EXISTS citext SCHEMA public`); err != nil {
		return err
	}
	// Drop the schemas of finished tests: their directory is gone, or, for :memory:, they
	// are hours old. One at a time: a schema holds hundreds of objects to lock.
	rows, err := db.Query(`SELECT nspname, COALESCE(obj_description(oid, 'pg_namespace'), '') FROM pg_namespace WHERE nspname LIKE 'kt\_%'`)
	if err != nil {
		return err
	}
	var stale []string
	for rows.Next() {
		var name, note string
		if err := rows.Scan(&name, &note); err != nil {
			rows.Close()
			return err
		}
		if dir, ok := strings.CutPrefix(note, "path:"); ok {
			if _, err := os.Stat(filepath.Dir(dir)); os.IsNotExist(err) {
				stale = append(stale, name)
			}
		} else if at, ok := strings.CutPrefix(note, "memory:"); ok {
			if t, err := time.Parse(time.RFC3339, at); err != nil || time.Since(t) > 3*time.Hour {
				stale = append(stale, name)
			}
		}
	}
	rows.Close()
	for _, name := range stale {
		if _, err := db.Exec(`DROP SCHEMA IF EXISTS "` + name + `" CASCADE`); err != nil {
			return err
		}
	}
	return nil
})

// testSchema names the Postgres schema a test path maps to and the note that lets a later
// run drop it once the test is gone.
func testSchema(path string) (schema, note string, err error) {
	if path == ":memory:" || path == "" {
		var b [8]byte
		_, _ = rand.Read(b[:])
		return "kt_mem_" + hex.EncodeToString(b[:]), "memory:" + time.Now().UTC().Format(time.RFC3339), nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(abs))
	return "kt_" + hex.EncodeToString(sum[:12]), "path:" + abs, nil
}

// newTestPostgres is New(path) in a test binary with KYIDENTITY_TEST_DATABASE_URL set.
func newTestPostgres(rawURL, path string, migrate bool) (*Store, error) {
	if err := testSetup(); err != nil {
		return nil, fmt.Errorf("preparing the test database: %w", err)
	}
	schema, note, err := testSchema(path)
	if err != nil {
		return nil, err
	}
	if migrate {
		db, err := sql.Open("kypg", rawURL)
		if err != nil {
			return nil, err
		}
		defer db.Close()
		if _, err := db.Exec(`CREATE SCHEMA IF NOT EXISTS "` + schema + `"; COMMENT ON SCHEMA "` + schema + `" IS '` + strings.ReplaceAll(note, "'", "''") + `'`); err != nil {
			return nil, err
		}
	}
	return openPostgres(rawURL, schema+",public", migrate, false)
}

// OpenRawForTest opens the database New(path) uses, for tests that read or change rows
// directly: the SQLite file (a ?query suffix is kept), or on Postgres its test schema
// through the kypg driver, so the same SQL runs.
func OpenRawForTest(path string) (*sql.DB, error) {
	rawURL := testDatabaseURL()
	if rawURL == "" {
		return sql.Open("sqlite", path)
	}
	path, _, _ = strings.Cut(path, "?")
	schema, _, err := testSchema(path)
	if err != nil {
		return nil, err
	}
	return sql.Open("kypg", withSearchPath(rawURL, schema+",public"))
}

// SkipOnPostgres skips a test that is about SQLite itself (it opens the file, reads the
// SQLite catalog or fakes a legacy install) when the suite runs on Postgres.
func SkipOnPostgres(t testing.TB, reason string) {
	t.Helper()
	if OnPostgresTest() {
		t.Skip("SQLite only: " + reason)
	}
}
