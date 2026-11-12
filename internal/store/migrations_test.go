package store

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// forgetSchemaVersions turns a database into one written before schema versions existed.
func forgetSchemaVersions(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.db.Exec(`DROP TABLE schema_migrations`); err != nil {
		t.Fatal(err)
	}
}

// withTestMigration appends m to migrations for the length of the test.
func withTestMigration(t *testing.T, m migration) {
	t.Helper()
	saved := migrations
	migrations = append(append([]migration{}, migrations...), m)
	t.Cleanup(func() { migrations = saved })
}

func schemaVersions(t *testing.T, path string) string {
	t.Helper()
	s, err := OpenInstallerStore(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rows, err := s.db.Query(`SELECT version, name FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v int
		var name string
		if err := rows.Scan(&v, &name); err != nil {
			t.Fatal(err)
		}
		out = append(out, fmt.Sprintf("%d:%s", v, name))
	}
	return strings.Join(out, ",")
}

// v1 is the version-1 row a fresh database records: the legacy pass on SQLite, the
// hand-written schema on Postgres.
var v1 = map[bool]string{false: "1:legacy", true: "1:postgres"}[OnPostgresTest()]

func openAndClose(t *testing.T, path string) {
	t.Helper()
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

// A fresh database records version 1 once, and a later start never probes the legacy schema.
func TestFreshDatabaseRecordsVersionOneAndSkipsLegacyAfter(t *testing.T) {
	SkipOnPostgres(t, "counts runs of the SQLite legacy migration")
	path := filepath.Join(t.TempDir(), "fresh.db")
	before := legacyRuns.Load()
	openAndClose(t, path)
	if got := legacyRuns.Load() - before; got != 1 {
		t.Fatalf("first start ran migrateLegacy %d times, want 1", got)
	}
	openAndClose(t, path)
	if got := legacyRuns.Load() - before; got != 1 {
		t.Fatalf("second start ran migrateLegacy again (%d runs)", got)
	}
	if got := schemaVersions(t, path); got != "1:legacy" {
		t.Fatalf("schema_migrations = %q, want 1:legacy", got)
	}
}

// A database from a release before versions is upgraded in place to version 1 and the
// shape of a fresh install, with its data.
func TestUnversionedDatabaseUpgradesToVersionOne(t *testing.T) {
	SkipOnPostgres(t, "exercises a SQLite legacy migration (pre-version schema, pragma_table_info or sqlite_master)")
	refPath := filepath.Join(t.TempDir(), "reference.db")
	openAndClose(t, refPath)
	want := schemaFingerprint(t, refPath)

	current := func(t *testing.T) string {
		path := filepath.Join(t.TempDir(), "current.db")
		s, err := New(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(`INSERT INTO users(id,username,display_name,email,password_hash,role,status) VALUES
 ('u-staff','staff','Staff','staff@test.invalid','x','user','active')`); err != nil {
			t.Fatal(err)
		}
		forgetSchemaVersions(t, s)
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for name, build := range map[string]func(*testing.T) string{"pre-feature": legacyDatabase, "current release": current} {
		t.Run(name, func(t *testing.T) {
			path := build(t)
			before := legacyRuns.Load()
			s, err := New(path)
			if err != nil {
				t.Fatal(err)
			}
			var id string
			if err := s.db.QueryRow(`SELECT id FROM users WHERE username='staff'`).Scan(&id); err != nil || id != "u-staff" {
				t.Fatalf("data lost in upgrade: %q %v", id, err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if got := legacyRuns.Load() - before; got != 1 {
				t.Fatalf("migrateLegacy ran %d times, want 1", got)
			}
			if got := schemaVersions(t, path); got != "1:legacy" {
				t.Fatalf("schema_migrations = %q", got)
			}
			sameFingerprint(t, "upgraded against fresh", want, schemaFingerprint(t, path))
			openAndClose(t, path)
			if got := legacyRuns.Load() - before; got != 1 {
				t.Fatalf("restart after upgrade ran migrateLegacy again (%d runs)", got)
			}
		})
	}
}

// Six replicas starting together apply a new migration once.
func TestVersionedMigrationAppliesOnceAcrossReplicas(t *testing.T) {
	var ups atomic.Int64
	withTestMigration(t, migration{version: 2, name: "test_probe", up: func(tx *sql.Tx) error {
		ups.Add(1)
		_, err := tx.Exec(`CREATE TABLE test_probe (n INTEGER); INSERT INTO test_probe VALUES (1)`)
		return err
	}})
	path := filepath.Join(t.TempDir(), "replicas.db")
	before := legacyRuns.Load()
	const n = 6
	stores := make([]*Store, n)
	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			stores[i], errs[i] = New(path)
		}()
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
		defer stores[i].Close()
	}
	var rows int
	if err := stores[0].db.QueryRow(`SELECT COUNT(*) FROM test_probe`).Scan(&rows); err != nil || rows != 1 || ups.Load() != 1 {
		t.Fatalf("migration applied %d times, %d rows: %v", ups.Load(), rows, err)
	}
	if got := legacyRuns.Load() - before; got != 1 && !OnPostgresTest() {
		t.Fatalf("migrateLegacy ran %d times across replicas, want 1", got)
	}
	if got := schemaVersions(t, path); got != v1+",2:test_probe" {
		t.Fatalf("schema_migrations = %q", got)
	}
}

// A failing migration leaves neither its change nor its version row, and the next start
// retries it.
func TestFailingMigrationRollsBackAndRetries(t *testing.T) {
	fail := true
	withTestMigration(t, migration{version: 2, name: "test_flaky", up: func(tx *sql.Tx) error {
		if _, err := tx.Exec(`CREATE TABLE test_flaky (n INTEGER)`); err != nil {
			return err
		}
		if fail {
			return errors.New("boom")
		}
		return nil
	}})
	path := filepath.Join(t.TempDir(), "flaky.db")
	if s, err := New(path); err == nil || !strings.Contains(err.Error(), "boom") {
		if s != nil {
			s.Close()
		}
		t.Fatalf("failing migration started: %v", err)
	}
	if got := schemaVersions(t, path); got != v1 {
		t.Fatalf("schema_migrations after failure = %q", got)
	}
	if _, ok := schemaFingerprint(t, path)["table test_flaky"]; ok {
		t.Fatal("failed migration left its table")
	}
	fail = false
	openAndClose(t, path)
	if got := schemaVersions(t, path); got != v1+",2:test_flaky" {
		t.Fatalf("schema_migrations after retry = %q", got)
	}
	if _, ok := schemaFingerprint(t, path)["table test_flaky"]; !ok {
		t.Fatal("retried migration did not apply")
	}
}

// A binary older than the database refuses to start on it.
func TestNewerSchemaIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "newer.db")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO schema_migrations(version,name,applied_at) VALUES(99,'from_the_future',?)`, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	s.Close()
	before := legacyRuns.Load()
	if s, err := New(path); err == nil || !strings.Contains(err.Error(), "version 99") {
		if s != nil {
			s.Close()
		}
		t.Fatalf("newer schema accepted: %v", err)
	}
	if legacyRuns.Load() != before {
		t.Fatal("refused start still ran migrateLegacy")
	}
}

// Every reconciliation in reconcileOnStart still runs on a versioned start.
func TestReconciliationRunsOnEveryStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reconcile.db")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePairedSystem(&PairedSystem{ID: "sys", Name: "sys", SystemType: "scim", CallbackURL: "https://example.com/scim", Status: "active"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateOAuthClient(&OAuthClient{ID: "app", ClientName: "app", ClientType: "public", RedirectURIsJSON: "[]", AllowedScopesJSON: "[]", Enabled: true}, nil); err != nil {
		t.Fatal(err)
	}
	past := time.Now().UTC().Add(-time.Hour)
	for _, q := range []struct {
		sql  string
		args []any
	}{
		// reconcileSyncEvents: an event whose connector is gone, and exhausted legacy work.
		{`INSERT INTO account_sync_events(id,user_id,system_id,event_type,payload_json,attempts,status) VALUES('ghost','u','gone','user.created','{}',0,'pending')`, nil},
		{`INSERT INTO account_sync_events(id,user_id,system_id,event_type,payload_json,attempts,status) VALUES('spent','u','sys','user.created','{}',?,'pending')`, []any{SyncAttemptBudget}},
		// reconcileAuthorizationInteractionsTx: an expired interaction.
		{`INSERT INTO authorization_interactions(hash,browser_hash,request,created_at,expires_at) VALUES('old','b','{}',?,?)`, []any{past, past}},
		// backfillAppRegistryTx: a client that lost its app record.
		{`DELETE FROM app_registry WHERE client_id='app'`, nil},
	} {
		if _, err := s.db.Exec(q.sql, q.args...); err != nil {
			t.Fatalf("%s: %v", q.sql, err)
		}
	}
	s.Close()

	before := legacyRuns.Load()
	if s, err = New(path); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if legacyRuns.Load() != before {
		t.Fatal("versioned start ran migrateLegacy")
	}
	count := func(query string) int {
		t.Helper()
		var n int
		if err := s.db.QueryRow(query).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count(`SELECT COUNT(*) FROM account_sync_events WHERE id='ghost'`) != 0 {
		t.Error("event of a deleted connector survived the start")
	}
	if count(`SELECT COUNT(*) FROM account_sync_events WHERE id='spent' AND status='failed'`) != 1 {
		t.Error("exhausted pending event was not failed")
	}
	if count(`SELECT COUNT(*) FROM authorization_interactions WHERE hash='old'`) != 0 {
		t.Error("expired interaction survived the start")
	}
	if count(`SELECT COUNT(*) FROM app_registry WHERE client_id='app'`) != 1 {
		t.Error("client's app record was not backfilled")
	}
}
