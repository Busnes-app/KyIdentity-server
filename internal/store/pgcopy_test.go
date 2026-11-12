package store

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/google/uuid"
)

// copyFixture fills s through the store's own methods, with the ephemeral credential rows
// the restore tests seed, so that most tables hold at least one row.
func copyFixture(t *testing.T, s *Store) {
	t.Helper()
	admin := &User{ID: uuid.NewString(), Username: "Zoë-Ångström", DisplayName: "Zoë 🙂 Ångström", Email: "Zoe@Example.test",
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA", Role: "admin", Status: "active"}
	if err := s.CreateUser(admin); err != nil {
		t.Fatal(err)
	}
	user := createTestUserNamed(t, s, "MixedCase.User")
	disabled := createTestUserNamed(t, s, "gone")
	disabled.Status = "disabled"
	if err := s.UpdateUserWithSyncEvents(disabled, true, nil); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		id, name string
		enabled  bool
	}{{"client-1", "App", true}, {"client-2", "Off", false}} {
		if err := s.CreateOAuthClient(&OAuthClient{ID: c.id, ClientName: c.name, ClientType: "public", RedirectURIsJSON: `["https://app.test/cb"]`, AllowedScopesJSON: `["openid"]`, Enabled: c.enabled, BackchannelLogoutURI: "https://app.test/logout"}, nil); err != nil {
			t.Fatal(err)
		}
	}
	app := provisioningFixture(t, s, "hr")
	g := &Group{ID: uuid.NewString(), Name: "Staff Ünits"}
	if err := s.CreateGroup(g, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGroupMembership(g.ID, user.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppAssignment(app, "groups", g.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppAssignment(app, "users", admin.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	sealed, err := crypto.Seal(key, "mfa_totp", user.ID, []byte("JBSWY3DPEHPK3PXP"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetMFAMethod(&MFAMethod{ID: uuid.NewString(), UserID: user.ID, MethodType: "totp", EncryptedSecret: sealed, IsPrimary: true, CreatedAt: time.Now().UTC()}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetBrandingLogo("image/png", []byte{0x89, 'P', 'N', 'G', 0, 0xff, 0}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSetting("kyrecovery_token", "v2:sealed-ish"); err != nil {
		t.Fatal(err)
	}
	for i := range 4 {
		if err := s.CreateAccountSyncEvent(&AccountSyncEvent{ID: fmt.Sprintf("ev-%d", i), UserID: user.ID, SystemID: "hr", EventType: "user.updated", PayloadJSON: `{"n":` + fmt.Sprint(i) + `}`, Status: "pending"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.RecordAuditEvent(&AuditEvent{ID: uuid.NewString(), ActorID: admin.ID, ActorUsername: admin.Username, Action: "user.created", TargetID: user.ID, TargetType: "user", IPAddress: "::1", UserAgent: "ua", Outcome: "success", DetailsJSON: `{"k":"Ü"}`, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, q := range []string{
		`INSERT INTO alerts(id,rule,key,severity,status,title,summary,count,first_seen,last_seen) VALUES('al-1','r','k','critical','open','t','d',1,?,?)`,
		`INSERT INTO alert_deliveries(alert_id,user_id,kind,status,next_attempt_at,created_at,updated_at) VALUES('al-1','u','opened','pending',?,?,?)`,
		`INSERT INTO alert_deliveries(alert_id,user_id,kind,status,next_attempt_at,created_at,updated_at) VALUES('al-1','v','opened','pending',?,?,?)`,
	} {
		args := []any{now, now, now}[:strings.Count(q, "?")]
		if _, err := s.db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	role, err := s.CreateAppRole(app, "Editors", "edit things", nil)
	if err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.SetAppRoleAssignment(app, role.ID, "users", user.ID, true, nil))
	must(s.SetAppRoleAssignment(app, role.ID, "groups", g.ID, true, nil))
	must(s.SetDelegations(user.ID, Delegations{Helpdesk: true, AppOwner: []string{app}}, nil))
	must(s.CreateApplication(&Application{ID: uuid.NewString(), Name: "Wiki", URL: "https://wiki.test", IconName: "book", Enabled: false, CreatedAt: now}, nil))
	must(s.CreateLauncherIcon(&LauncherIcon{ID: uuid.NewString(), ContentType: "image/png", Data: []byte{1, 2, 3}, CreatedAt: now}, nil))
	must(s.SetLauncherPrefs(user.ID, LauncherPrefs{Layout: "tiles", Groups: []LauncherGroup{{Name: "Wörk", Apps: []string{"client:client-1"}}}, Hidden: []string{}}))
	if _, ok, err := s.AcquireLease("fixture", time.Hour); err != nil || !ok {
		t.Fatal("lease", ok, err)
	}
	if _, err := s.AllowRate("login:1.2.3.4", 5, 1, now, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetRelayKey("push-relay-a.key", "v2:sealed-relay-key", 0); err != nil {
		t.Fatal(err)
	}
	must(s.UpsertNativeDevice(&NativeDevice{ID: uuid.NewString(), UserID: user.ID, DeviceName: "Phone", DeviceIdentifier: "dev-1", Platform: "android", PushTransport: "fcm", AttestedLevel: "none", IsMFAApprover: true}))
	must(s.CreateWebAuthnCredential(&WebAuthnCredential{ID: uuid.NewString(), UserID: admin.ID, CredentialID: "cred-1", PublicKeySPKI: "spki", Name: "Key", BackupEligible: true}, nil))
	must(s.SaveSCIMUserLink("hr", user.ID, "remote-1"))
	if _, err := s.CreateReconcileJob("hr", "preview", admin.ID, nil); err != nil {
		t.Fatal(err)
	}
	inbound, err := s.CreateSCIMConnector("Inbound", nil)
	if err != nil {
		t.Fatal(err)
	}
	// The rest have no method that writes them outside a longer flow.
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO recovery_codes(id,user_id,code_hash,used_at,created_at) VALUES('rc-1',?,'h1',NULL,?),('rc-2',?,'h2',?,?)`, []any{user.ID, now, user.ID, now, now}},
		{`INSERT INTO device_signon_jtis(jti,expires_at) VALUES('jti-x',?)`, []any{now.Add(time.Minute)}},
		{`INSERT INTO sync_delivery_attempts(system_id,user_id,token,event_id,event_type,started_at,recover_after) VALUES('hr',?,'tok','ev-0','user.updated',?,?)`, []any{user.ID, now, now}},
		{`INSERT INTO enrollment_deadlines(user_id,scope,due_at) SELECT ?, scope, 1700000000 FROM enrollment_policies LIMIT 1`, []any{user.ID}},
		{`INSERT INTO scim_connector_tokens(id,connector_id,token_hash,scope,created_at) VALUES('sct-1',?,'th','write',?)`, []any{inbound.ID, now}},
		{`INSERT INTO access_requests(id,app_id,user_id,reason,status,created_at,expires_at) VALUES('ar-1',?,?,'need it','pending',?,1900000000)`, []any{app, user.ID, now}},
		{`INSERT INTO installer_setup_resources(kind,name,setup_id,object_id,contract) VALUES('group','Ops','setup-1','obj-1','c')`, nil},
	} {
		if _, err := s.db.Exec(q.sql, q.args...); err != nil {
			t.Fatalf("%s: %v", q.sql[:40], err)
		}
	}
	seedEphemeral(t, s, user.ID, "client-1")
}

// openSQLiteForTest opens a SQLite file read-only, whatever backend the suite runs on.
func openSQLiteForTest(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// dump reads every table as sorted rows of normalised values. Times compare at the
// microsecond Postgres keeps; a TEXT value compares by content whether stored as text or blob.
func dump(t *testing.T, db querier, cat catalog) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for name, tbl := range cat {
		if name == "schema_migrations" {
			continue
		}
		cols := colNames(tbl.cols)
		for i := range cols {
			cols[i] = quoteIdent(cols[i])
		}
		rows, err := db.Query(`SELECT ` + strings.Join(cols, ",") + ` FROM ` + quoteIdent(name))
		if err != nil {
			t.Fatal(err)
		}
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		lines := []string{}
		for rows.Next() {
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			parts := make([]string, len(vals))
			for i, v := range vals {
				switch x := v.(type) {
				case nil:
					parts[i] = "NULL"
				case time.Time:
					parts[i] = "T" + x.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
				case []byte:
					parts[i] = "S" + string(x)
				case string:
					parts[i] = "S" + x
				case bool:
					parts[i] = map[bool]string{false: "0", true: "1"}[x]
				default:
					parts[i] = fmt.Sprint(x)
				}
			}
			lines = append(lines, strings.Join(parts, "\x1f"))
		}
		rows.Close()
		slices.Sort(lines)
		out[name] = lines
	}
	return out
}

func compareDumps(t *testing.T, want, got map[string][]string) (empty []string) {
	t.Helper()
	for _, name := range slices.Sorted(maps.Keys(want)) {
		if len(want[name]) == 0 {
			empty = append(empty, name)
		}
		if !slices.Equal(want[name], got[name]) {
			t.Errorf("table %s differs:\n first %q\n last  %q", name, want[name], got[name])
		}
	}
	if len(got) != len(want) {
		t.Errorf("%d tables before, %d after", len(want), len(got))
	}
	return empty
}

// testPostgres opens the test schema for path without migrating, after an import made it.
func testPostgres(t *testing.T, path string) *Store {
	t.Helper()
	s, err := newTestPostgres(testDatabaseURL(), path, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func testURL(t *testing.T, path string) string {
	t.Helper()
	u, err := PostgresURLForTest(path)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func liteCatalogFor(t *testing.T, db querier, pg catalog) catalog {
	t.Helper()
	c, err := sqliteCatalog(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := matchCatalogs(c, pg); err != nil {
		t.Fatal(err)
	}
	return c
}

func pgCatalogFor(t *testing.T, s *Store) catalog {
	t.Helper()
	c, err := pgCatalog(s.db)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// SQLite -> Postgres -> SQLite and Postgres -> SQLite -> Postgres keep every row of every
// table.
func TestCopyRoundTripIsLossless(t *testing.T) {
	requirePostgres(t)
	dir := t.TempDir()
	first, last := filepath.Join(dir, "first.db"), filepath.Join(dir, "last.db")
	lite, err := newSQLite(first)
	if err != nil {
		t.Fatal(err)
	}
	copyFixture(t, lite)
	lite.Close()
	pgPath := filepath.Join(dir, "pg")
	if _, err := ImportSQLite(testURL(t, pgPath), first, ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	pg := testPostgres(t, pgPath)
	if err := pg.SnapshotTo(last); err != nil {
		t.Fatal(err)
	}
	pgCat := pgCatalogFor(t, pg)
	a, b := openSQLiteForTest(t, first), openSQLiteForTest(t, last)
	empty := compareDumps(t, dump(t, a, liteCatalogFor(t, a, pgCat)), dump(t, b, liteCatalogFor(t, b, pgCat)))
	// Every table must hold a row, so a table the copy skipped loses data and fails above.
	if len(empty) > 0 {
		t.Errorf("the fixture leaves %v empty; give each a row", empty)
	}
	t.Logf("SQLite round trip: %d tables, every one with rows", len(pgCat)-1)

	// The other way: a store populated on Postgres, out to SQLite and into a fresh schema.
	origin, err := New(filepath.Join(dir, "origin"))
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	copyFixture(t, origin)
	mid := filepath.Join(dir, "mid.db")
	if err := origin.SnapshotTo(mid); err != nil {
		t.Fatal(err)
	}
	backPath := filepath.Join(dir, "back")
	if _, err := ImportSQLite(testURL(t, backPath), mid, ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	back := testPostgres(t, backPath)
	empty = compareDumps(t, dump(t, origin.db, pgCatalogFor(t, origin)), dump(t, back.db, pgCatalogFor(t, back)))
	if len(empty) > 0 {
		t.Errorf("Postgres round trip: the fixture leaves %v empty", empty)
	}
}

// liteFixture writes a SQLite file holding copyFixture's rows and returns its path.
func liteFixture(t *testing.T, path string) string {
	t.Helper()
	s, err := newSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	copyFixture(t, s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// rawSQLite edits a SQLite file with foreign keys off.
func rawSQLite(t *testing.T, path string, queries ...string) {
	t.Helper()
	db, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(0)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range queries {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

// withOrphan copies src and adds a row Postgres refuses to the table copied last.
func withOrphan(t *testing.T, src, dest string) string {
	t.Helper()
	if err := copyFile(src, dest); err != nil {
		t.Fatal(err)
	}
	rawSQLite(t, dest, `INSERT INTO oidc_client_sessions(sid,client_id,session_id,user_id,created_at) VALUES('orphan','client-1','no-such-session','nobody','2026-01-01 00:00:00')`)
	return dest
}

func pgDump(t *testing.T, s *Store) map[string][]string {
	t.Helper()
	return dump(t, s.db, pgCatalogFor(t, s))
}

// schemaObjects counts the relations in the schema a test URL points at.
func schemaObjects(t *testing.T, rawURL string) int {
	t.Helper()
	db, err := sql.Open("kypg", rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pg_class WHERE relnamespace=current_schema()::regnamespace`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Writes committed while an export runs are in it whole or not at all: each writer
// transaction inserts a pair of rows in two tables the export copies at different times.
func TestExportIsAConsistentSnapshot(t *testing.T) {
	requirePostgres(t)
	s, cleanup := setupTestStore(t)
	defer cleanup()
	var stop atomic.Bool
	var next atomic.Int64
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				key := fmt.Sprintf("pair-%d", next.Add(1))
				if err := s.inTx(func(tx *sql.Tx) error {
					if _, err := tx.Exec(`INSERT INTO leases(name,token,until_ms) VALUES(?,'x',0)`, key); err != nil {
						return err
					}
					_, err := tx.Exec(`INSERT INTO system_settings(key,value,updated_at) VALUES(?,'x',?)`, key, time.Now().UTC())
					return err
				}); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	defer func() { stop.Store(true); wg.Wait() }()
	read := func(db *sql.DB, q string) map[string]bool {
		rows, err := db.Query(q)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]bool{}
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				t.Fatal(err)
			}
			out[k] = true
		}
		return out
	}
	for i := range 5 {
		path := filepath.Join(t.TempDir(), fmt.Sprintf("snap-%d.db", i))
		before := next.Load()
		if err := s.SnapshotTo(path); err != nil {
			t.Fatal(err)
		}
		db := openSQLiteForTest(t, path)
		leases := read(db, `SELECT name FROM leases WHERE name LIKE 'pair-%'`)
		settings := read(db, `SELECT key FROM system_settings WHERE key LIKE 'pair-%'`)
		if !maps.Equal(leases, settings) {
			t.Fatalf("export %d holds half a transaction: %d lease rows, %d setting rows", i, len(leases), len(settings))
		}
		t.Logf("export %d: %d whole pairs, %d writes ran during it", i, len(leases), next.Load()-before)
	}
}

// The exported file is a SQLite install: it opens without the legacy migration, finds a
// user by a case-different name and has the triggers and views of a fresh install.
func TestExportedFileIsAWorkingSQLiteInstall(t *testing.T) {
	requirePostgres(t)
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUserNamed(t, s, "Mixed.Case")
	dir := t.TempDir()
	path := filepath.Join(dir, "export.db")
	if err := s.SnapshotTo(path); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot mode %v %v, want 0600", fi.Mode().Perm(), err)
	}
	if left, _ := filepath.Glob(path + "-*"); len(left) != 0 {
		t.Fatalf("the snapshot left %v beside it", left)
	}
	runs := legacyRuns.Load()
	lite, err := newSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lite.Close()
	if legacyRuns.Load() != runs {
		t.Fatal("opening the exported file ran the legacy migration")
	}
	got, err := lite.GetUserByUsername("mIXED.cASE")
	if err != nil || got == nil || got.ID != u.ID {
		t.Fatalf("user by a case-different name: %+v %v", got, err)
	}
	var versions string
	if err := lite.db.QueryRow(`SELECT group_concat(version||':'||name) FROM schema_migrations`).Scan(&versions); err != nil || versions != "1:legacy" {
		t.Fatalf("schema_migrations %q %v", versions, err)
	}
	fresh, err := newSQLite(filepath.Join(dir, "fresh.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	objects := func(s *Store) string {
		var names string
		if err := s.db.QueryRow(`SELECT group_concat(type||' '||name, ', ') FROM (SELECT type, name FROM sqlite_master WHERE type IN ('trigger','view','index') ORDER BY 1, 2)`).Scan(&names); err != nil {
			t.Fatal(err)
		}
		return names
	}
	if a, b := objects(lite), objects(fresh); a != b || !strings.Contains(a, "trigger ") {
		t.Fatalf("exported file's triggers, views and indexes:\n%s\nfresh install's:\n%s", a, b)
	}
}

// An import that fails part-way leaves nothing behind, and a database holding rows is
// refused without a change.
func TestImportLeavesPostgresUnchangedOnFailure(t *testing.T) {
	requirePostgres(t)
	dir := t.TempDir()
	src := liteFixture(t, filepath.Join(dir, "src.db"))
	bad := withOrphan(t, src, filepath.Join(dir, "bad.db"))
	url := testURL(t, filepath.Join(dir, "pg"))
	if _, err := ImportSQLite(url, bad, ImportOptions{}); err == nil || !strings.Contains(err.Error(), "oidc_client_sessions") {
		t.Fatalf("an orphan row in the last table: %v", err)
	}
	if n := schemaObjects(t, url); n != 0 {
		t.Fatalf("a failed import into a fresh database left %d relations", n)
	}
	if _, err := ImportSQLite(url, src, ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	pg := testPostgres(t, filepath.Join(dir, "pg"))
	before := pgDump(t, pg)

	// A file whose rows conflict with nothing: only the guard can refuse it.
	other := filepath.Join(dir, "other.db")
	o, err := newSQLite(other)
	if err != nil {
		t.Fatal(err)
	}
	o.Close()
	rawSQLite(t, other, `DELETE FROM enrollment_policies`, `DELETE FROM system_settings`,
		`INSERT INTO users(id,username,display_name,email,password_hash,role,status) VALUES('u-other','other','Other','other@test.invalid','x','user','active')`)
	if _, err := ImportSQLite(url, other, ImportOptions{}); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("an import over rows: %v", err)
	}
	compareDumps(t, before, pgDump(t, pg))
}

// -replace-database's import replaces every row in one transaction; a failure part-way
// keeps the old rows.
func TestImportReplaceIsOneTransaction(t *testing.T) {
	requirePostgres(t)
	dir := t.TempDir()
	src := liteFixture(t, filepath.Join(dir, "src.db"))
	small := filepath.Join(dir, "small.db")
	sm, err := newSQLite(small)
	if err != nil {
		t.Fatal(err)
	}
	createTestUserNamed(t, sm, "only-here")
	sm.Close()

	url := testURL(t, filepath.Join(dir, "pg"))
	if _, err := ImportSQLite(url, src, ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportSQLite(url, small, ImportOptions{Replace: true}); err != nil {
		t.Fatal(err)
	}
	pg := testPostgres(t, filepath.Join(dir, "pg"))
	refURL := testURL(t, filepath.Join(dir, "ref"))
	if _, err := ImportSQLite(refURL, small, ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	replaced := pgDump(t, pg)
	compareDumps(t, pgDump(t, testPostgres(t, filepath.Join(dir, "ref"))), replaced)

	bad := withOrphan(t, src, filepath.Join(dir, "bad.db"))
	if _, err := ImportSQLite(url, bad, ImportOptions{Replace: true}); err == nil {
		t.Fatal("a replace with an orphan row succeeded")
	}
	compareDumps(t, replaced, pgDump(t, pg))
}

// Imported rows keep their rowid and ids; new rows are numbered after them.
func TestImportMovesIdentitiesPastImportedRows(t *testing.T) {
	requirePostgres(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "src.db")
	s, err := newSQLite(src)
	if err != nil {
		t.Fatal(err)
	}
	u := createTestUser(t, s)
	provisioningFixture(t, s, "hr")
	for i := range 4 {
		if err := s.CreateAccountSyncEvent(&AccountSyncEvent{ID: fmt.Sprintf("ev-%d", i), UserID: u.ID, SystemID: "hr", EventType: "user.updated", PayloadJSON: "{}", Status: "delivered"}); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	if _, err := s.db.Exec(`DELETE FROM account_sync_events WHERE id='ev-1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO alerts(id,rule,key,severity,status,title,summary,first_seen,last_seen) VALUES('al','r','k','warning','open','t','s',?,?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO alert_deliveries(id,alert_id,user_id,kind,status,next_attempt_at,created_at,updated_at) VALUES(9,'al','u','opened','pending',?,?,?)`, now, now, now); err != nil {
		t.Fatal(err)
	}
	var wantRowids string
	if err := s.db.QueryRow(`SELECT group_concat(id||'@'||rowid) FROM (SELECT id, rowid FROM account_sync_events ORDER BY rowid)`).Scan(&wantRowids); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := ImportSQLite(testURL(t, filepath.Join(dir, "pg")), src, ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	pg := testPostgres(t, filepath.Join(dir, "pg"))
	var gotRowids string
	if err := pg.db.QueryRow(`SELECT string_agg(id||'@'||rowid, ',' ORDER BY rowid) FROM account_sync_events`).Scan(&gotRowids); err != nil {
		t.Fatal(err)
	}
	if gotRowids != wantRowids {
		t.Fatalf("rowids on Postgres %s, on SQLite %s", gotRowids, wantRowids)
	}
	if err := pg.CreateAccountSyncEvent(&AccountSyncEvent{ID: "ev-new", UserID: u.ID, SystemID: "hr", EventType: "user.updated", PayloadJSON: "{}", Status: "pending"}); err != nil {
		t.Fatal("a new event after the import:", err)
	}
	var order string
	if err := pg.db.QueryRow(`SELECT string_agg(id, ',' ORDER BY rowid) FROM account_sync_events`).Scan(&order); err != nil || order != "ev-0,ev-2,ev-3,ev-new" {
		t.Fatalf("events by rowid: %q %v", order, err)
	}
	var id int64
	if err := pg.db.QueryRow(`INSERT INTO alert_deliveries(alert_id,user_id,kind,status,next_attempt_at,created_at,updated_at) VALUES('al','v','opened','pending',?,?,?) RETURNING id`, now, now, now).Scan(&id); err != nil || id <= 9 {
		t.Fatalf("a new alert delivery got id %d (%v), want above 9", id, err)
	}
}

// dirState is every file in dir with its content hash.
func dirState(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = fmt.Sprintf("%x", sha256.Sum256(b))
	}
	return out
}

// The import reads its file and nothing else: a versioned file is opened read-only, an
// unversioned one is brought up to date on a copy, and a newer one is refused by version.
func TestImportNeverWritesTheFile(t *testing.T) {
	requirePostgres(t)
	srcDir := t.TempDir()
	src := liteFixture(t, filepath.Join(srcDir, "kyidentity.db"))
	before := dirState(t, srcDir)
	if _, err := ImportSQLite(testURL(t, filepath.Join(t.TempDir(), "pg")), src, ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	if after := dirState(t, srcDir); !maps.Equal(before, after) {
		t.Fatalf("the import changed the source directory: %v -> %v", before, after)
	}

	legacyDir := t.TempDir()
	legacy := filepath.Join(legacyDir, "old.db")
	s, err := newSQLite(legacy)
	if err != nil {
		t.Fatal(err)
	}
	u := createTestUserNamed(t, s, "Legacy.User")
	forgetSchemaVersions(t, s)
	s.Close()
	before = dirState(t, legacyDir)
	runs := legacyRuns.Load()
	pgPath := filepath.Join(t.TempDir(), "pg")
	if _, err := ImportSQLite(testURL(t, pgPath), legacy, ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	if legacyRuns.Load() != runs+1 {
		t.Fatal("an unversioned file was not brought up to date once")
	}
	if after := dirState(t, legacyDir); !maps.Equal(before, after) {
		t.Fatalf("the import changed the unversioned file's directory: %v -> %v", before, after)
	}
	if got, err := testPostgres(t, pgPath).GetUserByUsername("legacy.user"); err != nil || got == nil || got.ID != u.ID {
		t.Fatalf("the unversioned file's user: %+v %v", got, err)
	}

	rawSQLite(t, src, `INSERT INTO schema_migrations(version,name,applied_at) VALUES(99,'future','2030-01-01 00:00:00')`)
	_, err = ImportSQLite(testURL(t, filepath.Join(t.TempDir(), "pg")), src, ImportOptions{})
	if err == nil || !strings.Contains(err.Error(), "[1 99]") || !strings.Contains(err.Error(), "knows [1]") {
		t.Fatalf("a file at a newer schema version: %v", err)
	}
}

// Foreign keys that form a cycle have no insert order; the copy refuses rather than guess.
func TestFKOrderRefusesACycle(t *testing.T) {
	order, err := fkOrder(catalog{"a": {refs: []string{"b"}}, "b": {refs: []string{"c"}}, "c": {}, "d": {refs: []string{"a"}}})
	if err != nil || strings.Join(order, ",") != "c,b,a,d" {
		t.Fatalf("order %v %v", order, err)
	}
	if _, err := fkOrder(catalog{"a": {refs: []string{"b"}}, "b": {refs: []string{"a"}}, "c": {}}); err == nil || !strings.Contains(err.Error(), "[a b]") {
		t.Fatalf("a cycle: %v", err)
	}
	if _, err := fkOrder(catalog{"a": {refs: []string{"a"}}}); err == nil {
		t.Fatal("a table referencing itself was ordered")
	}
}

// The two schemas must have the same tables and columns, and a difference is named.
func TestMatchCatalogsNamesTheDifference(t *testing.T) {
	cols := func(names ...string) []copyColumn {
		var out []copyColumn
		for _, n := range names {
			out = append(out, copyColumn{name: n})
		}
		return out
	}
	lite := catalog{"users": {cols: cols("id", "name")}, "events": {cols: cols("id"), rowid: true}, "old": {}}
	pg := catalog{"users": {cols: cols("email", "id")}, "events": {cols: cols("id", "rowid"), identity: []string{"rowid"}}, "new": {}}
	err := matchCatalogs(lite, pg)
	if err == nil {
		t.Fatal("different schemas matched")
	}
	for _, want := range []string{"table new exists only on Postgres", "table old exists only on SQLite", "table users has columns [id name] on SQLite and [email id] on Postgres"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q does not say %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "events") {
		t.Errorf("the Postgres rowid identity must stand for SQLite's rowid: %v", err)
	}
}

// The export's last checks refuse a file with a dangling reference.
func TestSQLiteChecksRefuseAnOrphan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "orphan.db")
	s, err := newSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	db, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(0)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := sqliteChecks(db); err != nil {
		t.Fatal("a fresh install failed the checks:", err)
	}
	if _, err := db.Exec(`INSERT INTO sessions(id,user_id,session_token_hash,ip_address,user_agent,expires_at) VALUES('s','nobody','h','::1','ua','2030-01-01 00:00:00')`); err != nil {
		t.Fatal(err)
	}
	if err := sqliteChecks(db); err == nil || !strings.Contains(err.Error(), "sessions") {
		t.Fatalf("an orphan session: %v", err)
	}
}

// A value that does not convert stops the import, naming the table and column, never the value.
func TestImportNamesAValueThatDoesNotConvert(t *testing.T) {
	requirePostgres(t)
	dir := t.TempDir()
	src := liteFixture(t, filepath.Join(dir, "src.db"))
	rawSQLite(t, src, `UPDATE sessions SET expires_at='sometime-secret-ish' WHERE id='sess-1'`)
	url := testURL(t, filepath.Join(dir, "pg"))
	_, err := ImportSQLite(url, src, ImportOptions{})
	if err == nil || !strings.Contains(err.Error(), "table sessions column expires_at") || strings.Contains(err.Error(), "secret-ish") {
		t.Fatalf("an unconvertible time: %v", err)
	}
	if n := schemaObjects(t, url); n != 0 {
		t.Fatalf("the failed import left %d relations", n)
	}
}

// A failed export leaves no file: the snapshot holds every secret.
func TestExportRemovesItsFileOnFailure(t *testing.T) {
	requirePostgres(t)
	s, cleanup := setupTestStore(t)
	defer cleanup()
	if _, err := s.db.Exec(`ALTER TABLE leases ADD COLUMN extra TEXT`); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	err := s.SnapshotTo(filepath.Join(dir, "snap.db"))
	if err == nil || !strings.Contains(err.Error(), "table leases has columns") {
		t.Fatalf("an export across different schemas: %v", err)
	}
	if left := dirNames(t, dir); len(left) != 0 {
		t.Fatalf("the failed export left %v", left)
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

// An export outlasts the pool's idle-in-transaction limit: the snapshot waits while SQLite
// writes, here for longer than a deliberately short limit.
func TestExportOutlastsTheIdleTimeout(t *testing.T) {
	requirePostgres(t)
	path := filepath.Join(t.TempDir(), "idle")
	s, err := newTestPostgres(testDatabaseURL()+"&idle_in_transaction_session_timeout=20", path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.db.Exec(`INSERT INTO leases(name,token,until_ms) SELECT 'l'||g, repeat('x', 200), 0 FROM generate_series(1, 20000) g`); err != nil {
		t.Fatal(err)
	}
	if err := s.SnapshotTo(filepath.Join(t.TempDir(), "snap.db")); err != nil {
		t.Fatal(err)
	}
}
