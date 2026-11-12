package store

import (
	"database/sql"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
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
