package store

import (
	"database/sql"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// The table inventory of the tenancy design (appendix). Every table is in exactly one
// class: org-owned tables carry org_id, derived tables reach an org through the parent
// their foreign key names, and platform tables are global.
var (
	orgOwnedTables = []string{"users", "directory_groups", "group_memberships", "account_sync_events", "audit_events",
		"scim_user_links", "sync_delivery_attempts", "scim_connectors", "logout_deliveries", "sync_resource_state", "alerts",
		"suite_groups", "org_apps"}
	derivedTables = map[string]string{
		"sessions": "users", "login_failures": "users", "native_devices": "users", "device_pairing_tokens": "users",
		"mfa_methods": "users", "mfa_challenges": "users", "mfa_tokens": "users", "recovery_codes": "users",
		"authorization_codes": "users", "issued_tokens": "users", "step_up_tokens": "users", "webauthn_credentials": "users",
		"webauthn_challenges": "users", "step_up_challenges": "users", "app_user_assignments": "users",
		"app_group_assignments": "directory_groups", "oidc_client_sessions": "sessions", "account_tokens": "users",
		"scim_connector_tokens": "scim_connectors", "app_role_user_assignments": "users",
		"app_role_group_assignments": "directory_groups", "admin_delegations": "users", "access_requests": "users",
		"enrollment_deadlines": "users", "alert_queue": "audit_events", "alert_deliveries": "alerts",
		"launcher_prefs": "users", "refresh_families": "issued_tokens", "refresh_tokens": "refresh_families",
		"forward_codes": "users", "forward_sessions": "users", "hr_connections": "scim_connectors",
		"hr_workers": "hr_connections", "suite_group_apps": "suite_groups",
		// A code is bound to a user on approval and cascades with them; a pending one is flow
		// state, like authorization_interactions.
		"device_codes": "users",
		// One sealed directory password per connector and user.
		"ad_passwords": "users",
	}
	platformTables = []string{"schema_migrations", "leases", "installer_setup_resources", "paired_systems",
		"device_signon_jtis", "oauth_clients", "launcher_icons", "applications", "system_settings", "app_registry",
		"authorization_interactions", "app_roles", "enrollment_policies", "sync_reconcile_jobs", "rate_limits",
		"push_relay_keys", "proxy_apps", "workstation_apps", "ad_connectors", "orgs", "platform_tokens", "platform_requests", "platform_events",
		"org_erasures", "erased_subjects"}
)

// testCatalogs is the SQLite catalog of a fresh database, and the Postgres one when the
// suite runs there.
func testCatalogs(t *testing.T) map[string]catalog {
	t.Helper()
	lite, err := newSQLite(filepath.Join(t.TempDir(), "sqlite.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer lite.Close()
	out := map[string]catalog{}
	if out["sqlite"], err = sqliteCatalog(lite.db); err != nil {
		t.Fatal(err)
	}
	if OnPostgresTest() {
		pg, cleanup := setupTestStore(t)
		defer cleanup()
		if out["postgres"], err = pgCatalog(pg.db); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// A new table must say whether it belongs to an org, or deleting an org and scoping the
// store cannot know about it.
func TestEveryTableIsClassified(t *testing.T) {
	for backend, cat := range testCatalogs(t) {
		seen := map[string]int{}
		for _, name := range orgOwnedTables {
			seen[name]++
		}
		for _, name := range platformTables {
			seen[name]++
		}
		for name, parent := range derivedTables {
			seen[name]++
			if tbl := cat[name]; tbl != nil && !slices.Contains(tbl.refs, parent) {
				t.Errorf("%s: derived table %s has no foreign key to %s", backend, name, parent)
			}
		}
		for name, n := range seen {
			if n > 1 {
				t.Errorf("table %s is in %d classes", name, n)
			}
			if cat[name] == nil {
				t.Errorf("%s: classified table %s does not exist", backend, name)
			}
		}
		for _, name := range slices.Sorted(maps.Keys(cat)) {
			if seen[name] == 0 {
				t.Errorf("%s: table %s is not classified as org-owned, derived or platform", backend, name)
			}
		}
	}
}

// Every org-owned table has org_id, NOT NULL except the two named platform-row tables, an
// existence and an immutability trigger, and on Postgres the foreign key to orgs.
func TestOrgOwnedTablesHaveOrgID(t *testing.T) {
	if got := slices.Sorted(maps.Keys(nullableOrgID)); !slices.Equal(got, []string{"alerts", "audit_events"}) {
		t.Fatalf("nullableOrgID is %v; only audit_events and alerts may hold platform rows", got)
	}
	s, cleanup := setupTestStore(t)
	defer cleanup()
	for _, table := range orgOwnedTables {
		var nullable, triggers, fks int
		var err error
		if s.postgres {
			err = s.db.QueryRow(`SELECT
 (SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=$1 AND column_name='org_id' AND is_nullable='YES'),
 (SELECT count(*) FROM pg_trigger g JOIN pg_class c ON c.oid=g.tgrelid WHERE c.relnamespace=current_schema()::regnamespace AND c.relname=$1 AND g.tgname IN ($1||'_org_exists',$1||'_org_immutable')),
 (SELECT count(*) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_class r ON r.oid=k.confrelid JOIN pg_attribute a ON a.attrelid=k.conrelid AND a.attnum=k.conkey[1]
  WHERE k.contype='f' AND c.relnamespace=current_schema()::regnamespace AND c.relname=$1 AND r.relname='orgs' AND cardinality(k.conkey)=1 AND a.attname='org_id')`, table).Scan(&nullable, &triggers, &fks)
		} else {
			fks = 1
			err = s.db.QueryRow(`SELECT (SELECT count(*) FROM pragma_table_info(?1) WHERE name='org_id' AND NOT "notnull"),
 (SELECT count(*) FROM sqlite_master WHERE type='trigger' AND tbl_name=?1 AND name IN (?1||'_org_exists',?1||'_org_immutable'))`, table).Scan(&nullable, &triggers)
		}
		if err != nil {
			t.Fatal(err)
		}
		var hasColumn bool
		if err := s.db.QueryRow(`SELECT COUNT(org_id)>=0 FROM ` + table).Scan(&hasColumn); err != nil {
			t.Errorf("%s has no org_id: %v", table, err)
			continue
		}
		if want := map[bool]int{true: 1}[nullableOrgID[table]]; nullable != want {
			t.Errorf("%s.org_id nullable=%d, want %d", table, nullable, want)
		}
		if triggers != 2 {
			t.Errorf("%s has %d of its two org triggers", table, triggers)
		}
		if fks != 1 {
			t.Errorf("%s.org_id has no foreign key to orgs", table)
		}
	}
}

// tenancyExec runs statements that must succeed.
func tenancyExec(t *testing.T, s *Store, stmts ...string) {
	t.Helper()
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

// refused runs a statement that must fail with an error containing want: a trigger's
// message, or a constraint's. Any other error is a broken test, not a refusal.
func refused(t *testing.T, s *Store, want, q string) {
	t.Helper()
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(q); err == nil {
		t.Errorf("accepted %s", q)
	} else if !strings.Contains(err.Error(), want) {
		t.Errorf("%s: refused with %v, want %q", q, err, want)
	}
}

func newTestOrg(t *testing.T, s *Store, id, status string) {
	t.Helper()
	if _, err := s.db.Exec(`INSERT INTO orgs(id,name,kind,status,created_at,updated_at) VALUES(?,?,'household',?,?,?)`, id, id, status, time.Now().UTC(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
}

func newOrgUser(t *testing.T, s *Store, id, org, status string, pending bool) {
	t.Helper()
	if _, err := s.db.Exec(`INSERT INTO users(id,username,display_name,email,password_hash,role,status,pending,org_id) VALUES(?,?,?,?,'','user',?,?,?)`,
		id, id, id, id+"@test.invalid", status, pending, org); err != nil {
		t.Fatal(err)
	}
}

// An org-owned row names an org that exists, and keeps it.
func TestOrgIDExistsAndNeverChanges(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	newTestOrg(t, s, "org-b", "active")
	u := createTestUserNamed(t, s, "alice")
	var org string
	if err := s.db.QueryRow(`SELECT org_id FROM users WHERE id=?`, u.ID).Scan(&org); err != nil || org != DefaultOrgID {
		t.Fatalf("a new user is in org %q (%v), want the default org", org, err)
	}
	refused(t, s, msgOrgMissing, `INSERT INTO users(id,username,display_name,email,password_hash,role,status,org_id) VALUES('u-x','x','x','x@test.invalid','','user','active','no-such-org')`)
	refused(t, s, msgOrgChanged, `UPDATE users SET org_id='org-b' WHERE id='`+u.ID+`'`)
	refused(t, s, msgOrgMissing, `INSERT INTO directory_groups(id,name,created_at,updated_at,org_id) VALUES('g-x','x',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'no-such-org')`)
	// NULL is a platform audit row: admitted, and fixed once written.
	tenancyExec(t, s, `INSERT INTO audit_events(id,actor_id,actor_username,action,target_id,target_type,ip_address,user_agent,outcome,details_json,created_at,org_id)
 VALUES('ae-platform','','','platform.test','','','','','success','{}',CURRENT_TIMESTAMP,NULL)`)
	refused(t, s, msgOrgChanged, `UPDATE audit_events SET org_id='`+DefaultOrgID+`' WHERE id='ae-platform'`)
	refused(t, s, msgOrgMissing, `INSERT INTO audit_events(id,actor_id,actor_username,action,target_id,target_type,ip_address,user_agent,outcome,details_json,created_at,org_id)
 VALUES('ae-x','','','x','','','','','success','{}',CURRENT_TIMESTAMP,'no-such-org')`)
	tenancyExec(t, s, `UPDATE audit_events SET org_id=NULL WHERE id='ae-platform'`) // unchanged is not a change
}

// The account holder pointer names a live member of its org, and every path that would
// end that member is refused while it does.
func TestAccountHolderGuard(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	newTestOrg(t, s, "org-b", "active")
	newTestOrg(t, s, "org-c", "active")
	newOrgUser(t, s, "holder", "org-b", "disabled", true)
	newOrgUser(t, s, "member", "org-b", "active", false)
	newOrgUser(t, s, "gone", "org-b", "disabled", false)
	newOrgUser(t, s, "other", "org-c", "active", false)

	refused(t, s, msgHolderOnInsert, `INSERT INTO orgs(id,name,kind,status,account_holder_user_id,created_at,updated_at) VALUES('org-d','d','person','active','member',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`)
	refused(t, s, msgHolderNotLive, `UPDATE orgs SET account_holder_user_id='other' WHERE id='org-b'`)
	refused(t, s, msgHolderNotLive, `UPDATE orgs SET account_holder_user_id='gone' WHERE id='org-b'`)
	refused(t, s, msgHolderNotLive, `UPDATE orgs SET account_holder_user_id='nobody' WHERE id='org-b'`)
	// A pending member is live: billing names the holder before they activate.
	tenancyExec(t, s, `UPDATE orgs SET account_holder_user_id='holder' WHERE id='org-b'`)
	// Activation keeps the holder live.
	tenancyExec(t, s, `UPDATE users SET status='active', pending=FALSE WHERE id='holder'`)
	tenancyExec(t, s, `UPDATE users SET display_name='Holder' WHERE id='holder'`)
	refused(t, s, msgHolder, `UPDATE users SET status='disabled' WHERE id='holder'`)
	refused(t, s, msgHolder, `UPDATE users SET ends_at=4102444800 WHERE id='holder'`)
	refused(t, s, msgHolder, `DELETE FROM users WHERE id='holder'`)
	// Moving the pointer frees the old holder.
	tenancyExec(t, s, `UPDATE orgs SET account_holder_user_id='member' WHERE id='org-b'`, `DELETE FROM users WHERE id='holder'`)

	// The pointer is cleared only by the update that deletes the org after its grace period.
	refused(t, s, msgHolderNotLive, `UPDATE orgs SET account_holder_user_id=NULL WHERE id='org-b'`)
	tenancyExec(t, s, `UPDATE orgs SET status='suspended' WHERE id='org-b'`)
	refused(t, s, msgHolderNotLive, `UPDATE orgs SET account_holder_user_id=NULL WHERE id='org-b'`)
	tenancyExec(t, s, `UPDATE orgs SET status='deletion_scheduled', delete_after=4102444800 WHERE id='org-b'`)
	refused(t, s, msgHolderNotLive, `UPDATE orgs SET account_holder_user_id=NULL WHERE id='org-b'`)
	refused(t, s, msgDeleted, `UPDATE orgs SET status='deleted', name='', account_holder_user_id=NULL WHERE id='org-b'`)
	refused(t, s, msgDeleted, `UPDATE orgs SET status='deleted', delete_after=1, account_holder_user_id=NULL WHERE id='org-b'`)
	tenancyExec(t, s, `UPDATE orgs SET delete_after=1 WHERE id='org-b'`,
		`UPDATE orgs SET status='deleted', name='', account_holder_user_id=NULL WHERE id='org-b'`)
	var holder sql.NullString
	if err := s.db.QueryRow(`SELECT account_holder_user_id FROM orgs WHERE id='org-b'`).Scan(&holder); err != nil || holder.Valid {
		t.Fatalf("deleted org still names %v (%v)", holder, err)
	}
}

// deleted is entered only from deletion_scheduled once delete_after has passed, and is
// never left.
func TestOrgDeletedIsGatedAndTerminal(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	for _, status := range []string{"active", "suspended"} {
		newTestOrg(t, s, "org-"+status, status)
		tenancyExec(t, s, `UPDATE orgs SET delete_after=1 WHERE id='org-`+status+`'`)
		refused(t, s, msgDeleted, `UPDATE orgs SET status='deleted' WHERE id='org-`+status+`'`)
	}
	newTestOrg(t, s, "org-b", "deletion_scheduled")
	refused(t, s, msgDeleted, `UPDATE orgs SET status='deleted' WHERE id='org-b'`)
	tenancyExec(t, s, `UPDATE orgs SET delete_after=4102444800 WHERE id='org-b'`)
	refused(t, s, msgDeleted, `UPDATE orgs SET status='deleted' WHERE id='org-b'`)
	tenancyExec(t, s, `UPDATE orgs SET delete_after=1 WHERE id='org-b'`, `UPDATE orgs SET status='deleted' WHERE id='org-b'`)
	for _, status := range []string{"active", "suspended", "deletion_scheduled"} {
		refused(t, s, msgDeleted, `UPDATE orgs SET status='`+status+`' WHERE id='org-b'`)
	}
	refused(t, s, msgDeleted, `UPDATE orgs SET status='deleted' WHERE id='`+DefaultOrgID+`'`)
}

// A suite group is in its directory group's org.
func TestSuiteGroupIsInItsGroupsOrg(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	newTestOrg(t, s, "org-b", "active")
	g := &Group{ID: "g-1", Name: "Team"}
	if err := s.DefaultOrg().CreateGroup(g, nil); err != nil {
		t.Fatal(err)
	}
	refused(t, s, msgSuiteGroupOrg, `INSERT INTO suite_groups(group_id,slug,name,enabled,created_at,updated_at,org_id) VALUES('g-1','team','Team',TRUE,1,1,'org-b')`)
	refused(t, s, msgSuiteGroupOrg, `INSERT INTO suite_groups(org_id, group_id,slug,name,enabled,created_at,updated_at) VALUES('00000000-0000-0000-0000-000000000001', 'g-none','none','None',TRUE,1,1)`)
	if _, err := s.DefaultOrg().SetSuiteGroup(g.ID, true, nil, nil); err != nil {
		t.Fatal("the store's own suite group write:", err)
	}
	refused(t, s, msgOrgChanged, `UPDATE suite_groups SET org_id='org-b' WHERE group_id='g-1'`)
}

// A membership joins a user and a group of one org: the trigger on both backends, and on
// Postgres the composite foreign keys underneath it.
func TestMembershipsCannotSpanOrgs(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	newTestOrg(t, s, "org-b", "active")
	newOrgUser(t, s, "u-b", "org-b", "active", false)
	u := createTestUserNamed(t, s, "alice")
	tenancyExec(t, s, `INSERT INTO directory_groups(id,name,created_at,updated_at,org_id) VALUES('g-b','B team',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'org-b')`,
		`INSERT INTO directory_groups(org_id, id,name,created_at,updated_at) VALUES('00000000-0000-0000-0000-000000000001', 'g-a','A team',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`)
	cross := []string{
		`INSERT INTO group_memberships(org_id, group_id,user_id) VALUES('00000000-0000-0000-0000-000000000001', 'g-b','` + u.ID + `')`,
		`INSERT INTO group_memberships(group_id,user_id,org_id) VALUES('g-b','` + u.ID + `','org-b')`,
		`INSERT INTO group_memberships(group_id,user_id,org_id) VALUES('g-a','u-b','org-b')`,
	}
	for _, q := range cross {
		refused(t, s, msgMembershipOrgs, q)
	}
	if err := s.DefaultOrg().SetGroupMembership("g-a", u.ID, true, nil); err != nil {
		t.Fatal("a same-org membership:", err)
	}
	if err := s.DefaultOrg().SetGroupMembership("g-a", "no-such-user", true, nil); err != ErrGroupTargetMissing {
		t.Fatalf("a missing user is %v, want ErrGroupTargetMissing", err)
	}
	if !s.postgres {
		return
	}
	tenancyExec(t, s, `ALTER TABLE group_memberships DISABLE TRIGGER group_memberships_same_org`)
	defer tenancyExec(t, s, `ALTER TABLE group_memberships ENABLE TRIGGER group_memberships_same_org`)
	for _, q := range cross {
		refused(t, s, "foreign key", q)
	}
}

// pgOnlyKeys are the keys D2 puts on Postgres alone: the org foreign keys SQLite cannot add
// to an existing table, the composite membership keys, and the per-org names, whose global
// uniques SQLite keeps. TestBackendsHaveTheSameUniqueIndexesAndForeignKeys allows exactly these.
var pgOnlyKeys = func() map[string]map[string][]string {
	fks := map[string][]string{"group_memberships": {"org_id -> users CASCADE", "user_id -> users CASCADE", "org_id -> directory_groups CASCADE", "group_id -> directory_groups CASCADE"}}
	for _, table := range orgColumnTables {
		fks[table] = append(fks[table], "org_id -> orgs NO ACTION")
	}
	return map[string]map[string][]string{
		"foreign keys":   fks,
		"unique indexes": {"directory_groups": {"org_id,name"}, "suite_groups": {"org_id,slug"}},
	}
}()

var sqliteOnlyKeys = map[string]map[string][]string{"unique indexes": {"directory_groups": {"name"}, "suite_groups": {"slug"}}}

// withoutKeys removes one of each of drop from have, failing when one is missing, so an
// exception that no longer happens is noticed.
func withoutKeys(t *testing.T, what, table string, have, drop []string) []string {
	t.Helper()
	have = slices.Clone(have)
	for _, d := range drop {
		i := slices.Index(have, d)
		if i < 0 {
			t.Errorf("%s of %s: expected %q, which is gone", what, table, d)
			continue
		}
		have = slices.Delete(have, i, i+1)
	}
	return have
}

// The views answer the same on an install that upgrades into the tenancy version: one org
// with every app changes no row.
func TestTenancyUpgradeKeepsEveryView(t *testing.T) {
	saved := migrations
	t.Cleanup(func() { migrations = saved })
	i := slices.IndexFunc(migrations, func(m migration) bool { return m.name == "tenancy" })
	migrations = saved[:i]
	path := filepath.Join(t.TempDir(), "previous.db")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	// Today's store code names org_id and reads orgs, which the previous schema lacks: lend
	// it both for the fixture and take them back, so the upgrade adds them as it would.
	tenancyExec(t, s, `CREATE TABLE orgs (id TEXT PRIMARY KEY, kind TEXT NOT NULL)`, `INSERT INTO orgs VALUES ('`+DefaultOrgID+`','default')`)
	for _, table := range orgColumnTables {
		tenancyExec(t, s, `ALTER TABLE `+table+` ADD COLUMN org_id TEXT DEFAULT '`+DefaultOrgID+`'`)
	}
	copyFixture(t, s)
	for _, table := range orgColumnTables {
		tenancyExec(t, s, `ALTER TABLE `+table+` DROP COLUMN org_id`)
	}
	tenancyExec(t, s, `DROP TABLE orgs`)
	tenancyExec(t, s, `UPDATE enrollment_policies SET required=TRUE WHERE scope='administrators'`,
		`UPDATE group_memberships SET expires_at=1 WHERE group_id IN (SELECT id FROM directory_groups WHERE name='Staff Ünits')`)
	if err := s.SetSetting(BrandingNameSetting, "Example Household"); err != nil {
		t.Fatal(err)
	}
	before := viewRows(t, s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	migrations = saved
	s, err = New(path)
	if err != nil {
		t.Fatal("upgrade:", err)
	}
	defer s.Close()
	after := viewRows(t, s)
	for _, view := range slices.Sorted(maps.Keys(before)) {
		if len(before[view]) == 0 && view != "live_group_memberships" {
			t.Errorf("view %s is empty before the upgrade, so the comparison proves nothing", view)
		}
		if !slices.Equal(before[view], after[view]) {
			t.Errorf("view %s changed:\n before %q\n after  %q", view, before[view], after[view])
		}
	}
	var name, mode string
	var allApps bool
	if err := s.db.QueryRow(`SELECT name, all_apps FROM orgs WHERE id=? AND kind='default' AND status='active'`, DefaultOrgID).Scan(&name, &allApps); err != nil || name != "Example Household" || !allApps {
		t.Fatalf("default org: %q all_apps=%v (%v)", name, allApps, err)
	}
	if err := s.db.QueryRow(`SELECT value FROM system_settings WHERE key=?`, TenancySetting).Scan(&mode); err != nil || mode != "single" {
		t.Fatalf("tenancy_mode %q (%v)", mode, err)
	}
	for _, table := range orgColumnTables {
		var rows, elsewhere int
		if err := s.db.QueryRow(`SELECT COUNT(*), COUNT(*)-COUNT(CASE WHEN org_id=? THEN 1 END) FROM `+table, DefaultOrgID).Scan(&rows, &elsewhere); err != nil {
			t.Fatal(err)
		}
		if elsewhere != 0 {
			t.Errorf("%s: %d of %d rows are not in the default org", table, elsewhere, rows)
		}
	}
	if got := schemaVersions(t, path); got != v1 {
		t.Fatalf("schema_migrations = %q, want %q", got, v1)
	}
}

// viewRows reads every view as sorted rows.
func viewRows(t *testing.T, s *Store) map[string][]string {
	t.Helper()
	q := `SELECT m.name, p.name FROM sqlite_master m, pragma_table_info(m.name) p WHERE m.type='view' ORDER BY m.name, p.cid`
	if s.postgres {
		q = `SELECT c.table_name, c.column_name FROM information_schema.columns c JOIN information_schema.views v USING (table_schema, table_name) WHERE c.table_schema=current_schema() ORDER BY 1, c.ordinal_position`
	}
	cat := catalog{}
	if err := readPairs(s.db, q, func(view, col string) error {
		cat.table(view).cols = append(cat.table(view).cols, copyColumn{name: col})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(cat) < 7 {
		t.Fatalf("only %d views read", len(cat))
	}
	return dump(t, s.db, cat)
}

func hasTenancy() bool {
	return slices.ContainsFunc(migrations, func(m migration) bool { return m.name == "tenancy" })
}

// tenancyFixture gives each tenancy table a row, when the schema has them.
func tenancyFixture(t *testing.T, s *Store, appID string) {
	t.Helper()
	if !hasTenancy() {
		return
	}
	now := time.Now().UTC()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO org_apps(org_id,app_id,enabled,access_mode,quotas_json) VALUES(?,?,TRUE,NULL,'{"storage_gb":5}')`, []any{DefaultOrgID, appID}},
		{`INSERT INTO platform_tokens(id,name,token_hash,scopes,created_at,expires_at) VALUES('pt-1','Billing','pth','orgs:read orgs:write',?,?)`, []any{now, now.Add(time.Hour)}},
		{`INSERT INTO platform_requests(token_id,idempotency_key,request_hash,status,response_json,created_at) VALUES('pt-1','key-1','rh',200,'{}',?)`, []any{now}},
		{`INSERT INTO platform_events(id,org_id,type,payload_json,status,next_attempt_at,created_at) VALUES('pe-1',?,'org.created','{}','queued',?,?)`, []any{DefaultOrgID, now, now}},
	} {
		if _, err := s.db.Exec(q.sql, q.args...); err != nil {
			t.Fatalf("%s: %v", strings.Fields(q.sql)[2], err)
		}
	}
	var n int
	if s.db.QueryRow(`SELECT COUNT(*) FROM org_erasures`).Scan(&n) != nil {
		return // a schema from before Delete everything
	}
	// A household whose holder asked for Delete everything, and one erased subject.
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO orgs(id,name,kind,status,created_at,updated_at) VALUES('org-erasing','Erasing','household','active',?,?)`, []any{now, now}},
		{`INSERT INTO users(id,username,display_name,email,password_hash,role,status,org_id) VALUES('erasing-holder','erasing-holder','H','erasing-holder@test.invalid','','user','active','org-erasing')`, nil},
		{`INSERT INTO users(id,username,display_name,email,password_hash,role,status,org_id) VALUES('erasing-kid','erasing-kid','K','erasing-kid@test.invalid','','user','active','org-erasing')`, nil},
		{`UPDATE orgs SET account_holder_user_id='erasing-holder' WHERE id='org-erasing'`, nil},
		{`INSERT INTO org_erasures(org_id,holder_user_id,immediate,requested_at) VALUES('org-erasing','erasing-holder',FALSE,?)`, []any{now}},
		{`INSERT INTO erased_subjects(subject,org_id,revision,erased_at) VALUES('erased-1','org-erasing',1,?)`, []any{now}},
	} {
		if _, err := s.db.Exec(q.sql, q.args...); err != nil {
			t.Fatalf("%s: %v", q.sql, err)
		}
	}
}

// An app reaches a user only through the user's org: every app for the default org, and
// for any other org only an enabled org_apps row, whose access mode overrides the app's.
func TestAppAccessGoesThroughTheOrg(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	if err := s.CreateOAuthClient(&OAuthClient{ID: "c-open", ClientName: "Open", ClientType: "public", RedirectURIsJSON: `["https://open.test/cb"]`, AllowedScopesJSON: `["openid"]`, Enabled: true}, nil); err != nil {
		t.Fatal(err)
	}
	var app string
	if err := s.db.QueryRow(`SELECT id FROM app_registry WHERE client_id='c-open'`).Scan(&app); err != nil {
		t.Fatal(err)
	}
	tenancyExec(t, s, `UPDATE app_registry SET access_mode='all_active_users' WHERE id='`+app+`'`)
	newTestOrg(t, s, "org-b", "active")
	newOrgUser(t, s, "u-b", "org-b", "active", false)
	a := createTestUserNamed(t, s, "alice")
	allowed := func(user string) bool {
		t.Helper()
		var n int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM effective_app_access WHERE app_id=? AND user_id=?`, app, user).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}
	if !allowed(a.ID) || allowed("u-b") {
		t.Fatalf("all-users app: default org user %v, org-b user %v; want true, false", allowed(a.ID), allowed("u-b"))
	}
	tenancyExec(t, s, `INSERT INTO org_apps(org_id,app_id,enabled) VALUES('org-b','`+app+`',FALSE)`)
	if allowed("u-b") {
		t.Fatal("a disabled org_apps row gave access")
	}
	tenancyExec(t, s, `UPDATE org_apps SET enabled=TRUE WHERE org_id='org-b'`)
	if !allowed("u-b") {
		t.Fatal("an enabled org_apps row gave no access")
	}
	tenancyExec(t, s, `UPDATE org_apps SET access_mode='assigned_only' WHERE org_id='org-b'`)
	if allowed("u-b") || !allowed(a.ID) {
		t.Fatal("the org's access mode did not override the app's for that org alone")
	}
}

// active_principals holds active, unended users of active orgs.
func TestActivePrincipalsNeedAnActiveOrg(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	newTestOrg(t, s, "org-b", "suspended")
	newOrgUser(t, s, "u-b", "org-b", "active", false)
	newOrgUser(t, s, "u-pending", DefaultOrgID, "disabled", true)
	newOrgUser(t, s, "u-ended", DefaultOrgID, "active", false)
	tenancyExec(t, s, `UPDATE users SET ends_at=1 WHERE id='u-ended'`)
	a := createTestUserNamed(t, s, "alice")
	var got []string
	if err := readPairs(s.db, `SELECT id, org_id FROM active_principals ORDER BY id`, func(id, _ string) error {
		got = append(got, id)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{a.ID}) {
		t.Fatalf("active_principals = %v, want only %s", got, a.ID)
	}
}
