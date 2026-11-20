package store

import (
	"database/sql"
	"fmt"
	"strings"
)

// Tenancy (design: docs/superpowers/specs/2026-11-19-tenancy-design.md, build plan PR 1).
// Every org-owned row carries org_id. A single-tenant install has one org, DefaultOrgID,
// with all_apps set, so every view answers as before. Store code does not name org_id yet:
// the column default puts each new row in the default org until the store is org-bound.

// DefaultOrgID is the single-tenant org. Fixed, so a later conversion can find it.
const DefaultOrgID = "00000000-0000-0000-0000-000000000001"

// TenancySetting is the system_settings row recording the install's tenancy mode.
const TenancySetting = "tenancy_mode"

// orgColumnTables get org_id NOT NULL; audit_events and alerts keep it nullable, where NULL
// is a platform row. org_apps has org_id in its primary key and is created with it.
var (
	orgColumnTables = []string{"users", "directory_groups", "group_memberships", "account_sync_events", "audit_events",
		"scim_user_links", "sync_delivery_attempts", "scim_connectors", "logout_deliveries", "sync_resource_state", "alerts", "suite_groups"}
	nullableOrgID = map[string]bool{"audit_events": true, "alerts": true}
)

// liveHolder is the account holder predicate over a users row: pending or activated, not
// ended. A pending account is stored disabled, so status alone would refuse activation.
func liveHolder(u string) string {
	return "(" + u + ".pending OR " + u + ".status='active') AND " + u + ".ends_at IS NULL"
}

func tenancyTablesSQL(ts, num string) string {
	return `CREATE TABLE IF NOT EXISTS orgs (
 id TEXT PRIMARY KEY, name TEXT NOT NULL,
 kind TEXT NOT NULL CHECK (kind IN ('default','person','household','staff')),
 status TEXT NOT NULL CHECK (status IN ('active','suspended','deletion_scheduled','deleted')),
 status_reason TEXT NOT NULL DEFAULT '' CHECK (status_reason IN ('','payment','abuse','operator')),
 all_apps BOOLEAN NOT NULL DEFAULT FALSE, plan TEXT NOT NULL DEFAULT '', max_seats ` + num + ` NOT NULL DEFAULT 0,
 account_holder_user_id TEXT, billing_ref TEXT UNIQUE, create_request_hash TEXT,
 billing_revision ` + num + ` NOT NULL DEFAULT 0, revision ` + num + ` NOT NULL DEFAULT 1, delete_after ` + num + `,
 created_at ` + ts + ` NOT NULL, updated_at ` + ts + ` NOT NULL);
CREATE INDEX IF NOT EXISTS orgs_account_holder ON orgs(account_holder_user_id);
INSERT INTO orgs(id,name,kind,status,all_apps,created_at,updated_at)
 SELECT '` + DefaultOrgID + `', COALESCE((SELECT value FROM system_settings WHERE key='branding_org_name' AND value<>''),'Organisation'), 'default', 'active', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
 WHERE NOT EXISTS(SELECT 1 FROM orgs WHERE id='` + DefaultOrgID + `');
CREATE TABLE IF NOT EXISTS org_apps (
 org_id TEXT NOT NULL REFERENCES orgs(id), app_id TEXT NOT NULL REFERENCES app_registry(id) ON DELETE CASCADE,
 enabled BOOLEAN NOT NULL DEFAULT FALSE, access_mode TEXT CHECK (access_mode IN ('assigned_only','all_active_users')),
 quotas_json TEXT NOT NULL DEFAULT '{}', PRIMARY KEY(org_id,app_id));
CREATE TABLE IF NOT EXISTS platform_tokens (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, scopes TEXT NOT NULL,
 created_at ` + ts + ` NOT NULL, expires_at ` + ts + ` NOT NULL, last_used_at ` + ts + `, revoked_at ` + ts + `);
CREATE TABLE IF NOT EXISTS platform_requests (
 token_id TEXT NOT NULL REFERENCES platform_tokens(id) ON DELETE CASCADE, idempotency_key TEXT NOT NULL,
 request_hash TEXT NOT NULL, status ` + num + ` NOT NULL, response_json TEXT NOT NULL, created_at ` + ts + ` NOT NULL,
 PRIMARY KEY(token_id,idempotency_key));
CREATE TABLE IF NOT EXISTS platform_events (
 id TEXT PRIMARY KEY, org_id TEXT NOT NULL, type TEXT NOT NULL, payload_json TEXT NOT NULL,
 status TEXT NOT NULL CHECK (status IN ('queued','delivered','failed')), attempts ` + num + ` NOT NULL DEFAULT 0,
 next_attempt_at ` + ts + ` NOT NULL, lease_until ` + ts + `, claim_token TEXT NOT NULL DEFAULT '', created_at ` + ts + ` NOT NULL);
CREATE INDEX IF NOT EXISTS idx_platform_events_due ON platform_events(status, next_attempt_at);
INSERT INTO system_settings(key,value,updated_at) SELECT '` + TenancySetting + `','single',CURRENT_TIMESTAMP
 WHERE NOT EXISTS(SELECT 1 FROM system_settings WHERE key='` + TenancySetting + `');`
}

// orgKeysSQL runs once org_id exists: the keys composite foreign keys reference.
const orgKeysSQL = `CREATE UNIQUE INDEX IF NOT EXISTS users_org_id ON users(org_id,id);
CREATE UNIQUE INDEX IF NOT EXISTS directory_groups_org_id ON directory_groups(org_id,id);
`

// The checks every trigger makes, as SQL conditions that refuse when true. now is the
// backend's unix-seconds clock.
func tenancyRefusals(now string) map[string]string {
	return map[string]string{
		"org_missing":       `NEW.org_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM orgs WHERE id=NEW.org_id)`,
		"org_changed":       `NEW.org_id IS DISTINCT FROM OLD.org_id`,
		"holder_deleted":    `EXISTS(SELECT 1 FROM orgs WHERE account_holder_user_id=OLD.id)`,
		"holder_not_live":   `EXISTS(SELECT 1 FROM orgs WHERE account_holder_user_id=OLD.id) AND NOT (` + liveHolder("NEW") + ` AND NEW.org_id IS NOT DISTINCT FROM OLD.org_id)`,
		"holder_on_insert":  `NEW.account_holder_user_id IS NOT NULL`,
		"holder_bad_change": `NEW.account_holder_user_id IS DISTINCT FROM OLD.account_holder_user_id AND CASE WHEN NEW.account_holder_user_id IS NULL THEN NOT (OLD.status='deletion_scheduled' AND NEW.status='deleted') ELSE NOT EXISTS(SELECT 1 FROM users u WHERE u.id=NEW.account_holder_user_id AND u.org_id=NEW.id AND ` + liveHolder("u") + `) END`,
		"status_bad_change": `NEW.status IS DISTINCT FROM OLD.status AND (OLD.status='deleted' OR NEW.status='deleted' AND NOT (OLD.status='deletion_scheduled' AND OLD.delete_after IS NOT NULL AND OLD.delete_after<=` + now + `))`,
		"membership_orgs":   `EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id AND org_id IS DISTINCT FROM NEW.org_id) OR EXISTS(SELECT 1 FROM directory_groups WHERE id=NEW.group_id AND org_id IS DISTINCT FROM NEW.org_id)`,
		"suite_group_org":   `NOT EXISTS(SELECT 1 FROM directory_groups WHERE id=NEW.group_id AND org_id=NEW.org_id)`,
	}
}

// What each trigger raises. ponytail: map msgHolder to an ErrAccountHolder when a path can set the pointer.
const (
	msgOrgMissing     = "org does not exist"
	msgOrgChanged     = "org_id cannot change"
	msgHolder         = "the account holder cannot be deleted, disabled or ended"
	msgHolderOnInsert = "a new org has no account holder"
	msgHolderNotLive  = "the account holder must be a live member of the org"
	msgDeleted        = "deleted is entered only from deletion_scheduled after delete_after, and never left"
	msgMembershipOrgs = "user and group are in different orgs"
	msgSuiteGroupOrg  = "a suite group must be in the org of its group"
)

type tenancyTrigger struct{ name, timing, table, refusal, message string }

func tenancyTriggers() []tenancyTrigger {
	var out []tenancyTrigger
	for _, t := range append(append([]string{}, orgColumnTables...), "org_apps") {
		out = append(out,
			tenancyTrigger{t + "_org_exists", "BEFORE INSERT", t, "org_missing", msgOrgMissing},
			tenancyTrigger{t + "_org_immutable", "BEFORE UPDATE OF org_id", t, "org_changed", msgOrgChanged})
	}
	return append(out,
		tenancyTrigger{"users_account_holder_delete", "BEFORE DELETE", "users", "holder_deleted", msgHolder},
		tenancyTrigger{"users_account_holder_update", "BEFORE UPDATE", "users", "holder_not_live", msgHolder},
		tenancyTrigger{"orgs_account_holder_insert", "BEFORE INSERT", "orgs", "holder_on_insert", msgHolderOnInsert},
		tenancyTrigger{"orgs_account_holder_update", "BEFORE UPDATE OF account_holder_user_id", "orgs", "holder_bad_change", msgHolderNotLive},
		tenancyTrigger{"orgs_status", "BEFORE UPDATE OF status", "orgs", "status_bad_change", msgDeleted},
		tenancyTrigger{"group_memberships_same_org", "BEFORE INSERT", "group_memberships", "membership_orgs", msgMembershipOrgs},
		tenancyTrigger{"suite_groups_same_org", "BEFORE INSERT", "suite_groups", "suite_group_org", msgSuiteGroupOrg})
}

// appAccessFactsSQL is app_access_facts with the org gate: an app counts for a user only
// when the user's org has every app or an enabled org_apps row. With one all_apps org the
// rows are the same as before.
func appAccessFactsSQL(now string) string {
	return `SELECT a.id app_id,u.id user_id,
 (u.status='active' AND (u.ends_at IS NULL OR u.ends_at>` + now + `)) active,COALESCE(oa.access_mode,a.access_mode) access_mode,a.enabled,
 (a.client_id IS NULL OR EXISTS(SELECT 1 FROM oauth_clients c WHERE c.id=a.client_id AND c.enabled)) client_enabled,
 EXISTS(SELECT 1 FROM app_user_assignments d WHERE d.app_id=a.id AND d.user_id=u.id AND (d.expires_at IS NULL OR d.expires_at>` + now + `)) direct,
 EXISTS(SELECT 1 FROM app_group_assignments g JOIN live_group_memberships m ON m.group_id=g.group_id WHERE g.app_id=a.id AND m.user_id=u.id) group_assigned
 FROM app_registry a CROSS JOIN users u JOIN orgs o ON o.id=u.org_id LEFT JOIN org_apps oa ON oa.org_id=u.org_id AND oa.app_id=a.id
 WHERE o.all_apps OR oa.enabled`
}

// activePrincipalsSQL is every user that may be granted access: active, not ended, in an
// active org.
func activePrincipalsSQL(now string) string {
	return `SELECT u.id,u.org_id FROM users u JOIN orgs o ON o.id=u.org_id
 WHERE o.status='active' AND u.status='active' AND (u.ends_at IS NULL OR u.ends_at>` + now + `)`
}

func migrateTenancy(tx *sql.Tx) error {
	if _, err := tx.Exec(tenancyTablesSQL("DATETIME", "INTEGER")); err != nil {
		return err
	}
	// SQLite cannot add a REFERENCES column with a non-NULL default while foreign keys are
	// on, so the default stays and the triggers stand in for the foreign key.
	for _, t := range orgColumnTables {
		var n int
		if err := tx.QueryRow(`SELECT count(*) FROM pragma_table_info(?) WHERE name='org_id'`, t).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			if _, err := tx.Exec(`ALTER TABLE ` + t + ` ADD COLUMN ` + orgIDColumn(t)); err != nil {
				return err
			}
		}
	}
	refusals := tenancyRefusals("unixepoch()")
	var b strings.Builder
	b.WriteString(orgKeysSQL)
	for _, t := range tenancyTriggers() {
		b.WriteString(sqliteTriggerSQL(t, refusals[t.refusal]))
	}
	b.WriteString(`DROP VIEW IF EXISTS effective_app_access; DROP VIEW IF EXISTS app_access_facts; DROP VIEW IF EXISTS active_principals;
CREATE VIEW app_access_facts AS ` + appAccessFactsSQL("unixepoch()") + `;
CREATE VIEW effective_app_access AS SELECT f.app_id,f.user_id FROM app_access_facts f WHERE ` + appAllowedSQL("f.access_mode", "f.enabled") + `;
CREATE VIEW active_principals AS ` + activePrincipalsSQL("unixepoch()") + `;`)
	_, err := tx.Exec(b.String())
	return err
}

func orgIDColumn(table string) string {
	if nullableOrgID[table] {
		return `org_id TEXT DEFAULT '` + DefaultOrgID + `'`
	}
	return `org_id TEXT NOT NULL DEFAULT '` + DefaultOrgID + `'`
}

const pgEpoch = `(floor(extract(epoch from statement_timestamp()))::bigint)`

func migrateTenancyPostgres(tx *sql.Tx) error {
	_, err := tx.Exec(tenancyPostgresSQL())
	return err
}

func tenancyPostgresSQL() string {
	var b strings.Builder
	b.WriteString(tenancyTablesSQL("TIMESTAMPTZ", "BIGINT") + "\n")
	// The default stays until store writes name org_id: without it every insert would fail.
	// A multi-tenant install has no default org, so a row that forgets org_id still fails.
	for _, t := range orgColumnTables {
		fmt.Fprintf(&b, "ALTER TABLE %s ADD COLUMN %s REFERENCES orgs(id);\n", t, orgIDColumn(t))
	}
	// Per-org names (D2: Postgres only), and memberships that cannot span two orgs.
	b.WriteString(orgKeysSQL + `ALTER TABLE directory_groups DROP CONSTRAINT directory_groups_name_key;
CREATE UNIQUE INDEX directory_groups_org_name ON directory_groups(org_id,name);
ALTER TABLE suite_groups DROP CONSTRAINT suite_groups_slug_key;
CREATE UNIQUE INDEX suite_groups_org_slug ON suite_groups(org_id,slug);
ALTER TABLE group_memberships ADD FOREIGN KEY (org_id,user_id) REFERENCES users(org_id,id) ON DELETE CASCADE,
 ADD FOREIGN KEY (org_id,group_id) REFERENCES directory_groups(org_id,id) ON DELETE CASCADE;
`)
	refusals := tenancyRefusals(`extract(epoch from now())`)
	for _, t := range tenancyTriggers() {
		b.WriteString(pgTriggerSQL(t, refusals[t.refusal]))
	}
	b.WriteString(`CREATE OR REPLACE VIEW app_access_facts AS ` + appAccessFactsSQL(pgEpoch) + `;
CREATE VIEW active_principals AS ` + activePrincipalsSQL(pgEpoch) + `;`)
	return b.String()
}

func sqliteTriggerSQL(t tenancyTrigger, cond string) string {
	// SQLite has IS NOT for IS DISTINCT FROM.
	cond = strings.NewReplacer("IS NOT DISTINCT FROM", "IS", "IS DISTINCT FROM", "IS NOT").Replace(cond)
	return fmt.Sprintf("CREATE TRIGGER IF NOT EXISTS %s %s ON %s FOR EACH ROW WHEN %s BEGIN SELECT RAISE(ABORT, '%s'); END;\n", t.name, t.timing, t.table, cond, t.message)
}

func pgTriggerSQL(t tenancyTrigger, cond string) string {
	ret := "NEW"
	if strings.Contains(t.timing, "DELETE") {
		ret = "OLD"
	}
	return fmt.Sprintf("CREATE FUNCTION %[1]s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN\n IF (%[2]s) THEN RAISE EXCEPTION '%[3]s'; END IF; RETURN %[4]s; END $$;\n"+
		"CREATE TRIGGER %[1]s %[5]s ON %[6]s FOR EACH ROW EXECUTE FUNCTION %[1]s();\n", t.name, cond, t.message, ret, t.timing, t.table)
}

// staffOrgTriggers refuse role='admin' and any delegation for an account outside an org
// that may hold them (D8): the staff org, or a single-tenant install's default org. They
// cover every write path, the installer and SCIM included.
func staffOrgTriggers() []tenancyTrigger {
	return []tenancyTrigger{
		{"users_staff_admin_insert", "BEFORE INSERT", "users", notStaffAdmin, msgStaffOnly},
		{"users_staff_admin_update", "BEFORE UPDATE OF role", "users", notStaffAdmin, msgStaffOnly},
		{"admin_delegations_staff_org", "BEFORE INSERT", "admin_delegations", `EXISTS(SELECT 1 FROM users u JOIN orgs o ON o.id=u.org_id WHERE u.id=NEW.user_id AND o.kind NOT IN ('default','staff'))`, msgStaffOnly},
	}
}

const notStaffAdmin = `NEW.role='admin' AND NOT EXISTS(SELECT 1 FROM orgs o WHERE o.id=NEW.org_id AND o.kind IN ('default','staff'))`

// In these triggers refusal holds the condition itself, not a tenancyRefusals key.
func migrateStaffOrg(tx *sql.Tx) error {
	var b strings.Builder
	for _, t := range staffOrgTriggers() {
		b.WriteString(sqliteTriggerSQL(t, t.refusal))
	}
	_, err := tx.Exec(b.String())
	return err
}

func migrateStaffOrgPostgres(tx *sql.Tx) error {
	var b strings.Builder
	for _, t := range staffOrgTriggers() {
		b.WriteString(pgTriggerSQL(t, t.refusal))
	}
	_, err := tx.Exec(b.String())
	return err
}

// Once every store insert names org_id (build plan PR 2), Postgres drops the backfill
// default, so an insert that forgets the org fails instead of landing in the default org.
// SQLite keeps it: ALTER TABLE cannot drop a column default there. On both, one live alert
// per rule and key becomes one per org (NULL, a platform alert, counts as one org).
const alertsLivePerOrgSQL = `DROP INDEX IF EXISTS alerts_live;
CREATE UNIQUE INDEX alerts_live ON alerts(COALESCE(org_id,''), rule, key) WHERE status<>'resolved';
`

func migrateOrgIDRequired(tx *sql.Tx) error {
	_, err := tx.Exec(alertsLivePerOrgSQL)
	return err
}

func migrateOrgIDRequiredPostgres(tx *sql.Tx) error {
	var b strings.Builder
	b.WriteString(alertsLivePerOrgSQL)
	for _, t := range orgColumnTables {
		fmt.Fprintf(&b, "ALTER TABLE %s ALTER COLUMN org_id DROP DEFAULT;\n", t)
	}
	_, err := tx.Exec(b.String())
	return err
}
