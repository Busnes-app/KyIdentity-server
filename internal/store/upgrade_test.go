package store

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// legacySchema is the directory as it was before the access lifecycle work: no app
// registry, no access modes, no authentication evidence on sessions, no delivery lease
// or provisioning revision on the outbox, and an outbox still foreign-keyed to users.
// Upgrading one of these is what an operator does when they pull a new image.
const legacySchema = `
CREATE TABLE users (
 id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE, display_name TEXT NOT NULL,
 email TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK (role IN ('user','admin')),
 status TEXT NOT NULL CHECK (status IN ('active','disabled')),
 created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE sessions (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 session_token_hash TEXT NOT NULL UNIQUE, ip_address TEXT NOT NULL, user_agent TEXT NOT NULL,
 expires_at DATETIME NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 last_active_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE oauth_clients (
 id TEXT PRIMARY KEY, client_name TEXT NOT NULL,
 client_type TEXT NOT NULL CHECK (client_type IN ('public','confidential')),
 client_secret_hash TEXT, redirect_uris_json TEXT NOT NULL, allowed_scopes_json TEXT NOT NULL,
 launch_url TEXT, enabled BOOLEAN NOT NULL DEFAULT 1,
 created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE paired_systems (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, system_type TEXT NOT NULL, callback_url TEXT NOT NULL,
 hmac_secret_encrypted TEXT NOT NULL,
 status TEXT NOT NULL CHECK (status IN ('active','failing','disabled')),
 last_synced_at DATETIME, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE account_sync_events (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 system_id TEXT NOT NULL, event_type TEXT NOT NULL, payload_json TEXT NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0,
 status TEXT NOT NULL CHECK (status IN ('pending','delivered','failed')),
 last_error TEXT, next_attempt_at DATETIME,
 created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP);
`

// legacyDatabase lays down a pre-feature directory with the state an upgrade must carry
// over: an administrator, an ordinary user with a live session, a launcher app, a
// paired system and its queued deliveries.
func legacyDatabase(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.Exec(query, args...); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}
	exec(legacySchema)
	exec(`INSERT INTO users(id,username,display_name,email,password_hash,role,status) VALUES
 ('u-admin','root','Root','root@test.invalid','x','admin','active'),
 ('u-staff','staff','Staff','staff@test.invalid','x','user','active')`)
	exec(`INSERT INTO sessions(id,user_id,session_token_hash,ip_address,user_agent,expires_at) VALUES
 ('s-legacy','u-staff','legacy-hash','203.0.113.4','old-browser',?)`, time.Now().UTC().Add(24*time.Hour))
	exec(`INSERT INTO oauth_clients(id,client_name,client_type,client_secret_hash,redirect_uris_json,allowed_scopes_json,launch_url)
 VALUES('c-wiki','Wiki','confidential','hash','["https://wiki.test/cb"]','["openid"]','https://wiki.test/')`)
	exec(`INSERT INTO paired_systems(id,name,system_type,callback_url,hmac_secret_encrypted,status)
 VALUES('sys-hr','HR','scim','https://hr.test/scim/v2','sealed','active')`)
	exec(`INSERT INTO account_sync_events(id,user_id,system_id,event_type,payload_json,status) VALUES
 ('ev-1','u-staff','sys-hr','user.created','{}','pending'),
 ('ev-2','u-staff','sys-hr','user.updated','{}','pending')`)
	return path
}

// schemaFingerprint is the shape of a database independent of how it got there: every
// object by name, and every table's columns as a set. Column order differs between a
// fresh install and one built by ALTER, so order is deliberately not compared.
func schemaFingerprint(t *testing.T, path string) map[string][]string {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	out := map[string][]string{}
	rows, err := db.Query(`SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var kind, name string
		if err := rows.Scan(&kind, &name); err != nil {
			t.Fatal(err)
		}
		out["objects"] = append(out["objects"], kind+" "+name)
		if kind == "table" {
			tables = append(tables, name)
		}
	}
	rows.Close()
	for _, table := range tables {
		cols, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for cols.Next() {
			var name string
			if err := cols.Scan(&name); err != nil {
				t.Fatal(err)
			}
			names = append(names, name)
		}
		cols.Close()
		sort.Strings(names)
		out["table "+table] = names
	}
	return out
}

func sameFingerprint(t *testing.T, what string, a, b map[string][]string) {
	t.Helper()
	for key, want := range a {
		got, ok := b[key]
		if !ok {
			t.Errorf("%s: %s is missing", what, key)
			continue
		}
		if fmt.Sprint(want) != fmt.Sprint(got) {
			t.Errorf("%s: %s differs\n  a: %v\n  b: %v", what, key, want, got)
		}
	}
	for key := range b {
		if _, ok := a[key]; !ok {
			t.Errorf("%s: %s is unexpected", what, key)
		}
	}
}

// Upgrading a pre-feature directory keeps every identifier, states the broad access the
// old server granted implicitly, invents no authentication evidence for sessions that
// predate it, and lands on the same schema as a fresh install. Running the upgrade
// again changes nothing.
func TestUpgradeFromPreFeatureDatabase(t *testing.T) {
	path := legacyDatabase(t)
	s, err := New(path)
	if err != nil {
		t.Fatal("upgrade:", err)
	}
	first := schemaFingerprint(t, path)

	// Identifiers are what every relying party, token and remote mapping refers to.
	for _, id := range []struct{ query, want string }{
		{`SELECT id FROM users WHERE username='staff'`, "u-staff"},
		{`SELECT id FROM sessions WHERE session_token_hash='legacy-hash'`, "s-legacy"},
		{`SELECT id FROM oauth_clients WHERE client_name='Wiki'`, "c-wiki"},
		{`SELECT id FROM paired_systems WHERE name='HR'`, "sys-hr"},
		{`SELECT client_id FROM app_registry WHERE client_id='c-wiki'`, "c-wiki"},
	} {
		var got string
		if err := s.db.QueryRow(id.query).Scan(&got); err != nil || got != id.want {
			t.Fatalf("%s: %q %v", id.query, got, err)
		}
	}

	// The old server let every active user reach every client. The upgrade says so
	// explicitly rather than leaving the app looking assignment-only and locked down.
	var mode string
	if err := s.db.QueryRow(`SELECT access_mode FROM app_registry WHERE client_id='c-wiki'`).Scan(&mode); err != nil || mode != "all_active_users" {
		t.Fatalf("legacy access mode: %q %v", mode, err)
	}
	explained, err := s.ExplainClientAccess("u-staff", "c-wiki")
	if err != nil || !explained.Allowed {
		t.Fatalf("legacy user lost access across the upgrade: %+v %v", explained, err)
	}
	// An app added after the upgrade starts closed, so the broad mode is a statement
	// about what already existed, not the new default.
	if err := s.CreateOAuthClient(&OAuthClient{ID: "c-new", ClientName: "New", ClientType: "public", RedirectURIsJSON: `["https://new.test/cb"]`, AllowedScopesJSON: `["openid"]`, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT access_mode FROM app_registry WHERE client_id='c-new'`).Scan(&mode); err != nil || mode != "assigned_only" {
		t.Fatalf("new app mode: %q %v", mode, err)
	}

	// A session that predates authentication evidence carries none: the upgrade must not
	// backfill a factor nobody proved.
	var primary, factor sql.NullTime
	var method string
	if err := s.db.QueryRow(`SELECT primary_authenticated_at, factor_authenticated_at, factor_method FROM sessions WHERE id='s-legacy'`).Scan(&primary, &factor, &method); err != nil {
		t.Fatal(err)
	}
	if primary.Valid || factor.Valid || method != "" {
		t.Fatalf("upgrade invented authentication evidence: %v %v %q", primary, factor, method)
	}

	// Queued deliveries survive with a revision, so provisioning picks up where it left off.
	var queued, revisions int
	if err := s.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(revision=0),0) FROM account_sync_events WHERE status='pending'`).Scan(&queued, &revisions); err != nil || queued != 2 || revisions != 2 {
		t.Fatalf("queued deliveries: %d %d %v", queued, revisions, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Second run: the same migrations over the same database change nothing.
	again, err := New(path)
	if err != nil {
		t.Fatal("second upgrade:", err)
	}
	defer again.Close()
	sameFingerprint(t, "second migration", first, schemaFingerprint(t, path))
	var users, events int
	if err := again.db.QueryRow(`SELECT (SELECT COUNT(*) FROM users), (SELECT COUNT(*) FROM account_sync_events)`).Scan(&users, &events); err != nil || users != 2 || events != 2 {
		t.Fatalf("second migration changed rows: %d %d %v", users, events, err)
	}

	// A resurrected uniqueness constraint is the worst kind of upgrade damage: it
	// rejects rows the product deliberately allows. A group and a user may share a
	// remote id on one connector.
	if _, err := again.db.Exec(`INSERT INTO scim_user_links(system_id,local_id,remote_id,kind) VALUES('sys-hr','u-staff','shared-1','user'),('sys-hr','g-team','shared-1','group')`); err != nil {
		t.Fatal("second migration restored the pre-group uniqueness rule:", err)
	}
	if _, err := again.db.Exec(`DELETE FROM scim_user_links WHERE remote_id='shared-1'`); err != nil {
		t.Fatal(err)
	}

	// And an upgraded database is the same shape as one that never held old data.
	fresh, cleanup := setupTestStore(t)
	defer cleanup()
	freshPath := filepath.Join(t.TempDir(), "fresh.db")
	if err := fresh.SnapshotTo(freshPath); err != nil {
		t.Fatal(err)
	}
	sameFingerprint(t, "upgraded against fresh", schemaFingerprint(t, freshPath), first)
}
