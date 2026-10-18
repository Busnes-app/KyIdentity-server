package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// Issue #109: an installer retires the bootstrap administrator without a person.
func TestDisableUser(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KYIDENTITY_DATA_DIR", dir)
	t.Setenv("KYIDENTITY_DB_PATH", "")
	dbPath := filepath.Join(dir, "kyidentity.db")
	s, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	user := func(name, role string) *store.User {
		t.Helper()
		u := &store.User{ID: uuid.NewString(), Username: name, DisplayName: name, Email: name + "@example.test", PasswordHash: "hash-" + name, Role: role, Status: "active"}
		if err := s.CreateUser(u); err != nil {
			t.Fatal(err)
		}
		return u
	}
	bootstrap, owner, everyday := user("kyq-bootstrap", "admin"), user("owner-admin", "admin"), user("owner", "user")
	// An unrelated permanent administrator keeps the general last-administrator rule
	// satisfied, so only the named guard can refuse below.
	user("third-admin", "admin")
	session := uuid.NewString()
	if err := s.CreateSession(&store.Session{ID: session, UserID: bootstrap.ID, SessionTokenHash: uuid.NewString(), ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	pass := filepath.Join(dir, "first-run-password.txt")
	if err := os.WriteFile(pass, []byte("User: kyq-bootstrap\nPassword: generated-password\n"), 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := raw.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	audits := func() int {
		t.Helper()
		var n int
		if err := raw.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE actor_username='kyidentity-cli' AND action='admin.user_updated'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	run := func(args ...string) (map[string]string, error) {
		var out bytes.Buffer
		err := runDisableUser(args, &out)
		var result map[string]string
		if err == nil {
			d := json.NewDecoder(&out)
			if d.Decode(&result) != nil || d.More() {
				t.Fatalf("stdout is not exactly one JSON object: %q", out.String())
			}
		} else if out.Len() != 0 {
			t.Fatalf("refusal wrote stdout: %q", out.String())
		}
		return result, err
	}
	status := func(u *store.User) string {
		t.Helper()
		got, err := s.GetUserByID(u.ID)
		if err != nil || got == nil {
			t.Fatal(err)
		}
		return got.Status
	}

	// Refusals change nothing and audit nothing.
	exec(`UPDATE users SET status='disabled' WHERE id=?`, owner.ID)
	refusedByGuard := func(name string, args ...string) {
		t.Helper()
		if _, err := run(args...); err == nil || !strings.Contains(err.Error(), "require-active-admin") {
			t.Fatalf("%s: %v", name, err)
		}
	}
	refusedByGuard("guard is the target", "--username", "kyq-bootstrap", "--require-active-admin", "KYQ-bootstrap")
	refusedByGuard("guard missing", "--username", "kyq-bootstrap", "--require-active-admin", "nobody")
	refusedByGuard("guard disabled", "--username", "kyq-bootstrap", "--require-active-admin", "owner-admin")
	refusedByGuard("guard not an admin", "--username", "kyq-bootstrap", "--require-active-admin", "owner")
	refusedByGuard("non-admin target, guard missing", "--username", "owner", "--require-active-admin", "nobody")
	for name, args := range map[string][]string{
		"unknown account":     {"--username", "nobody", "--require-active-admin", "third-admin"},
		"guard flag missing":  {"--username", "kyq-bootstrap"},
		"unexpected argument": {"--username", "kyq-bootstrap", "--require-active-admin", "third-admin", "extra"},
		"invalid name":        {"--username", "../x", "--require-active-admin", "third-admin"},
	} {
		if _, err := run(args...); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	exec(`UPDATE users SET status='active', ends_at=? WHERE id=?`, time.Now().Add(24*time.Hour).Unix(), owner.ID)
	refusedByGuard("guard end-dated", "--username", "kyq-bootstrap", "--require-active-admin", "owner-admin")
	exec(`UPDATE users SET ends_at=NULL WHERE id=?`, owner.ID)
	if status(bootstrap) != "active" || status(everyday) != "active" || audits() != 0 {
		t.Fatal("a refusal changed the account or wrote audit")
	}
	if _, err := os.Stat(pass); err != nil {
		t.Fatal("a refusal removed the first-run password file")
	}

	result, err := run("--username", "kyq-bootstrap", "--require-active-admin", "owner-admin")
	if err != nil || result["schema"] != "kyidentity.disable-user/1" || result["status"] != "disabled" || result["username"] != "kyq-bootstrap" {
		t.Fatalf("disable: %v %v", result, err)
	}
	if status(bootstrap) != "disabled" || status(owner) != "active" || status(everyday) != "active" {
		t.Fatal("wrong accounts changed")
	}
	got, _ := s.GetUserByID(bootstrap.ID)
	if got.Role != "admin" || got.PasswordHash != "hash-kyq-bootstrap" {
		t.Fatal("disable changed role or password")
	}
	if live, err := s.ListUserSessions(bootstrap.ID, time.Hour); err != nil || len(live) != 0 {
		t.Fatalf("sessions survived: %v %v", live, err)
	}
	var details string
	if err := raw.QueryRow(`SELECT details_json FROM audit_events WHERE actor_username='kyidentity-cli' AND target_id=?`, bootstrap.ID).Scan(&details); err != nil || !strings.Contains(details, `"via":"cli"`) || !strings.Contains(details, `"guard":"owner-admin"`) {
		t.Fatalf("audit: %q %v", details, err)
	}
	if _, err := os.Stat(pass); !os.IsNotExist(err) {
		t.Fatal("first-run password file naming the account survived")
	}

	// A rerun is a no-op.
	result, err = run("--username", "kyq-bootstrap", "--require-active-admin", "owner-admin")
	if err != nil || result["status"] != "unchanged" || audits() != 1 {
		t.Fatalf("rerun: %v %v audits=%d", result, err, audits())
	}

	// The file is kept when it names another account.
	other := []byte("User: owner-admin\nPassword: kept\n")
	if err := os.WriteFile(pass, other, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := run("--username", "owner", "--require-active-admin", "owner-admin"); err != nil {
		t.Fatal(err)
	}
	if kept, err := os.ReadFile(pass); err != nil || !bytes.Equal(kept, other) {
		t.Fatal("first-run password file for another account removed")
	}

	// An upstream-owned account stays disabled: the local override is set.
	c, err := s.CreateSCIMConnector("Upstream", nil)
	if err != nil {
		t.Fatal(err)
	}
	upstream := user("upstream", "user")
	exec(`UPDATE users SET source_connector_id=?, external_id='ext-1', source_active=1 WHERE id=?`, c.ID, upstream.ID)
	if _, err := run("--username", "upstream", "--require-active-admin", "owner-admin"); err != nil {
		t.Fatal(err)
	}
	var locally bool
	if err := raw.QueryRow(`SELECT locally_disabled FROM users WHERE id=?`, upstream.ID).Scan(&locally); err != nil || !locally || status(upstream) != "disabled" {
		t.Fatal("upstream account not locally disabled")
	}

	// Already disabled upstream is not "unchanged": the override is still recorded, so a
	// later upstream activation cannot bring the account back.
	paused := user("paused", "user")
	exec(`UPDATE users SET source_connector_id=?, external_id='ext-2', source_active=0, status='disabled' WHERE id=?`, c.ID, paused.ID)
	result, err = run("--username", "paused", "--require-active-admin", "owner-admin")
	if err != nil || result["status"] != "disabled" {
		t.Fatalf("upstream-disabled account: %v %v", result, err)
	}
	if _, err := s.UpdateUpstreamUser(c.ID, paused.ID, nil, func(u *store.User) error { u.SourceActive = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if status(paused) != "disabled" {
		t.Fatal("upstream activation undid the retirement")
	}
	if result, err := run("--username", "paused", "--require-active-admin", "owner-admin"); err != nil || result["status"] != "unchanged" {
		t.Fatalf("rerun after override: %v %v", result, err)
	}

	// A pending invitation is already "disabled", but its live activation link must not
	// outlive the retirement.
	invited := &store.User{ID: uuid.NewString(), Username: "invited", DisplayName: "invited", Email: "invited@example.test", Role: "user", Status: "disabled", Pending: true}
	if err := s.CreateUser(invited); err != nil {
		t.Fatal(err)
	}
	link, err := s.IssueAccountToken(invited.ID, "activation", "manual", time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err = run("--username", "invited", "--require-active-admin", "owner-admin")
	if err != nil || result["status"] != "disabled" {
		t.Fatalf("pending account with a live link: %v %v", result, err)
	}
	if _, err := s.RedeemAccountToken(link, "activation", "new-hash", nil); err == nil {
		t.Fatal("activation link redeemed after retirement")
	}
	if status(invited) != "disabled" {
		t.Fatal("retired invitation activated")
	}
	if result, err := run("--username", "invited", "--require-active-admin", "owner-admin"); err != nil || result["status"] != "unchanged" {
		t.Fatalf("rerun after revoking the link: %v %v", result, err)
	}
}

func TestDisableUserIsAdvertised(t *testing.T) {
	var out bytes.Buffer
	if err := runSetup([]string{"--capabilities"}, &out); err != nil || !strings.Contains(out.String(), `"disable-user"`) {
		t.Fatalf("capabilities: %s %v", out.String(), err)
	}
}
