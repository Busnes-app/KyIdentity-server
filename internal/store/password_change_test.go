package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

// An upgraded database flags only a bootstrap administrator still on its first password,
// once, and never re-evaluates: a later start changes nothing and writes no audit row.
func TestPasswordChangeMigrationFlagsUnchangedBootstrapAdminOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "upgrade.db")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	created := time.Now().UTC().Add(-400 * 24 * time.Hour)
	user := func(name, role string, modified bool) string {
		t.Helper()
		id := uuid.NewString()
		updated := created
		if modified {
			updated = created.Add(time.Hour)
		}
		if _, err := s.db.Exec(`INSERT INTO users (id,username,display_name,email,password_hash,role,status,created_at,updated_at) VALUES (?,?,?,?,'hash',?,'active',?,?)`,
			id, name, name, name+"@x.test", role, created, updated); err != nil {
			t.Fatal(err)
		}
		return id
	}
	audit := func(action, actor, target, details string) {
		t.Helper()
		if _, err := insertAuditEvent(s.db, &AuditEvent{ID: uuid.NewString(), ActorUsername: actor, Action: action, TargetID: target, TargetType: "user", Outcome: "success", DetailsJSON: details, CreatedAt: created}); err != nil {
			t.Fatal(err)
		}
	}
	bootstrap := func(name string, modified bool) string {
		id := user(name, "admin", modified)
		audit("admin.user_created", "bootstrap", id, `{"role":"admin"}`)
		return id
	}
	want := map[string]bool{}
	want[bootstrap("unchanged", false)] = true
	// A profile edit is not a password change.
	edited := bootstrap("profile-edited", true)
	audit("admin.user_updated", "unchanged", edited, `{"accessRevoked":false}`)
	want[edited] = true
	changed := bootstrap("changed", true)
	audit("user.password_changed", "changed", changed, "")
	want[changed] = false
	reset := bootstrap("reset", true)
	audit("auth.password_reset", "reset", reset, `{"kind":"reset"}`)
	want[reset] = false
	// An edit that may have set a password, or predates the detail, counts as a change.
	adminSet := bootstrap("admin-set", true)
	audit("admin.user_updated", "other", adminSet, `{"accessRevoked":true}`)
	want[adminSet] = false
	legacyEdit := bootstrap("legacy-edit", true)
	audit("admin.user_updated", "other", legacyEdit, `not json`)
	want[legacyEdit] = false
	other := user("created-by-alice", "admin", false)
	audit("admin.user_created", "alice", other, `{"role":"admin"}`)
	want[other] = false
	// Retention pruned the creation row: only a never-modified administrator is flagged.
	want[user("pruned-unmodified", "admin", false)] = true
	want[user("pruned-modified", "admin", true)] = false
	want[user("pruned-user", "user", false)] = false
	installer := user("installer-admin", "admin", false)
	if _, err := s.db.Exec(`INSERT INTO installer_setup_resources(kind,name,setup_id,object_id,contract) VALUES('user','installer-admin','setup',?,'{}')`, installer); err != nil {
		t.Fatal(err)
	}
	want[installer] = false

	// The fixture was written after this database's own one-time pass: make it pre-feature.
	if _, err := s.db.Exec(`DELETE FROM system_settings WHERE key=?`, PasswordChangeMigrationSetting); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	check := func(s *Store) {
		t.Helper()
		for id, flagged := range want {
			u, err := s.GetUserByID(id)
			if err != nil || u == nil {
				t.Fatal(id, err)
			}
			if u.PasswordChangeRequired != flagged {
				t.Errorf("%s: passwordChangeRequired=%v, want %v", u.Username, u.PasswordChangeRequired, flagged)
			}
		}
		var rows int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action='system.password_change_required'`).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		if rows != 3 {
			t.Errorf("migration audit rows = %d, want 3", rows)
		}
	}
	for range 2 {
		s, err = New(path)
		if err != nil {
			t.Fatal(err)
		}
		check(s)
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

// Choosing a password, by change or by reset link, clears the flag; the old password and
// every other session end exactly as an ordinary change does.
func TestChoosingAPasswordClearsTheFlag(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	for _, viaLink := range []bool{false, true} {
		u := &User{ID: uuid.NewString(), Username: "f" + uuid.NewString()[:8], DisplayName: "F", Email: uuid.NewString()[:8] + "@x.test", PasswordHash: "old", Role: "admin", Status: "active", PasswordChangeRequired: true}
		if err := s.CreateUserWithSyncEvents(u, nil); err != nil {
			t.Fatal(err)
		}
		if got, _ := s.GetUserByID(u.ID); !got.PasswordChangeRequired {
			t.Fatal("flag not stored at creation")
		}
		if viaLink {
			raw, err := s.IssueAccountToken(u.ID, "reset", "manual", time.Hour, nil)
			if err != nil {
				t.Fatal(err)
			}
			event := &AuditEvent{ID: uuid.NewString(), Action: "auth.password_reset", TargetType: "user", Outcome: "success"}
			if _, err := s.RedeemAccountToken(raw, "reset", "new", event); err != nil {
				t.Fatal(err)
			}
			var target string
			if err := s.db.QueryRow(`SELECT target_id FROM audit_events WHERE id=?`, event.ID).Scan(&target); err != nil || target != u.ID {
				t.Fatalf("reset audit row names %q, want %q (%v)", target, u.ID, err)
			}
		} else if err := s.ChangePassword(u.ID, "", "new", nil); err != nil {
			t.Fatal(err)
		}
		got, _ := s.GetUserByID(u.ID)
		if got.PasswordChangeRequired || got.PasswordHash != "new" {
			t.Fatalf("viaLink=%v: flag=%v hash=%q", viaLink, got.PasswordChangeRequired, got.PasswordHash)
		}
	}
}
