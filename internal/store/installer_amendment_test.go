package store

import (
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func amendmentFixture(parent string) InstallerSetup {
	return InstallerSetup{ID: uuid.NewString(), Extends: parent, Clients: []InstallerClient{{ID: "kyrecovery", Name: "KyRecovery", SecretHash: "recovery-hash",
		RedirectURIs: []string{"https://recovery.example.test/callback"}, PostLogoutURIs: []string{}, AdministratorRole: "admin", EverydayRole: "user", Groups: []string{"Suite users"}}}}
}

func auditCount(t *testing.T, s *Store) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM audit_events`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestInstallerAmendmentAddsClientToParentAccounts(t *testing.T) {
	s, close := setupTestStore(t)
	defer close()
	parent := groupInstallerFixture()
	if _, err := s.ApplyInstallerSetup(parent, false); err != nil {
		t.Fatal(err)
	}
	users := auditCount(t, s)
	a := amendmentFixture(parent.ID)
	r, err := s.ApplyInstallerSetup(a, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range r.Created {
		if o.Kind == "user" || o.Kind == "group" {
			t.Fatalf("amendment created %+v", o)
		}
	}
	var owner, contract string
	if err := s.db.QueryRow(`SELECT setup_id,contract FROM installer_setup_resources WHERE kind='client' AND name='kyrecovery'`).Scan(&owner, &contract); err != nil || owner != a.ID {
		t.Fatal("amendment client ownership", owner, err)
	}
	if want := `"extends","` + parent.ID + `"`; !strings.Contains(contract, want) {
		t.Fatalf("client contract %s lacks parent binding", contract)
	}
	admin, _ := s.GetUserByUsername(parent.Admin.Username)
	day, _ := s.GetUserByUsername(parent.Everyday.Username)
	for user, role := range map[string]string{admin.ID: "admin", day.ID: "user"} {
		claims, err := s.UserAppClaims(user, "kyrecovery")
		if err != nil || !slices.Equal(claims.Roles, []string{role}) {
			t.Fatalf("amendment role for %s: %+v %v", role, claims, err)
		}
	}
	if claims, _ := s.UserAppClaims(day.ID, "kyrecovery"); !slices.Equal(claims.Groups, []string{"Suite users"}) {
		t.Fatalf("amendment group claim %+v", claims)
	}
	// One audit per client, assignment (2), role (2+2) and group assignment.
	if got := auditCount(t, s) - users; got != 8 {
		t.Fatalf("amendment wrote %d audits", got)
	}
	before := auditCount(t, s)
	for _, inspect := range []bool{false, true} {
		for _, p := range []InstallerSetup{parent, a} {
			r, err := s.ApplyInstallerSetup(p, inspect)
			if err != nil || len(r.Created) != 0 {
				t.Fatalf("rerun/check of %s: %+v %v", p.ID, r, err)
			}
		}
	}
	if auditCount(t, s) != before {
		t.Fatal("rerun wrote audits")
	}
	// The parent cannot be an amendment, so amendments do not chain.
	if _, err := s.ApplyInstallerSetup(amendmentFixture(a.ID), false); err == nil {
		t.Fatal("amendment of an amendment accepted")
	}
}

func TestInstallerAmendmentRefusals(t *testing.T) {
	// Each refusal must come from its own guard, not a later constraint.
	reasons := map[string]string{"missing-parent": "parent setup has no owned", "admin-disabled": "no longer matches", "admin-renamed": "conflicting ownership",
		"everyday-delegated": "delegated privileges", "parent-client": "client kydrive has conflicting ownership", "foreign-client": "already exists without this installer's ownership",
		"foreign-group": "not owned by the parent setup", "accounts": "adds clients only", "self": "adds clients only"}
	for kind, reason := range reasons {
		t.Run(kind, func(t *testing.T) {
			s, close := setupTestStore(t)
			defer close()
			parent := groupInstallerFixture()
			if _, err := s.ApplyInstallerSetup(parent, false); err != nil {
				t.Fatal(err)
			}
			a := amendmentFixture(parent.ID)
			switch kind {
			case "missing-parent":
				a.Extends = uuid.NewString()
			case "admin-disabled":
				mustExec(t, s, `UPDATE users SET status='disabled' WHERE username=?`, parent.Admin.Username)
			case "admin-renamed":
				mustExec(t, s, `UPDATE users SET username='renamed' WHERE username=?`, parent.Admin.Username)
			case "everyday-delegated":
				mustExec(t, s, `INSERT INTO admin_delegations(user_id,kind,created_at) SELECT id,'helpdesk',CURRENT_TIMESTAMP FROM users WHERE username=?`, parent.Everyday.Username)
			case "parent-client":
				a.Clients[0].ID = parent.Clients[0].ID
			case "foreign-client":
				mustExec(t, s, `INSERT INTO oauth_clients(id,client_name,client_type,client_secret_hash,redirect_uris_json,allowed_scopes_json,enabled,created_at,post_logout_redirect_uris_json) VALUES('kyrecovery','Foreign','confidential','x','[]','["openid"]',1,CURRENT_TIMESTAMP,'[]')`)
			case "foreign-group":
				mustExec(t, s, `INSERT INTO directory_groups(id,name,description,created_at,updated_at) VALUES('g','Foreign','',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`)
				a.Clients[0].Groups = []string{"Foreign"}
			case "accounts":
				a.Admin = parent.Admin
			case "self":
				a.Extends = a.ID
			}
			before := auditCount(t, s)
			var clients int
			s.db.QueryRow(`SELECT count(*) FROM oauth_clients`).Scan(&clients)
			for _, inspect := range []bool{false, true} {
				_, err := s.ApplyInstallerSetup(a, inspect)
				if err == nil || !strings.Contains(err.Error(), reason) {
					t.Fatalf("amendment refusal %v, want %q", err, reason)
				}
			}
			var after int
			s.db.QueryRow(`SELECT count(*) FROM oauth_clients`).Scan(&after)
			if after != clients || auditCount(t, s) != before {
				t.Fatal("refused amendment changed the database")
			}
			var owned int
			s.db.QueryRow(`SELECT count(*) FROM installer_setup_resources WHERE setup_id=?`, a.ID).Scan(&owned)
			if owned != 0 {
				t.Fatal("refused amendment recorded ownership")
			}
		})
	}
}

func mustExec(t *testing.T, s *Store, q string, args ...any) {
	t.Helper()
	if _, err := s.db.Exec(q, args...); err != nil {
		t.Fatal(err)
	}
}
