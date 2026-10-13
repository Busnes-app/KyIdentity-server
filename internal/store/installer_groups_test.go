package store

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/uuid"
)

func groupInstallerFixture() InstallerSetup {
	p := installerFixture()
	p.Groups = []InstallerGroup{{Name: "Suite users", Description: "Initial ordinary workspace", IncludeEveryday: true}}
	p.Clients[0].Groups = []string{"Suite users"}
	p.Clients[0].AdministratorRole = "admin"
	p.Clients[0].EverydayRole = "editor"
	return p
}

func TestInstallerGroupsOwnedClaimsReadOnlyAndDrift(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.db")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p := groupInstallerFixture()
	r, err := s.ApplyInstallerSetup(p, false)
	if err != nil || len(r.Created) != 6 {
		t.Fatalf("group setup %+v %v", r, err)
	}
	day, _ := s.GetUserByUsername(p.Everyday.Username)
	admin, _ := s.GetUserByUsername(p.Admin.Username)
	for _, user := range []*User{day, admin} {
		claims, err := s.UserAppClaims(user.ID, p.Clients[0].ID)
		want := []string{}
		if user.ID == day.ID {
			want = []string{"Suite users"}
		}
		if err != nil || !claims.GroupsClaim || !slices.Equal(claims.Groups, want) {
			t.Fatalf("native group claims %+v %v", claims, err)
		}
	}
	var before int
	if err := s.db.QueryRow(`SELECT count(*) FROM audit_events`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	ro, err := OpenInstallerStore(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	for _, st := range []*Store{s, ro} {
		r, err := st.ApplyInstallerSetup(p, true)
		if err != nil || len(r.Created) != 0 || len(r.Reused) != 6 {
			t.Fatalf("read-only group inspection %+v %v", r, err)
		}
	}
	r, err = s.ApplyInstallerSetup(p, false)
	if err != nil || len(r.Created) != 0 {
		t.Fatal("group resume changed native state", err)
	}
	var after int
	if err := s.db.QueryRow(`SELECT count(*) FROM audit_events`).Scan(&after); err != nil || before != after {
		t.Fatal("inspection/resume appended audit", err)
	}
	var groupID string
	if err := s.db.QueryRow(`SELECT id FROM directory_groups WHERE name='Suite users'`).Scan(&groupID); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGroupMembership(groupID, day.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyInstallerSetup(p, false); err == nil {
		t.Fatal("missing membership silently repaired")
	}
	var members int
	if err := s.db.QueryRow(`SELECT count(*) FROM group_memberships WHERE group_id=?`, groupID).Scan(&members); err != nil || members != 0 {
		t.Fatal("drift refusal changed membership", err)
	}
}

func TestInstallerGroupsRollbackForeignConflictsAndAuditFailure(t *testing.T) {
	for _, cause := range []string{"foreign", "audit", "assignment audit"} {
		t.Run(cause, func(t *testing.T) {
			s, close := setupTestStore(t)
			defer close()
			p := groupInstallerFixture()
			if cause == "foreign" {
				if err := s.CreateGroup(&Group{ID: uuid.NewString(), Name: "Suite users", Description: "preserve foreign"}, nil); err != nil {
					t.Fatal(err)
				}
			} else {
				action := "installer.group_created"
				if cause == "assignment audit" {
					action = "installer.group_assignment_created"
				}
				if _, err := s.db.Exec(`CREATE TRIGGER refuse_installer_group_audit BEFORE INSERT ON audit_events WHEN NEW.action='` + action + `' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.ApplyInstallerSetup(p, false); err == nil {
				t.Fatal("group conflict/audit failure accepted")
			}
			for _, table := range []string{"users", "oauth_clients", "installer_setup_resources", "group_memberships", "app_group_assignments", "app_roles"} {
				var count int
				if err := s.db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); err != nil || count != 0 {
					t.Fatalf("partial %s creation %d %v", table, count, err)
				}
			}
			if cause == "foreign" {
				var desc string
				if err := s.db.QueryRow(`SELECT description FROM directory_groups`).Scan(&desc); err != nil || desc != "preserve foreign" {
					t.Fatal("foreign group changed", err)
				}
			}
		})
	}
}

func TestInstallerGroupAssignmentAndDefinitionDriftAreNotRepaired(t *testing.T) {
	for _, cause := range []string{"assignment", "claim", "definition"} {
		t.Run(cause, func(t *testing.T) {
			s, close := setupTestStore(t)
			defer close()
			p := groupInstallerFixture()
			if _, err := s.ApplyInstallerSetup(p, false); err != nil {
				t.Fatal(err)
			}
			var appID, groupID string
			if err := s.db.QueryRow(`SELECT id FROM app_registry WHERE client_id=?`, p.Clients[0].ID).Scan(&appID); err != nil {
				t.Fatal(err)
			}
			if err := s.db.QueryRow(`SELECT id FROM directory_groups WHERE name='Suite users'`).Scan(&groupID); err != nil {
				t.Fatal(err)
			}
			var err error
			switch cause {
			case "assignment":
				err = s.SetAppAssignment(appID, "groups", groupID, false, nil)
			case "claim":
				_, err = s.db.Exec(`UPDATE app_registry SET groups_claim=0 WHERE id=?`, appID)
			case "definition":
				err = s.UpdateGroup(&Group{ID: groupID, Name: "Suite users", Description: "retain operator change"}, nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			var before, after int
			if err := s.db.QueryRow(`SELECT count(*) FROM audit_events`).Scan(&before); err != nil {
				t.Fatal(err)
			}
			for _, inspect := range []bool{true, false} {
				if _, err := s.ApplyInstallerSetup(p, inspect); err == nil {
					t.Fatal("group drift accepted")
				}
			}
			if err := s.db.QueryRow(`SELECT count(*) FROM audit_events`).Scan(&after); err != nil || before != after {
				t.Fatal("drift appended successful setup audit", err)
			}
			if cause == "definition" {
				var description string
				if err := s.db.QueryRow(`SELECT description FROM directory_groups WHERE id=?`, groupID).Scan(&description); err != nil || description != "retain operator change" {
					t.Fatal("operator group change overwritten", err)
				}
			}
		})
	}
}
