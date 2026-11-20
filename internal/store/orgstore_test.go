package store

import (
	"database/sql"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func testOrg(t *testing.T, s *Store, kind string) *OrgStore {
	t.Helper()
	id, err := CreateOrgForTest(s, kind)
	if err != nil {
		t.Fatal(err)
	}
	return s.Org(id)
}

func testOrgUser(t *testing.T, o *OrgStore, role string) *User {
	t.Helper()
	name := "u-" + uuid.NewString()[:8]
	u := &User{ID: uuid.NewString(), Username: name, DisplayName: name, Email: name + "@test.invalid", Role: role, Status: "active"}
	if err := o.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	return u
}

func testOrgGroup(t *testing.T, o *OrgStore) *Group {
	t.Helper()
	g := &Group{ID: uuid.NewString(), Name: "g-" + uuid.NewString()[:8]}
	if err := o.CreateGroup(g, nil); err != nil {
		t.Fatal(err)
	}
	return g
}

// orgRows is every row an org owns in the tables this handle scopes, for "unchanged".
func orgRows(t *testing.T, s *Store, org OrgID) []string {
	t.Helper()
	var out []string
	for _, q := range []string{
		`SELECT id||'|'||username||'|'||display_name||'|'||email||'|'||role||'|'||status||'|'||COALESCE(ends_at,0) FROM users WHERE org_id=?`,
		`SELECT id||'|'||name||'|'||description FROM directory_groups WHERE org_id=?`,
		`SELECT group_id||'|'||user_id||'|'||COALESCE(expires_at,0) FROM group_memberships WHERE org_id=?`,
		`SELECT group_id||'|'||slug||'|'||CASE WHEN enabled THEN 'on' ELSE 'off' END FROM suite_groups WHERE org_id=?`,
	} {
		rows, err := scanStrings(s.db.Query(q, org.String()))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, rows...)
	}
	slices.Sort(out)
	return out
}

// An OrgStore bound to org A answers B's users and groups as missing, lists none of B's
// rows, and changes nothing in B, whatever mix of A's and B's IDs it is given.
func TestOrgStoreRefusesAnotherOrgsIDs(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	a, b := testOrg(t, s, "household"), testOrg(t, s, "household")
	userA, userB := testOrgUser(t, a, "user"), testOrgUser(t, b, "user")
	groupA, groupB := testOrgGroup(t, a), testOrgGroup(t, b)
	if err := b.SetGroupMembership(groupB.ID, userB.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := b.SetSuiteGroup(groupB.ID, true, nil, nil); err != nil {
		t.Fatal(err)
	}
	before := orgRows(t, s, b.ID())
	if len(before) != 4 {
		t.Fatalf("B fixture: %q", before)
	}
	missing := func(name string, err, want error) {
		t.Helper()
		if !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", name, err, want)
		}
		if after := orgRows(t, s, b.ID()); !slices.Equal(after, before) {
			t.Fatalf("%s changed org B:\n before %q\n after  %q", name, before, after)
		}
	}

	if u, err := a.GetUserByID(userB.ID); err != nil || u != nil {
		t.Errorf("GetUserByID found B's user: %v %v", u, err)
	}
	users, err := a.ListUsers()
	if err != nil || len(users) != 1 || users[0].ID != userA.ID {
		t.Errorf("ListUsers: %v %v", users, err)
	}
	_, err = a.EditUser(userB.ID, nil, func(u *User) (bool, error) { u.DisplayName = "taken"; u.Status = "disabled"; return true, nil })
	missing("EditUser", err, sql.ErrNoRows)
	missing("DeleteUserWithSyncEvents", a.DeleteUserWithSyncEvents(userB.ID, nil), sql.ErrNoRows)
	missing("UpdateGroup", a.UpdateGroup(&Group{ID: groupB.ID, Name: "taken"}, nil), ErrGroupTargetMissing)
	missing("DeleteGroup", a.DeleteGroup(groupB.ID, nil), ErrGroupTargetMissing)
	for _, pair := range [][2]string{{groupB.ID, userB.ID}, {groupA.ID, userB.ID}, {groupB.ID, userA.ID}} {
		missing("SetGroupMembership add "+pair[0][:4], a.SetGroupMembership(pair[0], pair[1], true, nil), ErrGroupTargetMissing)
		missing("SetGroupMembership remove", a.SetGroupMembership(pair[0], pair[1], false, nil), ErrGroupTargetMissing)
		missing("SetGroupMembershipUntil", a.SetGroupMembershipUntil(pair[0], pair[1], nil, "", nil), ErrGroupTargetMissing)
	}
	groups, _, err := a.ListGroups("", "", 50, 0)
	if err != nil || len(groups) != 1 || groups[0].ID != groupA.ID {
		t.Errorf("ListGroups: %v %v", groups, err)
	}
	_, _, err = a.ListGroups("", userB.ID, 50, 0)
	missing("ListGroups for B's user", err, ErrGroupTargetMissing)
	_, _, err = a.ListGroupUsers(groupB.ID, "", true, 50, 0)
	missing("ListGroupUsers of B's group", err, ErrGroupTargetMissing)
	members, _, err := a.ListGroupUsers(groupA.ID, "", true, 50, 0)
	if err != nil || len(members) != 1 || members[0].ID != userA.ID {
		t.Errorf("ListGroupUsers listed another org's users: %v %v", members, err)
	}
	_, err = a.GetSuiteGroup(groupB.ID)
	missing("GetSuiteGroup", err, ErrGroupTargetMissing)
	_, err = a.SetSuiteGroup(groupB.ID, false, nil, nil)
	missing("SetSuiteGroup", err, ErrGroupTargetMissing)
	missing("SetDelegations", a.SetDelegations(userB.ID, Delegations{}, nil), ErrUserMissing)

	staff := testOrg(t, s, "staff")
	helpdesk := testOrgUser(t, staff, "user")
	if err := staff.SetDelegations(helpdesk.ID, Delegations{Helpdesk: true}, nil); err != nil {
		t.Fatal(err)
	}
	if d, err := a.Delegations(helpdesk.ID); err != nil || d.Helpdesk {
		t.Errorf("Delegations read another org's account: %+v %v", d, err)
	}
	// The membership a cross-org write could not make is refused by the schema too.
	if _, err := s.db.Exec(`INSERT INTO group_memberships(org_id,group_id,user_id) VALUES(?,?,?)`, a.org, groupA.ID, userB.ID); err == nil {
		t.Error("the schema took a membership spanning two orgs")
	}
}

// D8: an administrator or a delegation only in the staff org (or a single-tenant default
// org), on every write path, raw SQL included.
func TestStaffOrgRule(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	if err := s.CreateOAuthClient(&OAuthClient{ID: "staff-rule", ClientName: "Staff rule", ClientType: "public", RedirectURIsJSON: `["https://a/cb"]`, AllowedScopesJSON: `["openid"]`, Enabled: true}, nil); err != nil {
		t.Fatal(err)
	}
	apps, _, err := s.ListAppRecords("staff-rule", 1, 0)
	if err != nil || len(apps) != 1 {
		t.Fatal(apps, err)
	}
	app := apps[0]
	staff, member := testOrg(t, s, "staff"), testOrg(t, s, "household")
	for name, o := range map[string]*OrgStore{"staff": staff, "default": s.DefaultOrg()} {
		admin := testOrgUser(t, o, "admin")
		if admin.Org() != o.ID() {
			t.Errorf("%s: CreateUser left the user's org %q", name, admin.Org())
		}
		u := testOrgUser(t, o, "user")
		if err := o.SetDelegations(u.ID, Delegations{Helpdesk: true, Auditor: true, AppOwner: []string{app.ID}}, nil); err != nil {
			t.Errorf("%s: delegation refused: %v", name, err)
		}
	}

	u := &User{ID: uuid.NewString(), Username: "would-be-admin", DisplayName: "x", Email: "wba@test.invalid", Role: "admin", Status: "active"}
	if err := member.CreateUser(u); !errors.Is(err, ErrStaffOnly) {
		t.Errorf("CreateUser admin in a customer org: %v", err)
	}
	if err := member.CreateUserWithSyncEvents(u, nil); !errors.Is(err, ErrStaffOnly) {
		t.Errorf("CreateUserWithSyncEvents admin in a customer org: %v", err)
	}
	plain := testOrgUser(t, member, "user")
	if _, err := member.EditUser(plain.ID, nil, func(u *User) (bool, error) { u.Role = "admin"; return false, nil }); !errors.Is(err, ErrStaffOnly) {
		t.Errorf("EditUser to admin in a customer org: %v", err)
	}
	for _, d := range []Delegations{{Helpdesk: true}, {Auditor: true}, {AppOwner: []string{app.ID}}} {
		if err := member.SetDelegations(plain.ID, d, nil); !errors.Is(err, ErrStaffOnly) {
			t.Errorf("SetDelegations %+v in a customer org: %v", d, err)
		}
	}
	for _, q := range []string{
		`INSERT INTO users(id,username,display_name,email,password_hash,role,status,org_id) VALUES('raw','raw','raw','raw@test.invalid','','admin','active','` + member.org + `')`,
		`UPDATE users SET role='admin' WHERE id='` + plain.ID + `'`,
		`INSERT INTO admin_delegations(user_id,kind,created_at) VALUES('` + plain.ID + `','auditor',CURRENT_TIMESTAMP)`,
	} {
		if _, err := s.db.Exec(q); err == nil || !strings.Contains(err.Error(), msgStaffOnly) {
			t.Errorf("%.60s: %v", q, err)
		}
	}
	if got, err := member.GetUserByID(plain.ID); err != nil || got.Role != "user" {
		t.Errorf("customer account changed: %+v %v", got, err)
	}
	if d, err := member.Delegations(plain.ID); err != nil || d.Helpdesk || d.Auditor || len(d.AppOwner) != 0 {
		t.Errorf("customer account holds delegations: %+v %v", d, err)
	}
}

// A User the caller built names no org, and binding it is a bug, never every org.
func TestOrgNeedsAStoredPrincipal(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	defer func() {
		if recover() == nil {
			t.Error("Org bound a zero OrgID")
		}
	}()
	s.Org((&User{ID: "built"}).Org())
}

// Apps and roles are global; who holds them is per org. Bound to A, the store cannot
// grant, map, list, explain or decide anything for B's users and groups.
func TestOrgStoreAppsRefuseAnotherOrgsIDs(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	a, b := testOrg(t, s, "household"), testOrg(t, s, "household")
	adminA := testOrgUser(t, s.DefaultOrg(), "admin")
	userA, userB := testOrgUser(t, a, "user"), testOrgUser(t, b, "user")
	groupA, groupB := testOrgGroup(t, a), testOrgGroup(t, b)
	record := func(id string) AppRecord {
		if err := s.CreateOAuthClient(&OAuthClient{ID: id, ClientName: id, ClientType: "public", RedirectURIsJSON: `["https://a/cb"]`, AllowedScopesJSON: `["openid"]`, Enabled: true}, nil); err != nil {
			t.Fatal(err)
		}
		apps, _, err := s.ListAppRecords(id, 1, 0)
		if err != nil || len(apps) != 1 {
			t.Fatal(apps, err)
		}
		return apps[0]
	}
	app, requestable := record("org-app"), record("org-request")
	role, err := s.CreateAppRole(app.ID, "editor", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Both plans enable the app, so B's users are in app_access_facts for a leak to show.
	for _, o := range []*OrgStore{a, b} {
		if _, err := s.db.Exec(`INSERT INTO org_apps(org_id,app_id,enabled) VALUES(?,?,TRUE)`, o.org, app.ID); err != nil {
			t.Fatal(err)
		}
	}
	for kind, principal := range map[string]string{"users": userB.ID, "groups": groupB.ID} {
		if err := b.SetAppAssignment(app.ID, kind, principal, true, nil); err != nil {
			t.Fatal(err)
		}
		if err := b.SetAppRoleAssignment(app.ID, role.ID, kind, principal, true, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetAppRequestable(requestable.ID, true, requestable.Revision, nil); err != nil {
		t.Fatal(err)
	}
	req, err := s.CreateAccessRequest(userB.ID, requestable.ID, "please", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	grants := func() string {
		rows, err := scanStrings(s.db.Query(`SELECT 'u'||user_id FROM app_user_assignments UNION ALL SELECT 'g'||group_id FROM app_group_assignments
 UNION ALL SELECT 'ru'||user_id FROM app_role_user_assignments UNION ALL SELECT 'rg'||group_id FROM app_role_group_assignments
 UNION ALL SELECT 'r'||status FROM access_requests ORDER BY 1`))
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(rows, ",")
	}
	before := grants()
	for kind, principal := range map[string]string{"users": userB.ID, "groups": groupB.ID} {
		for _, on := range []bool{true, false} {
			if err := a.SetAppAssignment(app.ID, kind, principal, on, nil); !errors.Is(err, ErrAppRecordMissing) {
				t.Errorf("SetAppAssignment %s %v: %v", kind, on, err)
			}
			if err := a.SetAppRoleAssignment(app.ID, role.ID, kind, principal, on, nil); !errors.Is(err, ErrAppRecordMissing) {
				t.Errorf("SetAppRoleAssignment %s %v: %v", kind, on, err)
			}
		}
	}
	if err := a.SetAppAssignmentUntil(app.ID, "users", userB.ID, nil, nil); !errors.Is(err, ErrAppRecordMissing) {
		t.Errorf("SetAppAssignmentUntil: %v", err)
	}
	if _, err := a.ExplainAccess(userB.ID, app.ID); !errors.Is(err, ErrUserMissing) {
		t.Errorf("ExplainAccess: %v", err)
	}
	if _, err := a.DecideAccessRequest(req.ID, adminA.ID, true, "", nil); !errors.Is(err, ErrRequestNotPending) {
		t.Errorf("DecideAccessRequest: %v", err)
	}
	if after := grants(); after != before {
		t.Fatalf("grants changed:\n before %s\n after  %s", before, after)
	}
	users, err := a.ListAppAccessUsers(app.ID, "", "all_active_users", nil, 50, 0)
	if err != nil || users.Total != 1 || users.Users[0].ID != userA.ID || users.GainingAccess != 1 || users.LosingAccess != 0 {
		t.Errorf("ListAppAccessUsers: %+v %v", users, err)
	}
	groups, total, err := a.ListAppAccessGroups(app.ID, "", 50, 0)
	if err != nil || total != 1 || groups[0].ID != groupA.ID {
		t.Errorf("ListAppAccessGroups: %v %d %v", groups, total, err)
	}
	roles, err := a.ListAppRoles(app.ID)
	if err != nil || len(roles) != 1 || len(roles[0].Users)+len(roles[0].Groups) != 0 {
		t.Errorf("ListAppRoles shows B's mappings: %+v %v", roles, err)
	}
	if list, total, err := a.ListAccessRequests(AccessRequestFilter{Limit: 50}); err != nil || total != 0 || len(list) != 0 {
		t.Errorf("ListAccessRequests: %v %d %v", list, total, err)
	}
	if list, total, err := b.ListAccessRequests(AccessRequestFilter{Limit: 50}); err != nil || total != 1 || list[0].ID != req.ID {
		t.Errorf("B's own ListAccessRequests: %v %d %v", list, total, err)
	}
}
