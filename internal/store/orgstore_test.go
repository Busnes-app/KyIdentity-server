package store

import (
	"database/sql"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

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

// Sessions and credentials belong to a user, so a handle bound to A reaches none of B's:
// no listing, no revocation, no link, no MFA reset, no password change.
func TestOrgStoreSessionsRefuseAnotherOrgsIDs(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	a, b := testOrg(t, s, "household"), testOrg(t, s, "household")
	userB := testOrgUser(t, b, "user")
	sessB := &Session{ID: uuid.NewString(), UserID: userB.ID, SessionTokenHash: uuid.NewString(), IPAddress: "1.2.3.4", UserAgent: "t", ExpiresAt: time.Now().UTC().Add(time.Hour)}
	if err := s.CreateSession(sessB); err != nil {
		t.Fatal(err)
	}
	pending := &User{ID: uuid.NewString(), Username: "pending-b", DisplayName: "p", Email: "pending-b@test.invalid", Role: "user", Status: "disabled", Pending: true}
	if err := b.CreateUser(pending); err != nil {
		t.Fatal(err)
	}
	live := func() int {
		var n int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE user_id=?`, userB.ID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if got, err := a.ListUserSessions(userB.ID, time.Hour); err != nil || len(got) != 0 {
		t.Errorf("ListUserSessions: %v %v", got, err)
	}
	if got, err := a.ListUserAppGrants(userB.ID); err != nil || len(got) != 0 {
		t.Errorf("ListUserAppGrants: %v %v", got, err)
	}
	for name, err := range map[string]error{
		"RevokeSession":          a.RevokeSession(userB.ID, sessB.ID, nil),
		"RevokeOtherSessions":    a.RevokeOtherSessions(userB.ID, "", nil),
		"RevokeUserClientAccess": a.RevokeUserClientAccess(userB.ID, "x", nil),
		"RevokeUserAccess":       a.RevokeUserAccess(userB.ID, nil),
		"ResetUserMFA":           a.ResetUserMFA(userB.ID, nil),
		"ChangePassword":         a.ChangePassword(userB.ID, sessB.ID, "taken", nil),
	} {
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("%s on B's user: %v", name, err)
		}
	}
	for _, kind := range []string{"reset", "activation"} {
		target := userB.ID
		if kind == "activation" {
			target = pending.ID
		}
		if _, err := a.IssueAccountToken(target, kind, "email", time.Hour, nil); !errors.Is(err, ErrNotFound) {
			t.Errorf("IssueAccountToken %s: %v", kind, err)
		}
	}
	if found, err := a.RetryLogoutDeliveryNow(userB.ID, "x", nil); err != nil || found {
		t.Errorf("RetryLogoutDeliveryNow: %v %v", found, err)
	}
	if n := live(); n != 1 {
		t.Fatalf("B's session gone: %d", n)
	}
	var tokens int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM account_tokens`).Scan(&tokens); err != nil || tokens != 0 {
		t.Fatalf("account tokens issued: %d %v", tokens, err)
	}
	if u, err := b.GetUserByID(userB.ID); err != nil || u.PasswordHash == "taken" {
		t.Fatalf("B's password changed: %v", err)
	}
}

// A back-channel logout queued for a user carries that user's org, so it can be scoped
// after the user is gone.
func TestLogoutDeliveriesCarryTheUsersOrg(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	b := testOrg(t, s, "household")
	userB := testOrgUser(t, b, "user")
	c := &OAuthClient{ID: "bcl", ClientName: "bcl", ClientType: "public", RedirectURIsJSON: `["https://a/cb"]`, AllowedScopesJSON: `["openid"]`, Enabled: true, BackchannelLogoutURI: "https://a/logout"}
	if err := s.CreateOAuthClient(c, nil); err != nil {
		t.Fatal(err)
	}
	sess := &Session{ID: uuid.NewString(), UserID: userB.ID, SessionTokenHash: uuid.NewString(), IPAddress: "1.2.3.4", UserAgent: "t", ExpiresAt: time.Now().UTC().Add(time.Hour)}
	if err := s.CreateSession(sess); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnsureClientSession("bcl", sess.ID, userB.ID); err != nil {
		t.Fatal(err)
	}
	if err := b.RevokeSession(userB.ID, sess.ID, nil); err != nil {
		t.Fatal(err)
	}
	var org string
	if err := s.db.QueryRow(`SELECT org_id FROM logout_deliveries WHERE user_id=?`, userB.ID).Scan(&org); err != nil || org != b.org {
		t.Fatalf("delivery org %q (%v), want %q", org, err, b.org)
	}
	if got, err := s.DefaultOrg().ListLogoutDeliveries(userB.ID, 10); err != nil || len(got) != 0 {
		t.Errorf("another org listed B's delivery: %v %v", got, err)
	}
	if got, err := b.ListLogoutDeliveries(userB.ID, 10); err != nil || len(got) != 1 {
		t.Errorf("B's own listing: %v %v", got, err)
	}
}

// Audit and alerts: a row is in the org of its target or actor, and an org reads only its
// own rows. Platform rows (NULL) are read by the org that administers the install.
func TestAuditAndAlertsAreReadPerOrg(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	a, b, staff := testOrg(t, s, "household"), testOrg(t, s, "household"), testOrg(t, s, "staff")
	userA, userB := testOrgUser(t, a, "user"), testOrgUser(t, b, "user")
	for _, e := range []*AuditEvent{
		{ID: "on-b", ActorID: userA.ID, Action: "x.on_b", TargetID: userB.ID, TargetType: "user", Outcome: "success"},
		{ID: "by-b", ActorID: userB.ID, Action: "x.by_b", TargetID: "settings", TargetType: "settings", Outcome: "success"},
		{ID: "platform", Action: "x.platform", Outcome: "success"},
	} {
		if err := s.RecordAuditEvent(e); err != nil {
			t.Fatal(err)
		}
	}
	var orgs []string
	if err := readPairs(s.db, `SELECT id, COALESCE(org_id,'') FROM audit_events WHERE id IN ('on-b','by-b','platform') ORDER BY id`, func(id, org string) error {
		orgs = append(orgs, id+"="+org)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"by-b=" + b.org, "on-b=" + b.org, "platform="}; !slices.Equal(orgs, want) {
		t.Fatalf("audit orgs %v, want %v", orgs, want)
	}
	seen := func(o *OrgStore) []string {
		events, _, err := o.SearchAuditEvents(AuditFilter{Action: "x.", Limit: 50})
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, e := range events {
			ids = append(ids, e.ID)
		}
		slices.Sort(ids)
		return ids
	}
	if got := seen(a); len(got) != 0 {
		t.Errorf("A reads %v", got)
	}
	if got := seen(b); !slices.Equal(got, []string{"by-b", "on-b"}) {
		t.Errorf("B reads %v", got)
	}
	if got := seen(staff); !slices.Equal(got, []string{"platform"}) {
		t.Errorf("staff reads %v", got)
	}
	if n, err := a.CountAuditEvents(t.Context(), AuditFilter{Action: "x."}); err != nil || n != 0 {
		t.Errorf("A counts %d %v", n, err)
	}
	streamed := 0
	if _, err := a.StreamAuditEvents(t.Context(), AuditFilter{Action: "x."}, 50, func(AuditEvent) error { streamed++; return nil }); err != nil || streamed != 0 {
		t.Errorf("A streams %d %v", streamed, err)
	}

	// The same rule and key in two orgs are two alerts, each read only in its org.
	now := time.Now().UTC()
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	spec := alertSpec{"login_failures", "same-key", "warning", "t", "s", 1}
	for _, o := range []*OrgStore{a, b} {
		if err := raiseAlertTx(tx, now, spec, nil, sql.NullString{String: o.org, Valid: true}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	listA, totalA, err := a.ListAlerts("all", 50, 0)
	if err != nil || totalA != 1 {
		t.Fatalf("A alerts %v %d %v", listA, totalA, err)
	}
	listB, _, err := b.ListAlerts("all", 50, 0)
	if err != nil || len(listB) != 1 || listB[0].ID == listA[0].ID {
		t.Fatalf("B alerts %v %v", listB, err)
	}
	if err := a.AcknowledgeAlert(listB[0].ID, userA.ID, nil); !errors.Is(err, ErrAlertMissing) {
		t.Errorf("A acknowledged B's alert: %v", err)
	}
	if again, _, _ := b.ListAlerts("all", 50, 0); again[0].Status != "open" {
		t.Errorf("B's alert changed: %+v", again[0])
	}
}

// An inbound SCIM connector is its org's: another org cannot see, change, token or delete
// it, and what it creates lands in its org.
func TestSCIMConnectorsArePerOrg(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	a, b := testOrg(t, s, "household"), testOrg(t, s, "household")
	c, err := b.CreateSCIMConnector("b-directory", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := a.GetSCIMConnector(c.ID); err != nil || got != nil {
		t.Errorf("GetSCIMConnector: %v %v", got, err)
	}
	if list, err := a.ListSCIMConnectors(); err != nil || len(list) != 0 {
		t.Errorf("ListSCIMConnectors: %v %v", list, err)
	}
	if err := a.UpdateSCIMConnector(c.ID, "taken", "disabled", nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateSCIMConnector: %v", err)
	}
	if _, _, err := a.IssueSCIMToken(c.ID, "read", nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("IssueSCIMToken: %v", err)
	}
	if err := a.RevokeSCIMToken(c.ID, "x", nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("RevokeSCIMToken: %v", err)
	}
	if _, err := a.DeleteSCIMConnector(c.ID, false, nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteSCIMConnector: %v", err)
	}
	if err := a.ConfigureHR(HRConnection{ConnectorID: c.ID, SystemID: "x"}, nil); !errors.Is(err, ErrHRConflict) {
		t.Errorf("ConfigureHR: %v", err)
	}
	if got, err := b.GetSCIMConnector(c.ID); err != nil || got == nil || got.Name != "b-directory" || got.Status != "active" {
		t.Fatalf("B's connector changed: %+v %v", got, err)
	}
	u := &User{ID: uuid.NewString(), Username: "upstream-b", DisplayName: "u", Email: "upstream-b@test.invalid", Role: "user", Status: "disabled", Pending: true, SourceConnectorID: c.ID, ExternalID: "ext-1", SourceActive: true}
	if err := s.CreateUpstreamUser(u, nil); err != nil {
		t.Fatal(err)
	}
	if got, err := b.GetUserByID(u.ID); err != nil || got == nil {
		t.Fatalf("the connector's user is not in its org: %v %v", got, err)
	}
}

// Provisioning rows take the org of their resource, and on Postgres no org_id column keeps
// a default: an insert that forgets the org fails.
func TestProvisioningRowsAreInTheResourcesOrg(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	b := testOrg(t, s, "household")
	userB := testOrgUser(t, b, "user")
	provisioningFixture(t, s, "target")
	if err := s.SaveSCIMUserLink("target", userB.ID, "remote-b"); err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := queueDesiredStateTx(tx, desiredState{systemID: "target", resourceID: userB.ID, kind: "user", active: true, payload: []byte(`{}`)}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"scim_user_links WHERE local_id=?", "sync_resource_state WHERE resource_id=?", "account_sync_events WHERE user_id=?"} {
		var org string
		if err := s.db.QueryRow(`SELECT org_id FROM `+table, userB.ID).Scan(&org); err != nil || org != b.org {
			t.Errorf("%s: org %q (%v), want B", table, org, err)
		}
	}
	if !s.postgres {
		return
	}
	var defaults int
	if err := s.db.QueryRow(`SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND column_name='org_id' AND column_default IS NOT NULL`).Scan(&defaults); err != nil || defaults != 0 {
		t.Fatalf("%d org_id columns keep a default (%v)", defaults, err)
	}
}
