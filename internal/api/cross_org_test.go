package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/config"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

func newOrgUser(t *testing.T, db *store.Store, org store.OrgID, role string) *store.User {
	t.Helper()
	name := "u" + uuid.NewString()[:8]
	u := &store.User{ID: uuid.NewString(), Username: name, DisplayName: name, Email: name + "@x.test", PasswordHash: "x", Role: role, Status: "active"}
	if err := db.Org(org).CreateUser(u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return u
}

// takesID: an org route whose path names a user, group, request, connector or alert.
var takesID = regexp.MustCompile(`\{(principal|userId)\}|/(users|groups|access-requests|scim-connectors|alerts)/\{id\}`)

// The cross-org matrix (tenancy design, "Isolation enforcement"). Orgs A and B, and a staff
// org with an admin, a helpdesk and an auditor. Until staff select an org (build plan PR
// 5) an admin route is bound to the caller's own org, so here B's IDs reach staff only
// through a request, and must answer exactly as a missing ID does, changing nothing in B.
// Every admin route refuses A's account holder and member as it refuses a non-admin.
func TestCrossOrgMatrix(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	exp := time.Now().UTC().Add(time.Hour)
	org := func(kind string) store.OrgID {
		id, err := store.CreateOrgForTest(db, kind)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	orgA, orgB, staffOrg := org("household"), org("household"), org("staff")

	holderA, memberA := newOrgUser(t, db, orgA, "user"), newOrgUser(t, db, orgA, "user")
	raw, err := store.OpenRawForTest(srv.cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	q := `UPDATE orgs SET account_holder_user_id=? WHERE id=?`
	if store.OnPostgresTest() {
		q = `UPDATE orgs SET account_holder_user_id=$1 WHERE id=$2`
	}
	if _, err := raw.Exec(q, holderA.ID, orgA.String()); err != nil {
		t.Fatal(err)
	}
	userB := newOrgUser(t, db, orgB, "user")
	sessionB := newSession(t, db, userB, exp)
	groupB := &store.Group{ID: uuid.NewString(), Name: "b-" + uuid.NewString()[:8]}
	if err := db.Org(orgB).CreateGroup(groupB, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.Org(orgB).SetGroupMembership(groupB.ID, userB.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Org(orgB).SetSuiteGroup(groupB.ID, true, nil, nil); err != nil {
		t.Fatal(err)
	}
	app, req := crossOrgApps(t, db, orgB, userB, groupB)
	connB, err := db.Org(orgB).CreateSCIMConnector("b-directory", nil)
	if err != nil {
		t.Fatal(err)
	}
	alertB := crossOrgAlert(t, db, srv.cfg.DBPath, userB)
	if err := db.RecordAuditEvent(&store.AuditEvent{ID: "b-audit-" + uuid.NewString(), ActorID: userB.ID, ActorUsername: userB.Username, Action: "b.private", TargetID: userB.ID, TargetType: "user", Outcome: "success"}); err != nil {
		t.Fatal(err)
	}
	staffGroup := &store.Group{ID: uuid.NewString(), Name: "staff-" + uuid.NewString()[:8]}
	if err := db.Org(staffOrg).CreateGroup(staffGroup, nil); err != nil {
		t.Fatal(err)
	}
	staff := map[string]string{"admin": newSession(t, db, newOrgUser(t, db, staffOrg, "admin"), exp)}
	for name, d := range map[string]store.Delegations{"helpdesk": {Helpdesk: true}, "auditor": {Auditor: true}} {
		u := newOrgUser(t, db, staffOrg, "user")
		if err := db.Org(staffOrg).SetDelegations(u.ID, d, nil); err != nil {
			t.Fatal(err)
		}
		staff[name] = newSession(t, db, u, exp)
	}
	customers := map[string]string{"holder": newSession(t, db, holderA, exp), "member": newSession(t, db, memberA, exp)}

	snapshotB := func() string {
		t.Helper()
		b := db.Org(orgB)
		users, err1 := b.ListUsers()
		groups, _, err2 := b.ListGroups("", "", 100, 0)
		members, _, err3 := b.ListGroupUsers(groupB.ID, "", true, 100, 0)
		suite, err4 := b.GetSuiteGroup(groupB.ID)
		d, err5 := b.Delegations(userB.ID)
		access, err6 := b.ListAppAccessUsers(app.app, "", "", nil, 100, 0)
		roles, err7 := b.ListAppRoles(app.app)
		requests, _, err8 := b.ListAccessRequests(store.AccessRequestFilter{UserID: userB.ID, Limit: 100})
		conns, err9 := b.ListSCIMConnectors()
		alerts, _, err10 := b.ListAlerts("all", 100, 0)
		audit, _, err11 := b.SearchAuditEvents(store.AuditFilter{Action: "b.", Limit: 100})
		for _, err := range []error{err1, err2, err3, err4, err5, err6, err7, err8, err9, err10, err11} {
			if err != nil {
				t.Fatal(err)
			}
		}
		sess, err := db.GetSessionByTokenHash(crypto.HashSHA256(sessionB), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		out, _ := json.Marshal([]any{users, groups, members, suite, d, sess != nil, access.Users, roles, requests, conns, alerts, audit})
		return string(out)
	}
	before := snapshotB()
	call := func(rt adminRoute, path, cookie string) (int, string) {
		res := adminRequestWithStepUp(t, srv, rt.method, path, cookie, crossOrgBody(rt), mintStepUp(t, srv, cookie, rt.method+" "+path))
		return res.Code, res.Body.String()
	}
	// fill puts user, group (or, on a groups {kind}, group as the principal) and request
	// into the path; apps and roles are global, so they are real ones.
	fill := func(rt adminRoute, kind, user, group, request, other string) string {
		p := strings.Replace(rt.path, "{kind}", kind, 1)
		principal := user
		if kind == "groups" {
			principal = group
		}
		switch {
		case strings.HasPrefix(p, "/api/admin/groups/"):
			p = strings.Replace(p, "{id}", group, 1)
		case strings.HasPrefix(p, "/api/admin/app-registry/"):
			p = strings.Replace(p, "{id}", app.app, 1)
		case strings.HasPrefix(p, "/api/admin/access-requests/"):
			p = strings.Replace(p, "{id}", request, 1)
		case strings.HasPrefix(p, "/api/admin/scim-connectors/"), strings.HasPrefix(p, "/api/admin/alerts/"):
			p = strings.Replace(p, "{id}", other, 1)
		}
		p = strings.NewReplacer("{id}", user, "{userId}", user, "{principal}", principal, "{roleId}", app.role).Replace(p)
		for _, ph := range []string{"{sid}", "{clientId}", "{deliveryId}", "{tokenId}"} {
			p = strings.Replace(p, ph, "x", 1)
		}
		return p
	}
	names := []string{userB.ID, userB.Username, groupB.ID, groupB.Name, req, connB.ID, connB.Name, alertB, "b.private"}

	covered := 0
	for _, rt := range srv.adminRoutes {
		for name, cookie := range customers {
			if code, body := call(rt, fill(rt, "users", userB.ID, groupB.ID, req, connB.ID), cookie); code != http.StatusForbidden || !strings.Contains(body, `"error":"forbidden"`) {
				t.Errorf("%s %s as A's %s: %d %s", rt.method, rt.path, name, code, body)
			}
		}
		// Platform routes change what every org shares; TestPlatformRoutesNeedAnAdministrator
		// covers them.
		if rt.scope != orgRoute {
			continue
		}
		covered++
		takesB := takesID.MatchString(rt.path)
		for name, cookie := range staff {
			if !takesB {
				// Lists, creates and app-wide routes: nothing of B's comes back.
				_, body := call(rt, fill(rt, "users", userB.ID, groupB.ID, req, connB.ID), cookie)
				check := names
				if strings.HasPrefix(rt.path, "/api/admin/audit-events") {
					// Staff's own refused attempts on B's IDs are audited in the staff org,
					// naming those IDs; only what staff never sent may not appear.
					check = []string{userB.Username, groupB.Name, connB.Name, "b.private"}
				}
				for _, id := range check {
					if strings.Contains(body, id) {
						t.Errorf("%s %s as staff %s answered with B's %q", rt.method, rt.path, name, id)
					}
				}
				continue
			}
			kinds := []string{"users"}
			if strings.Contains(rt.path, "{kind}") {
				kinds = append(kinds, "groups")
			}
			for _, kind := range kinds {
				wantCode, wantBody := call(rt, fill(rt, kind, uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()), cookie)
				targets := [][4]string{{userB.ID, groupB.ID, req, connB.ID}}
				if strings.Contains(rt.path, "{userId}") {
					targets = append(targets, [4]string{userB.ID, staffGroup.ID, req, connB.ID})
				}
				if strings.HasPrefix(rt.path, "/api/admin/alerts/") {
					targets = [][4]string{{userB.ID, groupB.ID, req, alertB}}
				}
				for _, tg := range targets {
					code, body := call(rt, fill(rt, kind, tg[0], tg[1], tg[2], tg[3]), cookie)
					// A missing ID's error names the ID asked for; compare the rest.
					body = strings.NewReplacer(tg[0], "ID", tg[1], "ID", tg[2], "ID", tg[3], "ID").Replace(body)
					if code != wantCode || code == http.StatusOK || code/100 == 5 || !sameShape(body, wantBody) {
						t.Errorf("%s %s (%s) as staff %s with B's IDs: %d %s, a missing ID answers %d %s", rt.method, rt.path, kind, name, code, body, wantCode, wantBody)
					}
				}
			}
		}
		if after := snapshotB(); after != before {
			t.Fatalf("%s %s changed org B:\n before %s\n after  %s", rt.method, rt.path, before, after)
		}
	}
	if covered < 45 {
		t.Fatalf("only %d routes covered", covered)
	}

	// Account routes: A's member names B's session, request, passkey and device. Each
	// answers as a missing ID does; the lists show none of B's.
	passkeyB := &store.WebAuthnCredential{ID: uuid.NewString(), UserID: userB.ID, CredentialID: uuid.NewString(), PublicKeySPKI: "x", Name: "b-key"}
	if err := db.CreateWebAuthnCredential(passkeyB, nil); err != nil {
		t.Fatal(err)
	}
	deviceB := &store.NativeDevice{ID: uuid.NewString(), UserID: userB.ID, DeviceName: "b-phone", DeviceIdentifier: uuid.NewString()}
	if err := db.UpsertNativeDevice(deviceB); err != nil {
		t.Fatal(err)
	}
	sessB, err := db.GetSessionByTokenHash(crypto.HashSHA256(sessionB), time.Hour)
	if err != nil || sessB == nil {
		t.Fatal(sessB, err)
	}
	ownB := func() string {
		t.Helper()
		keys, err1 := db.ListUserWebAuthnCredentials(userB.ID)
		devices, err2 := db.ListUserNativeDevices(userB.ID)
		if err1 != nil || err2 != nil {
			t.Fatal(err1, err2)
		}
		out, _ := json.Marshal([]any{snapshotB(), keys, devices})
		return string(out)
	}
	beforeOwn := ownB()
	account := []struct{ method, path, id, body string }{
		{"DELETE", "/api/user/sessions/{id}", sessB.ID, ""},
		{"DELETE", "/api/user/access-requests/{id}", req, ""},
		{"DELETE", "/api/user/passkeys/{id}", passkeyB.ID, ""},
		{"DELETE", "/api/user/devices/{id}", deviceB.ID, ""},
		{"PUT", "/api/notifications/native/devices/{id}/mfa", deviceB.ID, `{"enabled":true}`},
		{"PUT", "/api/notifications/native/devices/{id}/sign-on", deviceB.ID, `{"enabled":true}`},
	}
	for name, cookie := range customers {
		for _, rt := range account {
			do := func(id string) *httptest.ResponseRecorder {
				path := strings.Replace(rt.path, "{id}", id, 1)
				return adminRequestWithStepUp(t, srv, rt.method, path, cookie, rt.body, mintStepUp(t, srv, cookie, rt.method+" "+path))
			}
			res, want := do(rt.id), do(uuid.NewString())
			body := strings.ReplaceAll(res.Body.String(), rt.id, "ID")
			if res.Code != want.Code || res.Code/100 == 2 || res.Code/100 == 5 || !sameShape(body, want.Body.String()) {
				t.Errorf("%s %s as A's %s with B's ID: %d %s, a missing ID answers %d %s", rt.method, rt.path, name, res.Code, body, want.Code, want.Body.String())
			}
		}
		for _, path := range []string{"/api/user/sessions", "/api/user/access-requests", "/api/user/passkeys", "/api/user/devices", "/api/user/applications"} {
			body := adminRequestWithStepUp(t, srv, "GET", path, cookie, "", "").Body.String()
			for _, id := range append(names, sessB.ID, passkeyB.ID, deviceB.ID) {
				if strings.Contains(body, id) {
					t.Errorf("GET %s as A's %s shows B's %q", path, name, id)
				}
			}
		}
	}
	if after := ownB(); after != beforeOwn {
		t.Fatalf("account routes changed org B:\n before %s\n after  %s", beforeOwn, after)
	}
}

// sameShape compares two error bodies with any UUIDs in them blanked.
func sameShape(a, b string) bool {
	blank := func(s string) string {
		var out strings.Builder
		for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == '"' || r == '/' || r == ' ' }) {
			if _, err := uuid.Parse(f); err == nil {
				f = "ID"
			}
			out.WriteString(f + " ")
		}
		return out.String()
	}
	return blank(a) == blank(b)
}

// crossOrgBody is a request body that passes validation, so the call reaches the lookup.
func crossOrgBody(rt adminRoute) string {
	switch {
	case rt.method == "GET" || rt.method == "DELETE":
		return ""
	case strings.HasSuffix(rt.path, "/delegations"):
		return `{"helpdesk":true}`
	case strings.HasSuffix(rt.path, "/suite"):
		return `{"enabled":false}`
	case rt.path == "/api/admin/groups" || rt.path == "/api/admin/groups/{id}":
		return `{"name":"cross-org"}`
	case rt.path == "/api/admin/users":
		return `{"username":"cross-org","displayName":"x","email":"cross-org@x.test","role":"user","pending":true}`
	case rt.path == "/api/admin/users/{id}":
		return `{"displayName":"taken","role":"admin","status":"disabled"}`
	}
	return `{}`
}

type crossOrgApp struct{ app, role string }

// crossOrgApps makes a global app with a role, and gives B's user and group a grant and
// the role on it; a second, requestable app holds a pending request of B's user.
func crossOrgApps(t *testing.T, db *store.Store, orgB store.OrgID, userB *store.User, groupB *store.Group) (crossOrgApp, string) {
	t.Helper()
	record := func(id string) store.AppRecord {
		if err := db.CreateOAuthClient(&store.OAuthClient{ID: id, ClientName: id, ClientType: "public", RedirectURIsJSON: `["https://a/cb"]`, AllowedScopesJSON: `["openid"]`, Enabled: true}, nil); err != nil {
			t.Fatal(err)
		}
		apps, _, err := db.ListAppRecords(id, 1, 0)
		if err != nil || len(apps) != 1 {
			t.Fatal(apps, err)
		}
		return apps[0]
	}
	granted, requestable := record("cross-org-app"), record("cross-org-request")
	role, err := db.CreateAppRole(granted.ID, "editor", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	b := db.Org(orgB)
	for kind, principal := range map[string]string{"users": userB.ID, "groups": groupB.ID} {
		if err := b.SetAppAssignment(granted.ID, kind, principal, true, nil); err != nil {
			t.Fatal(err)
		}
		if err := b.SetAppRoleAssignment(granted.ID, role.ID, kind, principal, true, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.SetAppRequestable(requestable.ID, true, requestable.Revision, nil); err != nil {
		t.Fatal(err)
	}
	req, err := db.CreateAccessRequest(userB.ID, requestable.ID, "please", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	return crossOrgApp{granted.ID, role.ID}, req.ID
}

// A platform route changes what every org shares, so in a multi-tenant install only a
// global administrator passes it, whatever the delegation; an org route keeps today's
// permissions. Single-tenant installs keep today's matrix (TestPermissionMatrixCoversEveryAdminRoute).
func TestPlatformRoutesNeedAnAdministrator(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServerWith(t, func(c *config.Config) { c.Tenancy = "multi" })
	defer cleanup()
	exp := time.Now().UTC().Add(time.Hour)
	staffOrg, err := store.CreateOrgForTest(db, "staff")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateOAuthClient(&store.OAuthClient{ID: "owned", ClientName: "owned", ClientType: "public", RedirectURIsJSON: `["https://a/cb"]`, AllowedScopesJSON: `["openid"]`, Enabled: true}, nil); err != nil {
		t.Fatal(err)
	}
	apps, _, _ := db.ListAppRecords("owned", 1, 0)
	admin := newSession(t, db, newOrgUser(t, db, staffOrg, "admin"), exp)
	delegates := map[string]string{}
	for name, d := range map[string]store.Delegations{"helpdesk": {Helpdesk: true}, "auditor": {Auditor: true}, "owner": {AppOwner: []string{apps[0].ID}}} {
		u := newOrgUser(t, db, staffOrg, "user")
		if err := db.Org(staffOrg).SetDelegations(u.ID, d, nil); err != nil {
			t.Fatal(err)
		}
		delegates[name] = newSession(t, db, u, exp)
	}
	forbidden := func(rt adminRoute, cookie string) bool {
		path := strings.NewReplacer("{id}", apps[0].ID, "{kind}", "users").Replace(rt.path)
		for _, ph := range []string{"{sid}", "{clientId}", "{deliveryId}", "{roleId}", "{principal}", "{token}", "{userId}", "{tokenId}"} {
			path = strings.Replace(path, ph, "x", 1)
		}
		res := adminRequestWithStepUp(t, srv, rt.method, path, cookie, `{}`, mintStepUp(t, srv, cookie, rt.method+" "+path))
		return res.Code == http.StatusForbidden && strings.Contains(res.Body.String(), `"error":"forbidden"`)
	}
	var platform, reachedByDelegate int
	for _, rt := range srv.adminRoutes {
		if rt.scope == platformRoute {
			platform++
			for name, cookie := range delegates {
				if !forbidden(rt, cookie) {
					t.Errorf("%s %s: staff %s passed a platform route", rt.method, rt.path, name)
				}
			}
		} else if !forbidden(rt, delegates["auditor"]) || !forbidden(rt, delegates["helpdesk"]) {
			reachedByDelegate++
		}
		if forbidden(rt, admin) {
			t.Errorf("%s %s: staff admin refused", rt.method, rt.path)
		}
	}
	if platform < 60 || reachedByDelegate < 10 {
		t.Fatalf("platform routes %d, org routes a delegate reaches %d", platform, reachedByDelegate)
	}
}

// crossOrgAlert raises a recovery-use alert in B's org, through the alert worker.
func crossOrgAlert(t *testing.T, db *store.Store, dbPath string, userB *store.User) string {
	t.Helper()
	if err := db.RecordAuditEvent(&store.AuditEvent{ID: uuid.NewString(), ActorID: userB.ID, ActorUsername: userB.Username, Action: "auth.mfa_recovery_consumed", TargetID: userB.ID, TargetType: "user", Outcome: "success"}); err != nil {
		t.Fatal(err)
	}
	if err := db.EvaluateAlerts(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	var id string
	raw, err := store.OpenRawForTest(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err := raw.QueryRow(`SELECT id FROM alerts WHERE org_id IS NOT NULL`).Scan(&id); err != nil {
		t.Fatalf("no alert in B: %v", err)
	}
	return id
}
