package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// crossOrgSteps names, per admin path prefix, the build plan step (tenancy design, PR 2)
// whose rows TestCrossOrgMatrix runs on that route. "2a" routes are covered; a later step
// moves its prefixes to "2a"'s list as it scopes them. A route under no prefix fails.
var crossOrgSteps = []struct{ prefix, step string }{
	{"/api/admin/users", "2a"},
	{"/api/admin/groups", "2a"},
	{"/api/admin/app-registry", "2b"},
	{"/api/admin/clients", "2b"},
	{"/api/admin/workstation-apps", "2b"},
	{"/api/admin/applications", "2b"},
	{"/api/admin/icons", "2b"},
	{"/api/admin/proxy-apps", "2b"},
	{"/api/admin/access-requests", "2b"},
	{"/api/admin/enrollment-policies", "2b"},
	{"/api/admin/mail", "2b"},
	{"/api/admin/session-settings", "2b"},
	{"/api/admin/rate-limit-networks", "2b"},
	{"/api/admin/attestation", "2b"},
	{"/api/admin/branding", "2b"},
	{"/api/admin/backup", "2b"},
	{"/api/admin/alerts/settings", "2b"},
	{"/api/admin/alerts", "2d"},
	{"/api/admin/audit-events", "2d"},
	{"/api/admin/scim-connectors", "2d"},
	{"/api/admin/systems", "2d"},
}

func crossOrgStep(path string) string {
	for _, s := range crossOrgSteps {
		if path == s.prefix || strings.HasPrefix(path, s.prefix+"/") {
			return s.step
		}
	}
	return ""
}

func newOrgUser(t *testing.T, db *store.Store, org store.OrgID, role string) *store.User {
	t.Helper()
	name := "u" + uuid.NewString()[:8]
	u := &store.User{ID: uuid.NewString(), Username: name, DisplayName: name, Email: name + "@x.test", PasswordHash: "x", Role: role, Status: "active"}
	if err := db.Org(org).CreateUser(u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return u
}

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
		for _, err := range []error{err1, err2, err3, err4, err5} {
			if err != nil {
				t.Fatal(err)
			}
		}
		sess, err := db.GetSessionByTokenHash(crypto.HashSHA256(sessionB), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		out, _ := json.Marshal([]any{users, groups, members, suite, d, sess != nil})
		return string(out)
	}
	before := snapshotB()
	call := func(rt adminRoute, path, cookie string) (int, string) {
		res := adminRequestWithStepUp(t, srv, rt.method, path, cookie, crossOrgBody(rt), mintStepUp(t, srv, cookie, rt.method+" "+path))
		return res.Code, res.Body.String()
	}
	fill := func(rt adminRoute, user, group string) string {
		p := rt.path
		if strings.HasPrefix(p, "/api/admin/groups/") {
			p = strings.Replace(p, "{id}", group, 1)
		}
		p = strings.Replace(strings.Replace(p, "{id}", user, 1), "{userId}", user, 1)
		for _, ph := range []string{"{sid}", "{clientId}", "{deliveryId}"} {
			p = strings.Replace(p, ph, "x", 1)
		}
		return p
	}

	covered := 0
	for _, rt := range srv.adminRoutes {
		step := crossOrgStep(rt.path)
		if step == "" {
			t.Errorf("%s %s: no build plan step in crossOrgSteps", rt.method, rt.path)
			continue
		}
		for name, cookie := range customers {
			if code, body := call(rt, fill(rt, userB.ID, groupB.ID), cookie); code != http.StatusForbidden || !strings.Contains(body, `"error":"forbidden"`) {
				t.Errorf("%s %s as A's %s: %d %s", rt.method, rt.path, name, code, body)
			}
		}
		if step != "2a" {
			continue
		}
		covered++
		for name, cookie := range staff {
			if !strings.Contains(rt.path, "{") {
				// Lists and creates: nothing of B's comes back.
				_, body := call(rt, rt.path, cookie)
				for _, id := range []string{userB.ID, userB.Username, groupB.ID, groupB.Name} {
					if strings.Contains(body, id) {
						t.Errorf("%s %s as staff %s answered with B's %q", rt.method, rt.path, name, id)
					}
				}
				continue
			}
			wantCode, wantBody := call(rt, fill(rt, uuid.NewString(), uuid.NewString()), cookie)
			targets := [][2]string{{userB.ID, groupB.ID}}
			if strings.Contains(rt.path, "{userId}") {
				targets = append(targets, [2]string{userB.ID, staffGroup.ID})
			}
			for _, tg := range targets {
				code, body := call(rt, fill(rt, tg[0], tg[1]), cookie)
				// A missing ID's error names the ID asked for; compare the rest.
				body = strings.ReplaceAll(strings.ReplaceAll(body, tg[0], "ID"), tg[1], "ID")
				if code != wantCode || code == http.StatusOK || code/100 == 5 || !sameShape(body, wantBody) {
					t.Errorf("%s %s as staff %s with B's IDs: %d %s, a missing ID answers %d %s", rt.method, rt.path, name, code, body, wantCode, wantBody)
				}
			}
		}
		if after := snapshotB(); after != before {
			t.Fatalf("%s %s changed org B:\n before %s\n after  %s", rt.method, rt.path, before, after)
		}
	}
	if covered < 20 {
		t.Fatalf("only %d routes covered", covered)
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
