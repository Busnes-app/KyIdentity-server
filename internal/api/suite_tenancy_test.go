package api

import (
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Busnes-app/kyidentity-server/internal/config"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

var updateGolden = flag.Bool("update-golden", false, "rewrite testdata/tenancy-golden from this build")

// suiteOrgFixture puts two everyday users, both with kycalendar, and a suite group holding
// both in org, with fixed IDs prefixed by tag.
func suiteOrgFixture(t *testing.T, db *store.Store, org *store.OrgStore, tag string) (me, other *store.User, group string) {
	t.Helper()
	mk := func(id, name string) *store.User {
		u := &store.User{ID: tag + "-" + id, Username: tag + "-" + id, DisplayName: name, Email: tag + "-" + id + "@example.test", PasswordHash: "x", Role: "user", Status: "active"}
		if err := org.CreateUser(u); err != nil {
			t.Fatal(err)
		}
		return u
	}
	me, other = mk("me", "Al Me"), mk("other", "Al Other")
	g := &store.Group{ID: tag + "-group", Name: tag + " team"}
	if err := org.CreateGroup(g, nil); err != nil {
		t.Fatal(err)
	}
	for _, u := range []*store.User{me, other} {
		if err := org.SetGroupMembership(g.ID, u.ID, true, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := org.SetSuiteGroup(g.ID, true, nil, nil); err != nil {
		t.Fatal(err)
	}
	return me, other, g.ID
}

// The single-tenant suite directory answers exactly as before tenancy.
func TestSingleTenantSuiteAnswersAreUnchanged(t *testing.T) {
	srv, db, cleanup := suiteFixture(t)
	defer cleanup()
	allowTestAppAccess(t, db, "kycalendar")
	allowTestAppAccess(t, db, "kypost")
	me, _, _ := suiteOrgFixture(t, db, db.DefaultOrg(), "st")
	for name, path := range map[string]string{
		"suite_apps":     "/api/suite/apps",
		"suite_apps_sub": "/api/suite/apps?sub=" + me.ID,
		"suite_people":   "/api/suite/people?q=al&sub=" + me.ID,
		"suite_groups":   "/api/suite/groups",
	} {
		rr := suiteGet(t, srv, path, "kycalendar", "cal-secret")
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, rr.Code, rr.Body.String())
		}
		golden(t, name, rr.Body.String())
	}
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "tenancy-golden", name+".txt")
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("%s changed:\n got %s\nwant %s", name, strings.TrimSpace(got), want)
	}
}

// multiSuite is a multi-tenant server with kycalendar and kypost, both open to all active
// users, and two households: A has kycalendar, B has both.
func multiSuite(t *testing.T) (srv *Server, db *store.Store, orgA, orgB store.OrgID, cleanup func()) {
	t.Helper()
	srv, db, _, _, _, cleanup = setupTestServerWith(t, func(c *config.Config) { c.Tenancy = "multi" })
	createClient(t, db, "kycalendar", "confidential", crypto.HashSHA256("cal-secret"), "", "https://cal.example.test/cb")
	createClient(t, db, "kypost", "confidential", crypto.HashSHA256("post-secret"), "", "https://mail.example.test/cb")
	var err error
	if orgA, err = store.CreateOrgForTest(db, "customer"); err != nil {
		t.Fatal(err)
	}
	if orgB, err = store.CreateOrgForTest(db, "customer"); err != nil {
		t.Fatal(err)
	}
	for _, grant := range []struct {
		org    store.OrgID
		client string
	}{{orgA, "kycalendar"}, {orgB, "kycalendar"}, {orgB, "kypost"}} {
		if err := store.EnableOrgAppForTest(db, grant.org, suiteAppRecord(t, db, grant.client), `{"storage_gb":5}`); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []string{"kycalendar", "kypost"} {
		allowTestAppAccess(t, db, c)
	}
	return srv, db, orgA, orgB, cleanup
}

func suiteAppRecord(t *testing.T, db *store.Store, clientID string) string {
	t.Helper()
	apps, _, err := db.ListAppRecords(clientID, 1, 0)
	if err != nil || len(apps) != 1 {
		t.Fatal(apps, err)
	}
	return apps[0].ID
}

func suiteBody(t *testing.T, srv *Server, path, header string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.SetBasicAuth("kycalendar", "cal-secret")
	if header != "" {
		req.Header.Set("X-Ky-Org", header)
	}
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)
	return rr.Code, strings.TrimSpace(rr.Body.String())
}

// One org's sub never lists another org's apps, people or groups: the org comes from the
// sub's user row (or the stored org named by org_id), never from the caller or a header.
func TestMultiTenantSuiteIsScopedByOrg(t *testing.T) {
	srv, db, orgA, orgB, cleanup := multiSuite(t)
	defer cleanup()
	meA, _, groupA := suiteOrgFixture(t, db, db.Org(orgA), "a")
	meB, _, groupB := suiteOrgFixture(t, db, db.Org(orgB), "b")
	for _, c := range []struct{ path, header, want string }{
		{"/api/suite/apps?sub=" + meA.ID, orgB.String(), `{"apps":[{"id":"kycalendar","name":"kycalendar","url":"https://cal.example.test/api/sso/kysignon/login"}]}`},
		{"/api/suite/apps?sub=" + meB.ID, "", `{"apps":[{"id":"kycalendar","name":"kycalendar","url":"https://cal.example.test/api/sso/kysignon/login"},{"id":"kypost","name":"kypost","url":"https://mail.example.test/api/auth/oidc/login"}]}`},
		{"/api/suite/people?q=al&sub=" + meA.ID, orgB.String(), `{"people":[{"sub":"a-me","name":"Al Me","email":"a-me@example.test"},{"sub":"a-other","name":"Al Other","email":"a-other@example.test"}]}`},
		{"/api/suite/people?email=b-other@example.test&sub=" + meA.ID, "", `{"people":[]}`},
		{"/api/suite/groups?org_id=" + orgA.String(), orgB.String(), `{"groups":[{"id":"` + groupA + `","name":"a team","slug":"a-team","state":"active","members":["a-me","a-other"]}]}`},
		{"/api/suite/groups?org_id=" + orgB.String(), "", `{"groups":[{"id":"` + groupB + `","name":"b team","slug":"b-team","state":"active","members":["b-me","b-other"]}]}`},
		{"/api/suite/groups", orgA.String(), `{"error":"invalid_request"}`},
		{"/api/suite/groups?org_id=" + store.DefaultOrgID, "", `{"error":"unknown_org"}`},
		{"/api/suite/groups?org_id=nope", "", `{"error":"unknown_org"}`},
	} {
		if _, body := suiteBody(t, srv, c.path, c.header); body != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.path, body, c.want)
		}
	}
	if code, _ := suiteBody(t, srv, "/api/suite/groups", ""); code != http.StatusBadRequest {
		t.Fatalf("groups without org_id: %d", code)
	}
	// An org without the app is not the app's to read.
	orgC, err := store.CreateOrgForTest(db, "customer")
	if err != nil {
		t.Fatal(err)
	}
	suiteOrgFixture(t, db, db.Org(orgC), "c")
	if code, body := suiteBody(t, srv, "/api/suite/groups?org_id="+orgC.String(), ""); code != http.StatusNotFound {
		t.Fatalf("groups of an org without the app: %d %s", code, body)
	}
}

type wireOrg struct {
	ID       string          `json:"id"`
	Status   string          `json:"status"`
	Revision int64           `json:"revision"`
	Enabled  bool            `json:"enabled"`
	Quotas   json.RawMessage `json:"quotas"`
}

// /api/suite/orgs lists the orgs that have (or had) the caller's app, with only that app's
// enablement and quotas, paged by cursor in revision order, and since a revision.
func TestMultiTenantSuiteOrgs(t *testing.T) {
	srv, db, orgA, orgB, cleanup := multiSuite(t)
	defer cleanup()
	if _, err := store.CreateOrgForTest(db, "staff"); err != nil {
		t.Fatal(err)
	}
	orgOff, err := store.CreateOrgForTest(db, "customer")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnableOrgAppForTest(db, orgOff, suiteAppRecord(t, db, "kycalendar"), `{}`); err != nil {
		t.Fatal(err)
	}
	raw, err := store.OpenRawForTest(srv.cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	exec := func(q string, args ...any) {
		t.Helper()
		if store.OnPostgresTest() {
			for i := range args {
				q = strings.Replace(q, "?", "$"+strconv.Itoa(i+1), 1)
			}
		}
		if _, err := raw.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE org_apps SET enabled=FALSE WHERE org_id=?`, orgOff.String())
	exec(`UPDATE orgs SET revision=(SELECT MAX(revision)+1 FROM orgs) WHERE id=?`, orgOff.String())

	page := func(query string) (int, []wireOrg, string) {
		t.Helper()
		code, body := suiteBody(t, srv, "/api/suite/orgs"+query, "")
		var out struct {
			Orgs []wireOrg `json:"orgs"`
			Next string    `json:"next"`
		}
		if code == http.StatusOK && (json.Unmarshal([]byte(body), &out) != nil || out.Orgs == nil) {
			t.Fatalf("orgs%s: %s", query, body)
		}
		return code, out.Orgs, out.Next
	}
	var all []wireOrg
	for q := "?limit=1"; ; {
		code, orgs, next := page(q)
		if code != http.StatusOK || len(orgs) > 1 {
			t.Fatalf("orgs%s: %d %v", q, code, orgs)
		}
		all = append(all, orgs...)
		if next == "" {
			break
		}
		q = "?limit=1&cursor=" + next
	}
	want := []wireOrg{
		{orgA.String(), "active", 0, true, json.RawMessage(`{"storage_gb":5}`)},
		{orgB.String(), "active", 0, true, json.RawMessage(`{"storage_gb":5}`)},
		{orgOff.String(), "active", 0, false, json.RawMessage(`{}`)},
	}
	if len(all) != len(want) {
		t.Fatalf("orgs %+v", all)
	}
	for i, o := range all {
		if i > 0 && o.Revision <= all[i-1].Revision {
			t.Errorf("revisions out of order: %+v", all)
		}
		w := want[i]
		if o.ID != w.ID || o.Status != w.Status || o.Enabled != w.Enabled || string(o.Quotas) != string(w.Quotas) {
			t.Errorf("org %d = %+v, want %+v", i, o, w)
		}
	}
	// since: only what changed after the revision the app last saw.
	last := all[len(all)-1].Revision
	if _, orgs, next := page("?since=" + strconv.FormatInt(last, 10)); len(orgs) != 0 || next != "" {
		t.Fatalf("nothing changed since %d, got %+v %q (all %+v)", last, orgs, next, all)
	}
	exec(`UPDATE orgs SET status='deletion_scheduled', delete_after=1, revision=(SELECT MAX(revision)+1 FROM orgs) WHERE id=?`, orgA.String())
	exec(`DELETE FROM org_apps WHERE org_id=?`, orgA.String())
	exec(`UPDATE orgs SET status='deleted', revision=(SELECT MAX(revision)+1 FROM orgs) WHERE id=?`, orgA.String())
	if _, orgs, _ := page("?since=" + strconv.FormatInt(last, 10)); len(orgs) != 1 || orgs[0].ID != orgA.String() || orgs[0].Status != "deleted" || orgs[0].Enabled {
		t.Fatalf("a deleted org is listed once more, off: %+v", orgs)
	}
	for _, q := range []string{"?since=-1", "?since=x", "?limit=0", "?limit=501", "?cursor=5", "?cursor=x.y", "?since=1&cursor=1.a"} {
		if code, _, _ := page(q); code != http.StatusBadRequest {
			t.Errorf("orgs%s: %d, want 400", q, code)
		}
	}
}

// A single-tenant install has no orgs to list.
func TestSingleTenantHasNoSuiteOrgs(t *testing.T) {
	srv, _, cleanup := suiteFixture(t)
	defer cleanup()
	if rr := suiteGet(t, srv, "/api/suite/orgs", "kycalendar", "cal-secret"); rr.Code != http.StatusNotFound {
		t.Fatalf("orgs: %d %s", rr.Code, rr.Body.String())
	}
}
