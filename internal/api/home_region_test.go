package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// /api/suite/orgs carries each org's home region; the default for orgs made without one is local.
func TestSuiteOrgsCarryTheHomeRegion(t *testing.T) {
	srv, db, orgA, _, cleanup := multiSuite(t)
	defer cleanup()
	eu, err := store.CreateOrgInRegionForTest(db, "household", "eu-central")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnableOrgAppForTest(db, eu, suiteAppRecord(t, db, "kycalendar"), `{}`); err != nil {
		t.Fatal(err)
	}
	_, body := suiteBody(t, srv, "/api/suite/orgs", "")
	var out struct {
		Orgs []struct {
			ID         string `json:"id"`
			HomeRegion string `json:"home_region"`
		} `json:"orgs"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(body, err)
	}
	got := map[string]string{}
	for _, o := range out.Orgs {
		got[o.ID] = o.HomeRegion
	}
	if got[orgA.String()] != "local" || got[eu.String()] != "eu-central" || len(got) != 3 {
		t.Fatalf("home regions %v from %s", got, body)
	}
}

// regionalSuite adds kymessage, served from us and eu hostnames, to multiSuite, with a
// member in an eu org and one in a local org (which kymessage has no region for).
func regionalSuite(t *testing.T) (srv *Server, db *store.Store, euMember, localMember *store.User, cleanup func()) {
	t.Helper()
	srv, db, orgA, _, cleanup := multiSuite(t)
	createClient(t, db, "kymessage", "confidential", crypto.HashSHA256("msg-secret"), "",
		"https://us.chat.example.test/cb", "https://eu.chat.example.test/cb")
	allowTestAppAccess(t, db, "kymessage")
	eu, err := store.CreateOrgInRegionForTest(db, "household", "eu")
	if err != nil {
		t.Fatal(err)
	}
	for _, org := range []store.OrgID{eu, orgA} {
		for _, c := range []string{"kycalendar", "kymessage"} {
			if c == "kycalendar" && org == orgA {
				continue // multiSuite already enabled it
			}
			if err := store.EnableOrgAppForTest(db, org, suiteAppRecord(t, db, c), `{}`); err != nil {
				t.Fatal(err)
			}
		}
	}
	event := &store.AuditEvent{ID: "regions-fixture", Action: "admin.client_regions_changed", Outcome: "success", CreatedAt: time.Now().UTC()}
	// ap is not a redirect origin: written past the route's check, it must still never be used.
	if err := db.SetClientRegionOrigins("kymessage", map[string]string{"us": "https://us.chat.example.test", "eu": "https://eu.chat.example.test", "ap": "https://ap.chat.example.test"}, event); err != nil {
		t.Fatal(err)
	}
	return srv, db, newOrgUser(t, db, eu, "user"), newOrgUser(t, db, orgA, "user"), cleanup
}

func appURL(t *testing.T, body, id string) string {
	t.Helper()
	var out struct {
		Apps         []suiteApp `json:"apps"`
		Applications []suiteApp `json:"applications"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(body, err)
	}
	for _, a := range append(out.Apps, out.Applications...) {
		if a.ID == id {
			return a.URL
		}
	}
	return ""
}

// A regioned app opens at the viewer's home-region origin, keeping its path, and is left out
// for an org whose region it has no origin for. Unregioned apps and the sub-less list are as before.
func TestRegionalLaunchURLs(t *testing.T) {
	srv, db, euMember, localMember, cleanup := regionalSuite(t)
	defer cleanup()
	for _, c := range []struct {
		user          *store.User
		msg, calendar string
	}{
		{euMember, "https://eu.chat.example.test/api/sso/kyidentity/login", "https://cal.example.test/api/sso/kysignon/login"},
		{localMember, "", "https://cal.example.test/api/sso/kysignon/login"},
	} {
		_, body := suiteBody(t, srv, "/api/suite/apps?sub="+c.user.ID, "")
		if appURL(t, body, "kymessage") != c.msg || appURL(t, body, "kycalendar") != c.calendar {
			t.Errorf("suite apps for %s: %s", c.user.ID, body)
		}
		launcher := adminRequest(t, srv, "GET", "/api/user/applications", newSession(t, db, c.user, time.Now().UTC().Add(time.Hour)), "")
		if appURL(t, launcher.Body.String(), "kymessage") != c.msg {
			t.Errorf("launcher for %s: %s", c.user.ID, launcher.Body.String())
		}
	}
	if _, body := suiteBody(t, srv, "/api/suite/apps", ""); appURL(t, body, "kymessage") != "https://us.chat.example.test/api/sso/kyidentity/login" {
		t.Errorf("global list: %s", body)
	}

	// The peer answer publishes the verified map; url stays the redirect origin.
	_, body := suiteBody(t, srv, "/api/suite/peer?client=kymessage", "")
	var peer struct {
		URL     string            `json:"url"`
		Regions map[string]string `json:"regions"`
	}
	if err := json.Unmarshal([]byte(body), &peer); err != nil {
		t.Fatal(body, err)
	}
	if peer.URL != "https://us.chat.example.test" || len(peer.Regions) != 2 || peer.Regions["eu"] != "https://eu.chat.example.test" || peer.Regions["us"] != "https://us.chat.example.test" {
		t.Fatalf("peer: %s", body)
	}
	// An unregioned peer has no regions key.
	if rr := suiteGet(t, srv, "/api/suite/peer?client=kycalendar", "kymessage", "msg-secret"); rr.Code != http.StatusOK || strings.Contains(rr.Body.String(), "regions") {
		t.Fatalf("unregioned peer: %d %s", rr.Code, rr.Body.String())
	}
}

// Staff set a client's region map with step-up and an audit row; origins must be the
// client's redirect origins. Single-tenant installs have no such route.
func TestClientRegions(t *testing.T) {
	srv, db, staffOrg, _, cookie, cleanup := multiMailboxServer(t)
	defer cleanup()
	createClient(t, db, "kymessage", "confidential", crypto.HashSHA256("msg-secret"), "",
		"https://us.chat.example.test/cb", "https://EU.chat.example.test/cb")
	path := "/api/admin/clients/kymessage/regions"
	for _, bad := range []string{
		`{}`, `{"regions":null}`, `{"regions":{"us":"https://other.example.test"}}`,
		`{"regions":{"US":"https://us.chat.example.test"}}`, `{"regions":{"u":"https://us.chat.example.test"}}`,
		`{"regions":{"us":"https://us.chat.example.test/"}}`, `{"regions":{"us":"https://us.chat.example.test/cb"}}`,
		`{"regions":{"us":"http://us.chat.example.test"}}`, `{"regions":{"us":"https://u:p@us.chat.example.test"}}`,
		`{"regions":{"us":"https://us.chat.example.test"},"x":1}`,
	} {
		if rr := adminRequest(t, srv, "PUT", path, cookie, bad); rr.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", bad, rr.Code, rr.Body.String())
		}
	}
	if rr := adminRequest(t, srv, "PUT", "/api/admin/clients/nope/regions", cookie, `{"regions":{}}`); rr.Code != http.StatusNotFound {
		t.Errorf("unknown client: %d", rr.Code)
	}
	body := `{"regions":{"us":"https://us.chat.example.test","eu-central":"https://eu.CHAT.example.test"}}`
	if rr := adminRequestNoStepUp(t, srv, "PUT", path, cookie, body); rr.Code != http.StatusForbidden {
		t.Fatalf("without step-up: %d", rr.Code)
	}
	want := `{"regions":{"eu-central":"https://eu.chat.example.test","us":"https://us.chat.example.test"}}`
	if rr := adminRequest(t, srv, "PUT", path, cookie, body); rr.Code != http.StatusOK || strings.TrimSpace(rr.Body.String()) != want {
		t.Fatalf("set: %d %s", rr.Code, rr.Body.String())
	}
	if rr := adminRequest(t, srv, "GET", path, cookie, ""); strings.TrimSpace(rr.Body.String()) != want {
		t.Fatalf("get: %s", rr.Body.String())
	}
	rows, _, err := db.Org(staffOrg).SearchAuditEvents(store.AuditFilter{Action: "admin.client_regions_changed", Limit: 10})
	if err != nil || len(rows) != 1 || !strings.Contains(rows[0].DetailsJSON, `"eu-central":"https://eu.chat.example.test"`) {
		t.Fatalf("audit %+v %v", rows, err)
	}
	if rr := adminRequest(t, srv, "PUT", path, cookie, `{"regions":{}}`); rr.Code != http.StatusOK || strings.TrimSpace(rr.Body.String()) != `{"regions":{}}` {
		t.Fatalf("clear: %d %s", rr.Code, rr.Body.String())
	}
}

func TestSingleTenantHasNoClientRegions(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newSession(t, db, newUser(t, db, "admin"), time.Now().UTC().Add(time.Hour))
	createClient(t, db, "kymessage", "confidential", crypto.HashSHA256("msg-secret"), "", "https://us.chat.example.test/cb")
	for _, m := range []string{"GET", "PUT"} {
		if rr := adminRequest(t, srv, m, "/api/admin/clients/kymessage/regions", admin, `{"regions":{"us":"https://us.chat.example.test"}}`); rr.Code != http.StatusNotFound {
			t.Errorf("%s: %d %s", m, rr.Code, rr.Body.String())
		}
	}
	if got, err := db.ClientRegionOrigins("kymessage"); err != nil || len(got) != 0 {
		t.Fatalf("rows %v %v", got, err)
	}
}
