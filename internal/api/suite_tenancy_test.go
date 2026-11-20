package api

import (
	"flag"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

