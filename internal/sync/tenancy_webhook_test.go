package sync

import (
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Busnes-app/ky-primitives/syncauth"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

var updateGolden = flag.Bool("update-golden", false, "rewrite testdata/tenancy-golden from this build")

// Timestamps a delivery stamps when it is queued or sent.
var webhookVolatile = regexp.MustCompile(`"(created|lastModified|timestamp)":"[^"]*"`)

// webhookBodies delivers a create and then a removal of one user of org to a signed suite
// webhook, and returns each verified body with its event type.
func webhookBodies(t *testing.T, e *Engine, s *store.Store, org *store.OrgStore) []string {
	t.Helper()
	var secret string
	var bodies []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err == nil {
			_, err = syncauth.Verify([]byte(secret), syncauth.FromRequest(r), raw, syncauth.Options{})
		}
		if err != nil {
			t.Error(err)
			w.WriteHeader(401)
			return
		}
		bodies = append(bodies, r.Header.Get(syncauth.HeaderEventType)+" "+webhookVolatile.ReplaceAllString(string(raw), `"$1":"*"`))
	}))
	defer srv.Close()
	e.httpClient = srv.Client()
	sys, token, err := e.CreateSystem(&CreateSystemRequest{Name: "golden", SystemType: "suite_webhook", CallbackURL: srv.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	secret = token
	u := &store.User{ID: "golden-user", Username: "golden", DisplayName: "Golden", Email: "golden@example.com", PasswordHash: "x", Role: "user", Status: "active"}
	if err := org.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	app := appRecordFor(t, s, sys.ID)
	if org.ID().String() != store.DefaultOrgID {
		if err := store.EnableOrgAppForTest(s, org.ID(), app.ID, "{}"); err != nil {
			t.Fatal(err)
		}
	}
	if err := org.SetAppAssignment(app.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	dispatch(t, e)
	if err := org.SetAppAssignment(app.ID, "users", u.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	dispatch(t, e)
	if len(bodies) != 2 {
		t.Fatalf("bodies %q", bodies)
	}
	return bodies
}

// A single-tenant install signs the same webhook bodies as before tenancy.
func TestSingleTenantWebhookBodiesAreUnchanged(t *testing.T) {
	e, s, _, cleanup := setupTestSyncEngine(t)
	defer cleanup()
	got := strings.Join(webhookBodies(t, e, s, s.DefaultOrg()), "\n") + "\n"
	path := filepath.Join("testdata", "tenancy-golden", "webhook.txt")
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
		t.Errorf("webhook bodies changed:\n got %s\nwant %s", got, want)
	}
}

// In multi-tenant mode a signed suite webhook body carries the user's org as org_id,
// covered by the syncauth signature the receiver checks, and nothing else changes.
func TestMultiTenantWebhookCarriesTheOrg(t *testing.T) {
	e, s, _, cleanup := setupTestSyncEngine(t)
	defer cleanup()
	e.SetMultiTenant(true)
	org, err := store.CreateOrgForTest(s, "customer")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "tenancy-golden", "webhook.txt"))
	if err != nil {
		t.Fatal(err)
	}
	claim := regexp.MustCompile(`,"org_id":"([^"]*)"`)
	bodies := webhookBodies(t, e, s, s.Org(org))
	for _, b := range bodies {
		if m := claim.FindAllStringSubmatch(b, -1); len(m) != 1 || m[0][1] != org.String() {
			t.Errorf("org_id %v, want %s: %s", m, org, b)
		}
	}
	if got := claim.ReplaceAllString(strings.Join(bodies, "\n")+"\n", ""); got != string(want) {
		t.Errorf("more than org_id changed:\n got %s\nwant %s", got, want)
	}
}

// mailboxBodies delivers a household member with a mailbox address to a signed suite
// webhook: the create, a staff change of the address, and the removal.
func mailboxBodies(t *testing.T, e *Engine, s *store.Store) []string {
	t.Helper()
	var secret string
	var bodies []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err == nil {
			_, err = syncauth.Verify([]byte(secret), syncauth.FromRequest(r), raw, syncauth.Options{})
		}
		if err != nil {
			t.Error(err)
			w.WriteHeader(401)
			return
		}
		bodies = append(bodies, r.Header.Get(syncauth.HeaderEventType)+" "+webhookVolatile.ReplaceAllString(string(raw), `"$1":"*"`))
	}))
	defer srv.Close()
	e.httpClient = srv.Client()
	sys, token, err := e.CreateSystem(&CreateSystemRequest{Name: "golden", SystemType: "suite_webhook", CallbackURL: srv.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	secret = token
	if _, _, err := s.SetSuiteEmailDomains([]string{"bücher.example"}, nil); err != nil {
		t.Fatal(err)
	}
	id, err := store.CreateOrgForTest(s, "customer")
	if err != nil {
		t.Fatal(err)
	}
	org := s.Org(id)
	u := &store.User{ID: "golden-user", Username: "golden@gmail.example", DisplayName: "Golden", Email: "golden@gmail.example", PasswordHash: "x", Role: "user", Status: "active"}
	if err := org.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	if _, _, err := org.SetMailboxAddress(u.ID, "Golden@Bücher.example", false, nil); err != nil {
		t.Fatal(err)
	}
	app := appRecordFor(t, s, sys.ID)
	if err := store.EnableOrgAppForTest(s, id, app.ID, "{}"); err != nil {
		t.Fatal(err)
	}
	if err := org.SetAppAssignment(app.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	dispatch(t, e)
	if _, _, err := org.SetMailboxAddress(u.ID, "post@bücher.example", true, nil); err != nil {
		t.Fatal(err)
	}
	dispatch(t, e)
	if err := org.SetAppAssignment(app.ID, "users", u.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	dispatch(t, e)
	if len(bodies) != 3 {
		t.Fatalf("bodies %q", bodies)
	}
	return bodies
}

// A hosted member's mailbox address is a second emails entry of type "mailbox" in the
// org's signed events, beside the sign-in email, and follows a staff change.
func TestMultiTenantWebhookCarriesTheMailboxAddress(t *testing.T) {
	e, s, _, cleanup := setupTestSyncEngine(t)
	defer cleanup()
	e.SetMultiTenant(true)
	got := regexp.MustCompile(`"org_id":"[^"]+"`).ReplaceAllString(strings.Join(mailboxBodies(t, e, s), "\n")+"\n", `"org_id":"*"`)
	path := filepath.Join("testdata", "tenancy-golden", "webhook_mailbox.txt")
	if *updateGolden {
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
		t.Errorf("mailbox webhook bodies changed:\n got %s\nwant %s", got, want)
	}
}

// Outside a multi-tenant suite webhook (generic SCIM, AD, or an engine not in multi-tenant
// mode) the mailbox entry is dropped from the body.
func TestMailboxAddressStaysOffOtherBodies(t *testing.T) {
	e, s, _, cleanup := setupTestSyncEngine(t)
	defer cleanup()
	for _, b := range mailboxBodies(t, e, s) {
		if strings.Contains(b, `"mailbox"`) || strings.Contains(b, "xn--") || strings.Contains(b, "org_id") {
			t.Errorf("body carries the mailbox address or org: %s", b)
		}
	}
}
