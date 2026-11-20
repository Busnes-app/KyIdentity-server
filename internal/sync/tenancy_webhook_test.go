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
