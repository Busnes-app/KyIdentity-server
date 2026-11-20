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

func readAppearance(t *testing.T, srv *Server) string {
	t.Helper()
	rr := brandingPublic(t, srv, "/api/appearance")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/appearance: %d %s", rr.Code, rr.Body.String())
	}
	var b map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &b); err != nil || len(b) != 1 {
		t.Fatalf("appearance body %s: %v", rr.Body.String(), err)
	}
	return b["defaultTheme"]
}

// The default theme is public (no cookie, no client), set by an administrator with an
// audit row, and only to IDs the ky-ui catalog defines.
func TestSuiteDefaultTheme(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newSession(t, db, newUser(t, db, "admin"), time.Now().UTC().Add(time.Hour))
	if got := readAppearance(t, srv); got != "system" {
		t.Fatalf("fresh default = %q", got)
	}
	for _, bad := range []string{`{"theme":"sky"}`, `{"theme":""}`, `{"theme":"Ocean"}`, `{}`, `{"theme":"ocean","lock":true}`, `{"theme":"<script>"}`} {
		if rr := adminRequest(t, srv, "PUT", "/api/admin/suite-settings/default-theme", admin, bad); rr.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", bad, rr.Code)
		}
	}
	if rr := adminRequest(t, srv, "PUT", "/api/admin/suite-settings/default-theme", admin, `{"theme":"ocean-pair"}`); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"defaultTheme":"ocean-pair"`) {
		t.Fatalf("set: %d %s", rr.Code, rr.Body.String())
	}
	if got := readAppearance(t, srv); got != "ocean-pair" {
		t.Fatalf("public default = %q", got)
	}
	// A repeat changes nothing and writes no second row.
	adminRequest(t, srv, "PUT", "/api/admin/suite-settings/default-theme", admin, `{"theme":"ocean-pair"}`)
	rows := brandingAudits(t, db, "admin.suite_default_theme_changed")
	if len(rows) != 1 || !strings.Contains(rows[0].DetailsJSON, `"old":"system"`) || !strings.Contains(rows[0].DetailsJSON, `"new":"ocean-pair"`) {
		t.Fatalf("audit rows = %+v", rows)
	}
}

// The mail domains are validated, step-up protected, audited and reach suite apps only.
func TestSuiteEmailDomains(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newSession(t, db, newUser(t, db, "admin"), time.Now().UTC().Add(time.Hour))
	createClient(t, db, "kypost", "confidential", crypto.HashSHA256("post-secret"), "", "https://mail.example.test/cb")
	createClient(t, db, "kyweb", "public", "", "", "https://web.example.test/cb")

	for _, bad := range []string{
		`{"domains":["https://example.com"]}`, `{"domains":["*.example.com"]}`, `{"domains":["example.com:25"]}`,
		`{"domains":["example.com","Example.COM"]}`, `{"domains":["10.0.0.1"]}`, `{}`, `{"domains":"example.com"}`,
		`{"domains":["` + strings.Repeat(`a.example","`, 50) + `b.example"]}`,
	} {
		if rr := adminRequest(t, srv, "PUT", "/api/admin/suite-settings/email-domains", admin, bad); rr.Code != http.StatusBadRequest {
			t.Errorf("%.60s: %d, want 400 (%s)", bad, rr.Code, rr.Body.String())
		}
	}
	if rr := adminRequestNoStepUp(t, srv, "PUT", "/api/admin/suite-settings/email-domains", admin, `{"domains":["example.com"]}`); rr.Code != http.StatusForbidden {
		t.Fatalf("set without step-up: %d", rr.Code)
	}
	rr := adminRequest(t, srv, "PUT", "/api/admin/suite-settings/email-domains", admin, `{"domains":[" Example.com ","bücher.example"]}`)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"emailDomains":["example.com","xn--bcher-kva.example"]`) {
		t.Fatalf("set: %d %s", rr.Code, rr.Body.String())
	}
	rows := brandingAudits(t, db, "admin.suite_email_domains_changed")
	if len(rows) != 1 || !strings.Contains(rows[0].DetailsJSON, `"new":["example.com","xn--bcher-kva.example"]`) {
		t.Fatalf("audit rows = %+v", rows)
	}

	// Not public, and only an enabled confidential client with its secret reads them.
	if rr := brandingPublic(t, srv, "/api/suite/email-domains"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous read: %d", rr.Code)
	}
	for _, cred := range [][2]string{{"kypost", "wrong"}, {"kyweb", ""}, {"nobody", "x"}} {
		if rr := suiteGet(t, srv, "/api/suite/email-domains", cred[0], cred[1]); rr.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d, want 401", cred[0], rr.Code)
		}
	}
	got := suiteGet(t, srv, "/api/suite/email-domains", "kypost", "post-secret")
	if got.Code != http.StatusOK || strings.TrimSpace(got.Body.String()) != `{"domains":["example.com","xn--bcher-kva.example"]}` {
		t.Fatalf("suite read: %d %s", got.Code, got.Body.String())
	}
	// A browser session is not a suite credential.
	if rr := adminRequest(t, srv, "GET", "/api/suite/email-domains", admin, ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("cookie read: %d", rr.Code)
	}
}

// Only global administrators write either setting; helpdesk and auditors read.
func TestSuiteSettingsNeedAdministrator(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	user := newSession(t, db, newUser(t, db, "user"), time.Now().UTC().Add(time.Hour))
	for path, body := range map[string]string{
		"/api/admin/suite-settings/default-theme": `{"theme":"nord"}`,
		"/api/admin/suite-settings/email-domains": `{"domains":["example.com"]}`,
	} {
		if rr := adminRequest(t, srv, "PUT", path, user, body); rr.Code != http.StatusForbidden {
			t.Errorf("user PUT %s: %d", path, rr.Code)
		}
	}
	if rr := adminRequest(t, srv, "GET", "/api/admin/suite-settings", user, ""); rr.Code != http.StatusForbidden {
		t.Errorf("user GET: %d", rr.Code)
	}
	if got := readAppearance(t, srv); got != "system" {
		t.Fatalf("theme changed: %q", got)
	}
	if n := len(brandingAudits(t, db, "admin.suite_")); n != 0 {
		t.Fatalf("refused writes audited: %d", n)
	}
}

// A store failure on the suite route is logged before the generic 500 (AGENTS.md).
func TestSuiteEmailDomainsLogsReadFailure(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	createClient(t, db, "kypost", "confidential", crypto.HashSHA256("post-secret"), "", "https://mail.example.test/cb")
	if err := db.SetSetting(store.SuiteEmailDomainsSetting, "not json"); err != nil {
		t.Fatal(err)
	}
	output := captureOutput(t)
	rr := suiteGet(t, srv, "/api/suite/email-domains", "kypost", "post-secret")
	logged := output()
	if rr.Code != http.StatusInternalServerError || strings.TrimSpace(rr.Body.String()) != `{"error":"internal_error"}` {
		t.Fatalf("corrupt row: %d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(logged, "suite domains read failed") {
		t.Fatalf("500 not logged; output: %q", logged)
	}
}
