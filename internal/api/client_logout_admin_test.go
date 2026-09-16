package api

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAdminRegistersPostLogoutRedirectURIs(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))

	rr := adminRequestWithStepUp(t, srv, "POST", "/api/admin/clients", cookie,
		`{"clientId":"app","clientName":"App","redirectUris":["https://app.test/cb"],"postLogoutRedirectUris":["https://app.test/bye"]}`, mintStepUp(t, srv, cookie, "POST /api/admin/clients"))
	if rr.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	c, err := db.GetOAuthClientByID("app")
	if err != nil || c == nil || c.PostLogoutRedirectURIsJSON != `["https://app.test/bye"]` {
		t.Fatalf("stored %+v %v", c, err)
	}

	rr = adminRequestWithStepUp(t, srv, "POST", "/api/admin/clients", cookie,
		`{"clientId":"bad","clientName":"Bad","redirectUris":["https://app.test/cb"],"postLogoutRedirectUris":["http://insecure.test/bye"]}`, mintStepUp(t, srv, cookie, "POST /api/admin/clients"))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("insecure post-logout URI accepted: %d", rr.Code)
	}

	rr = adminRequestWithStepUp(t, srv, "PUT", "/api/admin/clients/app", cookie,
		`{"postLogoutRedirectUris":["https://app.test/bye","https://app.test/bye2"]}`, mintStepUp(t, srv, cookie, "PUT /api/admin/clients/app"))
	if rr.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rr.Code, rr.Body.String())
	}
	c, _ = db.GetOAuthClientByID("app")
	if c.PostLogoutRedirectURIsJSON != `["https://app.test/bye","https://app.test/bye2"]` {
		t.Fatalf("updated %q", c.PostLogoutRedirectURIsJSON)
	}
}

// Browsers apply form-action to the redirect that follows a form POST, so the confirmation
// page must permit the validated post-logout origin or the confirmed logout dead-ends.
func TestConfirmationPagePermitsTheValidatedRedirectOriginInCSP(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	u := newUser(t, db, "user")
	cookie := newSession(t, db, u, time.Now().UTC().Add(time.Hour))
	logoutClient(t, db, "kynotes")

	rr := endSession(t, srv, cookie, url.Values{"client_id": {"kynotes"}, "post_logout_redirect_uri": {bye}})
	csp := rr.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "form-action 'self' https://notes.urlxl.com;") {
		t.Fatalf("csp = %q", csp)
	}
	rr = endSession(t, srv, cookie, url.Values{"client_id": {"kynotes"}})
	if csp := rr.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self';") {
		t.Fatalf("without a redirect the policy must stay strict: %q", csp)
	}
}
