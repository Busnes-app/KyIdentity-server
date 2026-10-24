package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// covAdmin is an administrator's live session on a fresh server.
func covAdmin(t *testing.T) (*Server, *store.Store, string, *store.User, func()) {
	t.Helper()
	srv, db, _, _, _, cleanup := setupTestServer(t)
	admin := newUser(t, db, "admin")
	return srv, db, newSession(t, db, admin, time.Now().UTC().Add(time.Hour)), admin, cleanup
}

// covRefused asserts a JSON refusal with the given status and error code.
func covRefused(t *testing.T, rr *httptest.ResponseRecorder, status int, code string) map[string]string {
	t.Helper()
	if rr.Code != status {
		t.Fatalf("want %d %s, got %d: %s", status, code, rr.Code, rr.Body.String())
	}
	body := decodeAPIError(t, rr)
	if body["error"] != code {
		t.Fatalf("error %q, want %q (%s)", body["error"], code, rr.Body.String())
	}
	return body
}

// Account creation refuses a malformed body and a password the policy rejects, and in
// either case creates no account and records no successful creation.
func TestAdminCreateUserRefusals(t *testing.T) {
	srv, db, admin, _, cleanup := covAdmin(t)
	defer cleanup()
	covRefused(t, adminRequest(t, srv, "POST", "/api/admin/users", admin, `{"username":`), 400, "invalid_request")
	body := covRefused(t, adminRequest(t, srv, "POST", "/api/admin/users", admin, `{"username":"newbie","email":"n@x.test","password":"short"}`), 400, "password_policy")
	if !strings.Contains(body["error_description"], "12 characters") {
		t.Fatalf("policy refusal does not explain itself: %v", body)
	}
	if u, _ := db.GetUserByUsername("newbie"); u != nil {
		t.Fatal("a refused creation left an account behind")
	}
	if n := countAudit(t, db, "admin.user_created"); n != 0 {
		t.Fatalf("refused creations audited as success %d times", n)
	}

	// A given password activates the account but must be replaced by its owner.
	ok := adminRequest(t, srv, "POST", "/api/admin/users", admin, `{"username":"newbie","email":"n@x.test","password":"long-enough-password","role":"superuser","status":"weird"}`)
	if ok.Code != http.StatusOK {
		t.Fatalf("create: %d %s", ok.Code, ok.Body.String())
	}
	u, _ := db.GetUserByUsername("newbie")
	if u == nil || u.Pending || !u.PasswordChangeRequired || u.Role != "user" || u.Status != "active" {
		t.Fatalf("created account: %+v", u)
	}
}

// An administrator setting someone else's password unlocks the account, ends its sessions
// and forces the owner to choose a new password; refused edits change nothing.
func TestAdminUpdateUserPasswordAndRefusals(t *testing.T) {
	srv, db, admin, adminUser, cleanup := covAdmin(t)
	defer cleanup()
	target := newUser(t, db, "user")
	targetCookie := newSession(t, db, target, time.Now().UTC().Add(time.Hour))
	path := "/api/admin/users/" + target.ID

	covRefused(t, adminRequest(t, srv, "PUT", path, admin, `{"displayName":`), 400, "invalid_request")
	covRefused(t, adminRequest(t, srv, "PUT", path, admin, `{"password":"tiny"}`), 400, "password_policy")
	covRefused(t, adminRequest(t, srv, "PUT", "/api/admin/users/no-such-user", admin, `{"displayName":"X"}`), 404, "user_not_found")
	if !sessionAlive(t, srv, targetCookie) {
		t.Fatal("a refused edit ended the target's session")
	}

	for i := 0; i < store.MaxFailedLogins; i++ {
		if _, err := db.RecordFailedLogin(target.ID); err != nil {
			t.Fatal(err)
		}
	}
	if locked, _ := db.IsAccountLocked(target.ID); !locked {
		t.Fatal("setup: account not locked")
	}
	if rr := adminRequest(t, srv, "PUT", path, admin, `{"password":"brand-new-password-1"}`); rr.Code != http.StatusOK {
		t.Fatalf("set password: %d %s", rr.Code, rr.Body.String())
	}
	if locked, _ := db.IsAccountLocked(target.ID); locked {
		t.Fatal("an administrator-set password left the account locked out")
	}
	if u := mustUser(t, db, target.ID); !u.PasswordChangeRequired {
		t.Fatal("an administrator-set password need not be replaced by its owner")
	}
	if sessionAlive(t, srv, targetCookie) {
		t.Fatal("setting the password left the old session alive")
	}

	// The administrator's own password is theirs: no forced change.
	if rr := adminRequest(t, srv, "PUT", "/api/admin/users/"+adminUser.ID, admin, `{"password":"admins-own-password"}`); rr.Code != http.StatusOK {
		t.Fatalf("own password: %d %s", rr.Code, rr.Body.String())
	}
	if u := mustUser(t, db, adminUser.ID); u.PasswordChangeRequired {
		t.Fatal("an administrator's own password was marked for forced change")
	}
}

// Recovery and deletion of an unknown account are 404s, and the only active administrator
// cannot delete their own account and lock everyone out.
func TestAdminUserNotFoundAndLastAdmin(t *testing.T) {
	srv, db, admin, adminUser, cleanup := covAdmin(t)
	defer cleanup()
	covRefused(t, adminRequest(t, srv, "POST", "/api/admin/users/ghost/reset-mfa", admin, ""), 404, "user_not_found")
	covRefused(t, adminRequest(t, srv, "DELETE", "/api/admin/users/ghost", admin, ""), 404, "user_not_found")
	covRefused(t, adminRequest(t, srv, "DELETE", "/api/admin/users/"+adminUser.ID, admin, ""), 400, "cannot_delete_last_admin")
	if u, _ := db.GetUserByID(adminUser.ID); u == nil {
		t.Fatal("the last administrator was deleted")
	}
	if n := countAudit(t, db, "admin.user_deleted"); n != 0 {
		t.Fatalf("refused deletions audited as success %d times", n)
	}
}

// Client registration validates every URL it will later redirect to or launch, refuses a
// public registration of a suite service (and audits the attempt), and generates an id when
// none is given.
func TestAdminCreateOAuthClientValidation(t *testing.T) {
	srv, db, admin, _, cleanup := covAdmin(t)
	defer cleanup()
	for _, tc := range []struct{ name, body, code, detail string }{
		{"no redirect", `{"clientName":"A","redirectUris":[]}`, "invalid_request", "redirect URI is required"},
		{"plain http redirect", `{"clientName":"A","redirectUris":["http://app.example/cb"]}`, "invalid_request", "https"},
		{"credentials in redirect", `{"clientName":"A","redirectUris":["https://u:p@app.example/cb"]}`, "invalid_request", "credentials"},
		{"fragment launch url", `{"clientName":"A","redirectUris":["https://app.example/cb"],"launchUrl":"https://app.example/#x"}`, "invalid_request", "fragment"},
		{"bad post-logout", `{"clientName":"A","redirectUris":["https://app.example/cb"],"postLogoutRedirectUris":["ftp://app.example/bye"]}`, "invalid_request", "post-logout"},
		{"unknown scope", `{"clientName":"A","redirectUris":["https://app.example/cb"],"allowedScopes":["admin"]}`, "unknown_scope", "openid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := covRefused(t, adminRequest(t, srv, "POST", "/api/admin/clients", admin, tc.body), 400, tc.code)
			if !strings.Contains(body["error_description"], tc.detail) {
				t.Fatalf("description %q does not mention %q", body["error_description"], tc.detail)
			}
		})
	}
	covRefused(t, adminRequest(t, srv, "POST", "/api/admin/clients", admin, `{"clientId":"KyPost","clientName":"KyPost","clientType":"public","redirectUris":["https://mail.example/cb"]}`), 400, "invalid_client_type")
	if c, _ := db.GetOAuthClientByID("KyPost"); c != nil {
		t.Fatal("a public suite client was registered")
	}
	denied := 0
	for _, e := range auditRows(t, db, "admin.oauth_client_created") {
		if e.Outcome == "denied" && strings.Contains(e.DetailsJSON, "suite_client_must_be_confidential") {
			denied++
		}
	}
	if denied != 1 {
		t.Fatalf("public suite registration audited %d times, want 1", denied)
	}

	// Loopback http is allowed for development; an omitted id is generated; the secret
	// is shown once and the response is not cacheable.
	rr := adminRequest(t, srv, "POST", "/api/admin/clients", admin, `{"clientName":"Dev","redirectUris":["http://127.0.0.1:8080/cb"],"postLogoutRedirectUris":["", "https://dev.example/bye"]}`)
	var resp struct {
		ClientSecret string            `json:"clientSecret"`
		Client       store.OAuthClient `json:"client"`
	}
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &resp) != nil || len(resp.Client.ID) != 36 || resp.ClientSecret == "" || rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("generated client: %d %s", rr.Code, rr.Body.String())
	}
	if stored, _ := db.GetOAuthClientByID(resp.Client.ID); stored == nil || stored.PostLogoutRedirectURIsJSON != `["https://dev.example/bye"]` {
		t.Fatalf("stored client: %+v", stored)
	}
}

// Editing a client validates each field it touches and leaves the stored client unchanged
// on refusal; disabling it revokes the tokens issued under it.
func TestAdminUpdateOAuthClientValidationAndRevocation(t *testing.T) {
	srv, db, admin, _, cleanup := covAdmin(t)
	defer cleanup()
	newClient(t, db, "notes", []string{"https://notes.example/cb"}, []string{"openid"})
	path := "/api/admin/clients/notes"

	covRefused(t, adminRequest(t, srv, "PUT", path, admin, `{"clientName":`), 400, "invalid_request")
	covRefused(t, adminRequest(t, srv, "PUT", "/api/admin/clients/ghost", admin, `{"clientName":"X"}`), 404, "client_not_found")
	for _, tc := range []struct{ name, body, code string }{
		{"bad launch url", `{"launchUrl":"javascript:alert(1)"}`, "invalid_request"},
		{"empty redirects", `{"redirectUris":[]}`, "invalid_request"},
		{"http redirect", `{"redirectUris":["http://notes.example/cb"]}`, "invalid_request"},
		{"bad backchannel", `{"backchannelLogoutUri":"http://10.0.0.1/logout"}`, "invalid_request"},
		{"bad post-logout", `{"postLogoutRedirectUris":["https://x.example/#f"]}`, "invalid_request"},
		{"unknown scope", `{"allowedScopes":["openid","offline_admin"]}`, "unknown_scope"},
		{"bogus type", `{"clientType":"trusted"}`, "invalid_request"},
		{"rotate public secret", `{"rotateSecret":true}`, "invalid_request"},
		{"rename then bad scope", `{"clientName":"Renamed","allowedScopes":["root"]}`, "unknown_scope"},
	} {
		t.Run(tc.name, func(t *testing.T) { covRefused(t, adminRequest(t, srv, "PUT", path, admin, tc.body), 400, tc.code) })
	}
	if c, _ := db.GetOAuthClientByID("notes"); c.ClientName != "notes" || c.RedirectURIsJSON != `["https://notes.example/cb"]` || c.AllowedScopesJSON != `["openid"]` || c.ClientType != "public" || !c.Enabled {
		t.Fatalf("a refused edit changed the client: %+v", c)
	}

	// Valid edits land; disabling the client revokes what was issued under it.
	jti := issueToken(t, db, newUser(t, db, "user").ID, "notes")
	rr := adminRequest(t, srv, "PUT", path, admin, `{"launchUrl":" https://notes.example/ ","redirectUris":["https://notes.example/cb2"],"allowedScopes":["openid","email"],"enabled":false}`)
	if rr.Code != http.StatusOK || rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("edit: %d %s", rr.Code, rr.Body.String())
	}
	c, _ := db.GetOAuthClientByID("notes")
	if c.LaunchURL != "https://notes.example/" || c.RedirectURIsJSON != `["https://notes.example/cb2"]` || c.AllowedScopesJSON != `["openid","email"]` || c.Enabled {
		t.Fatalf("edit not applied: %+v", c)
	}
	assertRevoked(t, db, jti, true, "disabling the client")
}

// Launcher cards: URLs and descriptions are validated, unknown ids are 404s, and an edit
// can hide a card.
func TestAdminApplicationValidation(t *testing.T) {
	srv, db, admin, _, cleanup := covAdmin(t)
	defer cleanup()
	covRefused(t, adminRequest(t, srv, "POST", "/api/admin/applications", admin, `{"name":"Wiki","url":"http://wiki.example"}`), 400, "invalid_request")
	created := adminRequest(t, srv, "POST", "/api/admin/applications", admin, `{"name":"Wiki","url":"https://wiki.example"}`)
	var resp struct {
		Application store.Application `json:"application"`
	}
	if created.Code != http.StatusOK || json.Unmarshal(created.Body.Bytes(), &resp) != nil || resp.Application.IconName != "favicon" {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	path := "/api/admin/applications/" + resp.Application.ID
	body := covRefused(t, adminRequest(t, srv, "PUT", path, admin, `{"name":"Wiki","url":"https://wiki.example","description":"`+strings.Repeat("d", 201)+`"}`), 400, "invalid_request")
	if !strings.Contains(body["error_description"], "too long") {
		t.Fatalf("description refusal: %v", body)
	}
	covRefused(t, adminRequest(t, srv, "PUT", "/api/admin/applications/ghost", admin, `{"name":"Wiki","url":"https://wiki.example"}`), 404, "application_not_found")
	if rr := adminRequest(t, srv, "PUT", path, admin, `{"name":" Wiki 2 ","url":"https://wiki2.example","enabled":false}`); rr.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rr.Code, rr.Body.String())
	}
	if app, _ := db.GetApplicationByID(resp.Application.ID); app == nil || app.Enabled || app.Name != "Wiki 2" {
		t.Fatalf("update not applied: %+v", app)
	}
	covRefused(t, adminRequest(t, srv, "PUT", "/api/admin/clients/notes/launcher", admin, `{"description":`), 400, "invalid_request")
}

// Paired systems: malformed bodies and unknown ids are refused; an unsupported protocol
// choice is refused and audited as a failure; the connection test of a non-SCIM connector
// fails with an audited, actionable error; resync and delete work on a real system.
func TestAdminPairedSystemLifecycleRefusals(t *testing.T) {
	srv, db, admin, _, cleanup := covAdmin(t)
	defer cleanup()
	if err := db.CreatePairedSystem(&store.PairedSystem{ID: "hook", Name: "Hook", SystemType: "suite_webhook", CallbackURL: "https://hook.example/h", Status: "active"}, nil); err != nil {
		t.Fatal(err)
	}
	covRefused(t, adminRequest(t, srv, "POST", "/api/admin/systems", admin, `{"name":`), 400, "invalid_request")
	covRefused(t, adminRequest(t, srv, "PUT", "/api/admin/systems/hook/connection", admin, `[`), 400, "invalid_request")
	if rr := adminRequest(t, srv, "PUT", "/api/admin/systems/ghost/connection", admin, `{"systemType":"scim"}`); rr.Code != http.StatusNotFound {
		t.Fatalf("configure unknown: %d", rr.Code)
	}
	covRefused(t, adminRequest(t, srv, "PUT", "/api/admin/systems/hook/connection", admin, `{"systemType":"ldap"}`), 400, "invalid_connection")
	failed := 0
	for _, e := range auditRows(t, db, "admin.system_configured") {
		if e.Outcome == "failure" && strings.Contains(e.DetailsJSON, `"systemType":"invalid"`) {
			failed++
		}
	}
	if failed != 1 {
		t.Fatalf("refused configuration audited %d times with a sanitised protocol, want 1", failed)
	}

	if rr := adminRequest(t, srv, "POST", "/api/admin/systems/ghost/test", admin, ""); rr.Code != http.StatusNotFound {
		t.Fatalf("test unknown: %d", rr.Code)
	}
	covRefused(t, adminRequest(t, srv, "POST", "/api/admin/systems/hook/test", admin, ""), 400, "connection_test_failed")
	if rows := auditRows(t, db, "admin.system_tested"); len(rows) != 1 || rows[0].Outcome != "failure" || rows[0].TargetID != "hook" {
		t.Fatalf("connection test audit: %+v", rows)
	}

	if rr := adminRequest(t, srv, "POST", "/api/admin/systems/hook/resync", admin, ""); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"success":true`) {
		t.Fatalf("resync: %d %s", rr.Code, rr.Body.String())
	}
	if n := countAudit(t, db, "admin.system_resynced"); n != 1 {
		t.Fatalf("resync audited %d times", n)
	}
	covRefused(t, adminRequest(t, srv, "DELETE", "/api/admin/systems/ghost", admin, ""), 404, "system_not_found")
	if rr := adminRequest(t, srv, "DELETE", "/api/admin/systems/hook", admin, ""); rr.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rr.Code, rr.Body.String())
	}
	if sys, _ := db.GetPairedSystemByID("hook"); sys != nil {
		t.Fatal("deleted system still stored")
	}
	if n := countAudit(t, db, "admin.system_deleted"); n != 1 {
		t.Fatalf("deletion audited %d times", n)
	}
}

// Disabling an inbound SCIM connector cuts off its bearer tokens at once; edits are
// validated, unknown connectors are 404s, and re-enabling restores access.
func TestSCIMConnectorAdminUpdateGatesTokens(t *testing.T) {
	srv, db, admin, _, cleanup := covAdmin(t)
	defer cleanup()
	id, token := connectorWithToken(t, srv, db, admin, "write")
	path := "/api/admin/scim-connectors/" + id

	covRefused(t, adminRequest(t, srv, "PUT", path, admin, `{"name":`), 400, "invalid_request")
	covRefused(t, adminRequest(t, srv, "PUT", path, admin, `{"name":"Dir","status":"paused"}`), 400, "invalid_request")
	covRefused(t, adminRequest(t, srv, "PUT", path, admin, `{"name":" ","status":"active"}`), 400, "invalid_request")
	covRefused(t, adminRequest(t, srv, "PUT", "/api/admin/scim-connectors/ghost", admin, `{"name":"Dir","status":"active"}`), 404, "connector_not_found")
	covRefused(t, adminRequest(t, srv, "POST", path+"/tokens", admin, `{"scope":"admin"}`), 400, "invalid_request")
	covRefused(t, adminRequest(t, srv, "DELETE", path, admin, `{"users":"orphan"}`), 400, "invalid_request")
	covRefused(t, adminRequest(t, srv, "DELETE", "/api/admin/scim-connectors/ghost", admin, `{"users":"keep"}`), 404, "connector_not_found")

	if got := scimCall(t, srv, token, "GET", "/scim/v2/Users", ""); got.Code != http.StatusOK {
		t.Fatalf("active connector: %d", got.Code)
	}
	rr := adminRequest(t, srv, "PUT", path, admin, `{"name":"Renamed Directory","status":"disabled"}`)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Renamed Directory") {
		t.Fatalf("disable: %d %s", rr.Code, rr.Body.String())
	}
	if got := scimCall(t, srv, token, "GET", "/scim/v2/Users", ""); got.Code != http.StatusUnauthorized {
		t.Fatalf("a disabled connector's token still reads the directory: %d", got.Code)
	}
	if got := scimCall(t, srv, token, "POST", "/scim/v2/Users", `{"userName":"x","externalId":"x","emails":[{"value":"x@up.test"}]}`); got.Code != http.StatusUnauthorized {
		t.Fatalf("a disabled connector's token still writes: %d", got.Code)
	}
	if rr := adminRequest(t, srv, "PUT", path, admin, `{"name":"Renamed Directory","status":"active"}`); rr.Code != http.StatusOK {
		t.Fatalf("enable: %d", rr.Code)
	}
	if got := scimCall(t, srv, token, "GET", "/scim/v2/Users", ""); got.Code != http.StatusOK {
		t.Fatalf("re-enabled connector: %d", got.Code)
	}
}

// Delegation edits validate the app-owner list and the target, and never half-apply.
func TestAdminSetDelegationsValidation(t *testing.T) {
	srv, db, admin, _, cleanup := covAdmin(t)
	defer cleanup()
	target := newUser(t, db, "user")
	path := "/api/admin/users/" + target.ID + "/delegations"
	tooMany := make([]string, 201)
	for i := range tooMany {
		tooMany[i] = `"a` + itoa(i) + `"`
	}
	for name, body := range map[string]string{
		"malformed":      `{"helpdesk":`,
		"blank app id":   `{"appOwner":[""]}`,
		"long app id":    `{"appOwner":["` + strings.Repeat("x", 201) + `"]}`,
		"too many owned": `{"appOwner":[` + strings.Join(tooMany, ",") + `]}`,
	} {
		t.Run(name, func(t *testing.T) {
			covRefused(t, adminRequest(t, srv, "PUT", path, admin, body), 400, "invalid_request")
		})
	}
	covRefused(t, adminRequest(t, srv, "PUT", path, admin, `{"helpdesk":true,"appOwner":["no-such-app"]}`), 400, "unknown_app")
	covRefused(t, adminRequest(t, srv, "PUT", "/api/admin/users/ghost/delegations", admin, `{"helpdesk":true}`), 404, "user_not_found")
	if d, err := db.Delegations(target.ID); err != nil || d.Helpdesk || len(d.AppOwner) != 0 {
		t.Fatalf("a refused delegation edit applied: %+v %v", d, err)
	}
	if n := countAudit(t, db, "admin.delegations_updated"); n != 0 {
		t.Fatalf("refused edits audited as success %d times", n)
	}
	rr := adminRequest(t, srv, "PUT", path, admin, `{"helpdesk":true}`)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"helpdesk":true`) {
		t.Fatalf("grant helpdesk: %d %s", rr.Code, rr.Body.String())
	}
}
