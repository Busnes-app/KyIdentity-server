package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kyidentity-server/internal/store"
)

// scimCall is what an upstream directory sends: a Bearer token, no cookies, no CSRF.
func scimCall(t *testing.T, srv *Server, token, method, path, body string, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/scim+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	return rec
}

func connectorWithToken(t *testing.T, srv *Server, db *store.Store, admin, scope string) (string, string) {
	t.Helper()
	created := adminRequest(t, srv, "POST", "/api/admin/scim-connectors", admin, `{"name":"Upstream Directory"}`)
	if created.Code != http.StatusOK {
		t.Fatalf("create connector: %d %s", created.Code, created.Body.String())
	}
	var c struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(created.Body.Bytes(), &c)
	issued := adminRequest(t, srv, "POST", "/api/admin/scim-connectors/"+c.ID+"/tokens", admin, `{"scope":"`+scope+`"}`)
	if issued.Code != http.StatusOK {
		t.Fatalf("issue token: %d %s", issued.Code, issued.Body.String())
	}
	var tok struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(issued.Body.Bytes(), &tok)
	return c.ID, tok.Token
}

func scimUser(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("scim body: %s", body)
	}
	return m
}

// A realistic upstream lifecycle: discover, create, look up by externalId, replace, PATCH
// active, conditional writes, and delete-to-deactivate, all with stable ids.
func TestInboundSCIMUserLifecycle(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newSession(t, db, newUser(t, db, "admin"), time.Now().UTC().Add(time.Hour))
	_, token := connectorWithToken(t, srv, db, admin, "write")

	if got := scimCall(t, srv, "", "GET", "/scim/v2/ServiceProviderConfig", ""); got.Code != http.StatusUnauthorized || got.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("no token: %d", got.Code)
	}
	if got := scimCall(t, srv, "scim_wrong", "GET", "/scim/v2/Users", ""); got.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", got.Code)
	}
	cfg := scimCall(t, srv, token, "GET", "/scim/v2/ServiceProviderConfig", "")
	if cfg.Code != http.StatusOK || !strings.Contains(cfg.Body.String(), `"changePassword":{"supported":false}`) || !strings.Contains(cfg.Header().Get("Content-Type"), "application/scim+json") {
		t.Fatalf("discovery: %d %s", cfg.Code, cfg.Body.String())
	}
	if got := scimCall(t, srv, token, "GET", "/scim/v2/Schemas", ""); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "externalId") {
		t.Fatalf("schemas: %d", got.Code)
	}

	created := scimCall(t, srv, token, "POST", "/scim/v2/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"ext-1","userName":"alice","name":{"givenName":"Alice","familyName":"Adams"},"emails":[{"value":"alice@up.test","primary":true}],"active":true}`)
	if created.Code != http.StatusCreated || created.Header().Get("Location") == "" || created.Header().Get("ETag") == "" {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	res := scimUser(t, created.Body.Bytes())
	id, _ := res["id"].(string)
	if id == "" || res["userName"] != "alice" || res["externalId"] != "ext-1" || res["active"] != true || res["displayName"] != "Alice Adams" {
		t.Fatalf("created resource: %+v", res)
	}
	u, _ := db.GetUserByID(id)
	if !u.Pending || u.Status != "active" && u.Status != "disabled" || u.Status != "disabled" || u.PasswordHash != "" || u.Role != "user" {
		t.Fatalf("stored upstream account: %+v", u)
	}
	// Repeated create with the same externalId is a conflict, not a duplicate.
	if got := scimCall(t, srv, token, "POST", "/scim/v2/Users", `{"externalId":"ext-1","userName":"alice2","emails":[{"value":"a2@up.test"}]}`); got.Code != http.StatusConflict || !strings.Contains(got.Body.String(), "uniqueness") {
		t.Fatalf("duplicate externalId: %d %s", got.Code, got.Body.String())
	}
	// A password attribute is refused, not silently dropped.
	if got := scimCall(t, srv, token, "POST", "/scim/v2/Users", `{"externalId":"ext-2","userName":"bob","password":"hunter22hunter22","emails":[{"value":"b@up.test"}]}`); got.Code != http.StatusBadRequest {
		t.Fatalf("password accepted: %d", got.Code)
	}

	list := scimCall(t, srv, token, "GET", "/scim/v2/Users?filter=externalId%20eq%20%22ext-1%22", "")
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"totalResults":1`) || !strings.Contains(list.Body.String(), id) {
		t.Fatalf("filter: %d %s", list.Code, list.Body.String())
	}
	if got := scimCall(t, srv, token, "GET", "/scim/v2/Users?filter=userName%20co%20%22al%22", ""); got.Code != http.StatusBadRequest || !strings.Contains(got.Body.String(), "invalidFilter") {
		t.Fatalf("unsupported filter: %d %s", got.Code, got.Body.String())
	}
	if got := scimCall(t, srv, token, "GET", "/scim/v2/Users?filter=title%20eq%20%22x%22", ""); got.Code != http.StatusBadRequest {
		t.Fatalf("unsupported attribute: %d", got.Code)
	}

	// Activate locally, then let the upstream drive the active flag.
	raw, _ := db.IssueAccountToken(id, "activation", "manual", time.Hour, nil)
	if _, err := db.RedeemAccountToken(raw, "activation", "hash", nil); err != nil {
		t.Fatal(err)
	}
	sess := newSession(t, db, mustUser(t, db, id), time.Now().UTC().Add(time.Hour))
	etag := scimCall(t, srv, token, "GET", "/scim/v2/Users/"+id, "").Header().Get("ETag")
	if got := scimCall(t, srv, token, "PUT", "/scim/v2/Users/"+id, `{"externalId":"ext-1","userName":"alice.adams","displayName":"Alice A.","emails":[{"value":"alice@up.test","primary":true}],"active":true}`, "If-Match", `W/"stale"`); got.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale If-Match: %d %s", got.Code, got.Body.String())
	}
	replaced := scimCall(t, srv, token, "PUT", "/scim/v2/Users/"+id, `{"externalId":"ext-1","userName":"alice.adams","displayName":"Alice A.","emails":[{"value":"alice@up.test","primary":true}],"active":true}`, "If-Match", etag)
	if replaced.Code != http.StatusOK || scimUser(t, replaced.Body.Bytes())["userName"] != "alice.adams" {
		t.Fatalf("replace: %d %s", replaced.Code, replaced.Body.String())
	}
	if got := scimCall(t, srv, token, "PUT", "/scim/v2/Users/"+id, `{"externalId":"ext-9","userName":"alice.adams","emails":[{"value":"alice@up.test"}]}`); got.Code != http.StatusBadRequest || !strings.Contains(got.Body.String(), "mutability") {
		t.Fatalf("externalId change: %d %s", got.Code, got.Body.String())
	}

	patched := scimCall(t, srv, token, "PATCH", "/scim/v2/Users/"+id, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`)
	if patched.Code != http.StatusOK || scimUser(t, patched.Body.Bytes())["active"] != false {
		t.Fatalf("patch active: %d %s", patched.Code, patched.Body.String())
	}
	if got := call(t, srv, sess, "GET", "/api/auth/me"); got.Code != http.StatusUnauthorized {
		t.Fatalf("session survived upstream deactivation: %d", got.Code)
	}
	if got := scimCall(t, srv, token, "PATCH", "/scim/v2/Users/"+id, `{"Operations":[{"op":"replace","path":"externalId","value":"ext-2"}]}`); got.Code != http.StatusBadRequest {
		t.Fatalf("patch externalId: %d", got.Code)
	}
	if got := scimCall(t, srv, token, "PATCH", "/scim/v2/Users/"+id, `{"Operations":[{"op":"replace","value":{"active":true,"displayName":"Alice Back"}}]}`); got.Code != http.StatusOK || scimUser(t, got.Body.Bytes())["active"] != true {
		t.Fatalf("path-less patch: %d %s", got.Code, got.Body.String())
	}
	if u, _ = db.GetUserByID(id); u.Status != "active" || u.DisplayName != "Alice Back" {
		t.Fatalf("after reactivation: %+v", u)
	}

	if got := scimCall(t, srv, token, "DELETE", "/scim/v2/Users/"+id, ""); got.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", got.Code, got.Body.String())
	}
	if u, _ = db.GetUserByID(id); u == nil || u.Status != "disabled" || u.SourceActive {
		t.Fatalf("delete should deactivate, not erase: %+v", u)
	}
	if got := scimCall(t, srv, token, "GET", "/scim/v2/Users/"+id, ""); got.Code != http.StatusOK || scimUser(t, got.Body.Bytes())["active"] != false {
		t.Fatalf("deactivated resource still readable with active=false: %d", got.Code)
	}
}

func mustUser(t *testing.T, db *store.Store, id string) *store.User {
	t.Helper()
	u, err := db.GetUserByID(id)
	if err != nil || u == nil {
		t.Fatalf("user %s: %v", id, err)
	}
	return u
}

// An upstream never takes over a local account, cannot see one, cannot see another
// connector's accounts, and cannot lift a local disable.
func TestInboundSCIMBoundaries(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newSession(t, db, newUser(t, db, "admin"), time.Now().UTC().Add(time.Hour))
	local := newUser(t, db, "user")
	_, token := connectorWithToken(t, srv, db, admin, "write")
	_, other := connectorWithToken(t, srv, db, admin, "write")

	if got := scimCall(t, srv, token, "POST", "/scim/v2/Users", `{"externalId":"e1","userName":"`+local.Username+`","emails":[{"value":"new@up.test"}]}`); got.Code != http.StatusConflict {
		t.Fatalf("username takeover: %d", got.Code)
	}
	if got := scimCall(t, srv, token, "POST", "/scim/v2/Users", `{"externalId":"e1","userName":"fresh","emails":[{"value":"`+local.Email+`"}]}`); got.Code != http.StatusConflict {
		t.Fatalf("email takeover: %d", got.Code)
	}
	if got := scimCall(t, srv, token, "GET", "/scim/v2/Users?filter=userName%20eq%20%22"+local.Username+"%22", ""); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"totalResults":0`) {
		t.Fatalf("local account visible: %d %s", got.Code, got.Body.String())
	}
	if got := scimCall(t, srv, token, "GET", "/scim/v2/Users/"+local.ID, ""); got.Code != http.StatusNotFound {
		t.Fatalf("local account readable: %d", got.Code)
	}
	created := scimCall(t, srv, token, "POST", "/scim/v2/Users", `{"externalId":"e1","userName":"upstream1","emails":[{"value":"u1@up.test"}]}`)
	id, _ := scimUser(t, created.Body.Bytes())["id"].(string)
	if got := scimCall(t, srv, other, "GET", "/scim/v2/Users/"+id, ""); got.Code != http.StatusNotFound {
		t.Fatalf("other connector read: %d", got.Code)
	}
	if got := scimCall(t, srv, other, "DELETE", "/scim/v2/Users/"+id, ""); got.Code != http.StatusNotFound {
		t.Fatalf("other connector delete: %d", got.Code)
	}

	// Local override: an administrator disables; the upstream's active=true does not lift it.
	raw, _ := db.IssueAccountToken(id, "activation", "manual", time.Hour, nil)
	if _, err := db.RedeemAccountToken(raw, "activation", "hash", nil); err != nil {
		t.Fatal(err)
	}
	if got := adminRequest(t, srv, "PUT", "/api/admin/users/"+id, admin, `{"status":"disabled"}`); got.Code != http.StatusOK {
		t.Fatalf("local disable: %d %s", got.Code, got.Body.String())
	}
	if got := scimCall(t, srv, token, "PATCH", "/scim/v2/Users/"+id, `{"Operations":[{"op":"replace","path":"active","value":true}]}`); got.Code != http.StatusOK || scimUser(t, got.Body.Bytes())["active"] != false {
		t.Fatalf("upstream lifted a local disable: %d %s", got.Code, got.Body.String())
	}
	if u := mustUser(t, db, id); u.Status != "disabled" || !u.LocallyDisabled {
		t.Fatalf("override lost: %+v", u)
	}
	if got := adminRequest(t, srv, "PUT", "/api/admin/users/"+id, admin, `{"status":"active"}`); got.Code != http.StatusOK {
		t.Fatalf("local enable: %d %s", got.Code, got.Body.String())
	}
	if u := mustUser(t, db, id); u.Status != "active" || u.LocallyDisabled {
		t.Fatalf("override not lifted: %+v", u)
	}
	// Source-owned profile fields are read-only for local administrators; role is not.
	if got := adminRequest(t, srv, "PUT", "/api/admin/users/"+id, admin, `{"email":"changed@local.test"}`); got.Code != http.StatusBadRequest || !strings.Contains(got.Body.String(), "source_owned") {
		t.Fatalf("local edit of a source-owned field: %d %s", got.Code, got.Body.String())
	}
	if got := adminRequest(t, srv, "PUT", "/api/admin/users/"+id, admin, `{"role":"admin"}`); got.Code != http.StatusOK {
		t.Fatalf("local role change: %d %s", got.Code, got.Body.String())
	}
	if got := scimCall(t, srv, token, "PUT", "/scim/v2/Users/"+id, `{"externalId":"e1","userName":"upstream1","emails":[{"value":"u1@up.test"}],"roles":[{"value":"user"}],"active":true}`); got.Code != http.StatusOK {
		t.Fatalf("replace: %d %s", got.Code, got.Body.String())
	}
	if u := mustUser(t, db, id); u.Role != "admin" {
		t.Fatalf("upstream replace changed a local role: %+v", u)
	}
}

// Tokens are scoped, rotatable and never usable against the browser admin API; a browser
// session never authorizes SCIM.
func TestInboundSCIMCredentialsAreScopedAndSeparate(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newSession(t, db, newUser(t, db, "admin"), time.Now().UTC().Add(time.Hour))
	connectorID, writeToken := connectorWithToken(t, srv, db, admin, "write")
	issued := adminRequest(t, srv, "POST", "/api/admin/scim-connectors/"+connectorID+"/tokens", admin, `{"scope":"read"}`)
	var read struct {
		Token string `json:"token"`
		ID    string `json:"id"`
	}
	_ = json.Unmarshal(issued.Body.Bytes(), &read)

	if got := scimCall(t, srv, read.Token, "GET", "/scim/v2/Users", ""); got.Code != http.StatusOK {
		t.Fatalf("read token list: %d", got.Code)
	}
	if got := scimCall(t, srv, read.Token, "POST", "/scim/v2/Users", `{"externalId":"e","userName":"x","emails":[{"value":"x@up.test"}]}`); got.Code != http.StatusForbidden {
		t.Fatalf("read token wrote: %d", got.Code)
	}
	// A connector token is not a browser credential, and a cookie is not a SCIM credential.
	req := httptest.NewRequest("GET", "/api/admin/users", nil)
	req.Header.Set("Authorization", "Bearer "+writeToken)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("scim token reached the admin API: %d", rec.Code)
	}
	req = httptest.NewRequest("GET", "/scim/v2/Users", nil)
	req.AddCookie(&http.Cookie{Name: "kyidentity_session", Value: admin})
	rec = httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("admin cookie reached SCIM: %d", rec.Code)
	}

	// Rotation: issue a new write token, revoke the old one, old one is dead at once.
	rotated := adminRequest(t, srv, "POST", "/api/admin/scim-connectors/"+connectorID+"/tokens", admin, `{"scope":"write"}`)
	var fresh struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rotated.Body.Bytes(), &fresh)
	listing := call(t, srv, admin, "GET", "/api/admin/scim-connectors")
	if strings.Contains(listing.Body.String(), writeToken) || strings.Contains(listing.Body.String(), fresh.Token) {
		t.Fatal("raw token in the connector listing")
	}
	var view struct {
		Connectors []struct {
			Tokens []struct {
				ID string `json:"id"`
			} `json:"tokens"`
		} `json:"connectors"`
	}
	_ = json.Unmarshal(listing.Body.Bytes(), &view)
	// Revoke the oldest token (the first write token) and check exactly one credential died.
	if len(view.Connectors) != 1 || len(view.Connectors[0].Tokens) != 3 {
		t.Fatalf("listing: %s", listing.Body.String())
	}
	oldest := view.Connectors[0].Tokens[len(view.Connectors[0].Tokens)-1].ID
	if got := call(t, srv, admin, "DELETE", "/api/admin/scim-connectors/"+connectorID+"/tokens/"+oldest); got.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", got.Code, got.Body.String())
	}
	dead := 0
	for _, tok := range []string{writeToken, fresh.Token, read.Token} {
		if scimCall(t, srv, tok, "GET", "/scim/v2/Users", "").Code == http.StatusUnauthorized {
			dead++
		}
	}
	if dead != 1 {
		t.Fatalf("revoking one token killed %d tokens", dead)
	}
	if got := adminRequestNoStepUp(t, srv, "POST", "/api/admin/scim-connectors/"+connectorID+"/tokens", admin, `{"scope":"write"}`); got.Code == http.StatusOK {
		t.Fatal("token issued without step-up")
	}
	if got := call(t, srv, newSession(t, db, newUser(t, db, "user"), time.Now().UTC().Add(time.Hour)), "GET", "/api/admin/scim-connectors"); got.Code != http.StatusForbidden {
		t.Fatalf("non-admin listing: %d", got.Code)
	}
}

func TestDisconnectingAConnectorNeedsAChoiceForItsAccounts(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newSession(t, db, newUser(t, db, "admin"), time.Now().UTC().Add(time.Hour))
	connectorID, token := connectorWithToken(t, srv, db, admin, "write")
	created := scimCall(t, srv, token, "POST", "/scim/v2/Users", `{"externalId":"e1","userName":"leaver","emails":[{"value":"l@up.test"}]}`)
	id, _ := scimUser(t, created.Body.Bytes())["id"].(string)
	raw, _ := db.IssueAccountToken(id, "activation", "manual", time.Hour, nil)
	if _, err := db.RedeemAccountToken(raw, "activation", "hash", nil); err != nil {
		t.Fatal(err)
	}
	if got := adminRequest(t, srv, "DELETE", "/api/admin/scim-connectors/"+connectorID, admin, `{}`); got.Code != http.StatusBadRequest {
		t.Fatalf("delete without a choice: %d", got.Code)
	}
	preview := call(t, srv, admin, "GET", "/api/admin/scim-connectors")
	if !strings.Contains(preview.Body.String(), `"users":1`) {
		t.Fatalf("preview lacks the owned-account count: %s", preview.Body.String())
	}
	if got := adminRequest(t, srv, "DELETE", "/api/admin/scim-connectors/"+connectorID, admin, `{"users":"disable"}`); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"affectedUsers":1`) {
		t.Fatalf("delete: %d %s", got.Code, got.Body.String())
	}
	u := mustUser(t, db, id)
	if u.Status != "disabled" || u.SourceConnectorID != "" {
		t.Fatalf("after disconnect: %+v", u)
	}
	if got := scimCall(t, srv, token, "GET", "/scim/v2/Users", ""); got.Code != http.StatusUnauthorized {
		t.Fatalf("token outlived its connector: %d", got.Code)
	}
	if n := countAudit(t, db, "admin.scim_connector_deleted"); n != 1 {
		t.Fatalf("audit rows = %d", n)
	}
}
