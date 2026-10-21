package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// An account given its password by an administrator signs in, MFA and all, but its session
// can only read itself, step up for the change, change the password or leave. No app
// sign-in, admin API or unrelated grant is reachable until the change, which clears the
// flag, ends every other session and is audited.
func TestPasswordChangeRequiredRestrictsTheSessionUntilChanged(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	adminCookie := newSession(t, db, newUser(t, db, "admin"), time.Now().UTC().Add(time.Hour))
	newClient(t, db, "app", []string{"https://app.example/cb"}, []string{"openid"})
	r := adminRequest(t, srv, "POST", "/api/admin/users", adminCookie, `{"username":"newadmin","email":"newadmin@x.test","password":"temporary-password-1","role":"admin"}`)
	if r.Code != http.StatusOK || !strings.Contains(r.Body.String(), `"passwordChangeRequired":true`) {
		t.Fatalf("create: %d %s", r.Code, r.Body.String())
	}

	other := login(t, srv, "newadmin", "temporary-password-1")
	r = login(t, srv, "newadmin", "temporary-password-1")
	if r.Code != http.StatusOK || !strings.Contains(r.Body.String(), `"passwordChangeRequired":true`) {
		t.Fatalf("login: %d %s", r.Code, r.Body.String())
	}
	cookie := sessionCookie(r).Value

	if r := call(t, srv, cookie, "GET", "/api/auth/me"); r.Code != http.StatusOK || !strings.Contains(r.Body.String(), `"passwordChangeRequired":true`) {
		t.Fatalf("me: %d %s", r.Code, r.Body.String())
	}
	for _, route := range []struct{ method, path string }{
		{"GET", "/api/admin/users"}, {"POST", "/api/admin/users"}, {"GET", "/api/user/applications"},
		{"GET", "/api/user/sessions"}, {"POST", "/api/user/recovery-codes"}, {"GET", "/api/admin/audit-events"},
	} {
		if r := call(t, srv, cookie, route.method, route.path); r.Code != http.StatusForbidden || !strings.Contains(r.Body.String(), `"password_change_required"`) {
			t.Fatalf("%s %s escaped: %d %s", route.method, route.path, r.Code, r.Body.String())
		}
	}
	for _, prompt := range []string{"", "none"} {
		q := appAuthQuery("app")
		if prompt != "" {
			q.Set("prompt", prompt)
		}
		r := call(t, srv, cookie, "GET", "/oauth/authorize?"+q.Encode())
		target, _ := url.Parse(r.Header().Get("Location"))
		if target.Query().Get("error") != "interaction_required" || !strings.HasPrefix(target.Query().Get("error_description"), "password_change_required") {
			t.Fatalf("authorize (prompt=%q) escaped: %d %s", prompt, r.Code, r.Header().Get("Location"))
		}
	}
	stepUp := func(operation string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"password": "temporary-password-1", "operation": operation})
		return adminRequestNoStepUp(t, srv, "POST", "/api/auth/step-up", cookie, string(body))
	}
	if r := stepUp("PUT /api/admin/users/{id}"); r.Code != http.StatusForbidden || !strings.Contains(r.Body.String(), `"password_change_required"`) {
		t.Fatalf("unrelated grant: %d %s", r.Code, r.Body.String())
	}
	grant := func() string {
		r := stepUp("POST /api/user/password")
		var reply struct{ StepUpToken string }
		if r.Code != http.StatusOK || json.Unmarshal(r.Body.Bytes(), &reply) != nil || reply.StepUpToken == "" {
			t.Fatalf("password grant: %d %s", r.Code, r.Body.String())
		}
		return reply.StepUpToken
	}
	same := `{"currentPassword":"temporary-password-1","newPassword":"temporary-password-1"}`
	if r := adminRequestWithStepUp(t, srv, "POST", "/api/user/password", cookie, same, grant()); r.Code != http.StatusBadRequest || !strings.Contains(r.Body.String(), "password_reused") {
		t.Fatalf("kept the given password: %d %s", r.Code, r.Body.String())
	}
	body := `{"currentPassword":"temporary-password-1","newPassword":"my-own-password-42"}`
	if r := adminRequestWithStepUp(t, srv, "POST", "/api/user/password", cookie, body, grant()); r.Code != http.StatusOK {
		t.Fatalf("change: %d %s", r.Code, r.Body.String())
	}

	if r := call(t, srv, cookie, "GET", "/api/auth/me"); r.Code != http.StatusOK || !strings.Contains(r.Body.String(), `"passwordChangeRequired":false`) {
		t.Fatalf("me after change: %d %s", r.Code, r.Body.String())
	}
	if r := call(t, srv, cookie, "GET", "/api/admin/users"); r.Code != http.StatusOK {
		t.Fatalf("admin API after change: %d %s", r.Code, r.Body.String())
	}
	q := appAuthQuery("app")
	if r := call(t, srv, cookie, "GET", "/oauth/authorize?"+q.Encode()); !strings.HasPrefix(r.Header().Get("Location"), "https://app.example/cb?code=") {
		t.Fatalf("authorize after change: %s", r.Header().Get("Location"))
	}
	if r := call(t, srv, sessionCookie(other).Value, "GET", "/api/auth/me"); r.Code != http.StatusUnauthorized {
		t.Fatalf("other session survived the change: %d", r.Code)
	}
	events, _, err := db.ListAuditEvents(100, 0)
	if err != nil {
		t.Fatal(err)
	}
	var audited bool
	for _, e := range events {
		audited = audited || (e.Action == "user.password_changed" && e.Outcome == "success" && strings.Contains(e.DetailsJSON, `"required":true`))
	}
	if !audited {
		t.Fatal("forced change not audited")
	}
}

// The SQL behind code creation, token registration and online token checks refuses a
// flagged account on its own, so a session or token minted before the flag was set
// (an upgraded install) cannot reach an app either.
func TestPasswordChangeRequiredGatesIssuedTokens(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	u := newUser(t, db, "admin")
	cookie := newSession(t, db, u, time.Now().UTC().Add(time.Hour))
	sid := sessionIDFor(t, db, cookie)
	newClient(t, db, "app", []string{"https://example.com/cb"}, []string{"openid"})
	jti := uuid.NewString()
	if err := db.RecordIssuedToken(&store.IssuedToken{JTI: jti, UserID: u.ID, ClientID: "app", SessionID: sid, ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", srv.cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	flag := func(on bool) {
		t.Helper()
		if _, err := raw.Exec(`UPDATE users SET password_change_required=? WHERE id=?`, on, u.ID); err != nil {
			t.Fatal(err)
		}
	}
	flag(true)
	if revoked, err := db.IsTokenRevoked(jti); err != nil || !revoked {
		t.Fatalf("flagged account's token still valid: %v %v", revoked, err)
	}
	if err := db.RecordIssuedToken(&store.IssuedToken{JTI: uuid.NewString(), UserID: u.ID, ClientID: "app", SessionID: sid, ExpiresAt: time.Now().UTC().Add(time.Hour)}); !errors.Is(err, store.ErrAppAccessDenied) {
		t.Fatalf("token registered for a flagged account: %v", err)
	}
	if err := db.CreateAuthorizationCode(&store.AuthorizationCode{ID: uuid.NewString(), CodeHash: uuid.NewString(), ClientID: "app", UserID: u.ID, RedirectURI: "https://example.com/cb", Scope: "openid", SessionID: sid, ExpiresAt: time.Now().UTC().Add(time.Minute)}); !errors.Is(err, store.ErrAppAccessDenied) {
		t.Fatalf("code created for a flagged account: %v", err)
	}
	flag(false)
	if revoked, err := db.IsTokenRevoked(jti); err != nil || revoked {
		t.Fatalf("unflagged account's token refused: %v %v", revoked, err)
	}
}

// Only a password an administrator sets on someone else's account must be replaced; an
// account whose owner chose its password is untouched.
func TestAdminSetPasswordsAreFlagged(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	adminCookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	target, bystander := newUser(t, db, "user"), newUser(t, db, "user")
	flagged := func(id string) bool {
		t.Helper()
		u, err := db.GetUserByID(id)
		if err != nil || u == nil {
			t.Fatal(err)
		}
		return u.PasswordChangeRequired
	}
	if r := adminRequest(t, srv, "PUT", "/api/admin/users/"+target.ID, adminCookie, `{"displayName":"Renamed"}`); r.Code != http.StatusOK || flagged(target.ID) {
		t.Fatalf("profile edit flagged the account: %d %s", r.Code, r.Body.String())
	}
	if r := adminRequest(t, srv, "PUT", "/api/admin/users/"+target.ID, adminCookie, `{"password":"handed-over-password-1"}`); r.Code != http.StatusOK || !flagged(target.ID) {
		t.Fatalf("admin-set password not flagged: %d %s", r.Code, r.Body.String())
	}
	if r := adminRequest(t, srv, "POST", "/api/admin/users", adminCookie, `{"username":"invited","email":"invited@x.test"}`); r.Code != http.StatusOK || strings.Contains(r.Body.String(), `"passwordChangeRequired":true`) {
		t.Fatalf("invitation flagged: %d %s", r.Code, r.Body.String())
	}
	// Setting one's own password also ends one's own sessions, so it comes last for this admin.
	if r := adminRequest(t, srv, "PUT", "/api/admin/users/"+admin.ID, adminCookie, `{"password":"my-own-admin-password"}`); r.Code != http.StatusOK || flagged(admin.ID) {
		t.Fatalf("own password flagged: %d %s", r.Code, r.Body.String())
	}
	// An account that chose its own password signs in to an unrestricted session and may
	// even re-enter the same password, as before.
	cookie := sessionCookie(login(t, srv, bystander.Username, "correct-horse-battery")).Value
	if r := call(t, srv, cookie, "GET", "/api/user/sessions"); r.Code != http.StatusOK || flagged(bystander.ID) {
		t.Fatalf("unflagged session restricted: %d %s", r.Code, r.Body.String())
	}
	same := `{"currentPassword":"correct-horse-battery","newPassword":"correct-horse-battery"}`
	if r := adminRequest(t, srv, "POST", "/api/user/password", cookie, same); r.Code != http.StatusOK {
		t.Fatalf("unflagged change: %d %s", r.Code, r.Body.String())
	}
}
