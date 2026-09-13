package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kysignon-server/internal/store"
)

func login(t *testing.T, srv *Server, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	return anonPost(t, srv, "/api/auth/login", map[string]string{"username": username, "password": password})
}

func tokenFromLink(t *testing.T, body []byte) string {
	t.Helper()
	var out struct {
		Link     string `json:"link"`
		Delivery string `json:"delivery"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Delivery != "manual" || !strings.Contains(out.Link, "?token=") {
		t.Fatalf("link response: %s %v", body, err)
	}
	return out.Link[strings.Index(out.Link, "?token=")+7:]
}

func auditContains(t *testing.T, db *store.Store, needle string) bool {
	t.Helper()
	events, _, err := db.ListAuditEvents(500, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		raw, _ := json.Marshal(e)
		if strings.Contains(string(raw), needle) {
			return true
		}
	}
	return false
}

// An invited account has no credential until its link sets one; the link is single-use,
// only its POST spends it, and the raw token never reaches the audit log.
func TestInvitedAccountActivatesThroughItsLink(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newSession(t, db, newUser(t, db, "admin"), time.Now().UTC().Add(time.Hour))

	created := adminRequest(t, srv, "POST", "/api/admin/users", admin, `{"username":"newcomer","displayName":"New","email":"new@example.test","role":"user"}`)
	if created.Code != http.StatusOK {
		t.Fatalf("invite: %d %s", created.Code, created.Body.String())
	}
	var resp struct {
		User struct {
			ID      string `json:"id"`
			Pending bool   `json:"pending"`
			Status  string `json:"status"`
		} `json:"user"`
	}
	_ = json.Unmarshal(created.Body.Bytes(), &resp)
	if !resp.User.Pending || resp.User.Status != "disabled" {
		t.Fatalf("invited user: %+v", resp.User)
	}
	if got := login(t, srv, "newcomer", ""); got.Code != http.StatusUnauthorized {
		t.Fatalf("pending login with empty password: %d", got.Code)
	}
	if got := adminRequest(t, srv, "POST", "/api/admin/users/"+resp.User.ID+"/reset-link", admin, "{}"); got.Code != http.StatusConflict {
		t.Fatalf("reset link for a pending account: %d", got.Code)
	}
	if got := adminRequestNoStepUp(t, srv, "POST", "/api/admin/users/"+resp.User.ID+"/activation-link", admin, "{}"); got.Code == http.StatusOK {
		t.Fatal("activation link issued without step-up")
	}
	issued := adminRequest(t, srv, "POST", "/api/admin/users/"+resp.User.ID+"/activation-link", admin, "{}")
	if issued.Code != http.StatusOK {
		t.Fatalf("activation link: %d %s", issued.Code, issued.Body.String())
	}
	token := tokenFromLink(t, issued.Body.Bytes())
	if auditContains(t, db, token) {
		t.Fatal("raw activation token written to the audit log")
	}

	// Opening the link is a plain SPA page; nothing is spent.
	page := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(page, httptest.NewRequest("GET", "/activate?token="+token, nil))
	if page.Code != http.StatusOK || !strings.Contains(page.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("link GET: %d %s", page.Code, page.Header().Get("Content-Type"))
	}
	if got := anonPost(t, srv, "/api/auth/activate", map[string]string{"token": token, "password": "short"}); got.Code != http.StatusBadRequest || !strings.Contains(got.Body.String(), "password_policy") {
		t.Fatalf("weak password: %d %s", got.Code, got.Body.String())
	}
	if got := anonPost(t, srv, "/api/auth/password/reset", map[string]string{"token": token, "password": "a-long-enough-password"}); got.Code != http.StatusBadRequest || !strings.Contains(got.Body.String(), "invalid_link") {
		t.Fatalf("activation token accepted as reset: %d %s", got.Code, got.Body.String())
	}
	if got := anonPost(t, srv, "/api/auth/activate", map[string]string{"token": token, "password": "a-long-enough-password"}); got.Code != http.StatusOK {
		t.Fatalf("activate: %d %s", got.Code, got.Body.String())
	}
	if got := anonPost(t, srv, "/api/auth/activate", map[string]string{"token": token, "password": "another-long-password"}); got.Code != http.StatusBadRequest {
		t.Fatalf("replayed link: %d", got.Code)
	}
	if got := login(t, srv, "newcomer", "a-long-enough-password"); got.Code != http.StatusOK {
		t.Fatalf("login after activation: %d %s", got.Code, got.Body.String())
	}
	u, _ := db.GetUserByID(resp.User.ID)
	if u.Pending || u.Status != "active" || u.EmailVerifiedAt != nil {
		t.Fatalf("after activation: %+v", u)
	}
	if got := adminRequest(t, srv, "POST", "/api/admin/users/"+resp.User.ID+"/activation-link", admin, "{}"); got.Code != http.StatusConflict {
		t.Fatalf("activation link for an active account: %d", got.Code)
	}
}

// A pending account cannot be switched on by editing its status; setting a password is
// the manual activation.
func TestPendingAccountActivatesOnlyByPassword(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newSession(t, db, newUser(t, db, "admin"), time.Now().UTC().Add(time.Hour))
	created := adminRequest(t, srv, "POST", "/api/admin/users", admin, `{"username":"invited","email":"invited@example.test"}`)
	var resp struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	_ = json.Unmarshal(created.Body.Bytes(), &resp)
	if got := adminRequest(t, srv, "PUT", "/api/admin/users/"+resp.User.ID, admin, `{"status":"active"}`); got.Code != http.StatusBadRequest || !strings.Contains(got.Body.String(), "account_pending") {
		t.Fatalf("status flip on a pending account: %d %s", got.Code, got.Body.String())
	}
	if got := adminRequest(t, srv, "PUT", "/api/admin/users/"+resp.User.ID, admin, `{"status":"active","password":"set-by-the-admin-12"}`); got.Code != http.StatusOK {
		t.Fatalf("manual activation: %d %s", got.Code, got.Body.String())
	}
	u, _ := db.GetUserByID(resp.User.ID)
	if u.Pending || u.Status != "active" {
		t.Fatalf("after manual activation: %+v", u)
	}
}

// Forgot never reveals whether an account exists; a reset link replaces the password and
// signs the account out everywhere.
func TestForgotIsGenericAndResetSignsOutEverywhere(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	exp := time.Now().UTC().Add(time.Hour)
	admin := newSession(t, db, newUser(t, db, "admin"), exp)
	u := newUser(t, db, "user")
	old := newSession(t, db, u, exp)

	unknown := anonPost(t, srv, "/api/auth/password/forgot", map[string]string{"identifier": "nobody@example.test"})
	known := anonPost(t, srv, "/api/auth/password/forgot", map[string]string{"identifier": u.Username})
	if unknown.Code != http.StatusOK || known.Code != http.StatusOK || unknown.Body.String() != known.Body.String() {
		t.Fatalf("forgot answers differ: %d %s vs %d %s", unknown.Code, unknown.Body.String(), known.Code, known.Body.String())
	}

	issued := adminRequest(t, srv, "POST", "/api/admin/users/"+u.ID+"/reset-link", admin, "{}")
	if issued.Code != http.StatusOK {
		t.Fatalf("reset link: %d %s", issued.Code, issued.Body.String())
	}
	token := tokenFromLink(t, issued.Body.Bytes())
	if got := anonPost(t, srv, "/api/auth/password/reset", map[string]string{"token": token, "password": "brand-new-password-1"}); got.Code != http.StatusOK {
		t.Fatalf("reset: %d %s", got.Code, got.Body.String())
	}
	if got := call(t, srv, old, "GET", "/api/auth/me"); got.Code != http.StatusUnauthorized {
		t.Fatalf("old session survived the reset: %d", got.Code)
	}
	if got := login(t, srv, u.Username, "correct-horse-battery"); got.Code != http.StatusUnauthorized {
		t.Fatalf("old password still works: %d", got.Code)
	}
	if got := login(t, srv, u.Username, "brand-new-password-1"); got.Code != http.StatusOK {
		t.Fatalf("new password rejected: %d %s", got.Code, got.Body.String())
	}
	if auditContains(t, db, token) {
		t.Fatal("raw reset token written to the audit log")
	}
}

// Changing the password needs the current one and a step-up grant, keeps this session
// and ends the others.
func TestChangePasswordNeedsStepUpAndKeepsOnlyThisSession(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	exp := time.Now().UTC().Add(time.Hour)
	u := newUser(t, db, "user")
	mine, other := newSession(t, db, u, exp), newSession(t, db, u, exp)
	body := `{"currentPassword":"correct-horse-battery","newPassword":"a-new-long-password-9"}`
	if got := adminRequestNoStepUp(t, srv, "POST", "/api/user/password", mine, body); got.Code == http.StatusOK {
		t.Fatal("password changed without step-up")
	}
	if got := adminRequest(t, srv, "POST", "/api/user/password", mine, `{"currentPassword":"wrong-wrong-wrong","newPassword":"a-new-long-password-9"}`); got.Code != http.StatusUnauthorized {
		t.Fatalf("wrong current password: %d %s", got.Code, got.Body.String())
	}
	if got := adminRequest(t, srv, "POST", "/api/user/password", mine, body); got.Code != http.StatusOK {
		t.Fatalf("change: %d %s", got.Code, got.Body.String())
	}
	if got := call(t, srv, mine, "GET", "/api/auth/me"); got.Code != http.StatusOK {
		t.Fatalf("own session lost: %d", got.Code)
	}
	if got := call(t, srv, other, "GET", "/api/auth/me"); got.Code != http.StatusUnauthorized {
		t.Fatalf("other session survived: %d", got.Code)
	}
	if got := login(t, srv, u.Username, "a-new-long-password-9"); got.Code != http.StatusOK {
		t.Fatalf("new password rejected: %d", got.Code)
	}
	if n := countAudit(t, db, "user.password_changed"); n != 1 {
		t.Fatalf("password change audit rows = %d", n)
	}
}

// Mail settings are admin-only and the password is write-only.
func TestMailSettingsAreWriteOnlyAndAdminOnly(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	exp := time.Now().UTC().Add(time.Hour)
	admin := newSession(t, db, newUser(t, db, "admin"), exp)
	plain := newSession(t, db, newUser(t, db, "user"), exp)
	if got := call(t, srv, plain, "GET", "/api/admin/mail"); got.Code != http.StatusForbidden {
		t.Fatalf("non-admin read: %d", got.Code)
	}
	if got := call(t, srv, admin, "GET", "/api/admin/mail"); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"configured":false`) {
		t.Fatalf("unset: %d %s", got.Code, got.Body.String())
	}
	if got := call(t, srv, admin, "POST", "/api/admin/mail/test"); got.Code != http.StatusBadRequest {
		t.Fatalf("test without settings: %d", got.Code)
	}
	if got := adminRequestNoStepUp(t, srv, "PUT", "/api/admin/mail", admin, `{"host":"smtp.example.test","port":465,"from":"id@example.test","security":"tls","password":"p"}`); got.Code == http.StatusOK {
		t.Fatal("mail settings saved without step-up")
	}
	if got := adminRequest(t, srv, "PUT", "/api/admin/mail", admin, `{"host":"smtp.example.test","port":465,"from":"id@example.test","security":"tls","password":"hunter2-relay"}`); got.Code != http.StatusOK {
		t.Fatalf("save: %d %s", got.Code, got.Body.String())
	}
	got := call(t, srv, admin, "GET", "/api/admin/mail")
	if !strings.Contains(got.Body.String(), `"hasPassword":true`) || strings.Contains(got.Body.String(), "hunter2") {
		t.Fatalf("read back: %s", got.Body.String())
	}
	if auditContains(t, db, "hunter2") {
		t.Fatal("mail password written to the audit log")
	}
	if got := adminRequest(t, srv, "PUT", "/api/admin/mail", admin, `{"host":"smtp.example.test","port":465,"from":"id@example.test","security":"none"}`); got.Code != http.StatusBadRequest {
		t.Fatalf("cleartext accepted: %d", got.Code)
	}
	if got := adminRequest(t, srv, "PUT", "/api/admin/mail", admin, `{"host":""}`); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"configured":false`) {
		t.Fatalf("clear: %d %s", got.Code, got.Body.String())
	}
}
