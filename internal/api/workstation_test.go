package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/auth"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

type wsFixture struct {
	t        *testing.T
	srv      *Server
	db       *store.Store
	raw      *sql.DB
	admin    string
	clientID string
	appID    string
}

func newWSFixture(t *testing.T) (*wsFixture, func()) {
	t.Helper()
	srv, db, _, _, _, cleanup := setupTestServer(t)
	f := &wsFixture{t: t, srv: srv, db: db, admin: newSession(t, db, newUser(t, db, "admin"), time.Now().UTC().Add(time.Hour))}
	raw, err := store.OpenRawForTest(srv.cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	f.raw = raw
	rr := adminRequest(t, srv, "POST", "/api/admin/workstation-apps", f.admin, `{"clientName":"Office PCs"}`)
	var app store.WorkstationApp
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &app) != nil || app.DeviceGrantEnabled || app.DeviceCodeTTL != 300 || app.OfflineWindow != 604800 {
		t.Fatalf("create workstation app: %d %s", rr.Code, rr.Body.String())
	}
	f.clientID, f.appID = app.ClientID, app.AppID
	f.settings(true, 300, 604800)
	return f, func() { raw.Close(); cleanup() }
}

func (f *wsFixture) settings(grant bool, ttl, window int) *httptest.ResponseRecorder {
	f.t.Helper()
	rr := adminRequest(f.t, f.srv, "PUT", "/api/admin/workstation-apps/"+f.clientID, f.admin, fmt.Sprintf(`{"deviceGrantEnabled":%t,"deviceCodeTtl":%d,"offlineWindow":%d}`, grant, ttl, window))
	if rr.Code != http.StatusOK && rr.Code != http.StatusBadRequest {
		f.t.Fatalf("settings: %d %s", rr.Code, rr.Body.String())
	}
	return rr
}

// assignedUser is an active user assigned to the app, with a browser session.
func (f *wsFixture) assignedUser() (*store.User, string) {
	f.t.Helper()
	u := newUser(f.t, f.db, "user")
	if err := f.db.SetAppAssignment(f.appID, "users", u.ID, true, nil); err != nil {
		f.t.Fatal(err)
	}
	return u, newSession(f.t, f.db, u, time.Now().UTC().Add(time.Hour))
}

func (f *wsFixture) form(path string, form url.Values) (int, map[string]any) {
	f.t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	f.srv.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Header().Get("Cache-Control") != "no-store" {
		f.t.Fatalf("%s cacheable: %q", path, rr.Header().Get("Cache-Control"))
	}
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	return rr.Code, body
}

func (f *wsFixture) browser(cookie, path, body string) *httptest.ResponseRecorder {
	f.t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "kyidentity_session", Value: cookie})
	csrf := f.srv.middleware.IssueCSRFToken(cookie)
	req.AddCookie(&http.Cookie{Name: "kyidentity_csrf", Value: csrf})
	req.Header.Set("X-CSRF-Token", csrf)
	rr := httptest.NewRecorder()
	f.srv.httpServer.Handler.ServeHTTP(rr, req)
	return rr
}

func (f *wsFixture) start() (deviceCode, userCode string) {
	f.t.Helper()
	status, body := f.form("/oauth/device_authorization", url.Values{"client_id": {f.clientID}, "scope": {"openid profile email offline_access"}})
	deviceCode, _ = body["device_code"].(string)
	userCode, _ = body["user_code"].(string)
	if status != http.StatusOK || deviceCode == "" || body["interval"] != float64(5) || body["expires_in"] != float64(300) ||
		body["verification_uri_complete"] != f.srv.cfg.IssuerURL+"/device?user_code="+userCode {
		f.t.Fatalf("device authorization: %d %v", status, body)
	}
	if !regexp.MustCompile(`^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$`).MatchString(userCode) {
		f.t.Fatalf("user code %q is not 8 unambiguous uppercase letters", userCode)
	}
	return deviceCode, userCode
}

func (f *wsFixture) decide(cookie, userCode string, approve bool) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.browser(cookie, "/api/device/decision", fmt.Sprintf(`{"userCode":%q,"approve":%t}`, userCode, approve))
}

// poll polls as a client that waited its interval.
func (f *wsFixture) poll(clientID, deviceCode string) (int, map[string]any) {
	f.t.Helper()
	if _, err := f.raw.Exec(`UPDATE device_codes SET last_polled_at=? WHERE device_code_hash=?`, time.Now().UTC().Add(-time.Minute), crypto.HashSHA256(deviceCode)); err != nil {
		f.t.Fatal(err)
	}
	return f.form("/oauth/token", url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {deviceCode}, "client_id": {clientID}})
}

func (f *wsFixture) refresh(token string) (int, map[string]any) {
	f.t.Helper()
	return f.form("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}, "client_id": {f.clientID}})
}

// login runs the whole device grant for an assigned user and returns the token response.
func (f *wsFixture) login(cookie string) map[string]any {
	f.t.Helper()
	device, user := f.start()
	if rr := f.decide(cookie, user, true); rr.Code != http.StatusOK {
		f.t.Fatalf("approve: %d %s", rr.Code, rr.Body.String())
	}
	status, body := f.poll(f.clientID, device)
	if status != http.StatusOK || body["access_token"] == nil || body["id_token"] == nil {
		f.t.Fatalf("redeem: %d %v", status, body)
	}
	return body
}

func (f *wsFixture) workstationSessions(userID string) int {
	f.t.Helper()
	var n int
	if err := f.raw.QueryRow(`SELECT COUNT(*) FROM sessions WHERE user_id=? AND workstation_client_id=?`, userID, f.clientID).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *wsFixture) audits(action string) int {
	f.t.Helper()
	var n int
	if err := f.raw.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action=?`, action).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func userinfo(t *testing.T, srv *Server, access string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("GET", "/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	return rr.Code, body
}

// The full grant: pending, slow_down, approval, one redemption with a refresh token,
// groups in userinfo, rotation, refresh replay ending the family, and device-code replay
// ending the workstation session.
func TestDeviceGrantLifecycle(t *testing.T) {
	f, done := newWSFixture(t)
	defer done()
	u, cookie := f.assignedUser()
	g := &store.Group{ID: uuid.NewString(), Name: "linux-users"}
	if err := f.db.CreateGroup(g, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.db.SetGroupMembership(g.ID, u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.db.SetAppAssignment(f.appID, "groups", g.ID, true, nil); err != nil {
		t.Fatal(err)
	}

	device, userCode := f.start()
	if status, body := f.poll(f.clientID, device); status != 400 || body["error"] != "authorization_pending" {
		t.Fatalf("pending: %d %v", status, body)
	}
	// Polling again at once is faster than the interval.
	if status, body := f.form("/oauth/token", url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {device}, "client_id": {f.clientID}}); status != 400 || body["error"] != "slow_down" {
		t.Fatalf("fast poll: %d %v", status, body)
	}
	lookup := f.browser(cookie, "/api/device/lookup", fmt.Sprintf(`{"userCode":%q}`, strings.ToLower(strings.ReplaceAll(userCode, "-", " "))))
	if lookup.Code != http.StatusOK || !strings.Contains(lookup.Body.String(), `"clientName":"Office PCs"`) || !strings.Contains(lookup.Body.String(), f.clientID) {
		t.Fatalf("lookup: %d %s", lookup.Code, lookup.Body.String())
	}
	if rr := f.decide(cookie, userCode, true); rr.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rr.Code, rr.Body.String())
	}
	status, tokens := f.poll(f.clientID, device)
	rt, _ := tokens["refresh_token"].(string)
	if status != 200 || rt == "" || tokens["id_token"] == nil {
		t.Fatalf("redeem: %d %v", status, tokens)
	}
	if code, info := userinfo(t, f.srv, tokens["access_token"].(string)); code != 200 || info["preferred_username"] != u.Username || fmt.Sprint(info["groups"]) != "[linux-users]" {
		t.Fatalf("userinfo: %d %v", code, info)
	}
	if f.workstationSessions(u.ID) != 1 || f.audits("device_grant.approved") != 1 || f.audits("device_grant.redeemed") != 1 {
		t.Fatalf("session or audit rows missing")
	}
	// The session slides by the offline window, not the browser limits.
	var expires time.Time
	if err := f.raw.QueryRow(`SELECT expires_at FROM sessions WHERE workstation_client_id=?`, f.clientID).Scan(&expires); err != nil || expires.Sub(time.Now()) < 6*24*time.Hour {
		t.Fatalf("workstation session expiry %v %v", expires, err)
	}

	status, rotated := f.refresh(rt)
	next, _ := rotated["refresh_token"].(string)
	if status != 200 || next == "" || next == rt {
		t.Fatalf("refresh: %d %v", status, rotated)
	}
	if status, body := f.refresh(rt); status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("refresh replay: %d %v", status, body)
	}
	if status, body := f.refresh(next); status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("family survived a replay: %d %v", status, body)
	}

	// The device code is spent; presenting it again ends the session it created.
	second := f.login(cookie)
	_ = second
	var spent string
	if err := f.raw.QueryRow(`SELECT device_code_hash FROM device_codes WHERE redeemed_at IS NOT NULL ORDER BY created_at DESC LIMIT 1`).Scan(&spent); err != nil {
		t.Fatal(err)
	}
	before := f.workstationSessions(u.ID)
	if status, body := f.poll(f.clientID, device); status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("device code replay: %d %v", status, body)
	}
	if f.workstationSessions(u.ID) != before-1 || f.audits("device_grant.replayed") != 1 {
		t.Fatalf("replay left the session: %d -> %d", before, f.workstationSessions(u.ID))
	}
}

func TestDeviceGrantRefusals(t *testing.T) {
	f, done := newWSFixture(t)
	defer done()
	_, cookie := f.assignedUser()

	// Off by default, and an ordinary public client never gets it.
	f.settings(false, 300, 604800)
	if status, body := f.form("/oauth/device_authorization", url.Values{"client_id": {f.clientID}}); status != 400 || body["error"] != "unauthorized_client" {
		t.Fatalf("grant off: %d %v", status, body)
	}
	f.settings(true, 300, 604800)
	newClient(t, f.db, "spa", []string{"https://spa.test/cb"}, []string{"openid"})
	if status, body := f.form("/oauth/device_authorization", url.Values{"client_id": {"spa"}}); status != 400 || body["error"] != "unauthorized_client" {
		t.Fatalf("non-workstation client: %d %v", status, body)
	}

	// Another client cannot redeem this app's code.
	device, userCode := f.start()
	if rr := f.decide(cookie, userCode, true); rr.Code != 200 {
		t.Fatalf("approve: %d", rr.Code)
	}
	if status, body := f.poll("spa", device); status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("foreign client: %d %v", status, body)
	}
	if status, body := f.poll(f.clientID, "not-a-code"); status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("unknown code: %d %v", status, body)
	}

	// Denied.
	device, userCode = f.start()
	if rr := f.decide(cookie, userCode, false); rr.Code != 200 {
		t.Fatalf("deny: %d", rr.Code)
	}
	if status, body := f.poll(f.clientID, device); status != 400 || body["error"] != "access_denied" {
		t.Fatalf("denied: %d %v", status, body)
	}
	if rr := f.decide(cookie, userCode, true); rr.Code != http.StatusNotFound {
		t.Fatalf("a denied code was approved later: %d", rr.Code)
	}

	// Expired.
	device, _ = f.start()
	if _, err := f.raw.Exec(`UPDATE device_codes SET expires_at=? WHERE device_code_hash=?`, time.Now().UTC().Add(-time.Second), crypto.HashSHA256(device)); err != nil {
		t.Fatal(err)
	}
	if status, body := f.poll(f.clientID, device); status != 400 || body["error"] != "expired_token" {
		t.Fatalf("expired: %d %v", status, body)
	}

	// An unassigned user cannot approve.
	stranger := newSession(t, f.db, newUser(t, f.db, "user"), time.Now().UTC().Add(time.Hour))
	_, userCode = f.start()
	if rr := f.decide(stranger, userCode, true); rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "no_access") {
		t.Fatalf("unassigned approval: %d %s", rr.Code, rr.Body.String())
	}

	// Signing out of the approving browser before redemption stops the code.
	u2, c2 := f.assignedUser()
	device, userCode = f.start()
	if rr := f.decide(c2, userCode, true); rr.Code != 200 {
		t.Fatalf("approve: %d", rr.Code)
	}
	if err := f.db.RevokeUserAccess(u2.ID, nil); err != nil {
		t.Fatal(err)
	}
	if status, body := f.poll(f.clientID, device); status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("redeemed after the approving session ended: %d %v", status, body)
	}

	// Ranges and the client type are fixed.
	if rr := f.settings(true, 60, 604800); rr.Code != http.StatusBadRequest {
		t.Fatalf("2-minute floor: %d", rr.Code)
	}
	if rr := f.settings(true, 300, 31*24*3600); rr.Code != http.StatusBadRequest {
		t.Fatalf("30-day ceiling: %d", rr.Code)
	}
	if rr := adminRequest(t, f.srv, "PUT", "/api/admin/clients/"+f.clientID, f.admin, `{"clientType":"confidential"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("workstation app became confidential: %d %s", rr.Code, rr.Body.String())
	}
	if rr := adminRequestNoStepUp(t, f.srv, "PUT", "/api/admin/workstation-apps/"+f.clientID, f.admin, `{"deviceGrantEnabled":true,"deviceCodeTtl":300,"offlineWindow":0}`); rr.Code == http.StatusOK {
		t.Fatal("settings changed without step-up")
	}
}

// Guessing user codes: misses are uniform, audited and rate limited per account.
func TestDeviceUserCodeGuessing(t *testing.T) {
	f, done := newWSFixture(t)
	defer done()
	_, cookie := f.assignedUser()
	_, real := f.start()
	misses := 0
	for i := 0; i < 15; i++ {
		guess := "BCDF-GHJK"
		if i%2 == 1 {
			guess = "not a code"
		}
		rr := f.browser(cookie, "/api/device/lookup", fmt.Sprintf(`{"userCode":%q}`, guess))
		if rr.Code == http.StatusTooManyRequests {
			break
		}
		if rr.Code != http.StatusNotFound || !strings.Contains(rr.Body.String(), "code_not_found") {
			t.Fatalf("guess %d: %d %s", i, rr.Code, rr.Body.String())
		}
		misses++
	}
	if misses != 10 {
		t.Fatalf("rate limit after %d misses, want 10", misses)
	}
	// The limit holds for the real code too until it refills.
	if rr := f.browser(cookie, "/api/device/lookup", fmt.Sprintf(`{"userCode":%q}`, real)); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("limited account still looked up a code: %d", rr.Code)
	}
	if f.audits("device_grant.code_rejected") != 10 {
		t.Fatalf("misses audited: %d", f.audits("device_grant.code_rejected"))
	}
	var leaked int
	if err := f.raw.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE details_json LIKE ?`, "%"+real[:4]+"%").Scan(&leaked); err != nil || leaked != 0 {
		t.Fatalf("a user code reached the audit log: %d %v", leaked, err)
	}
	var stored string
	if err := f.raw.QueryRow(`SELECT user_code_hash FROM device_codes`).Scan(&stored); err != nil || stored == crypto.HashSHA256(strings.ReplaceAll(real, "-", "")) || strings.Contains(stored, real) {
		t.Fatalf("user code stored recoverably: %v", err)
	}
}

func TestDeviceAuthorizationRateLimit(t *testing.T) {
	f, done := newWSFixture(t)
	defer done()
	limited := false
	for i := 0; i < 15 && !limited; i++ {
		status, _ := f.form("/oauth/device_authorization", url.Values{"client_id": {f.clientID}})
		limited = status == http.StatusTooManyRequests
	}
	if !limited {
		t.Fatal("device authorization is not rate limited")
	}
}

func TestWorkstationOfflineWindowZero(t *testing.T) {
	f, done := newWSFixture(t)
	defer done()
	_, cookie := f.assignedUser()
	first := f.login(cookie)
	f.settings(true, 300, 0)
	if status, body := f.refresh(first["refresh_token"].(string)); status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("refresh after the window went to 0: %d %v", status, body)
	}
	tokens := f.login(cookie)
	if _, ok := tokens["refresh_token"]; ok {
		t.Fatalf("window 0 issued a refresh token: %v", tokens)
	}
}

// Every way of ending access ends a workstation session at once: the next refresh fails
// with invalid_grant, which is what makes Himmelblau drop its cache.
func TestWorkstationSessionsEndWithAccess(t *testing.T) {
	cases := map[string]func(f *wsFixture, u *store.User, cookie string){
		"disable": func(f *wsFixture, u *store.User, _ string) {
			if rr := adminRequest(f.t, f.srv, "PUT", "/api/admin/users/"+u.ID, f.admin, `{"status":"disabled"}`); rr.Code != 200 {
				f.t.Fatalf("disable: %d %s", rr.Code, rr.Body.String())
			}
		},
		"unassign": func(f *wsFixture, u *store.User, _ string) {
			if err := f.db.SetAppAssignment(f.appID, "users", u.ID, false, nil); err != nil {
				f.t.Fatal(err)
			}
		},
		"revoke own session": func(f *wsFixture, u *store.User, cookie string) {
			var id string
			if err := f.raw.QueryRow(`SELECT id FROM sessions WHERE workstation_client_id=? AND user_id=?`, f.clientID, u.ID).Scan(&id); err != nil {
				f.t.Fatal(err)
			}
			if rr := call(f.t, f.srv, cookie, "DELETE", "/api/user/sessions/"+id); rr.Code != 200 && rr.Code != 204 {
				f.t.Fatalf("revoke: %d %s", rr.Code, rr.Body.String())
			}
		},
		"admin revoke sessions": func(f *wsFixture, u *store.User, _ string) {
			if rr := adminRequestNoStepUp(f.t, f.srv, "POST", "/api/admin/users/"+u.ID+"/revoke-sessions", f.admin, ""); rr.Code != 200 {
				f.t.Fatalf("revoke: %d %s", rr.Code, rr.Body.String())
			}
		},
		"mfa reset": func(f *wsFixture, u *store.User, _ string) {
			if rr := adminRequest(f.t, f.srv, "POST", "/api/admin/users/"+u.ID+"/reset-mfa", f.admin, ""); rr.Code != 200 {
				f.t.Fatalf("reset: %d %s", rr.Code, rr.Body.String())
			}
		},
		"password change": func(f *wsFixture, u *store.User, cookie string) {
			sess, err := f.db.GetSessionByTokenHash(crypto.HashSHA256(cookie), time.Hour)
			if err != nil || sess == nil {
				f.t.Fatal(err)
			}
			hash, _ := auth.HashPassword("another-long-passphrase")
			if err := f.db.ChangePassword(u.ID, sess.ID, hash, nil); err != nil {
				f.t.Fatal(err)
			}
		},
	}
	for name, end := range cases {
		t.Run(name, func(t *testing.T) {
			f, done := newWSFixture(t)
			defer done()
			u, cookie := f.assignedUser()
			tokens := f.login(cookie)
			end(f, u, cookie)
			if status, body := f.refresh(tokens["refresh_token"].(string)); status != 400 || body["error"] != "invalid_grant" {
				t.Fatalf("refresh after %s: %d %v", name, status, body)
			}
			if code, _ := userinfo(t, f.srv, tokens["access_token"].(string)); code != http.StatusUnauthorized {
				t.Fatalf("access token after %s: %d", name, code)
			}
			if f.workstationSessions(u.ID) != 0 {
				t.Fatalf("workstation session survived %s", name)
			}
		})
	}
}

// SCIM deprovisioning (active=false from the upstream directory).
func TestWorkstationSessionEndsOnSCIMDeprovision(t *testing.T) {
	f, done := newWSFixture(t)
	defer done()
	_, token := connectorWithToken(t, f.srv, f.db, f.admin, "write")
	created := scimCall(t, f.srv, token, "POST", "/scim/v2/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"ext-ws","userName":"pc.user","emails":[{"value":"pc@up.test","primary":true}],"active":true}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("scim create: %d %s", created.Code, created.Body.String())
	}
	id := scimUser(t, created.Body.Bytes())["id"].(string)
	raw, _ := f.db.IssueAccountToken(id, "activation", "manual", time.Hour, nil)
	if _, err := f.db.RedeemAccountToken(raw, "activation", "hash", nil); err != nil {
		t.Fatal(err)
	}
	if err := f.db.SetAppAssignment(f.appID, "users", id, true, nil); err != nil {
		t.Fatal(err)
	}
	cookie := newSession(t, f.db, mustUser(t, f.db, id), time.Now().UTC().Add(time.Hour))
	tokens := f.login(cookie)
	if got := scimCall(t, f.srv, token, "PATCH", "/scim/v2/Users/"+id, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`); got.Code != http.StatusOK {
		t.Fatalf("deprovision: %d %s", got.Code, got.Body.String())
	}
	if status, body := f.refresh(tokens["refresh_token"].(string)); status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("refresh after SCIM deprovision: %d %v", status, body)
	}
	if f.workstationSessions(id) != 0 {
		t.Fatal("workstation session survived SCIM deprovisioning")
	}
}

// A workstation session is never a browser session, and browser limit edits leave it alone.
func TestWorkstationSessionIsNotABrowserSession(t *testing.T) {
	f, done := newWSFixture(t)
	defer done()
	u, cookie := f.assignedUser()
	tokens := f.login(cookie)
	// Age the session past every browser limit.
	if _, err := f.raw.Exec(`UPDATE sessions SET created_at=?, last_active_at=? WHERE workstation_client_id=?`, time.Now().UTC().Add(-10*24*time.Hour), time.Now().UTC().Add(-2*24*time.Hour), f.clientID); err != nil {
		t.Fatal(err)
	}
	if rr := adminRequest(t, f.srv, "PUT", "/api/admin/session-settings", f.admin, `{"absolute":3600,"idle":1800}`); rr.Code != 200 {
		t.Fatalf("session settings: %d %s", rr.Code, rr.Body.String())
	}
	if f.workstationSessions(u.ID) != 1 {
		t.Fatal("a browser limit change ended a workstation session")
	}
	if status, body := f.refresh(tokens["refresh_token"].(string)); status != 200 {
		t.Fatalf("refresh of an aged workstation session: %d %v", status, body)
	}
	// It shows in the user's session list, labelled with its app.
	if rr := call(t, f.srv, cookie, "GET", "/api/user/sessions"); !strings.Contains(rr.Body.String(), `"workstationClientId":"`+f.clientID+`"`) {
		t.Fatalf("session list: %s", rr.Body.String())
	}
	// A shorter window clamps it now.
	f.settings(true, 300, 3600)
	var expires time.Time
	if err := f.raw.QueryRow(`SELECT expires_at FROM sessions WHERE workstation_client_id=?`, f.clientID).Scan(&expires); err != nil || time.Until(expires) > time.Hour+time.Minute {
		t.Fatalf("window change did not clamp: %v %v", expires, err)
	}
}

func TestDevicePageAndDiscovery(t *testing.T) {
	f, done := newWSFixture(t)
	defer done()
	rr := httptest.NewRecorder()
	f.srv.httpServer.Handler.ServeHTTP(rr, httptest.NewRequest("GET", "/device?user_code=BCDF-GHJK", nil))
	if !strings.Contains(rr.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") || rr.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("device page frameable: %q %q", rr.Header().Get("Content-Security-Policy"), rr.Header().Get("X-Frame-Options"))
	}
	rr = httptest.NewRecorder()
	f.srv.httpServer.Handler.ServeHTTP(rr, httptest.NewRequest("GET", "/.well-known/openid-configuration", nil))
	var meta map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &meta)
	if meta["device_authorization_endpoint"] != f.srv.cfg.IssuerURL+"/oauth/device_authorization" || !strings.Contains(fmt.Sprint(meta["grant_types_supported"]), "urn:ietf:params:oauth:grant-type:device_code") {
		t.Fatalf("discovery: %v", meta)
	}
	if strings.Contains(fmt.Sprint(meta["grant_types_supported"]), "password") {
		t.Fatal("discovery advertises the password grant")
	}
}
