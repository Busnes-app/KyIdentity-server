package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

type fwdFixture struct {
	t      *testing.T
	srv    *Server
	db     *store.Store
	admin  string
	user   *store.User
	userSS string // KyIdentity login cookie with MFA evidence
	apps   map[string]fwdApp
	skew   time.Duration // added to the real clock the handler sees
}

type fwdApp struct {
	id, appID, secret string
}

func newFwdFixture(t *testing.T) *fwdFixture {
	t.Helper()
	srv, db, _, _, _, cleanup := setupTestServer(t)
	t.Cleanup(cleanup)
	f := &fwdFixture{t: t, srv: srv, db: db, apps: map[string]fwdApp{}}
	srv.forward.now = func() time.Time { return time.Now().Add(f.skew) }
	f.admin = newSession(t, db, newUser(t, db, "admin"), time.Now().UTC().Add(time.Hour))
	f.user = newUser(t, db, "user")
	f.userSS = f.loginSession(f.user, "totp", time.Now().UTC())
	for _, host := range []string{"app.example.test", "other.example.test"} {
		rr := adminRequest(t, srv, "POST", "/api/admin/proxy-apps", f.admin, `{"name":"App","host":"`+host+`","bypass":["/public"]}`)
		if rr.Code != http.StatusCreated {
			t.Fatalf("create proxy app: %d %s", rr.Code, rr.Body.String())
		}
		var out struct {
			ProxyApp   store.ProxyApp `json:"proxyApp"`
			EdgeSecret string         `json:"edgeSecret"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || len(out.EdgeSecret) != 64 {
			t.Fatalf("create response: %v %s", err, rr.Body.String())
		}
		p, _ := db.ProxyAppByHost(host)
		f.apps[host] = fwdApp{id: out.ProxyApp.ID, appID: p.AppID, secret: out.EdgeSecret}
		if err := db.SetAppAssignment(p.AppID, "users", f.user.ID, true, nil); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// loginSession is a KyIdentity browser session with password and, unless method is
// empty, second-factor evidence at the given time.
func (f *fwdFixture) loginSession(u *store.User, method string, at time.Time) string {
	f.t.Helper()
	raw, _ := crypto.GenerateRandomHex(32)
	s := &store.Session{ID: uuid.NewString(), UserID: u.ID, SessionTokenHash: crypto.HashSHA256(raw), IPAddress: "1.2.3.4", UserAgent: "t", ExpiresAt: time.Now().UTC().Add(time.Hour)}
	s.PrimaryAuthenticatedAt = &at
	if method != "" {
		s.FactorAuthenticatedAt, s.FactorMethod = &at, method
	}
	if err := f.db.CreateSession(s); err != nil {
		f.t.Fatal(err)
	}
	return raw
}

func (f *fwdFixture) edge(path, host, secret string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	f.t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	if host != "" {
		req.Header.Set("X-Forwarded-Host", host)
	}
	if secret != "" {
		req.Header.Set(edgeSecretHeader, secret)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	f.srv.httpServer.Handler.ServeHTTP(rr, req)
	return rr
}

func (f *fwdFixture) check(host, secret, uri string, cookie string) *httptest.ResponseRecorder {
	f.t.Helper()
	req := httptest.NewRequest("GET", "/api/forward/check", nil)
	req.Header.Set("X-Forwarded-Host", host)
	req.Header.Set(edgeSecretHeader, secret)
	req.Header.Set("X-Original-URI", uri)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: forwardCookie, Value: cookie})
	}
	rr := httptest.NewRecorder()
	f.srv.httpServer.Handler.ServeHTTP(rr, req)
	return rr
}

func (f *fwdFixture) start(rd, n, session string) *httptest.ResponseRecorder {
	f.t.Helper()
	q := url.Values{"rd": {rd}}
	if n != "" {
		q.Set("n", n)
	}
	req := httptest.NewRequest("GET", "/forward/start?"+q.Encode(), nil)
	if session != "" {
		req.AddCookie(&http.Cookie{Name: "kyidentity_session", Value: session})
	}
	rr := httptest.NewRecorder()
	f.srv.httpServer.Handler.ServeHTTP(rr, req)
	return rr
}

func cookieNamed(rr *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rr.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// begin returns the browser nonce and the start URL nginx's /.ky/start sends it to.
func (f *fwdFixture) begin(host, path string) (string, url.Values) {
	f.t.Helper()
	rr := f.edge("/forward/begin?rd="+url.QueryEscape(path), host, f.apps[host].secret)
	if rr.Code != http.StatusFound {
		f.t.Fatalf("begin: %d %s", rr.Code, rr.Body.String())
	}
	n := cookieNamed(rr, forwardNonceCookie)
	if n == nil || !n.Secure || !n.HttpOnly || n.Path != "/" || n.Domain != "" || n.SameSite != http.SameSiteLaxMode {
		f.t.Fatalf("nonce cookie %+v", n)
	}
	loc, _ := url.Parse(rr.Header().Get("Location"))
	if loc.Path != "/forward/start" {
		f.t.Fatalf("begin location %s", loc)
	}
	return n.Value, loc.Query()
}

// code runs begin and start for the fixture user and returns the nonce and code.
func (f *fwdFixture) code(host, path, session string) (string, string) {
	f.t.Helper()
	nonce, q := f.begin(host, path)
	rr := f.start(q.Get("rd"), q.Get("n"), session)
	if rr.Code != http.StatusFound {
		f.t.Fatalf("start: %d %s", rr.Code, rr.Body.String())
	}
	loc, _ := url.Parse(rr.Header().Get("Location"))
	if loc.Scheme != "https" || loc.Host != host || loc.Path != "/.ky/callback" {
		f.t.Fatalf("start location %s", loc)
	}
	return nonce, loc.Query().Get("code")
}

func (f *fwdFixture) callback(host, code, nonce string) *httptest.ResponseRecorder {
	f.t.Helper()
	var cookies []*http.Cookie
	if nonce != "" {
		cookies = append(cookies, &http.Cookie{Name: forwardNonceCookie, Value: nonce})
	}
	return f.edge("/forward/callback?code="+code, host, f.apps[host].secret, cookies...)
}

// signIn runs the whole flow and returns the forward cookie value.
func (f *fwdFixture) signIn(host, session string) string {
	f.t.Helper()
	nonce, code := f.code(host, "/dash?a=1&b=2", session)
	rr := f.callback(host, code, nonce)
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/dash?a=1&b=2" {
		f.t.Fatalf("callback: %d %s %s", rr.Code, rr.Header().Get("Location"), rr.Body.String())
	}
	c := cookieNamed(rr, forwardCookie)
	if c == nil || !c.Secure || !c.HttpOnly || c.Path != "/" || c.Domain != "" || c.SameSite != http.SameSiteLaxMode || c.MaxAge != store.DefaultForwardSession {
		f.t.Fatalf("forward cookie %+v", c)
	}
	return c.Value
}

const appHost, otherHost = "app.example.test", "other.example.test"

func TestForwardAuthFlow(t *testing.T) {
	f := newFwdFixture(t)
	cookie := f.signIn(appHost, f.userSS)
	rr := f.check(appHost, f.apps[appHost].secret, "/dash", cookie)
	if rr.Code != http.StatusOK || rr.Header().Get("X-Ky-User") != f.user.Username || rr.Header().Get("X-Ky-Email") != f.user.Email {
		t.Fatalf("check: %d %v", rr.Code, rr.Header())
	}
	// A cookie for one proxy host opens nothing on another.
	if rr := f.check(otherHost, f.apps[otherHost].secret, "/", cookie); rr.Code != http.StatusUnauthorized || rr.Header().Get("X-Ky-User") != "" {
		t.Fatalf("cookie replayed on another host: %d", rr.Code)
	}
	// Logout ends the session for this host.
	rr = f.edge("/forward/logout", appHost, f.apps[appHost].secret, &http.Cookie{Name: forwardCookie, Value: cookie})
	if rr.Code != http.StatusFound || cookieNamed(rr, forwardCookie).MaxAge >= 0 {
		t.Fatalf("logout: %d", rr.Code)
	}
	if rr := f.check(appHost, f.apps[appHost].secret, "/", cookie); rr.Code != http.StatusUnauthorized {
		t.Fatalf("check after logout: %d", rr.Code)
	}
}

func TestForwardLoginHeaderAndGroups(t *testing.T) {
	f := newFwdFixture(t)
	p, _ := f.db.ProxyAppByHost(appHost)
	rr := adminRequest(t, f.srv, "PUT", "/api/admin/proxy-apps/"+p.ID, f.admin, `{"host":"app.example.test","loginHeader":"X-WEBAUTH-USER"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rr.Code, rr.Body.String())
	}
	for _, name := range []string{"ops", "bad,name", "unassigned"} {
		g := &store.Group{ID: uuid.NewString(), Name: name}
		if err := f.db.CreateGroup(g, nil); err != nil {
			t.Fatal(err)
		}
		if err := f.db.SetGroupMembership(g.ID, f.user.ID, true, nil); err != nil {
			t.Fatal(err)
		}
		if name != "unassigned" {
			if err := f.db.SetAppAssignment(p.AppID, "groups", g.ID, true, nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	f.skew += 31 * time.Second // past the app cache
	cookie := f.signIn(appHost, f.userSS)
	rr = f.check(appHost, f.apps[appHost].secret, "/", cookie)
	if rr.Code != http.StatusOK || rr.Header().Get("X-Webauth-User") != f.user.Username || rr.Header().Get("X-Ky-User") != f.user.Username || rr.Header().Get("X-Ky-Groups") != "ops" {
		t.Fatalf("check: %d %v", rr.Code, rr.Header())
	}
}

func TestForwardEdgeSecret(t *testing.T) {
	f := newFwdFixture(t)
	cookie := f.signIn(appHost, f.userSS)
	for name, secret := range map[string]string{"missing": "", "wrong": strings.Repeat("a", 64), "other app's": f.apps[otherHost].secret} {
		if rr := f.check(appHost, secret, "/", cookie); rr.Code != http.StatusUnauthorized || rr.Header().Get("X-Ky-User") != "" {
			t.Errorf("%s secret: %d", name, rr.Code)
		}
		if rr := f.edge("/forward/begin", appHost, secret); rr.Code != http.StatusUnauthorized || rr.Header().Get("Location") != "" {
			t.Errorf("%s secret on begin: %d", name, rr.Code)
		}
	}
	if rr := f.check("unknown.example.test", f.apps[appHost].secret, "/", cookie); rr.Code != http.StatusUnauthorized {
		t.Errorf("unknown host: %d", rr.Code)
	}
	// Rotation: the old secret stops within the cache window, the new one works.
	p, _ := f.db.ProxyAppByHost(appHost)
	rr := adminRequest(t, f.srv, "POST", "/api/admin/proxy-apps/"+p.ID+"/secret", f.admin, "")
	var out struct{ EdgeSecret string }
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &out) != nil || len(out.EdgeSecret) != 64 {
		t.Fatalf("rotate: %d %s", rr.Code, rr.Body.String())
	}
	f.skew += 31 * time.Second
	if rr := f.check(appHost, f.apps[appHost].secret, "/", cookie); rr.Code != http.StatusUnauthorized {
		t.Errorf("old secret after rotation: %d", rr.Code)
	}
	if rr := f.check(appHost, out.EdgeSecret, "/", cookie); rr.Code != http.StatusOK {
		t.Errorf("new secret: %d", rr.Code)
	}
}

func TestForwardStartRefusesOpenRedirects(t *testing.T) {
	f := newFwdFixture(t)
	n := strings.Repeat("ab", 32)
	for _, rd := range []string{
		"https://evil.example.test/",
		"http://app.example.test/",
		"//app.example.test/",
		"/dash",
		"https://user@app.example.test/",
		"https://app.example.test@evil.example.test/",
		"https://app.example.test.evil.example.test/",
		"https://app.example.tes/",
		"https://APP.example.test/",
		"https://app.example.test:8443/",
		"https://app.example.test./",
		"https://app.example.test\\@evil.example.test/",
		"https://app.example.test/#frag",
		"https:app.example.test/",
		"https:///app.example.test/",
		"https://app.example.test//evil.example.test",
		"javascript:alert(1)",
		"",
	} {
		rr := f.start(rd, n, f.userSS)
		if rr.Code != http.StatusBadRequest || rr.Header().Get("Location") != "" {
			t.Errorf("rd %q: %d %s", rd, rr.Code, rr.Header().Get("Location"))
		}
	}
	// A valid rd without a nonce goes to the app host to get one, never elsewhere.
	rr := f.start("https://app.example.test/x", "", f.userSS)
	if loc := rr.Header().Get("Location"); rr.Code != http.StatusFound || !strings.HasPrefix(loc, "https://app.example.test/.ky/start?") {
		t.Fatalf("no nonce: %d %s", rr.Code, loc)
	}
	// Signed out: to the login page with a same-origin return path.
	rr = f.start("https://app.example.test/x?y=1&z=2", n, "")
	loc := rr.Header().Get("Location")
	if rr.Code != http.StatusFound || !strings.HasPrefix(loc, "/login?return_to=") {
		t.Fatalf("signed out: %d %s", rr.Code, loc)
	}
	u, _ := url.Parse(loc)
	once := u.Query().Get("return_to")
	inner, err := url.QueryUnescape(once) // what LoginView's second decode yields
	if err != nil || !strings.HasPrefix(inner, "/forward/start?") {
		t.Fatalf("return_to %q", inner)
	}
	back, _ := url.Parse(inner)
	if back.Query().Get("rd") != "https://app.example.test/x?y=1&z=2" || back.Query().Get("n") != n {
		t.Fatalf("return_to lost rd: %q", inner)
	}
}

func TestForwardCodeBinding(t *testing.T) {
	f := newFwdFixture(t)
	// Replay.
	nonce, code := f.code(appHost, "/", f.userSS)
	if rr := f.callback(appHost, code, nonce); rr.Code != http.StatusFound {
		t.Fatalf("first use: %d", rr.Code)
	}
	if rr := f.callback(appHost, code, nonce); rr.Code != http.StatusBadRequest || cookieNamed(rr, forwardCookie) != nil {
		t.Fatalf("replayed code: %d", rr.Code)
	}
	// Another host, even with that host's own secret.
	nonce, code = f.code(appHost, "/", f.userSS)
	if rr := f.callback(otherHost, code, nonce); rr.Code != http.StatusBadRequest || cookieNamed(rr, forwardCookie) != nil {
		t.Fatalf("code on another host: %d", rr.Code)
	}
	if rr := f.callback(appHost, code, nonce); rr.Code != http.StatusBadRequest {
		t.Fatalf("code refused once is spent: %d", rr.Code)
	}
	// Missing and foreign nonce (login CSRF).
	_, code = f.code(appHost, "/", f.userSS)
	if rr := f.callback(appHost, code, ""); rr.Code != http.StatusBadRequest || cookieNamed(rr, forwardCookie) != nil {
		t.Fatalf("code without nonce: %d", rr.Code)
	}
	_, code = f.code(appHost, "/", f.userSS)
	if rr := f.callback(appHost, code, strings.Repeat("c", 64)); rr.Code != http.StatusBadRequest || cookieNamed(rr, forwardCookie) != nil {
		t.Fatalf("code with another browser's nonce: %d", rr.Code)
	}
	// Expired.
	nonce, code = f.code(appHost, "/", f.userSS)
	raw, err := store.OpenRawForTest(f.srv.cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`UPDATE forward_codes SET expires_at=?`, time.Now().Add(-time.Second).Unix()); err != nil {
		t.Fatal(err)
	}
	if rr := f.callback(appHost, code, nonce); rr.Code != http.StatusBadRequest || cookieNamed(rr, forwardCookie) != nil {
		t.Fatalf("expired code: %d", rr.Code)
	}
	// Signing out of KyIdentity before redemption kills the code.
	nonce, code = f.code(appHost, "/", f.userSS)
	if err := f.db.RevokeUserAccess(f.user.ID, nil); err != nil {
		t.Fatal(err)
	}
	if rr := f.callback(appHost, code, nonce); rr.Code != http.StatusBadRequest {
		t.Fatalf("code after sign-out: %d", rr.Code)
	}
}

func TestForwardBypass(t *testing.T) {
	f := newFwdFixture(t)
	secret := f.apps[appHost].secret
	for _, uri := range []string{"/public", "/public/", "/public/a.css", "/public/x?y=1"} {
		if rr := f.check(appHost, secret, uri, ""); rr.Code != http.StatusOK || rr.Header().Get("X-Ky-User") != "" {
			t.Errorf("bypass %q: %d", uri, rr.Code)
		}
	}
	for _, uri := range []string{"/publicity", "/public/../admin", "/public/%2e%2e/admin", "/public%2F..%2Fadmin", "/public;/../admin", "//public/x", "/public\\..\\admin", "/PUBLIC/x", "/admin?/public", ""} {
		if rr := f.check(appHost, secret, uri, ""); rr.Code != http.StatusUnauthorized {
			t.Errorf("not a bypass %q: %d", uri, rr.Code)
		}
	}
	// A bypass never carries identity, even with a valid cookie.
	cookie := f.signIn(appHost, f.userSS)
	if rr := f.check(appHost, secret, "/public/x", cookie); rr.Code != http.StatusOK || rr.Header().Get("X-Ky-User") != "" {
		t.Errorf("bypass with cookie: %d %v", rr.Code, rr.Header())
	}
}

// Disabling or unassigning a user, or signing them out everywhere, takes effect within
// the 30-second cache.
func TestForwardRevocationWithin30Seconds(t *testing.T) {
	f := newFwdFixture(t)
	secret := f.apps[appHost].secret
	p, _ := f.db.ProxyAppByHost(appHost)
	cases := []struct {
		name   string
		revoke func(u *store.User)
		want   int
	}{
		{"disabled", func(u *store.User) {
			if _, err := f.db.EditUser(u.ID, nil, func(row *store.User) (bool, error) { row.Status = "disabled"; return false, nil }); err != nil {
				t.Fatal(err)
			}
		}, http.StatusUnauthorized},
		{"unassigned", func(u *store.User) {
			if err := f.db.SetAppAssignment(p.AppID, "users", u.ID, false, nil); err != nil {
				t.Fatal(err)
			}
		}, http.StatusForbidden},
		{"signed out everywhere", func(u *store.User) {
			if err := f.db.RevokeUserAccess(u.ID, nil); err != nil {
				t.Fatal(err)
			}
		}, http.StatusUnauthorized},
	}
	for _, c := range cases {
		u := newUser(t, f.db, "user")
		if err := f.db.SetAppAssignment(p.AppID, "users", u.ID, true, nil); err != nil {
			t.Fatal(err)
		}
		cookie := f.signIn(appHost, f.loginSession(u, "push", time.Now().UTC()))
		if rr := f.check(appHost, secret, "/", cookie); rr.Code != http.StatusOK {
			t.Fatalf("%s: before: %d", c.name, rr.Code)
		}
		c.revoke(u)
		f.skew += 29 * time.Second
		if rr := f.check(appHost, secret, "/", cookie); rr.Code != http.StatusOK {
			t.Fatalf("%s: cached answer: %d", c.name, rr.Code)
		}
		f.skew += 2 * time.Second
		if rr := f.check(appHost, secret, "/", cookie); rr.Code != c.want || rr.Header().Get("X-Ky-User") != "" {
			t.Fatalf("%s: after 31 s: %d, want %d", c.name, rr.Code, c.want)
		}
	}
}

func TestForwardMFAPolicy(t *testing.T) {
	f := newFwdFixture(t)
	// The default policy requires MFA: a password-only login gets an error page, no code.
	pwOnly := f.loginSession(f.user, "", time.Now().UTC())
	_, q := f.begin(appHost, "/")
	if rr := f.start(q.Get("rd"), q.Get("n"), pwOnly); rr.Code != http.StatusForbidden || rr.Header().Get("Location") != "" {
		t.Fatalf("password-only start: %d %s", rr.Code, rr.Header().Get("Location"))
	}
	// A factor age limit: a session whose factor is too old stops passing the check.
	recs, _, _ := f.db.ListAppRecords(f.apps[appHost].id, 1, 0)
	policy := `{"policy":{"mode":"reuse","factor":"mfa","factorMaxAge":3600},"revision":` + strconv.Itoa(recs[0].Revision) + `}`
	if rr := adminRequest(t, f.srv, "PUT", "/api/admin/app-registry/"+recs[0].ID+"/authentication-policy", f.admin, policy); rr.Code != http.StatusOK {
		t.Fatalf("set policy: %d %s", rr.Code, rr.Body.String())
	}
	stale := f.loginSession(f.user, "totp", time.Now().UTC().Add(-2*time.Hour))
	_, q = f.begin(appHost, "/")
	if rr := f.start(q.Get("rd"), q.Get("n"), stale); rr.Code != http.StatusForbidden {
		t.Fatalf("stale factor start: %d", rr.Code)
	}
	fresh := f.loginSession(f.user, "totp", time.Now().UTC().Add(-59*time.Minute))
	cookie := f.signIn(appHost, fresh)
	if rr := f.check(appHost, f.apps[appHost].secret, "/", cookie); rr.Code != http.StatusOK {
		t.Fatalf("fresh factor: %d", rr.Code)
	}
	// Fresh mode cannot be satisfied at the edge and is refused for proxy apps.
	recs, _, _ = f.db.ListAppRecords(f.apps[appHost].id, 1, 0)
	if rr := adminRequest(t, f.srv, "PUT", "/api/admin/app-registry/"+recs[0].ID+"/authentication-policy", f.admin, `{"policy":{"mode":"fresh","factor":"mfa"},"revision":`+strconv.Itoa(recs[0].Revision)+`}`); rr.Code == http.StatusOK {
		t.Fatal("fresh policy accepted for a proxy app")
	}
}

func TestForwardAdministratorIsNotExempt(t *testing.T) {
	f := newFwdFixture(t)
	admin := newUser(t, f.db, "admin")
	_, q := f.begin(appHost, "/")
	if rr := f.start(q.Get("rd"), q.Get("n"), f.loginSession(admin, "totp", time.Now().UTC())); rr.Code != http.StatusForbidden || rr.Header().Get("Location") != "" {
		t.Fatalf("unassigned administrator: %d", rr.Code)
	}
}

func TestProxyAppAdminValidation(t *testing.T) {
	f := newFwdFixture(t)
	for _, body := range []string{
		`{"name":"","host":"a.example.test"}`,
		`{"name":"x","host":"*.example.test"}`,
		`{"name":"x","host":"https://a.example.test"}`,
		`{"name":"x","host":"a.example.test:443"}`,
		`{"name":"x","host":"A.example.test"}`,
		`{"name":"x","host":"localhost"}`,
		`{"name":"x","host":"b.example.test","loginHeader":"Cookie"}`,
		`{"name":"x","host":"b.example.test","loginHeader":"X-Ky-Email"}`,
		`{"name":"x","host":"b.example.test","loginHeader":"X-Forwarded-User"}`,
		`{"name":"x","host":"b.example.test","loginHeader":"Bad Header"}`,
		`{"name":"x","host":"b.example.test","bypass":["/"]}`,
		`{"name":"x","host":"b.example.test","bypass":["public"]}`,
		`{"name":"x","host":"b.example.test","bypass":["/a/../b"]}`,
		`{"name":"x","host":"b.example.test","bypass":["/a%2f"]}`,
		`{"name":"x","host":"b.example.test","bypass":["/a/"]}`,
		`{"name":"x","host":"b.example.test","sessionSeconds":60}`,
		`{"name":"x","host":"app.example.test"}`,
	} {
		if rr := adminRequest(t, f.srv, "POST", "/api/admin/proxy-apps", f.admin, body); rr.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", body, rr.Code, rr.Body.String())
		}
	}
	if rr := adminRequestNoStepUp(t, f.srv, "POST", "/api/admin/proxy-apps", f.admin, `{"name":"x","host":"c.example.test"}`); rr.Code == http.StatusCreated {
		t.Fatal("created without step-up")
	}
	rr := adminRequestNoStepUp(t, f.srv, "GET", "/api/admin/proxy-apps", f.admin, "")
	if rr.Code != http.StatusOK || strings.Contains(rr.Body.String(), f.apps[appHost].secret) || strings.Contains(rr.Body.String(), crypto.HashSHA256(f.apps[appHost].secret)) {
		t.Fatalf("list leaks the secret or failed: %d", rr.Code)
	}
	// The card is a launcher app for assigned users only.
	apps, err := launcherApps(f.db, func(string) bool { return true }, nil)
	if err != nil || !hasLauncherURL(apps, "https://app.example.test/") {
		t.Fatalf("launcher card missing: %v", err)
	}
}

func hasLauncherURL(apps []store.Application, u string) bool {
	for _, a := range apps {
		if a.URL == u {
			return true
		}
	}
	return false
}

// enrollmentAdmin enrols a passkey for an administrator and gives them the recent login
// that activating a passkey-only policy requires.
func (f *fwdFixture) enrollmentAdmin() string {
	f.t.Helper()
	admin := newUser(f.t, f.db, "admin")
	enrolPasskey(f.t, f.db, admin.ID, newTestAuthenticator(f.t, "admin-key-"+admin.ID))
	now := time.Now().UTC()
	id := uuid.NewString()
	if err := f.db.CreateSession(&store.Session{ID: id, UserID: admin.ID, SessionTokenHash: id, ExpiresAt: now.Add(time.Hour), AuthenticationEvidence: store.AuthenticationEvidence{PrimaryAuthenticatedAt: &now, FactorAuthenticatedAt: &now, FactorMethod: "webauthn"}}); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func TestForwardEnrollmentPolicyEndsTOTPSession(t *testing.T) {
	f := newFwdFixture(t)
	secret := f.apps[appHost].secret
	if err := f.srv.mfaEngine.SaveUserTOTP(f.user.ID, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", nil); err != nil {
		t.Fatal(err)
	}
	cookie := f.signIn(appHost, f.userSS)
	if rr := f.check(appHost, secret, "/", cookie); rr.Code != http.StatusOK {
		t.Fatalf("before: %d", rr.Code)
	}
	if err := f.db.SetEnrollmentPolicy(store.EnrollmentPolicy{Scope: "organization", Required: true, AllowedMethods: []string{"webauthn"}, Revision: 1}, f.enrollmentAdmin(), nil); err != nil {
		t.Fatal(err)
	}
	f.skew += 31 * time.Second
	if rr := f.check(appHost, secret, "/", cookie); rr.Code != http.StatusUnauthorized || rr.Header().Get("X-Ky-User") != "" {
		t.Fatalf("TOTP forward session after passkey-only policy: %d", rr.Code)
	}
}

func TestForwardEnrollmentGraceDeadline(t *testing.T) {
	f := newFwdFixture(t)
	secret := f.apps[appHost].secret
	if err := f.srv.mfaEngine.SaveUserTOTP(f.user.ID, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", nil); err != nil {
		t.Fatal(err)
	}
	if err := f.db.SetEnrollmentPolicy(store.EnrollmentPolicy{Scope: "organization", Required: true, AllowedMethods: []string{"webauthn"}, GraceSeconds: 120, Revision: 1}, f.enrollmentAdmin(), nil); err != nil {
		t.Fatal(err)
	}
	// Inside the grace period the TOTP login is still unrestricted.
	cookie := f.signIn(appHost, f.loginSession(f.user, "totp", time.Now().UTC()))
	if rr := f.check(appHost, secret, "/", cookie); rr.Code != http.StatusOK {
		t.Fatalf("within grace: %d", rr.Code)
	}
	f.skew += 121 * time.Second
	if rr := f.check(appHost, secret, "/", cookie); rr.Code != http.StatusUnauthorized {
		t.Fatalf("after grace deadline: %d", rr.Code)
	}
}

func TestForwardRevokeOtherSessionsAfterLoginPurged(t *testing.T) {
	f := newFwdFixture(t)
	secret := f.apps[appHost].secret
	cookie := f.signIn(appHost, f.userSS)
	old, err := f.db.GetSessionByTokenHash(crypto.HashSHA256(f.userSS), time.Hour)
	if err != nil || old == nil {
		t.Fatalf("login session: %v", err)
	}
	if err := f.db.DeleteSession(old.ID); err != nil {
		t.Fatal(err)
	}
	if rr := f.check(appHost, secret, "/", cookie); rr.Code != http.StatusOK {
		t.Fatalf("forward session should outlive its login row: %d", rr.Code)
	}
	current, err := f.db.GetSessionByTokenHash(crypto.HashSHA256(f.loginSession(f.user, "totp", time.Now().UTC())), time.Hour)
	if err != nil || current == nil {
		t.Fatalf("current session: %v", err)
	}
	if err := f.db.RevokeOtherSessions(f.user.ID, current.ID, nil); err != nil {
		t.Fatal(err)
	}
	f.skew += 31 * time.Second
	if rr := f.check(appHost, secret, "/", cookie); rr.Code != http.StatusUnauthorized {
		t.Fatalf("after sign out other sessions: %d", rr.Code)
	}
}
