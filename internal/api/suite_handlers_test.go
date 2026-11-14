package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// createClient registers an OAuth client with the given type and launch URL; access stays
// at the registry default (assigned only).
func createClient(t *testing.T, db *store.Store, id, clientType, secretHash, launchURL string, uris ...string) {
	t.Helper()
	u, _ := json.Marshal(uris)
	if err := db.CreateOAuthClient(&store.OAuthClient{
		ID: id, ClientName: id, ClientType: clientType, ClientSecretHash: secretHash, LaunchURL: launchURL,
		RedirectURIsJSON: string(u), AllowedScopesJSON: `["openid"]`, Enabled: true,
	}, nil); err != nil {
		t.Fatalf("CreateOAuthClient %s: %v", id, err)
	}
}

// The launcher and the suite directory share launch-URL resolution; this pins what the
// launcher showed before the two were split apart.
func TestLauncherLaunchURLResolution(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	user := newUser(t, db, "user")
	cookie := newSession(t, db, user, time.Now().UTC().Add(time.Hour))

	createClient(t, db, "kypost", "public", "", "", "https://mail.example.test/cb")
	createClient(t, db, "KyNotes", "public", "", "", "http://localhost:3000/cb", "https://notes.example.test/cb")
	createClient(t, db, "explicit", "public", "", "https://explicit.example.test/start", "https://other.example.test/cb")
	createClient(t, db, "native", "public", "", "", "com.example.app:/cb")
	createClient(t, db, "plain", "public", "", "", "https://plain.example.test/cb")
	createClient(t, db, "nothing", "public", "", "")
	if err := db.CreateApplication(&store.Application{ID: "wiki", Name: "Wiki", URL: "https://wiki.example.test", IconName: "globe", SortOrder: -1, Enabled: true}, nil); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"kypost", "KyNotes", "explicit", "native", "plain", "nothing", "wiki"} {
		allowTestAppAccess(t, db, id)
	}

	var got []string
	for _, c := range launcherCards(t, srv, cookie) {
		got = append(got, fmt.Sprintf("%s %s %s %d", c.Key, c.Name, c.URL, c.SortOrder))
	}
	want := []string{
		"custom:wiki Wiki https://wiki.example.test -1",
		"client:KyNotes KyNotes https://notes.example.test/api/auth/oidc/login 0",
		"client:explicit explicit https://explicit.example.test/start 0",
		"client:kypost kypost https://mail.example.test/api/auth/oidc/login 0",
		"client:native native com.example.app:/cb 0",
		"client:plain plain https://plain.example.test 0",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("launcher cards\n got %q\nwant %q", got, want)
	}
}

func suiteGet(t *testing.T, srv *Server, path, id, secret string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	if id != "" {
		req.SetBasicAuth(id, secret)
	}
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("%s Cache-Control = %q, want no-store", path, got)
	}
	return rr
}

func assignApp(t *testing.T, db *store.Store, id, userID string) {
	t.Helper()
	recs, _, err := db.ListAppRecords(id, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range recs {
		if a.ClientID == id {
			if err := db.SetAppAssignment(a.ID, "users", userID, true, nil); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatalf("no app record for %s", id)
}

// suiteFixture: confidential kycalendar and kypost, a public client, a disabled
// confidential client, a loopback dev app, a native app and a custom card.
func suiteFixture(t *testing.T) (*Server, *store.Store, func()) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	createClient(t, db, "kycalendar", "confidential", crypto.HashSHA256("cal-secret"), "", "https://cal.example.test/cb")
	createClient(t, db, "kypost", "confidential", crypto.HashSHA256("post-secret"), "", "https://mail.example.test/cb")
	createClient(t, db, "pub", "public", "", "", "https://pub.example.test/cb")
	createClient(t, db, "devapp", "public", "", "", "http://localhost:8080/cb")
	createClient(t, db, "native", "public", "", "", "com.example.app:/cb")
	if err := db.CreateOAuthClient(&store.OAuthClient{ID: "off", ClientName: "off", ClientType: "confidential",
		ClientSecretHash: crypto.HashSHA256("off-secret"), RedirectURIsJSON: `["https://off.example.test/cb"]`,
		AllowedScopesJSON: `["openid"]`, Enabled: false}, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateApplication(&store.Application{ID: "wiki", Name: "Wiki", URL: "https://wiki.example.test", IconName: "globe", Enabled: true}, nil); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"devapp", "native", "wiki"} {
		allowTestAppAccess(t, db, id)
	}
	return srv, db, cleanup
}

func TestSuiteAuthFailuresAreUniform(t *testing.T) {
	srv, _, cleanup := suiteFixture(t)
	defer cleanup()
	for _, path := range []string{"/api/suite/apps", "/api/suite/peer?client=kypost", "/api/suite/people?sub=x&q=ab"} {
		for name, cred := range map[string][2]string{
			"none":            {"", ""},
			"wrong secret":    {"kycalendar", "post-secret"},
			"empty secret":    {"kycalendar", ""},
			"unknown client":  {"nobody", "cal-secret"},
			"public client":   {"pub", ""},
			"disabled client": {"off", "off-secret"},
		} {
			rr := suiteGet(t, srv, path, cred[0], cred[1])
			if rr.Code != http.StatusUnauthorized || strings.TrimSpace(rr.Body.String()) != `{"error":"invalid_client"}` {
				t.Errorf("%s %s: %d %s, want 401 invalid_client", path, name, rr.Code, rr.Body.String())
			}
		}
	}
	if rr := suiteGet(t, srv, "/api/suite/apps", "kycalendar", "cal-secret"); rr.Code != http.StatusOK {
		t.Fatalf("valid credentials: %d %s", rr.Code, rr.Body.String())
	}
}

func suiteApps(t *testing.T, srv *Server, query, id, secret string) []string {
	t.Helper()
	rr := suiteGet(t, srv, "/api/suite/apps"+query, id, secret)
	if rr.Code != http.StatusOK {
		t.Fatalf("apps%s: %d %s", query, rr.Code, rr.Body.String())
	}
	var resp struct {
		Apps []suiteApp `json:"apps"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil || resp.Apps == nil {
		t.Fatalf("apps%s body %s: %v", query, rr.Body.String(), err)
	}
	out := []string{}
	for _, a := range resp.Apps {
		out = append(out, a.ID+" "+a.URL)
	}
	return out
}

func TestSuiteAppsFiltersPerUser(t *testing.T) {
	srv, db, cleanup := suiteFixture(t)
	defer cleanup()
	both := newUser(t, db, "user")
	postOnly := newUser(t, db, "user")
	assignApp(t, db, "kycalendar", both.ID)
	assignApp(t, db, "kypost", both.ID)
	assignApp(t, db, "kypost", postOnly.ID)

	cases := []struct {
		name, caller, secret, query string
		want                        []string
	}{
		{"user with both", "kycalendar", "cal-secret", "?sub=" + both.ID, []string{
			"devapp http://localhost:8080",
			"kycalendar https://cal.example.test/api/sso/kysignon/login",
			"kypost https://mail.example.test/api/auth/oidc/login",
		}},
		{"user lacks the caller", "kycalendar", "cal-secret", "?sub=" + postOnly.ID, []string{}},
		{"user has the caller", "kypost", "post-secret", "?sub=" + postOnly.ID, []string{
			"devapp http://localhost:8080",
			"kypost https://mail.example.test/api/auth/oidc/login",
		}},
		{"unknown user", "kypost", "post-secret", "?sub=nobody", []string{}},
		{"empty sub", "kypost", "post-secret", "?sub=", []string{}},
		{"no sub", "kypost", "post-secret", "", []string{
			"devapp http://localhost:8080",
			"kycalendar https://cal.example.test/api/sso/kysignon/login",
			"kypost https://mail.example.test/api/auth/oidc/login",
			"pub https://pub.example.test",
		}},
	}
	for _, c := range cases {
		if got := suiteApps(t, srv, c.query, c.caller, c.secret); fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}

	// A disabled user sees nothing, and an app whose access policy is off leaves the
	// no-sub list.
	if _, err := db.EditUser(both.ID, nil, func(row *store.User) (bool, error) { row.Status = "disabled"; return false, nil }); err != nil {
		t.Fatal(err)
	}
	if got := suiteApps(t, srv, "?sub="+both.ID, "kycalendar", "cal-secret"); len(got) != 0 {
		t.Errorf("disabled user sees %q", got)
	}
	recs, _, _ := db.ListAppRecords("pub", 100, 0)
	for _, a := range recs {
		if a.ClientID == "pub" {
			if err := db.SetAppPolicy(a.ID, a.AccessMode, false, a.Revision, nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, app := range suiteApps(t, srv, "", "kypost", "post-secret") {
		if strings.HasPrefix(app, "pub ") {
			t.Error("app with access policy off is still listed")
		}
	}
}

func suitePeer(t *testing.T, srv *Server, id, secret, peer string) (int, map[string]string) {
	t.Helper()
	rr := suiteGet(t, srv, "/api/suite/peer?client="+peer, id, secret)
	var body map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	return rr.Code, body
}

func TestSuitePeerSharedSecret(t *testing.T) {
	srv, db, cleanup := suiteFixture(t)
	defer cleanup()

	code, cal := suitePeer(t, srv, "kycalendar", "cal-secret", "kypost")
	if code != http.StatusOK || cal["client"] != "kypost" || cal["url"] != "https://mail.example.test" {
		t.Fatalf("calendar->post: %d %v", code, cal)
	}
	code, post := suitePeer(t, srv, "kypost", "post-secret", "kycalendar")
	if code != http.StatusOK || post["client"] != "kycalendar" || post["url"] != "https://cal.example.test" {
		t.Fatalf("post->calendar: %d %v", code, post)
	}
	if cal["secret"] == "" || cal["secret"] != post["secret"] {
		t.Fatalf("the two sides got different secrets")
	}
	raw, err := base64.StdEncoding.DecodeString(cal["secret"])
	if err != nil || len(raw) != 32 {
		t.Fatalf("secret is not 32 bytes of std base64: %v", err)
	}
	key := srv.cfg.EncryptionKey
	want := base64.StdEncoding.EncodeToString(crypto.DeriveKey(key, "kyidentity:suite-peer:v1:kycalendar|kypost"))
	if cal["secret"] != want {
		t.Fatal("secret is not the documented derivation")
	}
	if suitePeerSecret(key, "kycalendar", "kydrive") == want || suitePeerSecret(key, "kypost", "kydrive") == want {
		t.Fatal("different pairs share a secret")
	}
	if other, _ := crypto.GenerateRandomBytes(32); suitePeerSecret(other, "kycalendar", "kypost") == want {
		t.Fatal("secret does not depend on the encryption key")
	}

	events, _, err := db.ListAuditEvents(100, 0)
	if err != nil {
		t.Fatal(err)
	}
	issued := 0
	for _, e := range events {
		if strings.Contains(e.DetailsJSON, cal["secret"]) {
			t.Fatalf("audit %s logs the secret", e.Action)
		}
		if e.Action == "suite.peer.issue" {
			issued++
			if !strings.Contains(e.DetailsJSON, `"peer"`) || !strings.Contains(e.DetailsJSON, `"client"`) {
				t.Errorf("audit details %s lack caller or peer", e.DetailsJSON)
			}
		}
	}
	if issued != 2 {
		t.Fatalf("suite.peer.issue audited %d times, want 2", issued)
	}
}

func TestSuitePeerRefusals(t *testing.T) {
	srv, db, cleanup := suiteFixture(t)
	defer cleanup()
	// A registration differing only in case is another client, outside the allowlist.
	createClient(t, db, "KyCalendar", "confidential", crypto.HashSHA256("case-secret"), "", "https://evil.example.test/cb")
	if code, body := suitePeer(t, srv, "KyCalendar", "case-secret", "kypost"); code != http.StatusNotFound || body["secret"] != "" {
		t.Errorf("case-distinct caller: %d %v, want 404 without a secret", code, body)
	}
	for _, peer := range []string{"", "pub", "kycalendar", "devapp", "nobody", "KyPost", "kydrive", "kymessage", "KyMessage"} {
		if code, body := suitePeer(t, srv, "kycalendar", "cal-secret", peer); code != http.StatusNotFound || body["error"] != "no_peer" {
			t.Errorf("peer %q: %d %v, want 404 no_peer", peer, code, body)
		}
	}

	post, err := db.GetOAuthClientByID("kypost")
	if err != nil {
		t.Fatal(err)
	}
	post.RedirectURIsJSON = `["com.example.mail:/cb"]`
	if err := db.UpdateOAuthClient(post); err != nil {
		t.Fatal(err)
	}
	if code, _ := suitePeer(t, srv, "kycalendar", "cal-secret", "kypost"); code != http.StatusNotFound {
		t.Errorf("peer without an HTTPS origin: %d, want 404", code)
	}
	post.RedirectURIsJSON = `["http://mail.example.test/cb"]`
	if err := db.UpdateOAuthClient(post); err != nil {
		t.Fatal(err)
	}
	if code, _ := suitePeer(t, srv, "kycalendar", "cal-secret", "kypost"); code != http.StatusNotFound {
		t.Errorf("peer with a plain HTTP origin: %d, want 404", code)
	}
	post.RedirectURIsJSON = `["https://mail.example.test/cb"]`
	post.Enabled = false
	if err := db.UpdateOAuthClient(post); err != nil {
		t.Fatal(err)
	}
	if code, _ := suitePeer(t, srv, "kycalendar", "cal-secret", "kypost"); code != http.StatusNotFound {
		t.Errorf("disabled peer: %d, want 404", code)
	}
	if events, _, _ := db.ListAuditEvents(100, 0); len(events) > 0 {
		for _, e := range events {
			if e.Action == "suite.peer.issue" {
				t.Fatal("a refused peer request was audited as issued")
			}
		}
	}
}

func TestSuiteRateLimitedPerClient(t *testing.T) {
	srv, _, cleanup := suiteFixture(t)
	defer cleanup()
	// A fresh source address per request, so only the per-client bucket can trip.
	limited := false
	for i := 0; i < 200 && !limited; i++ {
		req := httptest.NewRequest("GET", "/api/suite/apps", nil)
		req.RemoteAddr = fmt.Sprintf("198.51.100.%d:1234", i)
		req.SetBasicAuth("kycalendar", "cal-secret")
		rr := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rr, req)
		limited = rr.Code == http.StatusTooManyRequests
	}
	if !limited {
		t.Fatal("one client across many addresses was never rate limited")
	}
	if rr := suiteGet(t, srv, "/api/suite/apps", "kypost", "post-secret"); rr.Code != http.StatusOK {
		t.Fatalf("another client was limited too: %d", rr.Code)
	}
}

// The KyMessages case: everyday users see one "KyMessages" card opening the chat client and
// no console card, the console card stays for administrators, and hiding a card leaves
// access alone. The launcher and the suite directory agree.
func TestLauncherNameAndAudience(t *testing.T) {
	srv, db, cleanup := suiteFixture(t)
	defer cleanup()
	newClient(t, db, "kymessage", []string{covRedirect}, []string{"openid"})
	createClient(t, db, "kymessage-chat", "public", "", "https://chat.example.test/", "https://chat-auth.example.test/cb")
	allowTestAppAccess(t, db, "kymessage-chat")
	allowTestAppAccess(t, db, "kypost")
	admin := newUser(t, db, "admin")
	everyday := newUser(t, db, "user")
	adminCookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	everydayCookie := newSession(t, db, everyday, time.Now().UTC().Add(time.Hour))

	for _, c := range []struct{ id, body string }{
		{"kymessage", `{"launcherAudience":"admins"}`},
		{"kymessage-chat", `{"launcherName":"KyMessages"}`},
	} {
		if rr := adminRequestNoStepUp(t, srv, "PUT", "/api/admin/clients/"+c.id+"/launcher", adminCookie, c.body); rr.Code != http.StatusOK {
			t.Fatalf("launcher edit %s: %d %s", c.id, rr.Code, rr.Body.String())
		}
	}

	names := func(cards []store.Application) map[string]string {
		out := map[string]string{}
		for _, c := range cards {
			out[c.ID] = c.Name
		}
		return out
	}
	if got := names(launcherCards(t, srv, everydayCookie)); got["kymessage-chat"] != "KyMessages" || got["kymessage"] != "" {
		t.Fatalf("everyday launcher %v", got)
	}
	// No administrator roles on the console, so KyIdentity administrators count.
	if got := names(launcherCards(t, srv, adminCookie)); got["kymessage"] != "kymessage" || got["kymessage-chat"] != "KyMessages" {
		t.Fatalf("admin launcher %v", got)
	}

	suiteNames := func(query string) map[string]string {
		rr := suiteGet(t, srv, "/api/suite/apps"+query, "kypost", "post-secret")
		var resp struct {
			Apps []suiteApp `json:"apps"`
		}
		if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &resp) != nil {
			t.Fatalf("suite apps%s: %d %s", query, rr.Code, rr.Body.String())
		}
		out := map[string]string{}
		for _, a := range resp.Apps {
			out[a.ID] = a.Name
		}
		return out
	}
	if got := suiteNames("?sub=" + everyday.ID); got["kymessage-chat"] != "KyMessages" || got["kymessage"] != "" {
		t.Fatalf("suite everyday %v", got)
	}
	if got := suiteNames("?sub=" + admin.ID); got["kymessage"] == "" {
		t.Fatalf("suite admin %v", got)
	}
	if got := suiteNames(""); got["kymessage"] != "" || got["kymessage-chat"] != "KyMessages" {
		t.Fatalf("suite without a user lists an admins-only card: %v", got)
	}

	// Hidden is not denied: the everyday user still signs in to the console.
	rr := covAuthorize(t, srv, everydayCookie, covAuthorizeQuery("kymessage").Encode())
	loc, _ := url.Parse(rr.Header().Get("Location"))
	if rr.Code != http.StatusFound || loc == nil || loc.Query().Get("code") == "" {
		t.Fatalf("hidden card blocked sign-in: %d %q", rr.Code, rr.Header().Get("Location"))
	}
}

func TestClientLauncherEditNameAndAudience(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	newClient(t, db, "kydns", []string{"https://dns.example.test/cb"}, []string{"openid"})
	put := func(body string) int {
		return adminRequestNoStepUp(t, srv, "PUT", "/api/admin/clients/kydns/launcher", cookie, body).Code
	}
	if code := put(`{"description":"DNS","iconName":"globe","launcherName":"Name server","launcherAudience":"admins"}`); code != http.StatusOK {
		t.Fatalf("full edit %d", code)
	}
	// Omitted fields keep their values.
	if code := put(`{"launcherAudience":"everyone"}`); code != http.StatusOK {
		t.Fatalf("audience edit %d", code)
	}
	c, _ := db.GetOAuthClientByID("kydns")
	if c.Description != "DNS" || c.IconName != "globe" || c.LauncherName != "Name server" || c.LauncherAudience != "everyone" {
		t.Fatalf("client after partial edit %+v", c)
	}
	for _, bad := range []string{`{"launcherAudience":"staff"}`, `{"launcherName":"a\u0007b"}`, `{"launcherName":"` + strings.Repeat("x", 129) + `"}`} {
		if code := put(bad); code != http.StatusBadRequest {
			t.Errorf("%s returned %d, want 400", bad, code)
		}
	}
	// An empty name clears it back to the client name.
	if code := put(`{"launcherName":"  "}`); code != http.StatusOK {
		t.Fatalf("clear %d", code)
	}
	if card := cardByID(launcherCards(t, srv, cookie), "kydns"); card == nil || card.Name != "kydns" {
		t.Fatalf("cleared name card %+v", card)
	}
	if n := covAuditOutcomes(t, db, "admin.client_launcher_updated")["success"]; n != 3 {
		t.Fatalf("launcher edits audited %d times, want 3", n)
	}
}

func TestSuitePeerNewPairs(t *testing.T) {
	srv, db, cleanup := suiteFixture(t)
	defer cleanup()
	createClient(t, db, "kydrive", "confidential", crypto.HashSHA256("drive-secret"), "", "https://drive.example.test/cb")
	createClient(t, db, "kymessage", "confidential", crypto.HashSHA256("msg-secret"), "", "https://console.example.test/cb")
	creds := map[string]string{"kycalendar": "cal-secret", "kypost": "post-secret", "kydrive": "drive-secret", "kymessage": "msg-secret"}
	origin := map[string]string{"kycalendar": "https://cal.example.test", "kypost": "https://mail.example.test",
		"kydrive": "https://drive.example.test", "kymessage": "https://console.example.test"}
	key := srv.cfg.EncryptionKey
	for _, pair := range [][2]string{{"kycalendar", "kymessage"}, {"kydrive", "kypost"}, {"kycalendar", "kypost"}} {
		want := suitePeerSecret(key, pair[0], pair[1])
		for _, d := range [][2]string{pair, {pair[1], pair[0]}} {
			code, body := suitePeer(t, srv, d[0], creds[d[0]], d[1])
			if code != http.StatusOK || body["client"] != d[1] || body["url"] != origin[d[1]] || body["secret"] != want {
				t.Errorf("%s->%s: %d %v", d[0], d[1], code, body)
			}
		}
	}
	// Still unknown, though every client is registered.
	for _, d := range [][2]string{{"kycalendar", "kydrive"}, {"kydrive", "kymessage"}, {"kymessage", "kypost"}, {"kydrive", "kydrive"}} {
		for _, dir := range [][2]string{d, {d[1], d[0]}} {
			if code, body := suitePeer(t, srv, dir[0], creds[dir[0]], dir[1]); code != http.StatusNotFound || body["error"] != "no_peer" || body["secret"] != "" {
				t.Errorf("%s->%s: %d %v, want 404 no_peer", dir[0], dir[1], code, body)
			}
		}
	}
}

// person creates an active user with the given name, username and email.
func person(t *testing.T, db *store.Store, role, name, username, email string) *store.User {
	t.Helper()
	u := newUser(t, db, role)
	if _, err := db.EditUser(u.ID, nil, func(row *store.User) (bool, error) {
		row.DisplayName, row.Username, row.Email = name, username, email
		return false, nil
	}); err != nil {
		t.Fatal(err)
	}
	return u
}

func suitePeople(t *testing.T, srv *Server, query string) (int, []string) {
	t.Helper()
	rr := suiteGet(t, srv, "/api/suite/people?"+query, "kycalendar", "cal-secret")
	if rr.Code != http.StatusOK {
		return rr.Code, []string{strings.TrimSpace(rr.Body.String())}
	}
	var resp struct {
		People []suitePerson `json:"people"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil || resp.People == nil {
		t.Fatalf("people?%s body %s: %v", query, rr.Body.String(), err)
	}
	out := []string{}
	for _, p := range resp.People {
		out = append(out, p.Name+" <"+p.Email+">")
	}
	return rr.Code, out
}

func TestSuitePeople(t *testing.T) {
	srv, db, cleanup := suiteFixture(t)
	defer cleanup()
	me := person(t, db, "user", "Me Myself", "me", "me@example.test")
	alice := person(t, db, "user", "Alice Example", "alice", "alice@example.test")
	bob := person(t, db, "user", "Bob Stone", "bstone", "robert@example.test")
	noName := person(t, db, "user", "", "carl", "carl@example.test")
	postOnly := person(t, db, "user", "Alina Post", "alina", "alina@example.test")
	gone := person(t, db, "user", "Alix Gone", "alix", "alix@example.test")
	admin := person(t, db, "admin", "Alice Admin", "aliceadmin", "admin@example.test")
	for _, u := range []*store.User{me, alice, bob, noName, gone, admin} {
		assignApp(t, db, "kycalendar", u.ID)
	}
	assignApp(t, db, "kypost", postOnly.ID)
	if _, err := db.EditUser(gone.ID, nil, func(row *store.User) (bool, error) { row.Status = "disabled"; return false, nil }); err != nil {
		t.Fatal(err)
	}
	s := "sub=" + url.QueryEscape(me.ID)

	for _, c := range []struct {
		query string
		want  []string
	}{
		{s + "&q=ali", []string{"Alice Example <alice@example.test>"}},
		{s + "&q=ALI", []string{"Alice Example <alice@example.test>"}},
		{s + "&q=exa", []string{"Alice Example <alice@example.test>"}},
		{s + "&q=lice", []string{}},
		{s + "&q=bst", []string{"Bob Stone <robert@example.test>"}},
		{s + "&q=rob", []string{"Bob Stone <robert@example.test>"}},
		{s + "&q=carl", []string{"carl <carl@example.test>"}},
		{s + "&q=alice%40example", []string{"Alice Example <alice@example.test>"}},
		{s + "&q=" + url.QueryEscape("a%"), []string{}},
		{s + "&q=" + url.QueryEscape("_l"), []string{}},
		{s + "&q=" + url.QueryEscape("%%"), []string{}},
		{s + "&email=ALICE%40example.test&email=nobody%40example.test&email=alina%40example.test&email=admin%40example.test&email=alix%40example.test&email=robert%40example.test",
			[]string{"Alice Example <alice@example.test>", "Bob Stone <robert@example.test>"}},
		{s + "&email=alice%40example", []string{}},
		{s + "&email=" + url.QueryEscape("alice@example.tes_"), []string{}},
		// The user the caller acts for must be an active everyday user of the caller.
		{"sub=" + postOnly.ID + "&q=ali", []string{}},
		{"sub=" + admin.ID + "&q=ali", []string{}},
		{"sub=" + gone.ID + "&q=ali", []string{}},
		{"sub=nobody&q=ali", []string{}},
	} {
		if code, got := suitePeople(t, srv, c.query); code != http.StatusOK || fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("%s:\n got %d %q\nwant %q", c.query, code, got, c.want)
		}
	}

	// Result caps: default 10, at most 20.
	for i := 0; i < 25; i++ {
		u := person(t, db, "user", fmt.Sprintf("Zed %02d", i), fmt.Sprintf("zed%02d", i), fmt.Sprintf("zed%02d@example.test", i))
		assignApp(t, db, "kycalendar", u.ID)
	}
	for limit, want := range map[string]int{"": 10, "&limit=1": 1, "&limit=20": 20} {
		if _, got := suitePeople(t, srv, s+"&q=zed"+limit); len(got) != want || got[0] != "Zed 00 <zed00@example.test>" {
			t.Errorf("limit %q: %d people, want %d", limit, len(got), want)
		}
	}
	many := s
	for i := 0; i < 100; i++ {
		many += fmt.Sprintf("&email=zed%02d%%40example.test", i)
	}
	if _, got := suitePeople(t, srv, many); len(got) != 25 {
		t.Errorf("100 addresses resolved %d people, want 25", len(got))
	}

	for _, bad := range []string{
		"q=ali", "sub=&q=ali", s, s + "&q=ali&email=alice%40example.test", s + "&q=a", s + "&q=",
		s + "&q=" + strings.Repeat("a", 65), s + "&q=%ff%fe", s + "&q=ali&limit=0", s + "&q=ali&limit=21",
		s + "&q=ali&limit=x", s + "&q=ali&limit=", s + "&email=", s + "&email=alice%40example.test&limit=5",
		s + "&email=" + strings.Repeat("a", 250) + "%40x.test", many + "&email=one%40more.test",
	} {
		if code, got := suitePeople(t, srv, bad); code != http.StatusBadRequest || got[0] != `{"error":"invalid_request"}` {
			t.Errorf("%.80s: %d %q, want 400 invalid_request", bad, code, got)
		}
	}
	if code, got := suitePeople(t, srv, s+"&q="+url.QueryEscape(strings.Repeat("é", 64))); code != http.StatusOK || len(got) != 0 {
		t.Errorf("64 two-byte characters: %d %q", code, got)
	}

	for name, cred := range map[string][2]string{"none": {"", ""}, "wrong": {"kycalendar", "post-secret"}, "public": {"pub", ""}, "disabled": {"off", "off-secret"}} {
		rr := suiteGet(t, srv, "/api/suite/people?"+s+"&q=ali", cred[0], cred[1])
		if rr.Code != http.StatusUnauthorized || strings.TrimSpace(rr.Body.String()) != `{"error":"invalid_client"}` {
			t.Errorf("%s credentials: %d %s", name, rr.Code, rr.Body.String())
		}
	}
	// Another caller sees only its own users.
	rr := suiteGet(t, srv, "/api/suite/people?sub="+postOnly.ID+"&q=ali", "kypost", "post-secret")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "alina@example.test") || strings.Contains(rr.Body.String(), "alice@") {
		t.Errorf("kypost caller: %d %s", rr.Code, rr.Body.String())
	}
}

func TestSuitePeopleRateLimitedPerClient(t *testing.T) {
	srv, _, cleanup := suiteFixture(t)
	defer cleanup()
	limited := false
	for i := 0; i < 200 && !limited; i++ {
		req := httptest.NewRequest("GET", "/api/suite/people?sub=x&q=ab", nil)
		req.RemoteAddr = fmt.Sprintf("198.51.100.%d:1234", i)
		req.SetBasicAuth("kycalendar", "cal-secret")
		rr := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rr, req)
		limited = rr.Code == http.StatusTooManyRequests
	}
	if !limited {
		t.Fatal("people was never rate limited per client")
	}
}
