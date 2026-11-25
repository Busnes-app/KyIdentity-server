package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/config"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// platformSuite is a multi-tenant server with its platform handler, a billing token
// (orgs:*), a portal token (members:*) and a mail sink.
type platformSuite struct {
	t       *testing.T
	srv     *Server
	db      *store.Store
	h       http.Handler
	billing string
	portal  string
	mu      sync.Mutex
	mail    []sentMail
	noMail  bool
	remote  string // the caller's address, when set
}

type sentMail struct{ to, subject, body string }

func newPlatformSuite(t *testing.T) *platformSuite {
	t.Helper()
	srv, db, _, _, _, cleanup := setupTestServerWith(t, func(c *config.Config) { c.Tenancy = "multi" })
	t.Cleanup(cleanup)
	ps := &platformSuite{t: t, srv: srv, db: db}
	api := newPlatformAPI(srv)
	api.mailer = func() (func(to, subject, body string) error, error) {
		if ps.noMail {
			return nil, nil
		}
		return func(to, subject, body string) error {
			ps.mu.Lock()
			defer ps.mu.Unlock()
			ps.mail = append(ps.mail, sentMail{to, subject, body})
			return nil
		}, nil
	}
	ps.h = api.routes()
	ps.billing = ps.token(store.ScopeOrgsRead, store.ScopeOrgsWrite, store.ScopeOrgsDelete)
	ps.portal = ps.token(store.ScopeMembersRead, store.ScopeMembersWrite)
	if _, _, err := db.SetSuiteEmailDomains([]string{"mail.example.test"}, &store.AuditEvent{ID: "domains", Action: "test", Outcome: "success"}); err != nil {
		t.Fatal(err)
	}
	return ps
}

func (ps *platformSuite) token(scopes ...string) string {
	raw, _, err := ps.db.Platform().CreatePlatformToken("test "+strings.Join(scopes, " "), scopes, time.Hour, nil)
	if err != nil {
		ps.t.Fatal(err)
	}
	return raw
}

// call sends one request; key "" sends no Idempotency-Key.
func (ps *platformSuite) call(token, method, path, key, body string) (int, map[string]any, string) {
	ps.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	if ps.remote != "" {
		req.RemoteAddr = ps.remote + ":4000"
	}
	rr := httptest.NewRecorder()
	ps.h.ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out, rr.Body.String()
}

func orgBody(ref, email string, revision int, extra string) string {
	return fmt.Sprintf(`{"name":"Org %s","home_region":"us-east-2","plan":"family","max_seats":5,"storage_bytes":10737418240,"storage_per_seat_bytes":0,
"holder_email":%q,"holder_name":"Holder %s","billing_ref":%q,"revision":%d%s}`, ref, email, ref, ref, revision, extra)
}

func (ps *platformSuite) create(ref, email string) map[string]any {
	ps.t.Helper()
	code, out, raw := ps.call(ps.billing, "POST", "/platform/v1/orgs", "create-"+ref, orgBody(ref, email, 1, ""))
	if code != http.StatusCreated {
		ps.t.Fatalf("create %s: %d %s", ref, code, raw)
	}
	return out
}

func (ps *platformSuite) countOrgs() int {
	var n int
	orgs, err := ps.db.Platform().PlatformOrgs("", "", "", 1000)
	if err != nil {
		ps.t.Fatal(err)
	}
	n = len(orgs)
	return n
}

// activationLink is the token in the last invite mailed to addr.
func (ps *platformSuite) activationLink(addr string) string {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	for i := len(ps.mail) - 1; i >= 0; i-- {
		if m := ps.mail[i]; m.to == addr {
			_, tok, ok := strings.Cut(m.body, "/activate?token=")
			if ok {
				return strings.Fields(tok)[0]
			}
		}
	}
	ps.t.Fatalf("no invite mailed to %s", addr)
	return ""
}

// POST /orgs creates the org with a pending holder and mails the invite; the holder
// activates through the guard; the org reads back without any user's name or email.
func TestPlatformCreateOrg(t *testing.T) {
	ps := newPlatformSuite(t)
	org := ps.create("b1", "holder@example.test")
	id := org["id"].(string)
	if org["status"] != "active" || org["seats_used"] != 1.0 || org["pending_invites"] != 1.0 || org["holder_activated"] != false || org["revision"] != 1.0 || org["pool_bytes"] != 10737418240.0 {
		t.Fatalf("created org: %v", org)
	}
	if rr := anonPost(t, ps.srv, "/api/auth/activate", map[string]string{"token": ps.activationLink("holder@example.test"), "password": "correct-horse-battery"}); rr.Code != 200 {
		t.Fatalf("activate: %d %s", rr.Code, rr.Body.String())
	}
	code, got, raw := ps.call(ps.billing, "GET", "/platform/v1/orgs/"+id, "", "")
	if code != 200 || got["holder_activated"] != true || got["pending_invites"] != 0.0 || strings.Contains(raw, "holder@example.test") || strings.Contains(raw, "Holder b1") {
		t.Fatalf("get: %d %s", code, raw)
	}
	if rr := login(t, ps.srv, "holder@example.test", "correct-horse-battery"); rr.Code != 200 {
		t.Fatalf("holder login: %d %s", rr.Code, rr.Body.String())
	}
	// A reset link works for the activated holder.
	u, _ := ps.db.GetUserByEmail("holder@example.test")
	raw2, err := ps.db.Org(u.Org()).IssueAccountToken(u.ID, "reset", "email", time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rr := anonPost(t, ps.srv, "/api/auth/password/reset", map[string]string{"token": raw2, "password": "another-horse-battery"}); rr.Code != 200 {
		t.Fatalf("reset: %d %s", rr.Code, rr.Body.String())
	}
	code, list, _ := ps.call(ps.billing, "GET", "/platform/v1/orgs?billing_ref=b1", "", "")
	if code != 200 || len(list["orgs"].([]any)) != 1 {
		t.Fatalf("list: %d %v", code, list)
	}
	for _, c := range []struct{ body, want string }{
		{orgBody("x1", "x1@example.test", 1, "")[:20], "invalid_request"},
		{strings.Replace(orgBody("x2", "x2@example.test", 1, ""), "us-east-2", "US East", 1), "invalid_home_region"},
		{strings.Replace(orgBody("x3", "x3@example.test", 1, ""), `"max_seats":5`, `"max_seats":0`, 1), "invalid_max_seats"},
		{strings.Replace(orgBody("x4", "x4@example.test", 1, ""), `"max_seats":5`, `"max_seats":1001`, 1), "invalid_max_seats"},
		{strings.Replace(orgBody("x5", "x5@example.test", 1, ""), `10737418240`, `1`, 1), "invalid_storage"},
		{orgBody("x6", "holder@example.test", 1, ""), "email_in_use"},
		{orgBody("x7", "x7@example.test", 1, `,"holder_mailbox_address":"x7@elsewhere.test"`), "mailbox_domain"},
		{orgBody("x8", "x8@example.test", 1, `,"apps":{"kycalendar":{"enabled":true}}`), "invalid_request"},
		{orgBody("x9", "x9@example.test", 1, `} {`), "invalid_request"},
	} {
		code, out, raw := ps.call(ps.billing, "POST", "/platform/v1/orgs", "bad-"+c.want+c.body[len(c.body)-5:], c.body)
		if code/100 != 4 || out["error"] != c.want {
			t.Errorf("%s: %d %s", c.want, code, raw)
		}
	}
	if n := ps.countOrgs(); n != 1 {
		t.Fatalf("refused creates left orgs: %d", n)
	}
	// A mailbox address on the suite domains is set on the holder.
	ps.create("b2", "h2@example.test")
	code, out, raw := ps.call(ps.billing, "POST", "/platform/v1/orgs", "create-b3", orgBody("b3", "h3@example.test", 1, `,"holder_mailbox_address":"h3@mail.example.test"`))
	if h3, _ := ps.db.GetUserByEmail("h3@example.test"); code != 201 || h3 == nil || h3.MailboxAddress != "h3@mail.example.test" {
		t.Fatalf("mailbox create: %d %v %s", code, out, raw)
	}
	code, out, _ = ps.call(ps.billing, "POST", "/platform/v1/orgs", "create-b4", orgBody("b4", "h4@example.test", 1, `,"holder_mailbox_address":"h3@mail.example.test"`))
	if code != 409 || out["error"] != "email_in_use" {
		t.Fatalf("mailbox collision: %d %v", code, out)
	}
}

// Without platform mail a create is 503 and creates nothing; the same key works once mail is set.
func TestPlatformCreateNeedsMail(t *testing.T) {
	ps := newPlatformSuite(t)
	ps.noMail = true
	if code, out, _ := ps.call(ps.billing, "POST", "/platform/v1/orgs", "k1", orgBody("m1", "m1@example.test", 1, "")); code != 503 || out["error"] != "mail_not_configured" {
		t.Fatalf("no mail: %d %v", code, out)
	}
	if n := ps.countOrgs(); n != 0 {
		t.Fatalf("orgs after a 503: %d", n)
	}
	if u, _ := ps.db.GetUserByEmail("m1@example.test"); u != nil {
		t.Fatal("holder created without mail")
	}
	ps.noMail = false
	if code, _, raw := ps.call(ps.billing, "POST", "/platform/v1/orgs", "k1", orgBody("m1", "m1@example.test", 1, "")); code != 201 {
		t.Fatalf("retry: %d %s", code, raw)
	}
}

// Idempotency (build plan 4): replay, conflict, a lost create retried after a PATCH under
// the same key and a new one, and stale revisions.
func TestPlatformIdempotencyAndRevision(t *testing.T) {
	ps := newPlatformSuite(t)
	body := orgBody("r1", "r1@example.test", 1, "")
	code, first, firstRaw := ps.call(ps.billing, "POST", "/platform/v1/orgs", "c1", body)
	if code != 201 {
		t.Fatalf("create: %d %s", code, firstRaw)
	}
	id := first["id"].(string)
	// The create's answer was lost; billing PATCHes, then retries the create.
	if code, out, raw := ps.call(ps.billing, "PATCH", "/platform/v1/orgs/"+id, "p1", `{"revision":2,"plan":"business","max_seats":10}`); code != 200 || out["plan"] != "business" || out["revision"] != 2.0 {
		t.Fatalf("patch: %d %s", code, raw)
	}
	if code, _, raw := ps.call(ps.billing, "POST", "/platform/v1/orgs", "c1", body); code != 201 || raw != firstRaw {
		t.Fatalf("same-key retry: %d %s, want the stored answer %s", code, raw, firstRaw)
	}
	code, again, _ := ps.call(ps.billing, "POST", "/platform/v1/orgs", "c2", body)
	if code != 200 || again["id"] != id || again["plan"] != "business" {
		t.Fatalf("new-key retry: %d %v, want 200 with the org", code, again)
	}
	if code, out, _ := ps.call(ps.billing, "POST", "/platform/v1/orgs", "c3", strings.Replace(body, "Org r1", "Other", 1)); code != 409 || out["error"] != "billing_ref_conflict" {
		t.Fatalf("billing_ref conflict: %d %v", code, out)
	}
	if code, out, _ := ps.call(ps.billing, "POST", "/platform/v1/orgs", "c1", strings.Replace(body, "Org r1", "Other", 1)); code != 422 || out["error"] != "idempotency_conflict" {
		t.Fatalf("same key, other body: %d %v", code, out)
	}
	if n := ps.countOrgs(); n != 1 {
		t.Fatalf("orgs: %d", n)
	}
	// Suspend, then its retry under the same key and body: the stored answer, not stale.
	code, s1, sRaw := ps.call(ps.billing, "POST", "/platform/v1/orgs/"+id+"/suspend", "s1", `{"reason":"payment","revision":3}`)
	if code != 200 || s1["status"] != "suspended" {
		t.Fatalf("suspend: %d %s", code, sRaw)
	}
	if code, _, raw := ps.call(ps.billing, "POST", "/platform/v1/orgs/"+id+"/resume", "u1", `{"revision":4}`); code != 200 {
		t.Fatalf("resume: %d %s", code, raw)
	}
	if code, _, raw := ps.call(ps.billing, "POST", "/platform/v1/orgs/"+id+"/suspend", "s1", `{"reason":"payment","revision":3}`); code != 200 || raw != sRaw {
		t.Fatalf("suspend retry: %d %s", code, raw)
	}
	// A late PATCH or resume under a new key at or below the stored revision changes nothing.
	for _, c := range []struct{ method, path, body string }{
		{"PATCH", "/platform/v1/orgs/" + id, `{"revision":4,"plan":"late"}`},
		{"PATCH", "/platform/v1/orgs/" + id, `{"revision":1,"plan":"late"}`},
		{"POST", "/platform/v1/orgs/" + id + "/resume", `{"revision":3}`},
		{"POST", "/platform/v1/orgs/" + id + "/suspend", `{"reason":"abuse","revision":2}`},
	} {
		if code, out, _ := ps.call(ps.billing, c.method, c.path, "late"+c.body, c.body); code != 409 || out["error"] != "stale_revision" || out["revision"] != 4.0 {
			t.Errorf("%s %s: %d %v", c.method, c.body, code, out)
		}
	}
	if o, _ := ps.db.Platform().PlatformOrg(id); o.Plan != "business" || o.Status != "active" || o.Revision != 4 {
		t.Fatalf("a stale write changed the org: %+v", o)
	}
	// Every write needs a key; reads need none.
	if code, out, _ := ps.call(ps.billing, "PATCH", "/platform/v1/orgs/"+id, "", `{"revision":9}`); code != 400 || out["error"] != "idempotency_key_required" {
		t.Fatalf("no key: %d %v", code, out)
	}
	if code, out, _ := ps.call(ps.billing, "PATCH", "/platform/v1/orgs/"+id, strings.Repeat("k", 129), `{"revision":9}`); code != 400 || out["error"] != "idempotency_key_required" {
		t.Fatalf("long key: %d %v", code, out)
	}
	// Seats below those in use, and a pool below usage without the acknowledgement.
	if code, out, _ := ps.call(ps.billing, "PATCH", "/platform/v1/orgs/"+id, "p-seats", `{"revision":9,"max_seats":0}`); code != 400 || out["error"] != "invalid_max_seats" {
		t.Fatalf("seats 0: %d %v", code, out)
	}
	if _, err := ps.db.Platform().ReportStorage(suiteClient(t, ps, "r1@example.test"), []store.StorageReport{{OrgID: id, UsedBytes: 5 << 30, Seq: 1}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := ps.call(ps.billing, "PATCH", "/platform/v1/orgs/"+id, "p-pool", `{"revision":9,"storage_bytes":1073741824}`); code != 409 || out["error"] != "storage_over_pool" {
		t.Fatalf("pool below usage: %d %v", code, out)
	}
	if code, out, _ := ps.call(ps.billing, "PATCH", "/platform/v1/orgs/"+id, "p-pool-ack", `{"revision":9,"storage_bytes":1073741824,"storage_over_pool_ack":true}`); code != 200 || out["storage_over_since"] == nil {
		t.Fatalf("pool below usage, acknowledged: %d %v", code, out)
	}
}

// suiteClient registers a suite app with the org's app enabled, for storage reports.
func suiteClient(t *testing.T, ps *platformSuite, holder string) string {
	t.Helper()
	createClient(t, ps.db, "kydrive", "confidential", "x", "", "https://drive.example.test/cb")
	u, err := ps.db.GetUserByEmail(holder)
	if err != nil || u == nil {
		t.Fatal(u, err)
	}
	if err := store.EnableOrgAppForTest(ps.db, u.Org(), suiteAppRecord(t, ps.db, "kydrive"), "{}"); err != nil {
		t.Fatal(err)
	}
	return "kydrive"
}

// Tokens: platform tokens only on the platform listener, scopes per route, and no
// browser or SCIM credential is accepted there.
func TestPlatformTokensAndScopes(t *testing.T) {
	ps := newPlatformSuite(t)
	org := ps.create("t1", "t1@example.test")
	id := org["id"].(string)
	routes := []struct{ method, path, body string }{
		{"POST", "/platform/v1/orgs", orgBody("t2", "t2@example.test", 1, "")},
		{"GET", "/platform/v1/orgs", ""},
		{"GET", "/platform/v1/orgs/" + id, ""},
		{"PATCH", "/platform/v1/orgs/" + id, `{"revision":2}`},
		{"POST", "/platform/v1/orgs/" + id + "/suspend", `{"reason":"payment","revision":2}`},
		{"POST", "/platform/v1/orgs/" + id + "/resume", `{"revision":2}`},
		{"POST", "/platform/v1/orgs/" + id + "/schedule-deletion", `{"grace_days":7,"revision":2}`},
		{"DELETE", "/platform/v1/orgs/" + id, ""},
	}
	reader := ps.token(store.ScopeOrgsRead)
	for i, r := range routes {
		ps.remote = fmt.Sprintf("192.0.2.%d", 10+i)
		if code, out, _ := ps.call(ps.portal, r.method, r.path, "k", r.body); code != 403 || out["error"] != "insufficient_scope" {
			t.Errorf("members token on %s %s: %d %v", r.method, r.path, code, out)
		}
		if code, out, _ := ps.call("", r.method, r.path, "k", r.body); code != 401 || out["error"] != "invalid_token" {
			t.Errorf("no token on %s %s: %d %v", r.method, r.path, code, out)
		}
		if r.method != "GET" {
			if code, _, _ := ps.call(reader, r.method, r.path, "k", r.body); code != 403 {
				t.Errorf("read token on %s %s: %d", r.method, r.path, code)
			}
		}
	}
	ps.remote = "192.0.2.50"
	// A browser session or a SCIM-style bearer is no platform credential.
	admin := newUser(t, ps.db, "admin")
	cookie := newSession(t, ps.db, admin, time.Now().Add(time.Hour))
	req := httptest.NewRequest("GET", "/platform/v1/orgs", nil)
	req.AddCookie(&http.Cookie{Name: "kyidentity_session", Value: cookie})
	rr := httptest.NewRecorder()
	ps.h.ServeHTTP(rr, req)
	if rr.Code != 401 {
		t.Fatalf("session cookie on the platform listener: %d", rr.Code)
	}
	for _, bad := range []string{"scim-token", "kyp_" + strings.Repeat("a", 16) + "_" + strings.Repeat("b", 64), ps.billing + "x"} {
		if code, _, _ := ps.call(bad, "GET", "/platform/v1/orgs", "", ""); code != 401 {
			t.Errorf("bearer %q: %d", bad[:8], code)
		}
	}
	// A platform token is nothing on the public listener.
	for _, r := range routes {
		req := httptest.NewRequest(r.method, r.path, strings.NewReader(r.body))
		req.Header.Set("Authorization", "Bearer "+ps.billing)
		req.Header.Set("Idempotency-Key", "pub")
		rr := httptest.NewRecorder()
		ps.srv.httpServer.Handler.ServeHTTP(rr, req)
		// The public listener answers with its page or a refusal, never platform data.
		if body := rr.Body.String(); strings.Contains(body, id) || strings.Contains(body, "billing_ref") || strings.Contains(body, "insufficient_scope") {
			t.Errorf("public listener %s %s: %d %s", r.method, r.path, rr.Code, rr.Body.String())
		}
	}
	// A revoked or expired token stops at once.
	tid := strings.Split(reader, "_")[1]
	if err := ps.db.Platform().RevokePlatformToken(tid, nil); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := ps.call(reader, "GET", "/platform/v1/orgs", "", ""); code != 401 {
		t.Fatalf("revoked token: %d", code)
	}
	// Failed authentications from one address are cut off.
	ps.remote = "192.0.2.99"
	var limited bool
	for range 30 {
		if code, _, _ := ps.call("kyp_nope", "GET", "/platform/v1/orgs", "", ""); code == 429 {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("failed authentications were never rate limited")
	}
	if code, _, _ := ps.call(ps.billing, "GET", "/platform/v1/orgs", "", ""); code != 429 {
		t.Fatalf("a guessing address still reaches the lookup: %d", code)
	}
	ps.remote = "192.0.2.100"
	if code, _, _ := ps.call(ps.billing, "GET", "/platform/v1/orgs", "", ""); code != 200 {
		t.Fatalf("another address: %d", code)
	}
}

// Every call is audited with the token as actor; a call on one org in that org's log.
func TestPlatformCallsAreAudited(t *testing.T) {
	ps := newPlatformSuite(t)
	id := ps.create("a1", "a1@example.test")["id"].(string)
	ps.call(ps.billing, "GET", "/platform/v1/orgs/"+id, "", "")
	ps.call(ps.billing, "POST", "/platform/v1/orgs", "create-a1", orgBody("a1", "a1@example.test", 1, ""))
	ps.call(ps.billing, "PATCH", "/platform/v1/orgs/"+id, "stale", `{"revision":1}`)
	tid := strings.Split(ps.billing, "_")[1]
	raw, err := store.OpenRawForTest(ps.srv.cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	rows, err := raw.Query(`SELECT action, COALESCE(org_id,''), actor_id FROM audit_events WHERE action LIKE 'platform.%' ORDER BY created_at`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var action, org, actor string
		if err := rows.Scan(&action, &org, &actor); err != nil {
			t.Fatal(err)
		}
		if org != id || actor != tid {
			t.Errorf("%s: org %q actor %q", action, org, actor)
		}
		seen[action] = true
	}
	for _, a := range []string{"platform.org_created", "platform.org_read", "platform.replayed", "platform.refused"} {
		if !seen[a] {
			t.Errorf("no %s row (%v)", a, seen)
		}
	}
	if strings.Contains(fmt.Sprint(seen), ps.billing) {
		t.Fatal("the token reached the audit log")
	}
}

// A suspended org's member: a wrong password gets the usual answer, the right one reaches
// the second factor, and only after it does sign-in answer org_suspended, with no session.
// Sessions from before end; forgot-password mails nothing. A resume lets sign-in back in.
func TestPlatformSuspensionSignIn(t *testing.T) {
	ps := newPlatformSuite(t)
	id := ps.create("s1", "s1@example.test")["id"].(string)
	if rr := anonPost(t, ps.srv, "/api/auth/activate", map[string]string{"token": ps.activationLink("s1@example.test"), "password": "correct-horse-battery"}); rr.Code != 200 {
		t.Fatalf("activate: %d %s", rr.Code, rr.Body.String())
	}
	u, _ := ps.db.GetUserByEmail("s1@example.test")
	secret, _, err := ps.srv.mfaEngine.GenerateTOTPSecret(u.Username, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := ps.srv.mfaEngine.SaveUserTOTP(u.ID, secret, nil); err != nil {
		t.Fatal(err)
	}
	before := newSession(t, ps.db, u, time.Now().Add(time.Hour))
	if rr := adminRequestNoStepUp(t, ps.srv, "GET", "/api/auth/me", before, ""); rr.Code != 200 {
		t.Fatalf("me before: %d", rr.Code)
	}
	if code, _, raw := ps.call(ps.billing, "POST", "/platform/v1/orgs/"+id+"/suspend", "s", `{"reason":"payment","revision":2}`); code != 200 {
		t.Fatalf("suspend: %d %s", code, raw)
	}
	if rr := adminRequestNoStepUp(t, ps.srv, "GET", "/api/auth/me", before, ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("a session from before the suspension: %d", rr.Code)
	}
	wrong := login(t, ps.srv, u.Username, "wrong-password-entirely")
	unknown := login(t, ps.srv, "nobody@example.test", "wrong-password-entirely")
	if wrong.Code != http.StatusUnauthorized || wrong.Body.String() != unknown.Body.String() {
		t.Fatalf("wrong password: %d %s, unknown account: %s", wrong.Code, wrong.Body.String(), unknown.Body.String())
	}
	token := passwordLogin(t, ps.srv, u.Username, "correct-horse-battery")
	rr := anonPost(t, ps.srv, "/api/auth/mfa/totp/verify", map[string]string{"mfaToken": token, "code": testTOTPCode(t, secret)})
	var refusal map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &refusal)
	if rr.Code != http.StatusForbidden || refusal["error"] != "org_suspended" || hasSessionCookie(rr) {
		t.Fatalf("second factor in a suspended org: %d %s", rr.Code, rr.Body.String())
	}
	if rr := anonPost(t, ps.srv, "/api/auth/mfa/totp/verify", map[string]string{"mfaToken": token, "code": testTOTPCode(t, secret)}); rr.Code == 200 || hasSessionCookie(rr) {
		t.Fatalf("the spent challenge signed in: %d", rr.Code)
	}
	if rr := anonPost(t, ps.srv, "/api/auth/password/forgot", map[string]string{"identifier": u.Username}); rr.Code != 200 {
		t.Fatalf("forgot: %d", rr.Code)
	}
	raw, err := store.OpenRawForTest(ps.srv.cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var resets int
	if err := raw.QueryRow(`SELECT COUNT(*) FROM account_tokens WHERE user_id=? AND kind='reset'`, u.ID).Scan(&resets); err != nil || resets != 0 {
		t.Fatalf("forgot-password in a suspended org issued %d links (%v)", resets, err)
	}
	if code, _, raw := ps.call(ps.billing, "POST", "/platform/v1/orgs/"+id+"/resume", "r", `{"revision":3}`); code != 200 {
		t.Fatalf("resume: %d %s", code, raw)
	}
	// The TOTP step is spent, so the recovery code finishes this sign-in.
	codes, err := ps.srv.mfaEngine.GenerateRecoveryCodes(u.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	token = passwordLogin(t, ps.srv, u.Username, "correct-horse-battery")
	if rr := anonPost(t, ps.srv, "/api/auth/mfa/recovery/verify", map[string]string{"mfaToken": token, "code": codes[0]}); rr.Code != 200 || !hasSessionCookie(rr) {
		t.Fatalf("sign-in after resume: %d %s", rr.Code, rr.Body.String())
	}
}
