package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/syncauth"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	kysync "github.com/Busnes-app/kyidentity-server/internal/sync"
)

func (ps *platformSuite) activate(addr string) *store.User {
	ps.t.Helper()
	if rr := anonPost(ps.t, ps.srv, "/api/auth/activate", map[string]string{"token": ps.activationLink(addr), "password": "correct-horse-battery"}); rr.Code != 200 {
		ps.t.Fatalf("activate %s: %d %s", addr, rr.Code, rr.Body.String())
	}
	u, _ := ps.db.GetUserByEmail(addr)
	return u
}

func (ps *platformSuite) mailsTo(addr string) int {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	n := 0
	for _, m := range ps.mail {
		if m.to == addr {
			n++
		}
	}
	return n
}

func (ps *platformSuite) events(org string) []map[string]any {
	ps.t.Helper()
	raw, err := store.OpenRawForTest(ps.srv.cfg.DBPath)
	if err != nil {
		ps.t.Fatal(err)
	}
	defer raw.Close()
	rows, err := raw.Query(`SELECT payload_json FROM platform_events WHERE org_id=? ORDER BY created_at, id`, org)
	if err != nil {
		ps.t.Fatal(err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var p string
		_ = rows.Scan(&p)
		var m map[string]any
		_ = json.Unmarshal([]byte(p), &m)
		out = append(out, m)
	}
	return out
}

// The member endpoints (tenancy design, Member endpoints): add, the same add again,
// conflicts, seats, resend, activation, disable, enable and delete; the account holder can
// be neither disabled nor removed; every write is an event and a notice to the holder.
func TestPlatformMembers(t *testing.T) {
	ps := newPlatformSuite(t)
	org := ps.create("m1", "holder-m1@example.test")["id"].(string)
	holder := ps.activate("holder-m1@example.test")
	base := "/platform/v1/orgs/" + org + "/members"
	add := func(key, body string) (int, map[string]any) {
		code, out, _ := ps.call(ps.portal, "POST", base, key, body)
		return code, out
	}
	code, a := add("a1", `{"email":"Kid@Example.test","name":"Kid"}`)
	kid, _ := a["user_id"].(string)
	if code != 201 || a["status"] != "pending" || kid == "" {
		t.Fatalf("add: %d %v", code, a)
	}
	if ps.mailsTo("kid@example.test") != 1 || ps.mailsTo("holder-m1@example.test") != 2 {
		t.Fatalf("mail: invite %d, holder %d (invite + notice)", ps.mailsTo("kid@example.test"), ps.mailsTo("holder-m1@example.test"))
	}
	// A replay mails nothing again.
	if code, again := add("a1", `{"email":"Kid@Example.test","name":"Kid"}`); code != 201 || again["user_id"] != kid || ps.mailsTo("kid@example.test") != 1 || ps.mailsTo("holder-m1@example.test") != 2 {
		t.Fatalf("replay: %d %v, %d invites", code, again, ps.mailsTo("kid@example.test"))
	}
	// The same member again, under a new key: the same answer, no second invite.
	if code, again := add("a2", `{"email":"kid@example.test","name":"Kid"}`); code != 200 || again["user_id"] != kid {
		t.Fatalf("same member: %d %v", code, again)
	}
	if code, out := add("a3", `{"email":"kid@example.test","name":"Kid","mailbox_address":"kid@mail.example.test"}`); code != 200 || out["user_id"] != kid {
		t.Fatalf("mailbox on an existing member: %d %v", code, out)
	}
	if code, out := add("a4", `{"email":"kid@example.test","name":"Kid","mailbox_address":"other@mail.example.test"}`); code != 409 || out["error"] != "mailbox_address_set" {
		t.Fatalf("another mailbox: %d %v", code, out)
	}
	ps.create("m2", "holder-m2@example.test")
	for _, c := range []struct{ body, want string }{
		{`{"email":"holder-m2@example.test","name":"X"}`, "email_in_use"},
		{`{"email":"new@example.test","name":"X","mailbox_address":"kid@mail.example.test"}`, "email_in_use"},
		{`{"email":"new@example.test","name":"X","mailbox_address":"new@elsewhere.test"}`, "mailbox_domain"},
		{`{"email":"not-an-address","name":"X"}`, "invalid_request"},
	} {
		if code, out := add("bad"+c.body, c.body); code/100 != 4 || out["error"] != c.want {
			t.Errorf("%s: %d %v", c.body, code, out)
		}
	}
	// Five seats: the holder, kid and three more; the sixth is refused.
	for i, e := range []string{"c@example.test", "d@example.test", "e@example.test"} {
		if code, out := add("s"+e, `{"email":"`+e+`","name":"N"}`); code != 201 {
			t.Fatalf("seat %d: %d %v", i, code, out)
		}
	}
	if code, out := add("full", `{"email":"f@example.test","name":"N"}`); code != 409 || out["error"] != "seat_limit" {
		t.Fatalf("full org: %d %v", code, out)
	}
	code, list, raw := ps.call(ps.portal, "GET", base, "", "")
	if code != 200 || len(list["members"].([]any)) != 5 || strings.Contains(raw, "Kid\"") {
		t.Fatalf("list: %d %s", code, raw)
	}
	if code, out, _ := ps.call(ps.portal, "POST", base+"/"+kid+"/disable", "dp", ""); code != 409 || out["error"] != "member_state" {
		t.Fatalf("disable a pending member: %d %v", code, out)
	}
	// Resend ends the old link; the member activates with the new one.
	old := ps.activationLink("kid@example.test")
	if code, out, _ := ps.call(ps.portal, "POST", base+"/"+kid+"/resend-invite", "r1", ""); code != 200 || out["status"] != "pending" {
		t.Fatalf("resend: %d %v", code, out)
	}
	if rr := anonPost(t, ps.srv, "/api/auth/activate", map[string]string{"token": old, "password": "correct-horse-battery"}); rr.Code == 200 {
		t.Fatal("the old invite still works")
	}
	kidUser := ps.activate("kid@example.test")
	if code, out, _ := ps.call(ps.portal, "POST", base+"/"+kid+"/resend-invite", "r2", ""); code != 409 || out["error"] != "not_pending" {
		t.Fatalf("resend to an active member: %d %v", code, out)
	}
	// Disable ends the member's session; enable needs a seat, which the disable freed.
	cookie := newSession(t, ps.db, kidUser, time.Now().UTC().Add(time.Hour))
	if rr := adminRequestNoStepUp(t, ps.srv, "GET", "/api/auth/me", cookie, ""); rr.Code != 200 {
		t.Fatalf("the member's session before: %d", rr.Code)
	}
	if code, out, _ := ps.call(ps.portal, "POST", base+"/"+kid+"/disable", "d1", ""); code != 200 || out["status"] != "disabled" {
		t.Fatalf("disable: %d %v", code, out)
	}
	if rr := adminRequestNoStepUp(t, ps.srv, "GET", "/api/auth/me", cookie, ""); rr.Code != 401 {
		t.Fatalf("a disabled member's session: %d", rr.Code)
	}
	if code, out := add("fill", `{"email":"f@example.test","name":"N"}`); code != 201 {
		t.Fatalf("the freed seat: %d %v", code, out)
	}
	if code, out, _ := ps.call(ps.portal, "POST", base+"/"+kid+"/enable", "e1", ""); code != 409 || out["error"] != "seat_limit" {
		t.Fatalf("enable in a full org: %d %v", code, out)
	}
	f, _ := ps.db.GetUserByEmail("f@example.test")
	if code, out, _ := ps.call(ps.portal, "DELETE", base+"/"+f.ID, "x1", ""); code != 200 || out["status"] != "removed" {
		t.Fatalf("delete: %d %v", code, out)
	}
	if u, _ := ps.db.GetUserByEmail("f@example.test"); u != nil {
		t.Fatal("deleted member still exists")
	}
	if code, out, _ := ps.call(ps.portal, "POST", base+"/"+kid+"/enable", "e2", ""); code != 200 || out["status"] != "active" {
		t.Fatalf("enable: %d %v", code, out)
	}
	// The account holder can be neither disabled nor removed, and stays the live holder.
	for _, c := range []struct{ method, path string }{{"POST", base + "/" + holder.ID + "/disable"}, {"DELETE", base + "/" + holder.ID}} {
		if code, out, _ := ps.call(ps.portal, c.method, c.path, "h"+c.method, ""); code != 409 || out["error"] != "account_holder" {
			t.Errorf("%s holder: %d %v", c.method, code, out)
		}
	}
	if o, _ := ps.db.Platform().PlatformOrg(org); o.AccountHolderUserID != holder.ID || !o.HolderActivated {
		t.Fatalf("holder after the refusals: %+v", o)
	}
	// Another org's member is not found; an orgs:* token reaches no member route.
	other := "/platform/v1/orgs/" + ps.create("m3", "holder-m3@example.test")["id"].(string) + "/members/" + kid
	if code, _, _ := ps.call(ps.portal, "POST", other+"/disable", "o1", ""); code != 404 {
		t.Fatalf("another org's member: %d", code)
	}
	for _, r := range []struct{ method, path string }{{"GET", base}, {"POST", base}, {"POST", base + "/" + kid + "/resend-invite"},
		{"POST", base + "/" + kid + "/disable"}, {"POST", base + "/" + kid + "/enable"}, {"DELETE", base + "/" + kid}} {
		if code, out, _ := ps.call(ps.billing, r.method, r.path, "k", `{"email":"z@example.test","name":"Z"}`); code != 403 || out["error"] != "insufficient_scope" {
			t.Errorf("orgs token on %s %s: %d %v", r.method, r.path, code, out)
		}
	}
	// Every change is an event with its change, no personal data.
	var changes []string
	for _, e := range ps.events(org) {
		if e["type"] == "org.member_changed" {
			changes = append(changes, e["change"].(string))
		}
		if b, _ := json.Marshal(e); strings.Contains(string(b), "@example.test") {
			t.Fatalf("an event carries an address: %s", b)
		}
	}
	want := "activated added added added added activated disabled added removed enabled"
	if got := strings.Join(changes, " "); got != want {
		t.Fatalf("changes: %s, want %s", got, want)
	}
	// In a suspended org nobody is added or re-invited.
	if code, _, raw := ps.call(ps.billing, "POST", "/platform/v1/orgs/"+org+"/suspend", "sus", `{"reason":"payment","revision":2}`); code != 200 {
		t.Fatalf("suspend: %d %s", code, raw)
	}
	if code, out := add("late", `{"email":"late@example.test","name":"L"}`); code != 409 || out["error"] != "org_not_active" {
		t.Fatalf("add while suspended: %d %v", code, out)
	}
	c, _ := ps.db.GetUserByEmail("c@example.test")
	if code, out, _ := ps.call(ps.portal, "POST", base+"/"+c.ID+"/resend-invite", "late-r", ""); code != 409 || out["error"] != "org_not_active" {
		t.Fatalf("resend while suspended: %d %v", code, out)
	}
}

// Without mail, member adds and re-invites are 503 and change nothing.
func TestPlatformMembersNeedMail(t *testing.T) {
	ps := newPlatformSuite(t)
	org := ps.create("n1", "holder-n1@example.test")["id"].(string)
	ps.noMail = true
	if code, out, _ := ps.call(ps.portal, "POST", "/platform/v1/orgs/"+org+"/members", "k", `{"email":"n@example.test","name":"N"}`); code != 503 || out["error"] != "mail_not_configured" {
		t.Fatalf("add: %d %v", code, out)
	}
	if u, _ := ps.db.GetUserByEmail("n@example.test"); u != nil {
		t.Fatal("member created without mail")
	}
}

// Events are signed with the sealed secret and retried until billing takes them.
func TestPlatformEventsAreSignedAndRetried(t *testing.T) {
	ps := newPlatformSuite(t)
	org := ps.create("e1", "holder-e1@example.test")["id"].(string)
	secret := strings.Repeat("s", 40)
	var calls atomic.Int32
	var got []string
	billing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if _, err := syncauth.Verify([]byte(secret), syncauth.FromRequest(r), body, syncauth.Options{}); err != nil {
			t.Errorf("signature: %v", err)
			w.WriteHeader(401)
			return
		}
		if calls.Add(1) == 1 {
			w.WriteHeader(500)
			return
		}
		got = append(got, string(body))
	}))
	defer billing.Close()
	eng := kysync.NewEngine(ps.db, ps.srv.cfg.EncryptionKey)
	eng.SetPlatformEventsURL(billing.URL)
	// No secret yet: nothing is claimed.
	if err := eng.DeliverPlatformEvents(context.Background()); err != nil || calls.Load() != 0 {
		t.Fatalf("without a secret: %v, %d calls", err, calls.Load())
	}
	if err := ps.db.SetPlatformEventsSecret(secret, ps.srv.cfg.EncryptionKey, nil); err != nil {
		t.Fatal(err)
	}
	if err := eng.DeliverPlatformEvents(context.Background()); err != nil || calls.Load() != 1 || len(got) != 0 {
		t.Fatalf("first pass: %v, %d calls, %d delivered", err, calls.Load(), len(got))
	}
	raw, err := store.OpenRawForTest(ps.srv.cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`UPDATE platform_events SET next_attempt_at=? WHERE org_id=?`, time.Now().UTC().Add(-time.Second), org); err != nil {
		t.Fatal(err)
	}
	if err := eng.DeliverPlatformEvents(context.Background()); err != nil || len(got) != 1 || !strings.Contains(got[0], `"org.created"`) {
		t.Fatalf("retry: %v, %v", err, got)
	}
	var status string
	var attempts int
	if err := raw.QueryRow(`SELECT status, attempts FROM platform_events WHERE org_id=?`, org).Scan(&status, &attempts); err != nil || status != "delivered" || attempts != 2 {
		t.Fatalf("event row: %s %d %v", status, attempts, err)
	}
	var sealed string
	if err := raw.QueryRow(`SELECT value FROM system_settings WHERE key=?`, store.PlatformEventsSecretSetting).Scan(&sealed); err != nil || strings.Contains(sealed, secret) {
		t.Fatalf("the secret is not sealed: %v", err)
	}
}

// A disable with mail gone still commits; the missed notice is audited.
func TestPlatformMissedNoticeIsAudited(t *testing.T) {
	ps := newPlatformSuite(t)
	org := ps.create("q1", "holder-q1@example.test")["id"].(string)
	ps.activate("holder-q1@example.test")
	_, a, _ := ps.call(ps.portal, "POST", "/platform/v1/orgs/"+org+"/members", "a", `{"email":"q@example.test","name":"Q"}`)
	ps.activate("q@example.test")
	ps.noMail = true
	if code, out, _ := ps.call(ps.portal, "POST", "/platform/v1/orgs/"+org+"/members/"+a["user_id"].(string)+"/disable", "d", ""); code != 200 {
		t.Fatalf("disable: %d %v", code, out)
	}
	raw, err := store.OpenRawForTest(ps.srv.cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var n int
	if err := raw.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action='platform.notice_delivery' AND outcome='failure' AND org_id=?`, org).Scan(&n); err != nil || n != 1 {
		t.Fatalf("missed notice audit rows: %d %v", n, err)
	}
}
