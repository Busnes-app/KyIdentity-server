package api

import (
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// suiteOrgsFor is what /api/suite/orgs?since= tells one app about org id.
func suiteOrgsFor(t *testing.T, srv *Server, client, secret, id string, since int64) []wireOrg {
	t.Helper()
	req := httptest.NewRequest("GET", "/api/suite/orgs?since="+strconv.FormatInt(since, 10), nil)
	req.SetBasicAuth(client, secret)
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)
	var out struct{ Orgs []wireOrg }
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &out) != nil {
		t.Fatalf("suite orgs as %s: %d %s", client, rr.Code, rr.Body.String())
	}
	var mine []wireOrg
	for _, o := range out.Orgs {
		if o.ID == id {
			mine = append(mine, o)
		}
	}
	return mine
}

// Billing sets an org's apps and quotas on create and PATCH (build plan 6). Each app sees
// only its own entry in /api/suite/orgs, a change takes a new revision, a disabled app
// loses access, its listing and its live tokens, and a refused entry changes nothing.
func TestPlatformOrgApps(t *testing.T) {
	ps := newPlatformSuite(t)
	createClient(t, ps.db, "kycalendar", "confidential", crypto.HashSHA256("cal-secret"), "", "https://cal.example.test/cb")
	createClient(t, ps.db, "kypost", "confidential", crypto.HashSHA256("post-secret"), "", "https://mail.example.test/cb")
	for _, c := range []string{"kycalendar", "kypost"} {
		allowTestAppAccess(t, ps.db, c)
	}
	body := orgBody("a1", "a1@example.test", 1, `,"apps":{"kycalendar":{"enabled":true,"quotas":{"z":1,"bytes":9007199254740993,"nested":{"b":2,"a":1}}}}`)
	code, org, raw := ps.call(ps.billing, "POST", "/platform/v1/orgs", "create-a1", body)
	if code != 201 {
		t.Fatalf("create: %d %s", code, raw)
	}
	id := org["id"].(string)
	cal := suiteOrgsFor(t, ps.srv, "kycalendar", "cal-secret", id, 0)
	if len(cal) != 1 || !cal[0].Enabled || string(cal[0].Quotas) != `{"bytes":9007199254740993,"nested":{"a":1,"b":2},"z":1}` {
		t.Fatalf("kycalendar sees %+v", cal)
	}
	if post := suiteOrgsFor(t, ps.srv, "kypost", "post-secret", id, 0); len(post) != 0 {
		t.Fatalf("kypost was told about an org without it: %+v", post)
	}
	if rr := anonPost(t, ps.srv, "/api/auth/activate", map[string]string{"token": ps.activationLink("a1@example.test"), "password": "correct-horse-battery"}); rr.Code != 200 {
		t.Fatalf("activate: %d %s", rr.Code, rr.Body.String())
	}
	holder, _ := ps.db.GetUserByEmail("a1@example.test")
	if ok, err := ps.db.ClientAccessAllowed(holder.ID, "kycalendar"); err != nil || !ok {
		t.Fatalf("enabled app not allowed: %v", err)
	}
	if _, apps := suiteBody(t, ps.srv, "/api/suite/apps?sub="+holder.ID, ""); !strings.Contains(apps, `"id":"kycalendar"`) || strings.Contains(apps, `"id":"kypost"`) {
		t.Fatalf("apps of the holder: %s", apps)
	}
	cookie := newSession(t, ps.db, holder, time.Now().UTC().Add(time.Hour))
	sess, err := ps.db.GetSessionByTokenHash(crypto.HashSHA256(cookie), time.Hour)
	if err != nil || sess == nil {
		t.Fatal(sess, err)
	}
	if err := ps.db.RecordIssuedToken(&store.IssuedToken{JTI: "cal-token", UserID: holder.ID, ClientID: "kycalendar", SessionID: sess.ID, ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}

	// Refusals change nothing, the name in the same body included.
	for i, apps := range []string{
		`{"kycalendar":{"quotas":{}}}`,
		`{"nope":{"enabled":true}}`,
		`{"kycalendar":{"enabled":true,"quotas":[1]}}`,
		`{"kycalendar":{"enabled":true,"quotas":null}}`,
		`{"kycalendar":{"enabled":true,"quotas":{"x":"` + strings.Repeat("q", store.MaxQuotasBytes) + `"}}}`,
		`{"kycalendar":{"enabled":false},"nope":{"enabled":true}}`,
	} {
		code, out, raw := ps.call(ps.billing, "PATCH", "/platform/v1/orgs/"+id, "bad-"+strconv.Itoa(i), `{"revision":2,"name":"Renamed","apps":`+apps+`}`)
		if code != 400 || out["error"] != "invalid_apps" {
			t.Errorf("apps %d: %d %s", i, code, raw)
		}
	}
	if code, out, _ := ps.call(ps.billing, "POST", "/platform/v1/orgs", "create-bad", orgBody("a2", "a2@example.test", 1, `,"apps":{"nope":{"enabled":true}}`)); code != 400 || out["error"] != "invalid_apps" {
		t.Fatalf("create with an unknown app: %d %v", code, out)
	}
	if n := ps.countOrgs(); n != 1 {
		t.Fatalf("a refused create left an org: %d", n)
	}
	if got := suiteOrgsFor(t, ps.srv, "kycalendar", "cal-secret", id, 0); len(got) != 1 || got[0].Revision != cal[0].Revision || !got[0].Enabled {
		t.Fatalf("a refused patch changed the org: %+v", got)
	}
	if ok, _ := ps.db.ClientAccessAllowed(holder.ID, "kycalendar"); !ok {
		t.Fatal("a refused patch removed access")
	}

	// Off for kycalendar (quotas kept), on for kypost.
	patch := `{"revision":2,"apps":{"kycalendar":{"enabled":false},"kypost":{"enabled":true}}}`
	if code, _, raw := ps.call(ps.billing, "PATCH", "/platform/v1/orgs/"+id, "patch-2", patch); code != 200 {
		t.Fatalf("patch: %d %s", code, raw)
	}
	off := suiteOrgsFor(t, ps.srv, "kycalendar", "cal-secret", id, cal[0].Revision)
	if len(off) != 1 || off[0].Enabled || string(off[0].Quotas) != string(cal[0].Quotas) {
		t.Fatalf("kycalendar after disable, since %d: %+v", cal[0].Revision, off)
	}
	if post := suiteOrgsFor(t, ps.srv, "kypost", "post-secret", id, 0); len(post) != 1 || !post[0].Enabled || string(post[0].Quotas) != `{}` {
		t.Fatalf("kypost after enable: %+v", post)
	}
	if ok, _ := ps.db.ClientAccessAllowed(holder.ID, "kycalendar"); ok {
		t.Fatal("a disabled app is still allowed")
	}
	if revoked, err := ps.db.IsTokenRevoked("cal-token"); err != nil || !revoked {
		t.Fatalf("a disabled app's token is live: %v", err)
	}
	// kycalendar is no longer told about the holder's apps; kypost sees only itself.
	if _, apps := suiteBody(t, ps.srv, "/api/suite/apps?sub="+holder.ID, ""); apps != `{"apps":[]}` {
		t.Fatalf("apps of the holder, asked by the disabled app: %s", apps)
	}
	req := httptest.NewRequest("GET", "/api/suite/apps?sub="+holder.ID, nil)
	req.SetBasicAuth("kypost", "post-secret")
	rr := httptest.NewRecorder()
	ps.srv.httpServer.Handler.ServeHTTP(rr, req)
	if apps := rr.Body.String(); strings.Contains(apps, `"id":"kycalendar"`) || !strings.Contains(apps, `"id":"kypost"`) {
		t.Fatalf("apps of the holder after the patch: %s", apps)
	}
	// The same key and body replays; the same apps under a new key change no revision.
	if code, _, _ := ps.call(ps.billing, "PATCH", "/platform/v1/orgs/"+id, "patch-2", patch); code != 200 {
		t.Fatalf("replay: %d", code)
	}
	if code, _, raw := ps.call(ps.billing, "PATCH", "/platform/v1/orgs/"+id, "patch-3", strings.Replace(patch, `"revision":2`, `"revision":3`, 1)); code != 200 {
		t.Fatalf("same apps: %d %s", code, raw)
	}
	if again := suiteOrgsFor(t, ps.srv, "kycalendar", "cal-secret", id, off[0].Revision); len(again) != 0 {
		t.Fatalf("an unchanged apps entry took a revision: %+v", again)
	}
	// A late PATCH under a new key is stale and changes nothing.
	if code, out, _ := ps.call(ps.billing, "PATCH", "/platform/v1/orgs/"+id, "patch-old", `{"revision":2,"apps":{"kycalendar":{"enabled":true}}}`); code != 409 || out["error"] != "stale_revision" {
		t.Fatalf("stale: %d %v", code, out)
	}
	if ok, _ := ps.db.ClientAccessAllowed(holder.ID, "kycalendar"); ok {
		t.Fatal("a stale patch turned the app back on")
	}
}
