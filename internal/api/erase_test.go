package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// eraseMember adds an activated member to org, signed in, and returns them with a cookie.
func eraseMember(t *testing.T, srv *Server, db *store.Store, org store.OrgID, id string) (*store.User, string) {
	t.Helper()
	u := &store.User{ID: id, Username: id + "@example.test", DisplayName: id, Email: id + "@example.test", PasswordHash: "x", Role: "user", Status: "active"}
	if err := db.Org(org).CreateUser(u); err != nil {
		t.Fatal(err)
	}
	return u, newSession(t, db, u, time.Now().UTC().Add(time.Hour))
}

// eraseGrant is a step-up grant for the button, proved with factor ("" for password only).
func eraseGrant(t *testing.T, srv *Server, cookie, factor string) string {
	t.Helper()
	sess, err := srv.store.GetSessionByTokenHash(crypto.HashSHA256(cookie), time.Hour)
	if err != nil || sess == nil {
		t.Fatalf("no session: %v", err)
	}
	raw := uuid.NewString()
	if err := srv.store.CreateStepUpToken(&store.StepUpToken{ID: uuid.NewString(), UserID: sess.UserID, SessionID: sess.ID,
		Operation: eraseOperation, FactorMethod: factor, TokenHash: crypto.HashSHA256(raw), ExpiresAt: time.Now().UTC().Add(StepUpTTL)}, nil); err != nil {
		t.Fatal(err)
	}
	return raw
}

func erasePost(t *testing.T, srv *Server, cookie, address, grant string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"address": address})
	rr := adminRequestWithStepUp(t, srv, "POST", "/api/user/erase", cookie, string(body), grant)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

func suiteErased(t *testing.T, srv *Server, client, secret, query string) []store.ErasedSubject {
	t.Helper()
	req := httptest.NewRequest("GET", "/api/suite/erased"+query, nil)
	req.SetBasicAuth(client, secret)
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)
	var out struct {
		Subjects []store.ErasedSubject `json:"subjects"`
	}
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &out) != nil || out.Subjects == nil {
		t.Fatalf("erased%s: %d %s", query, rr.Code, rr.Body.String())
	}
	return out.Subjects
}

// A single-tenant install has no button and no erased list.
func TestSingleTenantHasNoErase(t *testing.T) {
	srv, db, cleanup := suiteFixture(t)
	defer cleanup()
	u, cookie := eraseMember(t, srv, db, db.DefaultOrg().ID(), "solo")
	if rr := adminRequestNoStepUp(t, srv, "GET", "/api/user/erase", cookie, ""); rr.Code != http.StatusNotFound {
		t.Fatalf("GET erase: %d", rr.Code)
	}
	if code, _ := erasePost(t, srv, cookie, u.Email, eraseGrant(t, srv, cookie, "totp")); code != http.StatusNotFound {
		t.Fatalf("POST erase: %d", code)
	}
	if rr := suiteGet(t, srv, "/api/suite/erased", "kycalendar", "cal-secret"); rr.Code != http.StatusNotFound {
		t.Fatalf("erased: %d", rr.Code)
	}
	if got, err := db.DefaultOrg().GetUserByID(u.ID); err != nil || got == nil {
		t.Fatalf("the account is gone: %v", err)
	}
}

// A member erases only themselves; each refusal changes nothing; apps see the subject.
func TestEraseMemberOverHTTP(t *testing.T) {
	srv, db, orgA, orgB, cleanup := multiSuite(t)
	defer cleanup()
	holder, _ := eraseMember(t, srv, db, orgA, "a-holder")
	if err := store.SetAccountHolderForTest(db, orgA, holder.ID); err != nil {
		t.Fatal(err)
	}
	kid, cookie := eraseMember(t, srv, db, orgA, "a-kid")
	eraseMember(t, srv, db, orgB, "b-kid")

	rr := adminRequestNoStepUp(t, srv, "GET", "/api/user/erase", cookie, "")
	if rr.Code != http.StatusOK || strings.TrimSpace(rr.Body.String()) != `{"holder":false,"otherMembers":0}` {
		t.Fatalf("options: %d %s", rr.Code, rr.Body.String())
	}
	for _, c := range []struct {
		name, address, grant, want string
		code                       int
	}{
		{"wrong address", "b-kid@example.test", eraseGrant(t, srv, cookie, "totp"), "address_mismatch", 400},
		{"no grant", kid.Email, "", "step_up_required", 403},
		{"password only", kid.Email, eraseGrant(t, srv, cookie, ""), "step_up_required", 403},
		{"recovery code", kid.Email, eraseGrant(t, srv, cookie, "recovery"), "step_up_required", 403},
	} {
		if code, out := erasePost(t, srv, cookie, c.address, c.grant); code != c.code || out["error"] != c.want {
			t.Errorf("%s: %d %v", c.name, code, out)
		}
	}
	if got, _ := db.Org(orgA).GetUserByID(kid.ID); got == nil {
		t.Fatal("a refusal erased the member")
	}
	if code, out := erasePost(t, srv, cookie, "  A-KID@example.test ", eraseGrant(t, srv, cookie, "totp")); code != 200 || out["deleted"] != true {
		t.Fatalf("erase: %d %v", code, out)
	}
	if got, _ := db.Org(orgA).GetUserByID(kid.ID); got != nil {
		t.Fatal("the member is still there")
	}
	// The session ended with the account: a replay is refused at the door.
	if code, _ := erasePost(t, srv, cookie, kid.Email, ""); code != http.StatusUnauthorized {
		t.Fatalf("replay: %d", code)
	}
	if got, _ := db.Org(orgA).GetUserByID(holder.ID); got == nil {
		t.Fatal("the holder went with the member")
	}
	subjects := suiteErased(t, srv, "kycalendar", "cal-secret", "")
	if len(subjects) != 1 || subjects[0].Sub != kid.ID || subjects[0].OrgID != orgA.String() {
		t.Fatalf("erased: %+v", subjects)
	}
	// kypost serves only org B, so org A's subjects are not its to see.
	if got := suiteErased(t, srv, "kypost", "post-secret", ""); len(got) != 0 {
		t.Fatalf("kypost sees %+v", got)
	}
	if got := suiteErased(t, srv, "kycalendar", "cal-secret", "?since="+jsonInt(subjects[0].Revision)); len(got) != 0 {
		t.Fatalf("since: %+v", got)
	}
	for _, q := range []string{"?since=-1", "?since=x", "?limit=0", "?limit=501"} {
		if rr := suiteGet(t, srv, "/api/suite/erased"+q, "kycalendar", "cal-secret"); rr.Code != http.StatusBadRequest {
			t.Errorf("erased%s: %d", q, rr.Code)
		}
	}
}

func jsonInt(n int64) string { b, _ := json.Marshal(n); return string(b) }

// The holder with members schedules the org's deletion, which nobody can resume; a holder
// alone deletes it now. Neither reaches another org.
func TestEraseHolderOverHTTP(t *testing.T) {
	srv, db, orgA, orgB, cleanup := multiSuite(t)
	defer cleanup()
	holderA, cookieA := eraseMember(t, srv, db, orgA, "a-holder")
	eraseMember(t, srv, db, orgA, "a-kid")
	holderB, cookieB := eraseMember(t, srv, db, orgB, "b-holder")
	for org, u := range map[store.OrgID]*store.User{orgA: holderA, orgB: holderB} {
		if err := store.SetAccountHolderForTest(db, org, u.ID); err != nil {
			t.Fatal(err)
		}
	}
	rr := adminRequestNoStepUp(t, srv, "GET", "/api/user/erase", cookieA, "")
	if rr.Code != http.StatusOK || strings.TrimSpace(rr.Body.String()) != `{"holder":true,"otherMembers":1}` {
		t.Fatalf("options: %d %s", rr.Code, rr.Body.String())
	}
	code, out := erasePost(t, srv, cookieA, holderA.Email, eraseGrant(t, srv, cookieA, "webauthn"))
	if code != 200 || out["deleted"] != false || out["deleteAfter"] == nil {
		t.Fatalf("household: %d %v", code, out)
	}
	if got, _ := db.Org(orgA).GetUserByID(holderA.ID); got == nil {
		t.Fatal("the window deleted the holder early")
	}
	code, out = erasePost(t, srv, cookieB, holderB.Email, eraseGrant(t, srv, cookieB, "totp"))
	if code != 200 || out["deleted"] != true {
		t.Fatalf("alone: %d %v", code, out)
	}
	subjects := suiteErased(t, srv, "kypost", "post-secret", "")
	if len(subjects) != 1 || subjects[0].Sub != holderB.ID {
		t.Fatalf("kypost erased: %+v", subjects)
	}
	var status string
	for org, want := range map[store.OrgID]string{orgA: "deletion_scheduled", orgB: "deleted"} {
		rr := suiteGet(t, srv, "/api/suite/orgs", "kycalendar", "cal-secret")
		var page struct {
			Orgs []wireOrg `json:"orgs"`
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &page)
		status = ""
		for _, o := range page.Orgs {
			if o.ID == org.String() {
				status = o.Status
			}
		}
		if status != want {
			t.Errorf("org %s is %q, want %s", org, status, want)
		}
	}
}

func TestEraseConfirmsTheMailboxAddress(t *testing.T) {
	srv, db, orgA, _, cleanup := multiSuite(t)
	defer cleanup()
	holder, _ := eraseMember(t, srv, db, orgA, "a-holder")
	if err := store.SetAccountHolderForTest(db, orgA, holder.ID); err != nil {
		t.Fatal(err)
	}
	kid, cookie := eraseMember(t, srv, db, orgA, "a-kid")
	if _, _, err := db.SetSuiteEmailDomains([]string{"mail.example"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.Org(orgA).SetMailboxAddress(kid.ID, "kid@mail.example", false, nil); err != nil {
		t.Fatal(err)
	}
	if code, out := erasePost(t, srv, cookie, kid.Email, eraseGrant(t, srv, cookie, "totp")); code != 400 || out["error"] != "address_mismatch" {
		t.Fatalf("sign-in email: %d %v", code, out)
	}
	if code, out := erasePost(t, srv, cookie, "Kid@Mail.example", eraseGrant(t, srv, cookie, "totp")); code != 200 || out["deleted"] != true {
		t.Fatalf("mailbox address: %d %v", code, out)
	}
}
