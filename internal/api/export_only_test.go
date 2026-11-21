package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/auth"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// After a holder's Delete everything: the holder's correct password gets org_suspended and
// no session, and another member's session reaches only the export routes.
func TestExportOnlySessionOverHTTP(t *testing.T) {
	srv, db, orgA, _, cleanup := multiSuite(t)
	defer cleanup()
	hash, err := auth.HashPassword("correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	mk := func(id string) *store.User {
		u := &store.User{ID: id, Username: id + "@example.test", DisplayName: id, Email: id + "@example.test", PasswordHash: hash, Role: "user", Status: "active"}
		if err := db.Org(orgA).CreateUser(u); err != nil {
			t.Fatal(err)
		}
		return u
	}
	holder, kid := mk("a-holder"), mk("a-kid")
	if err := store.SetAccountHolderForTest(db, orgA, holder.ID); err != nil {
		t.Fatal(err)
	}
	holderCookie := newSession(t, db, holder, time.Now().UTC().Add(time.Hour))
	// Before the request, the kid's sign-in is a full one.
	if rr := login(t, srv, kid.Username, "correct-horse-battery"); rr.Code != http.StatusOK {
		t.Fatalf("login before: %d %s", rr.Code, rr.Body.String())
	}
	if code, out := erasePost(t, srv, holderCookie, holder.Email, eraseGrant(t, srv, holderCookie, "totp")); code != 200 || out["deleted"] != false {
		t.Fatalf("erase: %d %v", code, out)
	}
	rr := login(t, srv, holder.Username, "correct-horse-battery")
	var refusal map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &refusal)
	if rr.Code != http.StatusForbidden || refusal["error"] != "org_suspended" || hasSessionCookie(rr) {
		t.Fatalf("holder login: %d %s", rr.Code, rr.Body.String())
	}
	if rr := login(t, srv, holder.Username, "wrong-password-entirely"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("holder with a wrong password: %d, want the usual 401", rr.Code)
	}
	rr = login(t, srv, kid.Username, "correct-horse-battery")
	if rr.Code != http.StatusOK || !hasSessionCookie(rr) {
		t.Fatalf("kid login: %d %s", rr.Code, rr.Body.String())
	}
	var cookie string
	for _, c := range rr.Result().Cookies() {
		if c.Name == "kyidentity_session" {
			cookie = c.Value
		}
	}
	me := adminRequestNoStepUp(t, srv, "GET", "/api/auth/me", cookie, "")
	var who struct {
		Enrollment struct {
			ExportOnly bool `json:"exportOnly"`
		} `json:"enrollment"`
	}
	if me.Code != 200 || json.Unmarshal(me.Body.Bytes(), &who) != nil || !who.Enrollment.ExportOnly {
		t.Fatalf("me: %d %s", me.Code, me.Body.String())
	}
	if rr := adminRequestNoStepUp(t, srv, "GET", "/api/user/applications", cookie, ""); rr.Code != 200 {
		t.Fatalf("applications: %d %s", rr.Code, rr.Body.String())
	}
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/user/devices"}, {"GET", "/api/user/sessions"}, {"POST", "/api/auth/step-up"},
		{"GET", "/api/user/erase"}, {"POST", "/api/user/devices/pairing-token"}, {"GET", "/api/admin/users"},
	} {
		rr := adminRequestNoStepUp(t, srv, c.method, c.path, cookie, "{}")
		var out map[string]string
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		if rr.Code != http.StatusForbidden || out["error"] != "export_only" {
			t.Errorf("%s %s: %d %s", c.method, c.path, rr.Code, rr.Body.String())
		}
	}
	// A password the account must replace stays replaceable, or it could never export.
	raw, err := store.OpenRawForTest(srv.cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	q := `UPDATE users SET password_change_required=TRUE WHERE id='a-kid'`
	if _, err := raw.Exec(q); err != nil {
		t.Fatal(err)
	}
	rr = adminRequestNoStepUp(t, srv, "POST", "/api/user/password", cookie, `{"newPassword":"another-long-password"}`)
	var out map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if rr.Code != http.StatusForbidden || out["error"] != "step_up_required" {
		t.Fatalf("password change under export-only: %d %s, want the step-up gate, not export_only", rr.Code, rr.Body.String())
	}
	if rr := adminRequestNoStepUp(t, srv, "GET", "/api/user/sessions", cookie, ""); rr.Code != http.StatusForbidden {
		t.Fatalf("sessions: %d", rr.Code)
	}
	// An enrollment-restricted export-only session reaches the enrollment routes too.
	for _, q := range []string{`UPDATE users SET password_change_required=FALSE WHERE id='a-kid'`, `UPDATE sessions SET enrollment_only=TRUE WHERE user_id='a-kid'`} {
		if _, err := raw.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if rr := adminRequestNoStepUp(t, srv, "GET", "/api/user/devices", cookie, ""); rr.Code != http.StatusOK {
		t.Fatalf("enrollment route under export-only and restricted: %d %s", rr.Code, rr.Body.String())
	}
	if rr := adminRequestNoStepUp(t, srv, "GET", "/api/user/sessions", cookie, ""); rr.Code != http.StatusForbidden {
		t.Fatalf("sessions under export-only and restricted: %d", rr.Code)
	}
	if rr := adminRequestNoStepUp(t, srv, "POST", "/api/auth/logout", cookie, ""); rr.Code != 200 {
		t.Fatalf("logout: %d", rr.Code)
	}
}

func hasSessionCookie(rr interface{ Result() *http.Response }) bool {
	for _, c := range rr.Result().Cookies() {
		if c.Name == "kyidentity_session" && c.Value != "" {
			return true
		}
	}
	return false
}
