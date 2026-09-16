package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestAdminRegistersBackchannelLogoutURI(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))

	rr := adminRequestWithStepUp(t, srv, "POST", "/api/admin/clients", cookie,
		`{"clientId":"app","clientName":"App","redirectUris":["https://app.test/cb"],"backchannelLogoutUri":"https://app.test/backchannel"}`, mintStepUp(t, srv, cookie, "POST /api/admin/clients"))
	if rr.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	c, err := db.GetOAuthClientByID("app")
	if err != nil || c == nil || c.BackchannelLogoutURI != "https://app.test/backchannel" {
		t.Fatalf("stored %+v %v", c, err)
	}

	for name, uri := range map[string]string{"plain http": "http://app.test/backchannel", "private address": "https://10.0.0.5/backchannel", "loopback": "https://127.0.0.1/backchannel"} {
		rr = adminRequestWithStepUp(t, srv, "PUT", "/api/admin/clients/app", cookie,
			`{"backchannelLogoutUri":"`+uri+`"}`, mintStepUp(t, srv, cookie, "PUT /api/admin/clients/app"))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s accepted: %d %s", name, rr.Code, rr.Body.String())
		}
	}
	rr = adminRequestWithStepUp(t, srv, "PUT", "/api/admin/clients/app", cookie,
		`{"backchannelLogoutUri":""}`, mintStepUp(t, srv, cookie, "PUT /api/admin/clients/app"))
	if rr.Code != http.StatusOK {
		t.Fatalf("clear: %d %s", rr.Code, rr.Body.String())
	}
	c, _ = db.GetOAuthClientByID("app")
	if c.BackchannelLogoutURI != "" {
		t.Fatalf("not cleared: %q", c.BackchannelLogoutURI)
	}
}

type logoutRow struct {
	ID         string `json:"id"`
	ClientID   string `json:"clientId"`
	ClientName string `json:"clientName"`
	Status     string `json:"status"`
	Attempts   int    `json:"attempts"`
	LastError  string `json:"lastError"`
}

func decodeLogouts(t *testing.T, body []byte) []logoutRow {
	t.Helper()
	var inv struct {
		Logouts []logoutRow `json:"logouts"`
	}
	if err := json.Unmarshal(body, &inv); err != nil {
		t.Fatal(err)
	}
	return inv.Logouts
}

func TestInventoryShowsLogoutDeliveriesAndAdminCanRetry(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	exp := time.Now().UTC().Add(time.Hour)
	admin := newSession(t, db, newUser(t, db, "admin"), exp)
	u := newUser(t, db, "user")
	mine, other := newSession(t, db, u, exp), newSession(t, db, u, exp)
	newClient(t, db, "kynotes", []string{"https://notes.urlxl.com/callback"}, []string{"openid"})
	c, _ := db.GetOAuthClientByID("kynotes")
	c.BackchannelLogoutURI = "https://notes.urlxl.com/backchannel"
	if err := db.UpdateOAuthClient(c); err != nil {
		t.Fatal(err)
	}
	if _, err := db.EnsureClientSession("kynotes", sessionIDFor(t, db, other), u.ID); err != nil {
		t.Fatal(err)
	}

	if got := call(t, srv, mine, "DELETE", "/api/user/sessions/"+sessionIDFor(t, db, other)); got.Code != http.StatusOK {
		t.Fatalf("revoke: %d", got.Code)
	}
	own := decodeLogouts(t, call(t, srv, mine, "GET", "/api/user/sessions").Body.Bytes())
	if len(own) != 1 || own[0].ClientID != "kynotes" || own[0].Status != "queued" || own[0].ClientName != "kynotes" {
		t.Fatalf("own inventory logouts = %+v", own)
	}

	d, err := db.ClaimLogoutDelivery(time.Minute)
	if err != nil || d == nil {
		t.Fatalf("claim: %v", err)
	}
	if err := db.FinishLogoutDelivery(d, errors.New("receiver answered 503")); err != nil {
		t.Fatal(err)
	}
	adminRows := decodeLogouts(t, call(t, srv, admin, "GET", "/api/admin/users/"+u.ID+"/sessions").Body.Bytes())
	if len(adminRows) != 1 || adminRows[0].Attempts != 1 || adminRows[0].LastError == "" {
		t.Fatalf("admin inventory logouts = %+v", adminRows)
	}
	// The owner sees the outcome, never the transport error: it can name internal hosts.
	own = decodeLogouts(t, call(t, srv, mine, "GET", "/api/user/sessions").Body.Bytes())
	if len(own) != 1 || own[0].Attempts != 1 || own[0].LastError != "" {
		t.Fatalf("own inventory leaks the transport error: %+v", own)
	}

	if got := call(t, srv, mine, "POST", "/api/admin/users/"+u.ID+"/logouts/"+d.ID+"/retry"); got.Code != http.StatusForbidden {
		t.Fatalf("non-admin retry: %d", got.Code)
	}
	if got := call(t, srv, admin, "POST", "/api/admin/users/"+u.ID+"/logouts/"+d.ID+"/retry"); got.Code != http.StatusOK {
		t.Fatalf("retry: %d %s", got.Code, got.Body.String())
	}
	if got := call(t, srv, admin, "POST", "/api/admin/users/"+u.ID+"/logouts/nope/retry"); got.Code != http.StatusNotFound {
		t.Fatalf("unknown retry: %d", got.Code)
	}
	stranger := newUser(t, db, "user")
	if got := call(t, srv, admin, "POST", "/api/admin/users/"+stranger.ID+"/logouts/"+d.ID+"/retry"); got.Code != http.StatusNotFound {
		t.Fatalf("retry under the wrong user: %d", got.Code)
	}
	adminRows = decodeLogouts(t, call(t, srv, admin, "GET", "/api/admin/users/"+u.ID+"/sessions").Body.Bytes())
	if adminRows[0].Attempts != 0 || adminRows[0].Status != "queued" {
		t.Fatalf("after retry = %+v", adminRows[0])
	}
	if n := countAudit(t, db, "admin.logout_retry"); n != 1 {
		t.Fatalf("retry audit rows = %d", n)
	}
}

// Replacing a factor is the path that exists to cut a stolen session, so the apps that
// saw the sibling sessions must be told like any other revocation.
func TestReplacingAFactorQueuesLogoutForSiblingSessions(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()
	other := newSession(t, f.store, f.user, time.Now().UTC().Add(time.Hour))
	newClient(t, f.store, "kynotes", []string{"https://notes.urlxl.com/callback"}, []string{"openid"})
	c, _ := f.store.GetOAuthClientByID("kynotes")
	c.BackchannelLogoutURI = "https://notes.urlxl.com/backchannel"
	if err := f.store.UpdateOAuthClient(c); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.EnsureClientSession("kynotes", sessionIDFor(t, f.store, other), f.user.ID); err != nil {
		t.Fatal(err)
	}

	grant := f.grant(t, "POST /api/user/mfa/totp/enable")
	secret, _, err := f.srv.mfaEngine.GenerateTOTPSecret(f.user.Username, "test")
	if err != nil {
		t.Fatal(err)
	}
	if r := f.post(t, "/api/user/mfa/totp/enable", map[string]string{"secret": secret, "code": testTOTPCode(t, secret)}, grant); r.Code != http.StatusOK {
		t.Fatalf("enable: %d %s", r.Code, r.Body.String())
	}
	rows, err := f.store.ListLogoutDeliveries(f.user.ID, 10)
	if err != nil || len(rows) != 1 || rows[0].ClientID != "kynotes" || rows[0].Status != "queued" {
		t.Fatalf("deliveries after factor replacement = %+v %v", rows, err)
	}
	if left, _ := f.store.ListUserSessions(f.user.ID, time.Hour); len(left) != 1 {
		t.Fatalf("sibling session survived: %d", len(left))
	}
}
