package api

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/Busnes-app/kyidentity-server/internal/auth"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// covDeadRelay configures mail delivery to a loopback port nothing listens on, so every
// send fails immediately with a connection refusal.
func covDeadRelay(t *testing.T, srv *Server, admin string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	body := fmt.Sprintf(`{"host":"127.0.0.1","port":%d,"from":"id@example.test","security":"tls","password":"relay-pass"}`, port)
	if rr := adminRequest(t, srv, "PUT", "/api/admin/mail", admin, body); rr.Code != http.StatusOK {
		t.Fatalf("configure mail: %d %s", rr.Code, rr.Body.String())
	}
}

// A relay that refuses the connection is reported to the administrator as mail_failed with
// the relay's own error, and the failed test is audited.
func TestMailTestReportsRelayFailure(t *testing.T) {
	srv, db, admin, _, cleanup := covAdmin(t)
	defer cleanup()
	covRefused(t, adminRequest(t, srv, "PUT", "/api/admin/mail", admin, `{"host":`), 400, "invalid_request")
	covDeadRelay(t, srv, admin)
	body := covRefused(t, call(t, srv, admin, "POST", "/api/admin/mail/test"), http.StatusBadGateway, "mail_failed")
	if !strings.Contains(body["error_description"], "refused") {
		t.Fatalf("relay error not passed on: %v", body)
	}
	if rows := auditRows(t, db, "admin.mail_tested"); len(rows) != 1 || rows[0].Outcome != "failure" {
		t.Fatalf("mail test audit: %+v", rows)
	}
}

// Asking for an emailed link: unknown accounts are 404s, no configured mail is a 400 that
// issues nothing, and a failed delivery is a 502 whose failure is audited.
func TestAdminIssueLinkDelivery(t *testing.T) {
	srv, db, admin, _, cleanup := covAdmin(t)
	defer cleanup()
	target := newUser(t, db, "user")
	path := "/api/admin/users/" + target.ID + "/reset-link"

	covRefused(t, adminRequest(t, srv, "POST", "/api/admin/users/ghost/reset-link", admin, `{}`), 404, "user_not_found")
	covRefused(t, adminRequest(t, srv, "POST", path, admin, `{"send":true}`), 400, "mail_not_configured")
	if n := countAudit(t, db, "admin.account_link_issued"); n != 0 {
		t.Fatalf("a link was issued without a way to deliver it: %d", n)
	}

	covDeadRelay(t, srv, admin)
	covRefused(t, adminRequest(t, srv, "POST", path, admin, `{"send":true}`), http.StatusBadGateway, "mail_failed")
	issued := auditRows(t, db, "admin.account_link_issued")
	if len(issued) != 1 || !strings.Contains(issued[0].DetailsJSON, `"delivery":"email"`) {
		t.Fatalf("issued link audit: %+v", issued)
	}
	if rows := auditRows(t, db, "admin.account_link_delivery"); len(rows) != 1 || rows[0].Outcome != "failure" || rows[0].TargetID != target.ID {
		t.Fatalf("delivery failure audit: %+v", rows)
	}
	// An activation link for a pending account mailed through the dead relay fails the same way.
	pending := covUserWith(t, db, "user", func(u *store.User) { u.Pending, u.Status = true, "disabled" })
	covRefused(t, adminRequest(t, srv, "POST", "/api/admin/users/"+pending.ID+"/activation-link", admin, `{"send":true}`), http.StatusBadGateway, "mail_failed")
}

// The forgot-password answer is always the same generic success, but the audit trail tells
// the operator why nothing was sent: an unproven address, the per-account limit, or no mail.
func TestForgotPasswordAuditsWhyNothingWasSent(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	covRefused(t, anonPostFrom(t, srv, "198.51.100.1", "/api/auth/password/forgot", map[string]string{"identifier": "  "}), 400, "invalid_request")

	unverified := newUser(t, db, "user")
	for i := 0; i < 4; i++ {
		rr := anonPostFrom(t, srv, fmt.Sprintf("198.51.100.%d", 10+i), "/api/auth/password/forgot", map[string]string{"identifier": unverified.Email})
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"success":true`) {
			t.Fatalf("forgot %d: %d %s", i, rr.Code, rr.Body.String())
		}
	}
	reasons := map[string]int{}
	for _, e := range auditRows(t, db, "auth.password_reset_requested") {
		for _, r := range []string{"email_unverified", "rate_limited", "mail_not_configured"} {
			if strings.Contains(e.DetailsJSON, r) {
				reasons[r]++
			}
		}
	}
	if reasons["email_unverified"] != 3 || reasons["rate_limited"] != 1 {
		t.Fatalf("per-account limit not applied: %v", reasons)
	}

	verified := newUser(t, db, "user")
	verifyEmail(t, srv, verified)
	if rr := anonPostFrom(t, srv, "198.51.100.30", "/api/auth/password/forgot", map[string]string{"identifier": verified.Username}); rr.Code != http.StatusOK {
		t.Fatalf("forgot verified: %d", rr.Code)
	}
	found := false
	for _, e := range auditRows(t, db, "auth.password_reset_requested") {
		if e.TargetID == verified.ID && e.Outcome == "failure" && strings.Contains(e.DetailsJSON, "mail_not_configured") {
			found = true
		}
	}
	if !found {
		t.Fatal("a reset without configured mail was not audited")
	}
}

// Changing your own password: a malformed request or a new password the policy rejects
// changes nothing, and the old password keeps working.
func TestChangePasswordRefusals(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()
	const op = "POST /api/user/password"
	covRefused(t, f.post(t, "/api/user/password", map[string]string{"currentPassword": f.pass}, f.grant(t, op)), 400, "invalid_request")
	covRefused(t, f.post(t, "/api/user/password", map[string]string{"currentPassword": f.pass, "newPassword": "short"}, f.grant(t, op)), 400, "password_policy")
	u := mustUser(t, f.store, f.user.ID)
	if ok, err := auth.VerifyPassword(f.pass, u.PasswordHash); err != nil || !ok {
		t.Fatal("a refused change replaced the password")
	}
	if !sessionAlive(t, f.srv, f.cookie.Value) {
		t.Fatal("a refused change ended the session")
	}
}

// Redeeming a link refuses malformed requests and weak passwords before spending the link.
func TestRedeemLinkRefusals(t *testing.T) {
	srv, _, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	covRefused(t, anonPost(t, srv, "/api/auth/password/reset", map[string]string{"token": "t"}), 400, "invalid_request")
	covRefused(t, anonPost(t, srv, "/api/auth/activate", map[string]string{"token": "t", "password": "short"}), 400, "password_policy")
	covRefused(t, anonPost(t, srv, "/api/auth/activate", map[string]string{"token": "never-issued", "password": "long-enough-password"}), 400, "invalid_link")
}
