package api

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// Logout ends the server-side session (not just the cookie), clears both cookies, and
// records who signed out; the old cookie is dead afterwards.
func TestLogoutRevokesSessionAndClearsCookies(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	u := newUser(t, db, "user")
	cookie := newSession(t, db, u, time.Now().UTC().Add(time.Hour))
	other := newSession(t, db, u, time.Now().UTC().Add(time.Hour))

	rr := call(t, srv, cookie, "POST", "/api/auth/logout")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"success":true`) {
		t.Fatalf("logout: %d %s", rr.Code, rr.Body.String())
	}
	cleared := map[string]bool{}
	for _, c := range rr.Result().Cookies() {
		if c.MaxAge < 0 && c.Value == "" {
			cleared[c.Name] = true
		}
	}
	if !cleared["kyidentity_session"] || !cleared["kyidentity_csrf"] {
		t.Fatalf("logout left cookies in place: %v", rr.Result().Cookies())
	}
	if sessionAlive(t, srv, cookie) {
		t.Fatal("the session survived logout server-side")
	}
	if !sessionAlive(t, srv, other) {
		t.Fatal("logout ended the user's other sessions")
	}
	rows := auditRows(t, db, "auth.logout")
	if len(rows) != 1 || rows[0].ActorID != u.ID || rows[0].Outcome != "success" {
		t.Fatalf("logout audit: %+v", rows)
	}
	// A logout without a session is refused by the auth middleware, not answered with success.
	if rr := call(t, srv, cookie, "POST", "/api/auth/logout"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("logout with a dead session: %d", rr.Code)
	}
}

// The first login leg refuses a malformed body before touching any account.
func TestLoginRefusesMalformedBody(t *testing.T) {
	srv, _, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	rr := anonPost(t, srv, "/api/auth/login", "not an object")
	body := covRefused(t, rr, 400, "invalid_request")
	if !strings.Contains(body["error_description"], "Malformed JSON") {
		t.Fatalf("login refusal: %v", body)
	}
}

// Recovery-code sign-in: malformed requests are 400s, a wrong code is a counted failure, a
// right code issues a session exactly once, and the second-factor token cannot be reused.
func TestRecoveryCodeLogin(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()
	enrolTOTP(t, f)
	codes, err := f.srv.mfaEngine.GenerateRecoveryCodes(f.user.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	token := passwordLogin(t, f.srv, f.user.Username, f.pass)

	covRefused(t, anonPost(t, f.srv, "/api/auth/mfa/recovery/verify", map[string]string{"mfaToken": token}), 400, "invalid_request")
	covRefused(t, anonPost(t, f.srv, "/api/auth/mfa/totp/verify", map[string]string{"code": "123456"}), 400, "invalid_request")
	covRefused(t, anonPost(t, f.srv, "/api/auth/mfa/recovery/verify", map[string]string{"mfaToken": "forged", "code": codes[0]}), 401, "invalid_mfa_token")

	covRefused(t, anonPost(t, f.srv, "/api/auth/mfa/recovery/verify", map[string]string{"mfaToken": token, "code": "wrong-code"}), 401, "invalid_recovery_code")
	failures := 0
	for _, e := range auditRows(t, f.store, "auth.mfa_recovery") {
		if e.Outcome == "failure" && e.ActorID == f.user.ID {
			failures++
		}
	}
	if failures != 1 {
		t.Fatalf("wrong recovery code audited %d times", failures)
	}

	rr := anonPost(t, f.srv, "/api/auth/mfa/recovery/verify", map[string]string{"mfaToken": token, "code": codes[0]})
	if rr.Code != http.StatusOK {
		t.Fatalf("recovery login: %d %s", rr.Code, rr.Body.String())
	}
	assertFactorEvidence(t, f.store, rr, "recovery")
	if rr := anonPost(t, f.srv, "/api/auth/mfa/recovery/verify", map[string]string{"mfaToken": token, "code": codes[1]}); rr.Code != http.StatusUnauthorized {
		t.Fatalf("a spent second-factor token signed in again: %d %s", rr.Code, rr.Body.String())
	}
	if valid, err := f.srv.mfaEngine.VerifyAndConsumeRecoveryCode(f.user.ID, codes[0], nil); err != nil || valid {
		t.Fatalf("the used recovery code is still valid: %v", err)
	}
}

// A locked account cannot finish any second factor, even with a token minted before the lock.
func TestSecondFactorRefusedWhileLocked(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()
	secret := enrolTOTP(t, f)
	token := passwordLogin(t, f.srv, f.user.Username, f.pass)
	recordFailures(t, f, 50)
	covRefused(t, anonPost(t, f.srv, "/api/auth/mfa/totp/verify", map[string]string{"mfaToken": token, "code": testTOTPCode(t, secret)}), 429, "account_locked")
}

// A TOTP user has no passkey ceremony to begin, and a token issued without a push
// challenge cannot poll or finish one.
func TestSecondFactorMethodMismatch(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()
	enrolTOTP(t, f)
	token := passwordLogin(t, f.srv, f.user.Username, f.pass)
	covRefused(t, anonPost(t, f.srv, "/api/auth/mfa/webauthn/begin", map[string]string{}), 400, "invalid_request")
	covRefused(t, anonPost(t, f.srv, "/api/auth/mfa/webauthn/begin", map[string]string{"mfaToken": token}), 400, "no_passkey")
	covRefused(t, anonPost(t, f.srv, "/api/auth/mfa/push/poll", map[string]string{"mfaToken": token, "challengeId": "c-1"}), 401, "challenge_mismatch")
}

// Push sign-in: polling with another challenge's id is refused, and finishing before the
// device approved issues no session.
func TestPushLoginRefusesUnapprovedOrForeignChallenge(t *testing.T) {
	f, cleanup := newPushFixture(t)
	defer cleanup()
	token, challengeID := f.login(t)
	covRefused(t, f.post(t, "/api/auth/mfa/push/poll", map[string]string{"mfaToken": token, "challengeId": "someone-elses"}), 401, "challenge_mismatch")
	rr := f.post(t, "/api/auth/mfa/push/poll", map[string]string{"mfaToken": token, "challengeId": challengeID})
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"status":"pending"`) {
		t.Fatalf("poll: %d %s", rr.Code, rr.Body.String())
	}
	finish := f.post(t, "/api/auth/mfa/push/finish", map[string]string{"mfaToken": token, "challengeId": challengeID})
	covRefused(t, finish, 401, "mfa_not_approved")
	for _, c := range finish.Result().Cookies() {
		if c.Name == "kyidentity_session" && c.Value != "" {
			t.Fatal("an unapproved push issued a session")
		}
	}
}
