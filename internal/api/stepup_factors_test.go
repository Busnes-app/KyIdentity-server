package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Busness-app/kyidentity-server/internal/crypto"
	"github.com/Busness-app/kyidentity-server/internal/store"
)

type stepUpReply struct {
	Kind           string
	ChallengeToken string
	StepUpToken    string
	MatchDigits    string
	Passkey        beginLoginResponse
}

func readStepUpReply(t *testing.T, r *httptest.ResponseRecorder) stepUpReply {
	t.Helper()
	var reply stepUpReply
	if r.Code != 200 {
		t.Fatalf("step-up: %d %s", r.Code, r.Body.String())
	}
	if err := json.Unmarshal(r.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	return reply
}

func TestPasskeyStepUpProofAndCancellation(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()
	a := newTestAuthenticator(t, "c3RlcC11cC1rZXk")
	enrolPasskey(t, f.store, f.user.ID, a)
	op := "POST /api/user/recovery-codes"
	if r := f.post(t, "/api/auth/step-up", map[string]string{"password": f.pass, "operation": op}, ""); r.Code != 400 {
		t.Fatalf("passkey-only account accepted password alone: %d %s", r.Code, r.Body.String())
	}
	begin := func() stepUpReply {
		return readStepUpReply(t, f.post(t, "/api/auth/step-up", map[string]string{"password": f.pass, "method": "webauthn", "operation": op}, ""))
	}
	finish := func(c stepUpReply) *httptest.ResponseRecorder {
		a.signCount++
		ad := a.authData(c.Passkey.RPID, 0x01|0x04)
		cd := a.clientData(t, "webauthn.get", c.Passkey.Challenge, "http://localhost:5867")
		return f.post(t, "/api/auth/step-up/finish", map[string]any{
			"challengeToken": c.ChallengeToken, "assertion": map[string]string{
				"credentialId": a.credID, "authenticatorData": b64(ad), "clientDataJSON": b64(cd), "signature": a.sign(t, ad, cd),
			},
		}, "")
	}
	c := begin()
	if c.Kind != "challenge" || len(c.Passkey.AllowCredentials) != 1 || c.Passkey.AllowCredentials[0] != a.credID {
		t.Fatalf("bad passkey request: %+v", c)
	}
	if r := f.post(t, "/api/user/recovery-codes", nil, c.ChallengeToken); r.Code != 403 {
		t.Fatal("unfinished challenge spent as grant")
	}
	// Login tokens cannot be substituted into the distinct step-up transaction.
	loginToken := passwordLogin(t, f.srv, f.user.Username, f.pass)
	loginAssertion := assertionFields(t, f.srv, loginToken, a, true)
	if r := f.post(t, "/api/auth/step-up/finish", map[string]any{"challengeToken": c.ChallengeToken, "assertion": loginAssertion}, ""); r.Code != 401 {
		t.Fatal("login assertion finished step-up")
	}
	other := newSession(t, f.store, f.user, time.Now().UTC().Add(time.Hour))
	if r := adminRequestNoStepUp(t, f.srv, "POST", "/api/auth/step-up/finish", other, `{"challengeToken":"`+c.ChallengeToken+`"}`); r.Code != 400 {
		t.Fatalf("cross-session finish: %d %s", r.Code, r.Body.String())
	}
	grant := readStepUpReply(t, finish(c))
	if grant.Kind != "grant" || grant.StepUpToken == "" {
		t.Fatal("valid signature produced no grant")
	}
	if r := finish(c); r.Code != 400 {
		t.Fatal("completed challenge replayed")
	}
	if r := f.post(t, "/api/user/mfa/totp/setup", nil, grant.StepUpToken); r.Code != 403 {
		t.Fatal("grant authorized different operation")
	}
	if r := f.post(t, "/api/user/recovery-codes", nil, grant.StepUpToken); r.Code != 200 {
		t.Fatalf("grant not spendable: %s", r.Body.String())
	}
	if r := f.post(t, "/api/user/recovery-codes", nil, grant.StepUpToken); r.Code != 403 {
		t.Fatal("grant replayed")
	}

	for _, afterFinish := range []bool{false, true} {
		c = begin()
		if afterFinish {
			readStepUpReply(t, finish(c))
		}
		if r := f.post(t, "/api/auth/step-up/cancel", map[string]string{"challengeToken": c.ChallengeToken}, ""); r.Code != 200 {
			t.Fatal(r.Body.String())
		}
		if r := finish(c); r.Code != 400 {
			t.Fatal("cancelled challenge completed")
		}
		if r := f.post(t, "/api/user/recovery-codes", nil, c.ChallengeToken); r.Code != 403 {
			t.Fatal("cancel failed to burn raced grant")
		}
	}
}

func TestPushStepUpRequiresSignedApproval(t *testing.T) {
	f, cleanup := newPushFixture(t)
	defer cleanup()
	cookie := newSession(t, f.store, f.user, time.Now().UTC().Add(time.Hour))
	call := func(path string, body any) *httptest.ResponseRecorder {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		return adminRequestNoStepUp(t, f.server, "POST", path, cookie, string(raw))
	}
	op := "POST /api/user/recovery-codes"
	if r := call("/api/auth/step-up", map[string]string{"password": testPassword, "operation": op}); r.Code != 400 {
		t.Fatalf("push-only password: %d %s", r.Code, r.Body.String())
	}
	c := readStepUpReply(t, call("/api/auth/step-up", map[string]string{"password": testPassword, "operation": op, "method": "push"}))
	sess, err := f.store.GetSessionByTokenHash(crypto.HashSHA256(cookie), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := f.store.GetStepUpChallenge(crypto.HashSHA256(c.ChallengeToken), f.user.ID, sess.ID)
	if err != nil || challenge == nil {
		t.Fatalf("challenge: %v", err)
	}
	body := map[string]string{"challengeToken": c.ChallengeToken}
	if r := readStepUpReply(t, call("/api/auth/step-up/finish", body)); r.Kind != "pending" {
		t.Fatal("pending push produced grant")
	}
	approval := map[string]any{"challengeId": challenge.Proof, "selectedDigits": c.MatchDigits, "approve": true}
	if r := f.post(t, "/api/mfa/push/respond", approval); r.Code == 200 {
		t.Fatal("unsigned approval accepted")
	}
	approval["signature"] = f.sign(t, challenge.Proof, true, c.MatchDigits)
	if r := f.post(t, "/api/mfa/push/respond", approval); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	grant := readStepUpReply(t, call("/api/auth/step-up/finish", body))
	if grant.Kind != "grant" {
		t.Fatal("approved push produced no grant")
	}
	if r := adminRequestWithStepUp(t, f.server, "POST", "/api/user/recovery-codes", cookie, "", grant.StepUpToken); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	if r := call("/api/auth/step-up/finish", body); r.Code != 400 {
		t.Fatal("push completion replayed")
	}
}

func TestRecoveryStepUpOnlyEnrollsReplacementFactor(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()
	a := newTestAuthenticator(t, "cmVjb3Zlcnkta2V5")
	enrolPasskey(t, f.store, f.user.ID, a)
	codes, err := f.srv.mfaEngine.GenerateRecoveryCodes(f.user.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := map[string]string{"password": f.pass, "method": "recovery", "code": codes[0], "operation": "POST /api/user/recovery-codes"}
	if r := f.post(t, "/api/auth/step-up", request, ""); r.Code != 400 {
		t.Fatal("recovery authorized unrelated action")
	}
	request["operation"] = "POST /api/user/mfa/totp/enable"
	grant := readStepUpReply(t, f.post(t, "/api/auth/step-up", request, ""))
	if r := f.post(t, "/api/user/recovery-codes", nil, grant.StepUpToken); r.Code != 403 {
		t.Fatal("restricted recovery grant regenerated codes")
	}
	if r := f.post(t, "/api/user/mfa/totp/setup", nil, grant.StepUpToken); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	if r := f.post(t, "/api/auth/step-up", request, ""); r.Code != 401 {
		t.Fatal("recovery code replayed")
	}
	// Recovery permits replacement enrollment, including its existing code-rotation side effect.
	secret, _, err := f.srv.mfaEngine.GenerateTOTPSecret(f.user.Username, "test")
	if err != nil {
		t.Fatal(err)
	}
	r := f.post(t, "/api/user/mfa/totp/enable", map[string]string{"secret": secret, "code": testTOTPCode(t, secret)}, grant.StepUpToken)
	if r.Code != 200 {
		t.Fatalf("replacement failed: %d %s", r.Code, r.Body.String())
	}
	var enabled struct {
		RecoveryCodes []string `json:"recoveryCodes"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &enabled); err != nil || len(enabled.RecoveryCodes) != 8 {
		t.Fatalf("enrollment did not rotate recovery codes: %v", err)
	}
	if valid, err := f.srv.mfaEngine.VerifyAndConsumeRecoveryCode(f.user.ID, codes[1]); err != nil || valid {
		t.Fatalf("old recovery set survived: %v", err)
	}
	if valid, err := f.srv.mfaEngine.VerifyAndConsumeRecoveryCode(f.user.ID, enabled.RecoveryCodes[0]); err != nil || !valid {
		t.Fatalf("new recovery set unusable: %v", err)
	}
	// Step-up never changes the login evidence used by OIDC.
	sess, err := f.store.GetSessionByTokenHash(crypto.HashSHA256(f.cookie.Value), time.Hour)
	if err != nil || sess == nil || sess.PrimaryAuthenticatedAt != nil || sess.FactorMethod != "" {
		t.Fatal("step-up invented login evidence")
	}
}

func TestStepUpGrantBindsExactTarget(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()
	token := f.grant(t, "DELETE /api/user/passkeys/one")
	for _, op := range []string{"DELETE /api/user/passkeys/two", "POST /api/user/passkeys/one"} {
		spent, err := f.store.ConsumeStepUpToken(crypto.HashSHA256(token), f.user.ID, f.session.ID, op)
		if err != nil || spent {
			t.Fatalf("wrong target spent: %s %v", op, err)
		}
	}
	spent, err := f.store.ConsumeStepUpToken(crypto.HashSHA256(token), f.user.ID, f.session.ID, "DELETE /api/user/passkeys/one")
	if err != nil || !spent {
		t.Fatalf("correct target failed: %v", err)
	}
}

func TestTOTPStepUp(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()
	secret, _, err := f.srv.mfaEngine.GenerateTOTPSecret(f.user.Username, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.srv.mfaEngine.SaveUserTOTP(f.user.ID, secret, nil); err != nil {
		t.Fatal(err)
	}
	request := map[string]string{"password": f.pass, "operation": "POST /api/user/recovery-codes", "method": "totp", "code": "invalid"}
	if r := f.post(t, "/api/auth/step-up", request, ""); r.Code != 401 {
		t.Fatal("invalid TOTP accepted")
	}
	request["code"] = testTOTPCode(t, secret)
	grant := readStepUpReply(t, f.post(t, "/api/auth/step-up", request, ""))
	if r := f.post(t, "/api/user/recovery-codes", nil, grant.StepUpToken); r.Code != 200 {
		t.Fatal(r.Body.String())
	}
}

func TestStepUpSupportsExistingClientIDsWithSpaces(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()
	f.user.Role = "admin"
	if err := f.store.UpdateUser(f.user); err != nil {
		t.Fatal(err)
	}
	newClient(t, f.store, "app one", []string{"https://app.test/cb"}, []string{"openid"})
	token := f.grant(t, "DELETE /api/admin/clients/app one")
	r := f.do(t, "DELETE", "/api/admin/clients/app%20one", token)
	if r.Code != 200 {
		t.Fatalf("existing client cannot be deleted: %d %s", r.Code, r.Body.String())
	}
}

func TestStepUpAuditsDeniedAndPending(t *testing.T) {
	for _, scenario := range []string{"account_locked", "mfa_required", "challenge_issued"} {
		t.Run(scenario, func(t *testing.T) {
			f, cleanup := newStepUpFixture(t)
			defer cleanup()
			a := newTestAuthenticator(t, "YXVkaXQta2V5")
			enrolPasskey(t, f.store, f.user.ID, a)
			if scenario == "account_locked" {
				for range store.MaxFailedLogins {
					if _, err := f.store.RecordFailedLogin(f.user.ID); err != nil {
						t.Fatal(err)
					}
				}
			}
			request := map[string]string{"password": f.pass, "operation": "POST /api/user/recovery-codes"}
			expected := 400
			action, outcome := "auth.step_up", "denied"
			if scenario == "account_locked" {
				expected = 429
			}
			if scenario == "challenge_issued" {
				request["method"] = "webauthn"
				expected = 200
				action = "auth.step_up_challenge"
				outcome = "success"
			}
			r := f.post(t, "/api/auth/step-up", request, "")
			if r.Code != expected {
				t.Fatalf("request: %d %s", r.Code, r.Body.String())
			}
			events, _, err := f.store.ListAuditEvents(100, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, event := range events {
				if event.Action != action || event.Outcome != outcome || event.ActorID != f.user.ID {
					continue
				}
				var details map[string]string
				if err := json.Unmarshal([]byte(event.DetailsJSON), &details); err != nil {
					t.Fatal(err)
				}
				if details["reason"] == scenario && details["operation"] == request["operation"] {
					if scenario == "challenge_issued" && details["method"] != "webauthn" {
						t.Fatal("missing method")
					}
					return
				}
			}
			t.Fatalf("no %s audit for %s", outcome, scenario)
		})
	}
}
