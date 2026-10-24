package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

const covStepUpOp = "POST /api/user/recovery-codes"

// A step-up request needs a password and a known target operation; anything else is a
// 400 that issues nothing. A password-only account cannot name a factor it does not have.
func TestStepUpRequestValidation(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()
	for name, body := range map[string]any{
		"not an object":      "x",
		"no password":        map[string]string{"operation": covStepUpOp},
		"non-API operation":  map[string]string{"password": f.pass, "operation": "POST /oauth/token"},
		"unsupported method": map[string]string{"password": f.pass, "operation": "PATCH /api/user/password"},
	} {
		t.Run(name, func(t *testing.T) { covRefused(t, f.post(t, "/api/auth/step-up", body, ""), 400, "invalid_request") })
	}
	covRefused(t, f.post(t, "/api/auth/step-up", map[string]string{"password": f.pass, "operation": covStepUpOp, "method": "totp"}, ""), 400, "invalid_method")
	if n := countAudit(t, f.store, "auth.step_up"); n != 0 {
		t.Fatalf("refused step-ups issued %d grants", n)
	}
}

// A grant never outlives the session it is bound to: with less than StepUpTTL left on the
// session, the grant expires with the session.
func TestStepUpGrantCappedBySessionExpiry(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()
	soon := time.Now().UTC().Add(time.Minute).Truncate(time.Second)
	cookie := newSession(t, f.store, f.user, soon)
	rr := adminRequestNoStepUp(t, f.srv, "POST", "/api/auth/step-up", cookie, `{"password":"`+f.pass+`","operation":"`+covStepUpOp+`"}`)
	var reply struct {
		Kind      string    `json:"kind"`
		ExpiresAt time.Time `json:"expiresAt"`
	}
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &reply) != nil || reply.Kind != "grant" {
		t.Fatalf("step-up: %d %s", rr.Code, rr.Body.String())
	}
	if reply.ExpiresAt.After(soon) {
		t.Fatalf("grant expires %v, after its session %v", reply.ExpiresAt, soon)
	}
}

// Finishing a step-up requires a challenge token this session holds, and re-checks lockout
// and enrollment: a challenge issued before the account locked, or before its factor was
// removed, cannot be completed.
func TestStepUpFinishRechecksState(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()
	a := newTestAuthenticator(t, "ZmluaXNoLWtleQ")
	enrolPasskey(t, f.store, f.user.ID, a)
	begin := func() stepUpReply {
		return readStepUpReply(t, f.post(t, "/api/auth/step-up", map[string]string{"password": f.pass, "method": "webauthn", "operation": covStepUpOp}, ""))
	}
	finish := func(token string, assertion map[string]string) *http.Response {
		rr := f.post(t, "/api/auth/step-up/finish", map[string]any{"challengeToken": token, "assertion": assertion}, "")
		return rr.Result()
	}

	covRefused(t, f.post(t, "/api/auth/step-up/finish", "x", ""), 400, "invalid_request")
	covRefused(t, f.post(t, "/api/auth/step-up/finish", map[string]string{}, ""), 400, "invalid_request")
	covRefused(t, f.post(t, "/api/auth/step-up/finish", map[string]string{"challengeToken": strings.Repeat("a", 64)}, ""), 400, "invalid_challenge")
	covRefused(t, f.post(t, "/api/auth/step-up/cancel", "x", ""), 400, "invalid_request")

	// Unknown credential and undecodable assertion both fail as a bad second factor.
	c := begin()
	if r := finish(c.ChallengeToken, map[string]string{"credentialId": "bm90LWEta2V5"}); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unknown credential: %d", r.StatusCode)
	}
	c = begin()
	if r := finish(c.ChallengeToken, map[string]string{"credentialId": a.credID, "authenticatorData": "!!", "clientDataJSON": "!!", "signature": "!!"}); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("undecodable assertion: %d", r.StatusCode)
	}

	// Locked between the two steps.
	c = begin()
	for i := 0; i < store.MaxFailedLogins; i++ {
		if _, err := f.store.RecordFailedLogin(f.user.ID); err != nil {
			t.Fatal(err)
		}
	}
	covRefused(t, f.post(t, "/api/auth/step-up/finish", map[string]string{"challengeToken": c.ChallengeToken}, ""), 429, "account_locked")
	lockedDenials := 0
	for _, e := range auditRows(t, f.store, "auth.step_up") {
		if e.Outcome == "denied" && strings.Contains(e.DetailsJSON, "account_locked") && strings.Contains(e.DetailsJSON, "webauthn") {
			lockedDenials++
		}
	}
	if lockedDenials != 1 {
		t.Fatalf("locked finish audited %d times", lockedDenials)
	}
	if err := f.store.ClearFailedLogins(f.user.ID); err != nil {
		t.Fatal(err)
	}

	// Factor removed between the two steps.
	c = begin()
	keys, err := f.store.ListUserWebAuthnCredentials(f.user.ID)
	if err != nil || len(keys) != 1 {
		t.Fatalf("keys: %v %v", keys, err)
	}
	if _, err := f.store.DeleteWebAuthnCredential(keys[0].ID, f.user.ID, nil); err != nil {
		t.Fatal(err)
	}
	covRefused(t, f.post(t, "/api/auth/step-up/finish", map[string]string{"challengeToken": c.ChallengeToken}, ""), 400, "invalid_method")
	if n := countAudit(t, f.store, "auth.step_up"); n != 0 {
		t.Fatalf("refused finishes issued %d grants", n)
	}
}

// A denied push ends the step-up: the finish call reports push_denied and the challenge is
// burned, so a later approval cannot revive it into a grant.
func TestStepUpPushDenialBurnsChallenge(t *testing.T) {
	f, cleanup := newPushFixture(t)
	defer cleanup()
	cookie := newSession(t, f.store, f.user, time.Now().UTC().Add(time.Hour))
	post := func(path, body string) *http.Response {
		return adminRequestNoStepUp(t, f.server, "POST", path, cookie, body).Result()
	}
	rr := adminRequestNoStepUp(t, f.server, "POST", "/api/auth/step-up", cookie, `{"password":"`+testPassword+`","operation":"`+covStepUpOp+`","method":"push"}`)
	c := readStepUpReply(t, rr)
	sess, err := f.store.GetSessionByTokenHash(crypto.HashSHA256(cookie), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := f.store.GetStepUpChallenge(crypto.HashSHA256(c.ChallengeToken), f.user.ID, sess.ID)
	if err != nil || challenge == nil {
		t.Fatalf("challenge: %v", err)
	}
	pc, err := f.store.GetMFAChallenge(challenge.Proof)
	if err != nil || pc == nil {
		t.Fatal(err)
	}
	deny := map[string]any{"challengeId": pc.ID, "deviceId": f.deviceID, "selectedDigits": c.MatchDigits, "approve": false, "signature": f.sign(t, pc, false, c.MatchDigits)}
	if r := f.post(t, "/api/mfa/push/respond", deny); r.Code != http.StatusOK {
		t.Fatalf("deny: %d %s", r.Code, r.Body.String())
	}
	body := `{"challengeToken":"` + c.ChallengeToken + `"}`
	covRefused(t, adminRequestNoStepUp(t, f.server, "POST", "/api/auth/step-up/finish", cookie, body), 400, "push_denied")
	// A later approval of the same push is refused and does not revive the step-up.
	approve := map[string]any{"challengeId": pc.ID, "deviceId": f.deviceID, "selectedDigits": c.MatchDigits, "approve": true, "signature": f.sign(t, pc, true, c.MatchDigits)}
	if r := f.post(t, "/api/mfa/push/respond", approve); r.Code == http.StatusOK {
		t.Fatalf("a denied push was approved afterwards: %s", r.Body.String())
	}
	if r := post("/api/auth/step-up/finish", body); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("burned challenge: %d", r.StatusCode)
	}
	if n := countAudit(t, f.store, "auth.step_up"); n != 0 {
		t.Fatalf("a denied push issued %d step-up grants", n)
	}
	if r := adminRequestWithStepUp(t, f.server, "POST", "/api/user/recovery-codes", cookie, "", c.ChallengeToken); r.Code != http.StatusForbidden {
		t.Fatalf("denied push challenge spent as a grant: %d", r.Code)
	}
}
