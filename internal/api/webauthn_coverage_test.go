package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

const covPasskeyOp = "POST /api/user/passkeys/register/finish"

// covBeginRegistration starts passkey enrolment with a minted grant and returns the challenge
// and the credential ids the server asked the authenticator to exclude.
func covBeginRegistration(t *testing.T, f *stepUpFixture) (string, []string) {
	t.Helper()
	rr := f.post(t, "/api/user/passkeys/register/begin", map[string]string{}, mintStepUp(t, f.srv, f.cookie.Value, covPasskeyOp))
	var begun struct {
		Challenge string   `json:"challenge"`
		Exclude   []string `json:"excludeCredentials"`
	}
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &begun) != nil || begun.Challenge == "" {
		t.Fatalf("begin: %d %s", rr.Code, rr.Body.String())
	}
	return begun.Challenge, begun.Exclude
}

func covRegistrationBody(t *testing.T, a *testAuthenticator, challenge, name string) map[string]string {
	t.Helper()
	cdj := a.clientData(t, "webauthn.create", challenge, "http://localhost:5867")
	return map[string]string{"credentialId": a.credID, "attestationObject": a.attestationObject(t, "localhost", 0x01|0x04|0x40), "clientDataJSON": b64(cdj), "name": name}
}

// Passkey enrolment refuses malformed ceremonies and unissued challenges, needs a step-up
// grant, and enrols nothing on refusal.
func TestPasskeyRegistrationValidation(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()
	grant := func() string { return mintStepUp(t, f.srv, f.cookie.Value, covPasskeyOp) }
	finish := func(body any, stepUp string) *http.Response {
		return f.post(t, "/api/user/passkeys/register/finish", body, stepUp).Result()
	}
	a := newTestAuthenticator(t, "Y292LWtleS0x")

	covRefused(t, f.post(t, "/api/user/passkeys/register/finish", map[string]string{"credentialId": "x"}, grant()), 400, "invalid_request")
	if r := finish(covRegistrationBody(t, a, "c", "k"), ""); r.StatusCode != http.StatusForbidden {
		t.Fatalf("finish without step-up: %d", r.StatusCode)
	}
	bad := covRegistrationBody(t, a, "c", "k")
	bad["attestationObject"] = "not base64url!"
	covRefused(t, f.post(t, "/api/user/passkeys/register/finish", bad, grant()), 400, "invalid_request")
	long := covRegistrationBody(t, a, "c", "k")
	long["credentialId"] = b64(make([]byte, 1024))
	body := covRefused(t, f.post(t, "/api/user/passkeys/register/finish", long, grant()), 400, "invalid_request")
	if !strings.Contains(body["error_description"], "maximum length") {
		t.Fatalf("oversized credential id: %v", body)
	}
	notJSON := covRegistrationBody(t, a, "c", "k")
	notJSON["clientDataJSON"] = b64([]byte("not json"))
	covRefused(t, f.post(t, "/api/user/passkeys/register/finish", notJSON, grant()), 400, "invalid_request")
	covRefused(t, f.post(t, "/api/user/passkeys/register/finish", covRegistrationBody(t, a, "never-issued", "k"), grant()), 400, "invalid_challenge")
	if creds, _ := f.store.ListUserWebAuthnCredentials(f.user.ID); len(creds) != 0 {
		t.Fatalf("refused ceremonies enrolled %d keys", len(creds))
	}
}

// Successful enrolment burns its challenge, excludes already-enrolled credentials from the
// next ceremony, names unnamed keys, truncates long names, and caps keys per account.
func TestPasskeyRegistrationEnrolment(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()
	grant := func() string { return mintStepUp(t, f.srv, f.cookie.Value, covPasskeyOp) }
	finish := func(body any, stepUp string) *http.Response {
		return f.post(t, "/api/user/passkeys/register/finish", body, stepUp).Result()
	}
	a := newTestAuthenticator(t, "Y292LWtleS0x")

	// An unnamed key is called "Passkey".
	challenge, exclude := covBeginRegistration(t, f)
	if len(exclude) != 0 {
		t.Fatalf("nothing enrolled yet, exclude = %v", exclude)
	}
	if r := finish(covRegistrationBody(t, a, challenge, ""), grant()); r.StatusCode != http.StatusOK {
		t.Fatalf("first enrolment: %d", r.StatusCode)
	}
	// The challenge was spent: replaying the same ceremony fails.
	covRefused(t, f.post(t, "/api/user/passkeys/register/finish", covRegistrationBody(t, a, challenge, ""), grant()), 400, "invalid_challenge")

	// The next ceremony excludes the enrolled key; a long name is cut to 64 bytes.
	b := newTestAuthenticator(t, "Y292LWtleS0y")
	challenge, exclude = covBeginRegistration(t, f)
	if len(exclude) != 1 || exclude[0] != a.credID {
		t.Fatalf("exclude list = %v, want [%s]", exclude, a.credID)
	}
	if r := finish(covRegistrationBody(t, b, challenge, strings.Repeat("n", 100)), grant()); r.StatusCode != http.StatusOK {
		t.Fatalf("second enrolment: %d", r.StatusCode)
	}
	creds, err := f.store.ListUserWebAuthnCredentials(f.user.ID)
	if err != nil || len(creds) != 2 {
		t.Fatalf("credentials: %v %v", creds, err)
	}
	names := map[string]bool{}
	for _, c := range creds {
		names[c.Name] = true
	}
	if !names["Passkey"] || !names[strings.Repeat("n", 64)] {
		t.Fatalf("stored names: %v", names)
	}

	for i := len(creds); i < maxPasskeysPerUser; i++ {
		enrolPasskey(t, f.store, f.user.ID, newTestAuthenticator(t, fmt.Sprintf("ZmlsbC0%d", i)))
	}
	covRefused(t, f.post(t, "/api/user/passkeys/register/begin", map[string]string{}, grant()), 409, "too_many_passkeys")
}

// Listing shows an empty account as [], and removing a key needs a grant and an id that is
// the caller's own.
func TestPasskeyListAndDelete(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()
	rr := f.do(t, "GET", "/api/user/passkeys", "")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "[]") {
		t.Fatalf("empty list: %d %s", rr.Code, rr.Body.String())
	}
	const op = "DELETE /api/user/passkeys/"
	covRefused(t, f.do(t, "DELETE", "/api/user/passkeys/ghost", mintStepUp(t, f.srv, f.cookie.Value, op+"ghost")), 404, "not_found")

	// Another account's key id is not found for this caller, and survives.
	enrolPasskey(t, f.store, f.user.ID, newTestAuthenticator(t, "bWluZQ"))
	theirs := newUser(t, f.store, "user")
	enrolPasskey(t, f.store, theirs.ID, newTestAuthenticator(t, "dGhlaXJz"))
	keys, _ := f.store.ListUserWebAuthnCredentials(theirs.ID)
	covRefused(t, f.do(t, "DELETE", "/api/user/passkeys/"+keys[0].ID, mintStepUp(t, f.srv, f.cookie.Value, op+keys[0].ID)), 404, "not_found")
	if still, _ := f.store.ListUserWebAuthnCredentials(theirs.ID); len(still) != 1 {
		t.Fatal("a user deleted another account's passkey")
	}

	mine, _ := f.store.ListUserWebAuthnCredentials(f.user.ID)
	if rr := f.do(t, "DELETE", "/api/user/passkeys/"+mine[0].ID, ""); rr.Code != http.StatusForbidden {
		t.Fatalf("delete without step-up: %d", rr.Code)
	}
	if rr := f.do(t, "DELETE", "/api/user/passkeys/"+mine[0].ID, mintStepUp(t, f.srv, f.cookie.Value, op+mine[0].ID)); rr.Code != http.StatusOK {
		t.Fatalf("delete own: %d %s", rr.Code, rr.Body.String())
	}
	if n := countAudit(t, f.store, "mfa.passkey_removed"); n != 1 {
		t.Fatalf("removals audited %d times", n)
	}
}

// Passkey sign-in refuses malformed or unissued ceremonies, and each refusal counts as a
// failed attempt on the second-factor token.
func TestPasskeyLoginRefusesMalformedCeremony(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()
	a := newTestAuthenticator(t, "bG9naW4ta2V5")
	enrolPasskey(t, f.store, f.user.ID, a)
	token := passwordLogin(t, f.srv, f.user.Username, f.pass)

	covRefused(t, anonPost(t, f.srv, "/api/auth/mfa/webauthn/verify", map[string]string{"mfaToken": token}), 400, "invalid_request")
	fields := assertionFields(t, f.srv, token, a, true)
	fields["clientDataJSON"] = b64([]byte("{}"))
	covRefused(t, anonPost(t, f.srv, "/api/auth/mfa/webauthn/verify", fields), 400, "invalid_request")
	fields = assertionFields(t, f.srv, token, a, true)
	fields["clientDataJSON"] = b64(a.clientData(t, "webauthn.get", "never-issued", "http://localhost:5867"))
	covRefused(t, anonPost(t, f.srv, "/api/auth/mfa/webauthn/verify", fields), 401, "invalid_assertion")
	failures := 0
	for _, e := range auditRows(t, f.store, "auth.mfa_passkey") {
		if e.Outcome == "failure" {
			failures++
		}
	}
	if failures != 2 {
		t.Fatalf("refused ceremonies audited %d times, want 2", failures)
	}
}
