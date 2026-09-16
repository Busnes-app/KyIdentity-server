package api

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Busnes-app/kyidentity-server/internal/auth"
	"github.com/Busnes-app/kyidentity-server/internal/mfa"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// testAuthenticator is a software authenticator good enough to exercise the endpoints.
type testAuthenticator struct {
	key       *ecdsa.PrivateKey
	credID    string
	signCount uint32
}

func newTestAuthenticator(t *testing.T, credID string) *testAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return &testAuthenticator{key: key, credID: credID}
}

func (a *testAuthenticator) spkiB64(t *testing.T) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&a.key.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(der)
}

func (a *testAuthenticator) authData(rpID string, flags byte) []byte {
	h := sha256.Sum256([]byte(rpID))
	b := make([]byte, 37)
	copy(b, h[:])
	b[32] = flags
	binary.BigEndian.PutUint32(b[33:37], a.signCount)
	return b
}

func (a *testAuthenticator) clientData(t *testing.T, typ, challenge, origin string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": origin, "crossOrigin": false})
	if err != nil {
		t.Fatalf("marshal client data: %v", err)
	}
	return b
}

func (a *testAuthenticator) sign(t *testing.T, ad, cdj []byte) string {
	t.Helper()
	cdHash := sha256.Sum256(cdj)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(sig)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// do issues a GET or DELETE with the fixture's session and CSRF credentials.
// stepUpFixture.post already covers POST; the passkey routes also need these two verbs.
func (f *stepUpFixture) do(t *testing.T, method, path, stepUp string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.AddCookie(f.cookie)
	req.AddCookie(f.csrfCk)
	req.Header.Set("X-CSRF-Token", f.csrf)
	if stepUp != "" {
		req.Header.Set(StepUpHeader, stepUp)
	}
	w := httptest.NewRecorder()
	f.srv.httpServer.Handler.ServeHTTP(w, req)
	return w
}

// anonPost issues an unauthenticated JSON POST with a self-consistent CSRF pair, which is
// all the double-submit check requires of a caller that holds no session.
func anonPost(t *testing.T, srv *Server, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	csrf := "test-csrf-" + uuid.New().String()
	req.AddCookie(&http.Cookie{Name: "kyidentity_csrf", Value: csrf})
	req.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(w, req)
	return w
}

func TestPasskeyRegistrationRequiresStepUp(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()

	rec := f.post(t, "/api/user/passkeys/register/begin", map[string]string{"name": "KyAuth"}, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("begin without a step-up grant returned %d, want 403: %s", rec.Code, rec.Body.String())
	}
}

func TestPasskeyRegistrationRoundTrip(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()

	a := newTestAuthenticator(t, "Y3JlZC1vbmU")

	rec := f.post(t, "/api/user/passkeys/register/begin", map[string]string{"name": "KyAuth on Pixel"}, f.grant(t, "POST /api/user/passkeys/register/finish"))
	if rec.Code != http.StatusOK {
		t.Fatalf("begin returned %d: %s", rec.Code, rec.Body.String())
	}

	var begun struct {
		Challenge string `json:"challenge"`
		RPID      string `json:"rpId"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &begun); err != nil {
		t.Fatalf("decode begin response: %v", err)
	}
	if begun.Challenge == "" || begun.RPID != "localhost" {
		t.Fatalf("unexpected begin response: %+v", begun)
	}

	ad := a.authData(begun.RPID, 0x01|0x04|0x40)
	cdj := a.clientData(t, "webauthn.create", begun.Challenge, "http://localhost:5867")
	rec = f.post(t, "/api/user/passkeys/register/finish", map[string]string{
		"credentialId":      a.credID,
		"authenticatorData": b64(ad),
		"clientDataJSON":    b64(cdj),
		"publicKey":         a.spkiB64(t),
		"name":              "KyAuth on Pixel",
	}, f.grant(t, "POST /api/user/passkeys/register/finish"))
	if rec.Code != http.StatusOK {
		t.Fatalf("finish returned %d: %s", rec.Code, rec.Body.String())
	}

	creds, err := f.store.ListUserWebAuthnCredentials(f.user.ID)
	if err != nil || len(creds) != 1 {
		t.Fatalf("expected one stored credential, got %d (%v)", len(creds), err)
	}
	if creds[0].Name != "KyAuth on Pixel" {
		t.Fatalf("credential name = %q", creds[0].Name)
	}
}

func TestPasskeyRegistrationRejectsForeignOrigin(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()

	a := newTestAuthenticator(t, "Y3JlZC1ldmls")

	rec := f.post(t, "/api/user/passkeys/register/begin", map[string]string{"name": "evil"}, f.grant(t, "POST /api/user/passkeys/register/finish"))
	var begun struct {
		Challenge string `json:"challenge"`
		RPID      string `json:"rpId"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &begun); err != nil {
		t.Fatalf("decode begin response: %v", err)
	}

	ad := a.authData(begun.RPID, 0x01)
	cdj := a.clientData(t, "webauthn.create", begun.Challenge, "https://evil.example.com")
	rec = f.post(t, "/api/user/passkeys/register/finish", map[string]string{
		"credentialId":      a.credID,
		"authenticatorData": b64(ad),
		"clientDataJSON":    b64(cdj),
		"publicKey":         a.spkiB64(t),
		"name":              "evil",
	}, f.grant(t, "POST /api/user/passkeys/register/finish"))

	if rec.Code == http.StatusOK {
		t.Fatal("a ceremony completed at another origin must not enrol a credential")
	}
}

// enrolPasskey registers a credential directly in the store, so login tests do not depend
// on the enrolment endpoints.
func enrolPasskey(t *testing.T, dbStore *store.Store, userID string, a *testAuthenticator) {
	t.Helper()
	if err := dbStore.CreateWebAuthnCredential(&store.WebAuthnCredential{
		ID:            uuid.New().String(),
		UserID:        userID,
		CredentialID:  a.credID,
		PublicKeySPKI: a.spkiB64(t),
		Name:          "test key",
	}, nil); err != nil {
		t.Fatalf("CreateWebAuthnCredential: %v", err)
	}
}

// passwordLogin performs the first leg and returns the second-factor token.
func passwordLogin(t *testing.T, srv *Server, username, password string) string {
	t.Helper()
	rec := anonPost(t, srv, "/api/auth/login", map[string]string{"username": username, "password": password})
	var resp struct {
		MFAToken string `json:"mfaToken"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.MFAToken == "" {
		t.Fatalf("login did not return an mfa token (%d): %s", rec.Code, rec.Body.String())
	}
	return resp.MFAToken
}

func TestLoginAdvertisesPasskeyMethod(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()

	enrolPasskey(t, f.store, f.user.ID, newTestAuthenticator(t, "Y3JlZC1sb2dpbg"))

	rec := anonPost(t, f.srv, "/api/auth/login", map[string]string{"username": f.user.Username, "password": f.pass})
	var resp struct {
		MFARequired bool     `json:"mfaRequired"`
		MFAMethods  []string `json:"mfaMethods"`
		MFAToken    string   `json:"mfaToken"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if !resp.MFARequired || resp.MFAToken == "" {
		t.Fatalf("a user with only a passkey must be challenged: %+v", resp)
	}
	found := false
	for _, m := range resp.MFAMethods {
		if m == "webauthn" {
			found = true
		}
	}
	if !found {
		t.Fatalf("mfaMethods = %v, want it to contain webauthn", resp.MFAMethods)
	}
}

// assertionFields drives the begin leg and returns a ready-to-post verify body signed by a.
// checkAllow is skipped for the cross-account test, whose whole point is presenting a
// credential the allow-list does not contain.
func assertionFields(t *testing.T, srv *Server, mfaToken string, a *testAuthenticator, checkAllow bool) map[string]string {
	t.Helper()

	rec := anonPost(t, srv, "/api/auth/mfa/webauthn/begin", map[string]string{"mfaToken": mfaToken})
	if rec.Code != http.StatusOK {
		t.Fatalf("begin returned %d: %s", rec.Code, rec.Body.String())
	}
	var begun struct {
		Challenge        string   `json:"challenge"`
		RPID             string   `json:"rpId"`
		AllowCredentials []string `json:"allowCredentials"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &begun); err != nil {
		t.Fatalf("decode begin response: %v", err)
	}
	if checkAllow && (len(begun.AllowCredentials) != 1 || begun.AllowCredentials[0] != a.credID) {
		t.Fatalf("allowCredentials = %v", begun.AllowCredentials)
	}

	a.signCount++
	ad := a.authData(begun.RPID, 0x01|0x04)
	cdj := a.clientData(t, "webauthn.get", begun.Challenge, "http://localhost:5867")
	return map[string]string{
		"mfaToken":          mfaToken,
		"credentialId":      a.credID,
		"authenticatorData": b64(ad),
		"clientDataJSON":    b64(cdj),
		"signature":         a.sign(t, ad, cdj),
	}
}

func TestPasskeyLoginIssuesSession(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()

	a := newTestAuthenticator(t, "Y3JlZC1sb2dpbg")
	enrolPasskey(t, f.store, f.user.ID, a)

	mfaToken := passwordLogin(t, f.srv, f.user.Username, f.pass)
	rec := anonPost(t, f.srv, "/api/auth/mfa/webauthn/verify", assertionFields(t, f.srv, mfaToken, a, true))
	if rec.Code != http.StatusOK {
		t.Fatalf("verify returned %d: %s", rec.Code, rec.Body.String())
	}

	assertFactorEvidence(t, f.store, rec, "webauthn")
	sessionIssued := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == "kyidentity_session" && c.Value != "" {
			sessionIssued = true
		}
	}
	if !sessionIssued {
		t.Fatal("a verified passkey assertion must issue a session cookie")
	}

	creds, _ := f.store.ListUserWebAuthnCredentials(f.user.ID)
	if creds[0].SignCount != 1 || creds[0].LastUsedAt == nil {
		t.Fatalf("use was not recorded on the credential: %+v", creds[0])
	}
}

func TestPasskeyLoginRejectsForgedSignature(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()

	a := newTestAuthenticator(t, "Y3JlZC1sb2dpbg")
	enrolPasskey(t, f.store, f.user.ID, a)

	mfaToken := passwordLogin(t, f.srv, f.user.Username, f.pass)
	fields := assertionFields(t, f.srv, mfaToken, a, true)
	fields["signature"] = b64([]byte("not a signature"))

	if rec := anonPost(t, f.srv, "/api/auth/mfa/webauthn/verify", fields); rec.Code == http.StatusOK {
		t.Fatal("a forged signature must not issue a session")
	}
}

func TestPasskeyAssertionIsSingleUse(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()

	a := newTestAuthenticator(t, "Y3JlZC1sb2dpbg")
	enrolPasskey(t, f.store, f.user.ID, a)

	mfaToken := passwordLogin(t, f.srv, f.user.Username, f.pass)
	fields := assertionFields(t, f.srv, mfaToken, a, true)

	if rec := anonPost(t, f.srv, "/api/auth/mfa/webauthn/verify", fields); rec.Code != http.StatusOK {
		t.Fatalf("first verify returned %d: %s", rec.Code, rec.Body.String())
	}
	if rec := anonPost(t, f.srv, "/api/auth/mfa/webauthn/verify", fields); rec.Code == http.StatusOK {
		t.Fatal("a replayed assertion must not issue a second session")
	}
}

func TestPasskeyLoginRejectsAnotherUsersCredential(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()

	// The victim holds their own passkey; the attacker holds one enrolled to a different
	// account and presents it against the victim's second-factor token.
	enrolPasskey(t, f.store, f.user.ID, newTestAuthenticator(t, "Y3JlZC12aWN0aW0"))

	hash, err := auth.HashPassword("AttackerPassword1!")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	attacker := &store.User{
		ID: uuid.New().String(), Username: "attacker-" + uuid.New().String()[:8],
		DisplayName: "Attacker", Email: uuid.New().String()[:8] + "@attacker.test",
		PasswordHash: hash, Role: "user", Status: "active",
	}
	if err := f.store.CreateUser(attacker); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	attackerAuth := newTestAuthenticator(t, "Y3JlZC1hdHRhY2tlcg")
	enrolPasskey(t, f.store, attacker.ID, attackerAuth)

	mfaToken := passwordLogin(t, f.srv, f.user.Username, f.pass)
	fields := assertionFields(t, f.srv, mfaToken, attackerAuth, false)

	if rec := anonPost(t, f.srv, "/api/auth/mfa/webauthn/verify", fields); rec.Code == http.StatusOK {
		t.Fatal("a credential belonging to another account must not satisfy this user's challenge")
	}
}

// TestPasskeyMalformedCeremonyCountsAsFailure proves a client holding a valid mfaToken
// cannot submit unparseable ceremony fields for free. If malformed input stopped counting
// against the token's attempt budget, this loop would keep returning 400 forever; instead
// the token itself becomes invalid once the budget is exhausted, and every subsequent
// request — malformed or not — fails token resolution first.
func TestPasskeyMalformedCeremonyCountsAsFailure(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()

	a := newTestAuthenticator(t, "Y3JlZC1sb2dpbg")
	enrolPasskey(t, f.store, f.user.ID, a)

	mfaToken := passwordLogin(t, f.srv, f.user.Username, f.pass)

	malformed := map[string]string{
		"mfaToken":          mfaToken,
		"credentialId":      a.credID,
		"authenticatorData": "not valid base64url!!",
		"clientDataJSON":    b64([]byte(`{"type":"webauthn.get","challenge":"x"}`)),
		"signature":         b64([]byte("sig")),
	}

	for i := 0; i < mfa.MaxMFAAttempts; i++ {
		rec := anonPost(t, f.srv, "/api/auth/mfa/webauthn/verify", malformed)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("malformed attempt %d returned %d, want 400: %s", i+1, rec.Code, rec.Body.String())
		}
	}

	// The budget is now exhausted. A further request against the same token must fail at
	// token resolution (401), not at field parsing (400) — proof the malformed attempts
	// above were each counted via RegisterMFAFailure.
	rec := anonPost(t, f.srv, "/api/auth/mfa/webauthn/verify", malformed)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("verify after exhausting the attempt budget returned %d, want 401 (token invalid): %s", rec.Code, rec.Body.String())
	}
}

func TestListAndDeletePasskeys(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()

	enrolPasskey(t, f.store, f.user.ID, newTestAuthenticator(t, "Y3JlZC1saXN0"))

	rec := f.do(t, http.MethodGet, "/api/user/passkeys", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list returned %d: %s", rec.Code, rec.Body.String())
	}

	var listed []struct {
		ID            string `json:"id"`
		Name          string `json:"name"`
		PublicKeySPKI string `json:"publicKeySpki"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listed) != 1 || listed[0].Name != "test key" {
		t.Fatalf("unexpected list: %+v", listed)
	}
	if listed[0].PublicKeySPKI != "" {
		t.Fatal("the credential public key must not be serialised to clients")
	}

	// Removing a factor is destructive, so it costs a step-up grant.
	rec = f.do(t, http.MethodDelete, "/api/user/passkeys/"+listed[0].ID, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("delete without step-up returned %d, want 403: %s", rec.Code, rec.Body.String())
	}

	rec = f.do(t, http.MethodDelete, "/api/user/passkeys/"+listed[0].ID, mintStepUp(t, f.srv, f.cookie.Value, "DELETE /api/user/passkeys/"+listed[0].ID))
	if rec.Code != http.StatusOK {
		t.Fatalf("delete returned %d: %s", rec.Code, rec.Body.String())
	}

	remaining, _ := f.store.ListUserWebAuthnCredentials(f.user.ID)
	if len(remaining) != 0 {
		t.Fatalf("%d passkeys survived deletion", len(remaining))
	}
}
