package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Busness-app/kyidentity-server/internal/auth"
	"github.com/Busness-app/kyidentity-server/internal/crypto"
	"github.com/Busness-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

type stepUpFixture struct {
	srv     *Server
	store   *store.Store
	user    *store.User
	session *store.Session
	cookie  *http.Cookie
	csrf    string
	csrfCk  *http.Cookie
	pass    string
}

func newStepUpFixture(t *testing.T) (*stepUpFixture, func()) {
	t.Helper()
	srv, dbStore, _, _, _, cleanup := setupTestServer(t)

	pass := "CorrectHorseBattery1!"
	hash, _ := auth.HashPassword(pass)
	user := &store.User{
		ID: uuid.New().String(), Username: "stepup-" + uuid.New().String()[:8],
		DisplayName: "Step Up", Email: uuid.New().String()[:8] + "@stepup.test",
		PasswordHash: hash, Role: "user", Status: "active",
	}
	if err := dbStore.CreateUser(user); err != nil {
		t.Fatal(err)
	}

	token, _ := crypto.GenerateRandomHex(32)
	sess := &store.Session{
		ID: uuid.New().String(), UserID: user.ID,
		SessionTokenHash: crypto.HashSHA256(token),
		IPAddress:        "127.0.0.1", UserAgent: "Go-Test",
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}
	if err := dbStore.CreateSession(sess); err != nil {
		t.Fatal(err)
	}
	csrf := srv.middleware.IssueCSRFToken(token)

	return &stepUpFixture{
		srv: srv, store: dbStore, user: user, session: sess, pass: pass, csrf: csrf,
		cookie: &http.Cookie{Name: "kyidentity_session", Value: token},
		csrfCk: &http.Cookie{Name: "kyidentity_csrf", Value: csrf},
	}, cleanup
}

func (f *stepUpFixture) post(t *testing.T, path string, body any, stepUp string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest("POST", path, reader)
	req.AddCookie(f.cookie)
	req.AddCookie(f.csrfCk)
	req.Header.Set("X-CSRF-Token", f.csrf)
	req.Header.Set("Content-Type", "application/json")
	if stepUp != "" {
		req.Header.Set(StepUpHeader, stepUp)
	}
	w := httptest.NewRecorder()
	f.srv.httpServer.Handler.ServeHTTP(w, req)
	return w
}

func (f *stepUpFixture) grant(t *testing.T, operation string) string {
	t.Helper()
	w := f.post(t, "/api/auth/step-up", map[string]string{"password": f.pass, "operation": operation}, "")
	if w.Code != http.StatusOK {
		t.Fatalf("step-up request failed: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		StepUpToken string `json:"stepUpToken"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil || resp.StepUpToken == "" {
		t.Fatalf("step-up returned no token: %v", err)
	}
	return resp.StepUpToken
}

// A live session is not entitlement to replace the account's authentication factors. Without
// this, a stolen cookie that cannot pass the victim's MFA simply installs its own.
func TestMFAChangesRequireStepUp(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()

	for _, path := range []string{
		"/api/user/mfa/totp/setup",
		"/api/user/recovery-codes",
	} {
		w := f.post(t, path, nil, "")
		if w.Code != http.StatusForbidden {
			t.Errorf("%s allowed a session with no step-up grant (status %d)", path, w.Code)
		}
	}

	// A forged grant is not a grant.
	forged, _ := crypto.GenerateRandomHex(32)
	if w := f.post(t, "/api/user/recovery-codes", nil, forged); w.Code != http.StatusForbidden {
		t.Errorf("a fabricated step-up token was accepted (status %d)", w.Code)
	}
}

// The grant authorizes exactly one change.
func TestStepUpGrantIsSingleUse(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()

	token := f.grant(t, "POST /api/user/recovery-codes")
	if w := f.post(t, "/api/user/recovery-codes", nil, token); w.Code != http.StatusOK {
		t.Fatalf("first use of the grant failed: %d %s", w.Code, w.Body.String())
	}
	if w := f.post(t, "/api/user/recovery-codes", nil, token); w.Code != http.StatusForbidden {
		t.Errorf("the same step-up grant authorized a second change (status %d)", w.Code)
	}
}

// A wrong password must not produce a grant.
func TestStepUpRejectsWrongPassword(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()

	w := f.post(t, "/api/auth/step-up", map[string]string{"password": "not-the-password", "operation": "POST /api/user/recovery-codes"}, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a wrong password, got %d: %s", w.Code, w.Body.String())
	}
}

// The grant belongs to the session that earned it, so a second stolen session cannot ride it.
func TestStepUpGrantIsBoundToItsSession(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()

	token := f.grant(t, "POST /api/user/recovery-codes")

	otherRaw, _ := crypto.GenerateRandomHex(32)
	if err := f.store.CreateSession(&store.Session{
		ID: uuid.New().String(), UserID: f.user.ID,
		SessionTokenHash: crypto.HashSHA256(otherRaw),
		IPAddress:        "10.0.0.9", UserAgent: "Thief",
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	otherCSRF := f.srv.middleware.IssueCSRFToken(otherRaw)

	req := httptest.NewRequest("POST", "/api/user/recovery-codes", nil)
	req.AddCookie(&http.Cookie{Name: "kyidentity_session", Value: otherRaw})
	req.AddCookie(&http.Cookie{Name: "kyidentity_csrf", Value: otherCSRF})
	req.Header.Set("X-CSRF-Token", otherCSRF)
	req.Header.Set(StepUpHeader, token)
	w := httptest.NewRecorder()
	f.srv.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("a different session replayed another session's step-up grant (status %d)", w.Code)
	}
}

// Revoking access must burn unspent step-up grants along with everything else.
func TestRevokeUserAccessBurnsStepUpGrants(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()

	token := f.grant(t, "POST /api/user/recovery-codes")
	if err := f.store.RevokeUserAccess(f.user.ID); err != nil {
		t.Fatal(err)
	}
	spent, err := f.store.ConsumeStepUpToken(crypto.HashSHA256(token), f.user.ID, f.session.ID, "POST /api/user/recovery-codes")
	if err != nil {
		t.Fatal(err)
	}
	if spent {
		t.Error("a step-up grant survived a full access revocation")
	}
}

// Revocation must be all-or-nothing and must never report a success it did not achieve.
func TestAdminRevocationIsTransactional(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()

	// A second live session and an issued access token stand in for what an attacker holds.
	otherRaw, _ := crypto.GenerateRandomHex(32)
	if err := f.store.CreateSession(&store.Session{
		ID: uuid.New().String(), UserID: f.user.ID,
		SessionTokenHash: crypto.HashSHA256(otherRaw),
		IPAddress:        "10.0.0.9", UserAgent: "Thief",
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	jti := uuid.New().String()
	newClient(t, f.store, "spa", []string{"https://example.com/cb"}, []string{"openid"})
	if err := f.store.RecordIssuedToken(&store.IssuedToken{
		JTI: jti, UserID: f.user.ID, ClientID: "spa", SessionID: oauthSession(t, f.store, f.user.ID),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	if err := f.store.RevokeUserAccess(f.user.ID); err != nil {
		t.Fatalf("RevokeUserAccess: %v", err)
	}

	sess, err := f.store.GetSessionByTokenHash(crypto.HashSHA256(otherRaw), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if sess != nil {
		t.Error("a session survived revocation")
	}
	revoked, err := f.store.IsTokenRevoked(jti)
	if err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Error("an issued access token survived revocation")
	}
}

// Resetting MFA must remove the factors, cut every session, and revoke every token together.
func TestResetUserMFAIsAtomic(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()

	secret, _, err := f.srv.mfaEngine.GenerateTOTPSecret(f.user.Username, "KyIdentity")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.srv.mfaEngine.SaveUserTOTP(f.user.ID, secret, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.srv.mfaEngine.GenerateRecoveryCodes(f.user.ID, nil); err != nil {
		t.Fatal(err)
	}
	jti := uuid.New().String()
	newClient(t, f.store, "spa", []string{"https://example.com/cb"}, []string{"openid"})
	if err := f.store.RecordIssuedToken(&store.IssuedToken{
		JTI: jti, UserID: f.user.ID, ClientID: "spa", SessionID: oauthSession(t, f.store, f.user.ID),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	if err := f.srv.syncEngine.ResetUserMFAAndRevoke(f.user.ID, nil); err != nil {
		t.Fatalf("ResetUserMFAAndRevoke: %v", err)
	}

	methods, err := f.store.ListUserMFAMethods(f.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(methods) != 0 {
		t.Errorf("%d MFA method(s) survived the reset", len(methods))
	}
	codes, err := f.store.GetValidRecoveryCodes(f.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 0 {
		t.Errorf("%d recovery code(s) survived the reset", len(codes))
	}
	if revoked, err := f.store.IsTokenRevoked(jti); err != nil || !revoked {
		t.Errorf("an access token survived the MFA reset (revoked=%v err=%v)", revoked, err)
	}
	sess, err := f.store.GetSessionByTokenHash(f.session.SessionTokenHash, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if sess != nil {
		t.Error("a session survived the MFA reset")
	}
}
