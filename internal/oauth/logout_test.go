package oauth

import (
	"strings"
	"testing"
	"time"
)

func exchange(t *testing.T, e *Engine, clientID, sessionID string) map[string]any {
	t.Helper()
	verifier, challenge := pkcePair()
	code, err := e.CreateAuthorizationCode(clientID, sessionID, "https://app/cb", "openid", challenge, "S256")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := e.ExchangeAuthorizationCode(code, clientID, "", "https://app/cb", verifier)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := e.keyManager.VerifyJWT(resp.IDToken)
	if err != nil {
		t.Fatal(err)
	}
	return claims
}

// The sid lets a relying party name the login it wants ended without learning the internal
// session ID, and without two relying parties being able to correlate their users' logins.
func TestIDTokenCarriesAClientScopedSessionID(t *testing.T) {
	e, db, cleanup := setupTestOAuthEngine(t)
	defer cleanup()
	u := testUser(t, db)
	testClient(t, db, "app-a", "public", []string{"https://app/cb"}, []string{"openid"})
	testClient(t, db, "app-b", "public", []string{"https://app/cb"}, []string{"openid"})
	sess := oauthSession(t, db, u.ID)

	first, _ := exchange(t, e, "app-a", sess)["sid"].(string)
	second, _ := exchange(t, e, "app-a", sess)["sid"].(string)
	other, _ := exchange(t, e, "app-b", sess)["sid"].(string)
	if first == "" || first != second {
		t.Fatalf("sid should be stable for one client and session: %q %q", first, second)
	}
	if other == first || other == sess {
		t.Fatalf("sid must be client-scoped and opaque: %q", other)
	}
	if first == sess {
		t.Fatal("sid leaks the internal session ID")
	}
}

func TestDiscoveryAdvertisesEndSessionAndSID(t *testing.T) {
	e, _, cleanup := setupTestOAuthEngine(t)
	defer cleanup()
	cfg := e.GetOIDCConfiguration()
	if cfg.EndSessionEndpoint != cfg.Issuer+"/oauth/logout" {
		t.Fatalf("end_session_endpoint = %q", cfg.EndSessionEndpoint)
	}
	if !strings.Contains(strings.Join(cfg.ClaimsSupported, " "), "sid") {
		t.Fatal("sid missing from claims_supported")
	}
}

func TestIDTokenHintAcceptsExpiredButNotForgedOrForeignTokens(t *testing.T) {
	e, db, cleanup := setupTestOAuthEngine(t)
	defer cleanup()
	u := testUser(t, db)
	testClient(t, db, "app", "public", []string{"https://app/cb"}, []string{"openid"})
	sess := oauthSession(t, db, u.ID)
	verifier, challenge := pkcePair()
	code, err := e.CreateAuthorizationCode("app", sess, "https://app/cb", "openid", challenge, "S256")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := e.ExchangeAuthorizationCode(code, "app", "", "https://app/cb", verifier)
	if err != nil {
		t.Fatal(err)
	}

	hint, err := e.ParseIDTokenHint(resp.IDToken)
	if err != nil || hint.ClientID != "app" || hint.Subject != u.ID || hint.SID == "" {
		t.Fatalf("hint = %+v, %v", hint, err)
	}
	if _, err := e.ParseIDTokenHint(resp.AccessToken); err == nil {
		t.Fatal("an access token is not an ID token hint")
	}
	parts := strings.Split(resp.IDToken, ".")
	if _, err := e.ParseIDTokenHint(parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-2] + "AA"); err == nil {
		t.Fatal("tampered signature accepted")
	}

	expired, err := e.keyManager.SignJWT(map[string]any{"iss": e.issuerURL, "sub": u.ID, "aud": "app", "sid": hint.SID, "token_use": "id_token", "exp": time.Now().Add(-time.Hour).Unix(), "iat": time.Now().Add(-2 * time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if h, err := e.ParseIDTokenHint(expired); err != nil || h.SID != hint.SID {
		t.Fatalf("an expired ID token still identifies the login: %+v %v", h, err)
	}
	foreign, _ := e.keyManager.SignJWT(map[string]any{"iss": "https://other", "sub": u.ID, "aud": "app", "token_use": "id_token", "exp": time.Now().Add(time.Hour).Unix()})
	if _, err := e.ParseIDTokenHint(foreign); err == nil {
		t.Fatal("token from another issuer accepted")
	}
}
