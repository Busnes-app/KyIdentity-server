package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

func testClient(t *testing.T, db *store.Store, id, ctype string, uris, scopes []string) *store.OAuthClient {
	t.Helper()
	u, _ := json.Marshal(uris)
	s, _ := json.Marshal(scopes)
	c := &store.OAuthClient{
		ID: id, ClientName: id, ClientType: ctype,
		RedirectURIsJSON: string(u), AllowedScopesJSON: string(s), Enabled: true,
	}
	if err := db.CreateOAuthClient(c); err != nil {
		t.Fatalf("CreateOAuthClient: %v", err)
	}
	allowTestAppAccess(t, db, id)
	return c
}

func testUser(t *testing.T, db *store.Store) *store.User {
	t.Helper()
	u := &store.User{
		ID: uuid.New().String(), Username: "u" + uuid.New().String()[:8],
		DisplayName: "U", Email: uuid.New().String()[:8] + "@x.test",
		PasswordHash: "x", Role: "user", Status: "active",
	}
	if err := db.CreateUser(u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return u
}

func pkcePair() (verifier, challenge string) {
	verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(h[:])
}

// A redirect URI must match a registered one exactly. Host aliases, path suffix rules,
// and per-client fallbacks all turn registration into a suggestion.
func TestRedirectURIRequiresExactRegisteredMatch(t *testing.T) {
	e, db, cleanup := setupTestOAuthEngine(t)
	defer cleanup()

	suite := testClient(t, db, "kypasswords", "public",
		[]string{"https://passwords.urlxl.com/callback"}, []string{"openid"})
	notes := testClient(t, db, "kynotes", "public",
		[]string{"https://notes.urlxl.com/callback"}, []string{"openid"})
	empty := testClient(t, db, "kypost", "public", []string{}, []string{"openid"})
	custom := testClient(t, db, "custom", "public",
		[]string{"https://app.example.com/oauth/callback"}, []string{"openid"})

	rejected := []struct {
		name   string
		client *store.OAuthClient
		uri    string
	}{
		{"localhost default port via suite fallback", suite, "http://localhost/callback"},
		{"attacker path on an allowlisted port", notes, "http://localhost:8080/attacker/owned/callback"},
		{"client with no registered URIs at all", empty, "https://mail.urlxl.com/anything/callback"},
		{"different path on a registered host", custom, "https://app.example.com/totally/different/callback"},
		{"hardcoded container IP", suite, "http://10.89.0.4/callback"},
		{"scheme downgrade", custom, "http://app.example.com/oauth/callback"},
		{"open redirect via userinfo host", suite, "https://evil.tld/callback"},
		{"subdomain of a registered host", custom, "https://evil.app.example.com/oauth/callback"},
		{"trailing junk after the registered path", custom, "https://app.example.com/oauth/callback/../../evil"},
		{"empty uri", custom, ""},
	}
	for _, c := range rejected {
		if e.ValidateRedirectURI(c.client, c.uri) {
			t.Errorf("%s: %q was accepted for client %q (registered: %s)",
				c.name, c.uri, c.client.ID, c.client.RedirectURIsJSON)
		}
	}

	accepted := []struct {
		client *store.OAuthClient
		uri    string
	}{
		{suite, "https://passwords.urlxl.com/callback"},
		{notes, "https://notes.urlxl.com/callback"},
		{custom, "https://app.example.com/oauth/callback"},
	}
	for _, c := range accepted {
		if !e.ValidateRedirectURI(c.client, c.uri) {
			t.Errorf("registered URI %q was rejected for client %q", c.uri, c.client.ID)
		}
	}
}

// Public clients have no secret, so PKCE is the only thing binding a code to its requester.
func TestPublicClientCannotSkipPKCE(t *testing.T) {
	e, db, cleanup := setupTestOAuthEngine(t)
	defer cleanup()
	testClient(t, db, "kynotes", "public", []string{"https://notes.urlxl.com/callback"}, []string{"openid"})
	u := testUser(t, db)

	code, err := e.CreateAuthorizationCode("kynotes", oauthSession(t, db, u.ID), "https://notes.urlxl.com/callback", "openid", "", "")
	if err == nil {
		if _, err := e.ExchangeAuthorizationCode(code, "kynotes", "", "https://notes.urlxl.com/callback", ""); err == nil {
			t.Error("a public client redeemed a code with no PKCE challenge and no secret")
		}
		return
	}
	// Rejecting at code creation is also acceptable, and stricter.
}

func TestPKCEVerifierIsEnforced(t *testing.T) {
	e, db, cleanup := setupTestOAuthEngine(t)
	defer cleanup()
	testClient(t, db, "kynotes", "public", []string{"https://notes.urlxl.com/callback"}, []string{"openid"})
	u := testUser(t, db)
	verifier, challenge := pkcePair()

	code, err := e.CreateAuthorizationCode("kynotes", oauthSession(t, db, u.ID), "https://notes.urlxl.com/callback", "openid", challenge, "S256")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.ExchangeAuthorizationCode(code, "kynotes", "", "https://notes.urlxl.com/callback", "wrong-verifier"); err == nil {
		t.Error("a wrong code_verifier was accepted")
	}

	code, _ = e.CreateAuthorizationCode("kynotes", oauthSession(t, db, u.ID), "https://notes.urlxl.com/callback", "openid", challenge, "S256")
	if _, err := e.ExchangeAuthorizationCode(code, "kynotes", "", "https://notes.urlxl.com/callback", verifier); err != nil {
		t.Errorf("the correct code_verifier was rejected: %v", err)
	}
}

// plain leaves the challenge equal to the verifier, so anyone who sees the authorize
// request can complete the exchange. Only S256 is acceptable.
func TestPlainPKCEIsRejected(t *testing.T) {
	e, db, cleanup := setupTestOAuthEngine(t)
	defer cleanup()
	testClient(t, db, "kynotes", "public", []string{"https://notes.urlxl.com/callback"}, []string{"openid"})
	u := testUser(t, db)

	code, err := e.CreateAuthorizationCode("kynotes", oauthSession(t, db, u.ID), "https://notes.urlxl.com/callback", "openid", "plainsecret", "plain")
	if err == nil {
		if _, err := e.ExchangeAuthorizationCode(code, "kynotes", "", "https://notes.urlxl.com/callback", "plainsecret"); err == nil {
			t.Error("plain PKCE was accepted")
		}
	}
	if ValidatePKCE("x", "x", "plain") {
		t.Error("ValidatePKCE still accepts the plain method")
	}
	if ValidatePKCE("x", "x", "") {
		t.Error("ValidatePKCE treats an empty method as plain")
	}
}

func TestConfidentialClientRequiresCorrectSecret(t *testing.T) {
	e, db, cleanup := setupTestOAuthEngine(t)
	defer cleanup()

	secret := "s3cret-value"
	c := testClient(t, db, "kypost", "confidential", []string{"https://mail.urlxl.com/callback"}, []string{"openid"})
	c.ClientSecretHash = hashFor(secret)
	if err := db.UpdateOAuthClient(c); err != nil {
		t.Fatal(err)
	}
	u := testUser(t, db)
	verifier, challenge := pkcePair()

	code, _ := e.CreateAuthorizationCode("kypost", oauthSession(t, db, u.ID), "https://mail.urlxl.com/callback", "openid", challenge, "S256")
	if _, err := e.ExchangeAuthorizationCode(code, "kypost", "", "https://mail.urlxl.com/callback", verifier); err == nil {
		t.Error("a confidential client redeemed a code with an empty secret")
	}

	code, _ = e.CreateAuthorizationCode("kypost", oauthSession(t, db, u.ID), "https://mail.urlxl.com/callback", "openid", challenge, "S256")
	if _, err := e.ExchangeAuthorizationCode(code, "kypost", "wrong", "https://mail.urlxl.com/callback", verifier); err == nil {
		t.Error("a confidential client redeemed a code with the wrong secret")
	}

	code, _ = e.CreateAuthorizationCode("kypost", oauthSession(t, db, u.ID), "https://mail.urlxl.com/callback", "openid", challenge, "S256")
	if _, err := e.ExchangeAuthorizationCode(code, "kypost", secret, "https://mail.urlxl.com/callback", verifier); err != nil {
		t.Errorf("the correct client secret was rejected: %v", err)
	}
}

// A confidential client with no secret configured must not authenticate by existing.
func TestConfidentialClientWithNoSecretCannotAuthenticate(t *testing.T) {
	e, db, cleanup := setupTestOAuthEngine(t)
	defer cleanup()
	testClient(t, db, "broken", "confidential", []string{"https://x.test/callback"}, []string{"openid"})
	u := testUser(t, db)
	verifier, challenge := pkcePair()

	code, _ := e.CreateAuthorizationCode("broken", oauthSession(t, db, u.ID), "https://x.test/callback", "openid", challenge, "S256")
	if _, err := e.ExchangeAuthorizationCode(code, "broken", "", "https://x.test/callback", verifier); err == nil {
		t.Error("a confidential client with no stored secret was authenticated")
	}
}

func TestAuthorizationCodeIsSingleUseUnderConcurrency(t *testing.T) {
	e, db, cleanup := setupTestOAuthEngine(t)
	defer cleanup()
	testClient(t, db, "kydns", "public", []string{"https://dns.urlxl.com/callback"}, []string{"openid"})
	u := testUser(t, db)
	verifier, challenge := pkcePair()

	for attempt := 0; attempt < 25; attempt++ {
		code, err := e.CreateAuthorizationCode("kydns", oauthSession(t, db, u.ID), "https://dns.urlxl.com/callback", "openid", challenge, "S256")
		if err != nil {
			t.Fatal(err)
		}
		var mu sync.Mutex
		successes := 0
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if _, err := e.ExchangeAuthorizationCode(code, "kydns", "", "https://dns.urlxl.com/callback", verifier); err == nil {
					mu.Lock()
					successes++
					mu.Unlock()
				}
			}()
		}
		close(start)
		wg.Wait()
		if successes != 1 {
			t.Fatalf("attempt %d: authorization code redeemed %d times, want exactly 1", attempt, successes)
		}
	}
}

func TestGrantedScopeIsIntersectedWithClientAllowlist(t *testing.T) {
	e, db, cleanup := setupTestOAuthEngine(t)
	defer cleanup()
	testClient(t, db, "kynotes", "public", []string{"https://notes.urlxl.com/callback"}, []string{"openid", "profile"})
	u := testUser(t, db)
	verifier, challenge := pkcePair()

	granted, err := e.GrantedScope("kynotes", "openid admin vault:read profile")
	if err != nil {
		t.Fatalf("GrantedScope: %v", err)
	}
	for _, forbidden := range []string{"admin", "vault:read"} {
		if strings.Contains(granted, forbidden) {
			t.Errorf("scope %q leaked into the granted scope %q", forbidden, granted)
		}
	}

	code, _ := e.CreateAuthorizationCode("kynotes", oauthSession(t, db, u.ID), "https://notes.urlxl.com/callback", granted, challenge, "S256")
	resp, err := e.ExchangeAuthorizationCode(code, "kynotes", "", "https://notes.urlxl.com/callback", verifier)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(resp.Scope, "admin") {
		t.Errorf("token carries an unallowed scope: %q", resp.Scope)
	}
}

func TestRequestingOnlyForbiddenScopesIsAnError(t *testing.T) {
	e, db, cleanup := setupTestOAuthEngine(t)
	defer cleanup()
	testClient(t, db, "kynotes", "public", []string{"https://notes.urlxl.com/callback"}, []string{"openid"})

	if _, err := e.GrantedScope("kynotes", "admin vault:write"); err == nil {
		t.Error("a request for only unallowed scopes was not an error")
	}
}

// An ID token is handed to the browser. An access token is a credential. They must not
// be interchangeable at the userinfo endpoint.
func TestUserinfoRejectsIDToken(t *testing.T) {
	e, db, cleanup := setupTestOAuthEngine(t)
	defer cleanup()
	testClient(t, db, "kybookmarks", "public", []string{"https://bookmarks.urlxl.com/callback"}, []string{"openid", "profile"})
	u := testUser(t, db)
	verifier, challenge := pkcePair()

	code, _ := e.CreateAuthorizationCode("kybookmarks", oauthSession(t, db, u.ID), "https://bookmarks.urlxl.com/callback", "openid profile", challenge, "S256")
	resp, err := e.ExchangeAuthorizationCode(code, "kybookmarks", "", "https://bookmarks.urlxl.com/callback", verifier)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IDToken == "" {
		t.Fatal("expected an id_token for the openid scope")
	}

	if _, err := e.GetUserinfo(resp.IDToken); err == nil {
		t.Error("an ID token was accepted as a bearer credential at userinfo")
	}
	if _, err := e.GetUserinfo(resp.AccessToken); err != nil {
		t.Errorf("the access token was rejected at userinfo: %v", err)
	}
}

// A token minted by a different issuer with the same key must not be honoured.
func TestUserinfoChecksIssuer(t *testing.T) {
	e, db, cleanup := setupTestOAuthEngine(t)
	defer cleanup()
	u := testUser(t, db)

	foreign, err := e.keyManager.SignJWT(map[string]any{
		"iss": "https://evil.example.com", "sub": u.ID, "token_use": "access_token",
		"exp": 1 << 40, "aud": "kynotes",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.GetUserinfo(foreign); err == nil {
		t.Error("userinfo accepted a token issued by another issuer")
	}
}

func TestNonceIsEchoedIntoIDToken(t *testing.T) {
	e, db, cleanup := setupTestOAuthEngine(t)
	defer cleanup()
	testClient(t, db, "kynotes", "public", []string{"https://notes.urlxl.com/callback"}, []string{"openid"})
	u := testUser(t, db)
	verifier, challenge := pkcePair()

	code, err := e.CreateAuthorizationCodeWithNonce("kynotes", oauthSession(t, db, u.ID), "https://notes.urlxl.com/callback",
		"openid", challenge, "S256", "n-0S6_WzA2Mj")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := e.ExchangeAuthorizationCode(code, "kynotes", "", "https://notes.urlxl.com/callback", verifier)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := e.keyManager.VerifyJWT(resp.IDToken)
	if err != nil {
		t.Fatal(err)
	}
	if claims["nonce"] != "n-0S6_WzA2Mj" {
		t.Errorf("id_token nonce = %v, want the nonce from the authorize request", claims["nonce"])
	}
}

func TestDiscoveryAdvertisesOnlyWhatIsImplemented(t *testing.T) {
	e, _, cleanup := setupTestOAuthEngine(t)
	defer cleanup()
	cfg := e.GetOIDCConfiguration()

	for _, m := range cfg.CodeChallengeMethodsSupported {
		if m == "plain" {
			t.Error("discovery advertises the plain PKCE method, which is rejected")
		}
	}
	if cfg.RevocationEndpoint != "" && !e.SupportsRevocation() {
		t.Error("discovery advertises a revocation endpoint that does not revoke anything")
	}
}

func hashFor(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hexEncode(sum[:])
}

func hexEncode(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0x0f]
	}
	return string(out)
}

// A failed exchange must not burn a legitimate code. Consuming before validating turned any
// party who could observe or guess a code into a reliable login-denial: submit it once with
// a junk verifier and the real client is told it has already been redeemed.
func TestFailedExchangeDoesNotBurnTheCode(t *testing.T) {
	e, db, cleanup := setupTestOAuthEngine(t)
	defer cleanup()

	user := testUser(t, db)
	client := testClient(t, db, "spa", "public",
		[]string{"https://app.example.com/cb"}, []string{"openid"})
	verifier, challenge := pkcePair()

	attempts := []struct {
		name                                        string
		clientID, secret, redirectURI, codeVerifier string
	}{
		{"wrong PKCE verifier", client.ID, "", "https://app.example.com/cb", "attacker-chosen-verifier-value-000000000000"},
		{"wrong redirect URI", client.ID, "", "https://evil.example.com/cb", verifier},
		{"wrong client", "someone-else", "", "https://app.example.com/cb", verifier},
	}

	for _, attempt := range attempts {
		code, err := e.CreateAuthorizationCode(client.ID, oauthSession(t, db, user.ID), "https://app.example.com/cb", "openid", challenge, "S256")
		if err != nil {
			t.Fatal(err)
		}

		if _, err := e.ExchangeAuthorizationCode(code, attempt.clientID, attempt.secret, attempt.redirectURI, attempt.codeVerifier); err == nil {
			t.Fatalf("%s: the exchange succeeded", attempt.name)
		}

		// The legitimate client must still be able to redeem its own code.
		tok, err := e.ExchangeAuthorizationCode(code, client.ID, "", "https://app.example.com/cb", verifier)
		if err != nil {
			t.Errorf("%s burned the code: the legitimate exchange then failed with %v", attempt.name, err)
			continue
		}
		if tok.AccessToken == "" {
			t.Errorf("%s: legitimate exchange returned no access token", attempt.name)
		}

		// Single use still holds.
		if _, err := e.ExchangeAuthorizationCode(code, client.ID, "", "https://app.example.com/cb", verifier); err == nil {
			t.Errorf("%s: the code was redeemable twice", attempt.name)
		}
	}
}

// Concurrent redemptions of one valid code must yield exactly one token.
func TestValidCodeIsRedeemableExactlyOnceUnderRace(t *testing.T) {
	e, db, cleanup := setupTestOAuthEngine(t)
	defer cleanup()

	user := testUser(t, db)
	client := testClient(t, db, "spa", "public", []string{"https://app.example.com/cb"}, []string{"openid"})
	verifier, challenge := pkcePair()
	code, err := e.CreateAuthorizationCode(client.ID, oauthSession(t, db, user.ID), "https://app.example.com/cb", "openid", challenge, "S256")
	if err != nil {
		t.Fatal(err)
	}

	const racers = 8
	var wg sync.WaitGroup
	results := make(chan error, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.ExchangeAuthorizationCode(code, client.ID, "", "https://app.example.com/cb", verifier)
			results <- err
		}()
	}
	wg.Wait()
	close(results)

	var succeeded int
	for err := range results {
		if err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Errorf("expected exactly one successful redemption, got %d", succeeded)
	}
}
