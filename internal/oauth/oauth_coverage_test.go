package oauth

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// covFailWrites makes every op (INSERT or UPDATE) on table fail inside SQLite, so a test
// can prove the engine refuses rather than issues when that write is lost.
func covFailWrites(t *testing.T, raw *sql.DB, table, op string) {
	t.Helper()
	name := "cov_fail_" + table + "_" + strings.ToLower(op)
	if _, err := raw.Exec(`CREATE TRIGGER ` + name + ` BEFORE ` + op + ` ON ` + table + ` BEGIN SELECT RAISE(ABORT, 'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
}

// covCodeFor issues an authorization code on the refresh fixture's confidential client.
func (f *refreshFixture) covCodeFor(scope string) (code, verifier string) {
	f.t.Helper()
	verifier, challenge := pkcePair()
	code, err := f.e.CreateAuthorizationCode(f.client.ID, f.session, "https://app.example/cb", scope, challenge, "S256")
	if err != nil {
		f.t.Fatal(err)
	}
	return code, verifier
}

func (f *refreshFixture) covCount(query string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.raw.QueryRow(query, args...).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

// RFC 7009: a client revokes its own access tokens; another client's authenticated
// request is a silent no-op (no oracle), and unauthenticated callers are refused.
func TestRevokeTokenEndsAccessTokenOnlyForItsOwnClient(t *testing.T) {
	f := newRefreshFixture(t)
	resp := f.login("openid")
	other := f.newClient("kypost", "confidential")

	// An authenticated foreign client cannot revoke this client's token.
	if err := f.e.RevokeToken(resp.AccessToken, other.ID, f.secret); err != nil {
		t.Fatalf("foreign revoke must be a silent no-op, got %v", err)
	}
	if _, err := f.e.GetUserinfo(resp.AccessToken); err != nil {
		t.Fatalf("foreign client revoked the token: %v", err)
	}
	// Refused callers: wrong secret, unknown client, disabled client.
	if err := f.e.RevokeToken(resp.AccessToken, f.client.ID, "wrong"); err == nil {
		t.Fatal("revoke with a wrong client secret accepted")
	}
	if err := f.e.RevokeToken(resp.AccessToken, "no-such-client", f.secret); err == nil {
		t.Fatal("revoke by an unknown client accepted")
	}
	f.exec(`UPDATE oauth_clients SET enabled=0 WHERE id=?`, other.ID)
	if err := f.e.RevokeToken(resp.AccessToken, other.ID, f.secret); err == nil {
		t.Fatal("revoke by a disabled client accepted")
	}
	if n := f.covCount(`SELECT COUNT(*) FROM issued_tokens WHERE revoked_at IS NOT NULL`); n != 0 {
		t.Fatalf("refused revocations revoked %d token(s)", n)
	}

	// A signed token of ours without a jti names nothing to revoke: still not an error.
	noJTI, err := f.e.keyManager.SignJWT(map[string]any{"iss": f.e.issuerURL, "aud": f.client.ID, "token_use": "access_token", "exp": time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.e.RevokeToken(noJTI, f.client.ID, f.secret); err != nil {
		t.Fatalf("jti-less token: %v", err)
	}

	// The owner revokes: the registry marks it and userinfo refuses it.
	if err := f.e.RevokeToken(resp.AccessToken, f.client.ID, f.secret); err != nil {
		t.Fatal(err)
	}
	if _, err := f.e.GetUserinfo(resp.AccessToken); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked access token still served userinfo: %v", err)
	}
	// The refresh family is a separate grant; revoking one access token leaves it alive.
	if _, err := f.refresh(resp.RefreshToken); err != nil {
		t.Fatalf("revoking an access token ended the refresh family: %v", err)
	}
	// An unknown opaque token is not an error either (RFC 7009 section 2.2).
	if err := f.e.RevokeToken("not-a-token", f.client.ID, f.secret); err != nil {
		t.Fatalf("unknown token: %v", err)
	}
}

// Userinfo is the online check: it refuses garbage, tokens without a jti or subject,
// unknown or inactive users, and fails closed when the revocation registry is unreadable.
func TestUserinfoRefusesMalformedAndOrphanedTokens(t *testing.T) {
	f := newRefreshFixture(t)
	resp := f.login("openid profile")
	claims, err := f.e.keyManager.VerifyJWT(resp.AccessToken, f.e.issuerURL, "access_token")
	if err != nil {
		t.Fatal(err)
	}
	jti := claims["jti"].(string)
	sign := func(mutate func(map[string]any)) string {
		c := map[string]any{"iss": f.e.issuerURL, "sub": f.user.ID, "aud": f.client.ID, "jti": jti, "scope": "openid", "token_use": "access_token", "exp": time.Now().Add(time.Hour).Unix()}
		mutate(c)
		s, err := f.e.keyManager.SignJWT(c)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	cases := map[string]struct {
		token, want string
	}{
		"not a JWT":    {"garbage.token.value", ""},
		"no jti":       {sign(func(c map[string]any) { delete(c, "jti") }), "no jti"},
		"no sub":       {sign(func(c map[string]any) { delete(c, "sub") }), "missing sub"},
		"unknown user": {sign(func(c map[string]any) { c["sub"] = uuid.NewString() }), "user not found"},
	}
	for name, c := range cases {
		info, err := f.e.GetUserinfo(c.token)
		if err == nil || info != nil {
			t.Errorf("%s: served userinfo %v", name, info)
			continue
		}
		if c.want != "" && !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}

	// A user made inactive outside the revocation path is still refused.
	f.exec(`UPDATE users SET status='disabled' WHERE id=?`, f.user.ID)
	if _, err := f.e.GetUserinfo(resp.AccessToken); err == nil || !strings.Contains(err.Error(), "inactive") {
		t.Fatalf("inactive user served userinfo: %v", err)
	}
	f.exec(`UPDATE users SET status='active' WHERE id=?`, f.user.ID)
	if _, err := f.e.GetUserinfo(resp.AccessToken); err != nil {
		t.Fatalf("reactivated user: %v", err)
	}

	// An unreadable registry must not read as "not revoked".
	f.exec(`ALTER TABLE issued_tokens RENAME TO issued_tokens_hidden`)
	if info, err := f.e.GetUserinfo(resp.AccessToken); err == nil || info != nil {
		t.Fatalf("userinfo served with the revocation registry unreadable: %v", info)
	}
}

// The code exchange refuses an expired code, a code presented by another client
// (without burning it), a disabled client, and a user
// deactivated after login.
func TestExchangeAuthorizationCodeRefusals(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		f := newRefreshFixture(t)
		code, verifier := f.covCodeFor("openid")
		f.exec(`UPDATE authorization_codes SET expires_at=?`, time.Now().UTC().Add(-time.Second))
		if _, err := f.e.ExchangeAuthorizationCode(code, f.client.ID, f.secret, "https://app.example/cb", verifier); err == nil || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("expired code: %v", err)
		}
	})
	t.Run("wrong client keeps code redeemable", func(t *testing.T) {
		f := newRefreshFixture(t)
		other := f.newClient("kypost", "confidential")
		code, verifier := f.covCodeFor("openid")
		if _, err := f.e.ExchangeAuthorizationCode(code, other.ID, f.secret, "https://app.example/cb", verifier); err == nil || !strings.Contains(err.Error(), "client mismatch") {
			t.Fatalf("another client's code: %v", err)
		}
		if _, err := f.e.ExchangeAuthorizationCode(code, f.client.ID, f.secret, "https://app.example/cb", verifier); err != nil {
			t.Fatalf("mismatch burned the code: %v", err)
		}
	})
	t.Run("disabled client", func(t *testing.T) {
		f := newRefreshFixture(t)
		code, verifier := f.covCodeFor("openid")
		f.exec(`UPDATE oauth_clients SET enabled=0 WHERE id=?`, f.client.ID)
		if _, err := f.e.ExchangeAuthorizationCode(code, f.client.ID, f.secret, "https://app.example/cb", verifier); err == nil || !strings.Contains(err.Error(), "disabled client") {
			t.Fatalf("disabled client: %v", err)
		}
		if n := f.covCount(`SELECT COUNT(*) FROM authorization_codes WHERE used_at IS NOT NULL`); n != 0 {
			t.Fatal("refused exchange spent the code")
		}
	})
	t.Run("user deactivated after login", func(t *testing.T) {
		f := newRefreshFixture(t)
		code, verifier := f.covCodeFor("openid")
		f.exec(`UPDATE users SET status='disabled' WHERE id=?`, f.user.ID)
		resp, err := f.e.ExchangeAuthorizationCode(code, f.client.ID, f.secret, "https://app.example/cb", verifier)
		if err == nil || resp != nil || !strings.Contains(err.Error(), "inactive") {
			t.Fatalf("inactive user: %+v %v", resp, err)
		}
		if n := f.covCount(`SELECT COUNT(*) FROM issued_tokens WHERE user_id=?`, f.user.ID); n != 0 {
			t.Fatalf("%d token(s) registered for an inactive user", n)
		}
	})
	t.Run("session ended before refresh family", func(t *testing.T) {
		f := newRefreshFixture(t)
		code, verifier := f.covCodeFor("openid")
		if err := f.db.RevokeSession(f.user.ID, f.session, nil); err != nil {
			t.Fatal(err)
		}
		resp, err := f.e.ExchangeAuthorizationCode(code, f.client.ID, f.secret, "https://app.example/cb", verifier)
		if err == nil || resp != nil {
			t.Fatalf("ended session exchanged: %+v", resp)
		}
		if n := f.covCount(`SELECT COUNT(*) FROM refresh_families`); n != 0 {
			t.Fatal("refresh family created for an ended session")
		}
	})
}

// A storage failure at any write of the exchange returns no tokens, and a failed
// spend leaves the code unspent.
func TestExchangeAuthorizationCodeFailsClosedOnStoreErrors(t *testing.T) {
	for _, c := range []struct{ table, op string }{
		{"authorization_codes", "UPDATE"},
		{"refresh_families", "INSERT"},
		{"oidc_client_sessions", "INSERT"},
	} {
		t.Run(c.table, func(t *testing.T) {
			f := newRefreshFixture(t)
			code, verifier := f.covCodeFor("openid")
			covFailWrites(t, f.raw, c.table, c.op)
			resp, err := f.e.ExchangeAuthorizationCode(code, f.client.ID, f.secret, "https://app.example/cb", verifier)
			if err == nil || resp != nil {
				t.Fatalf("tokens issued despite a failed %s %s: %+v", c.op, c.table, resp)
			}
			if c.table == "authorization_codes" {
				if n := f.covCount(`SELECT COUNT(*) FROM authorization_codes WHERE used_at IS NULL`); n != 1 {
					t.Fatal("failed spend changed the code")
				}
			}
		})
	}
}

// A refresh family never outlives the user's access grant, and neither does a
// rotated access token.
func TestRefreshFamilyAndRotatedTokenEndWithAccessGrant(t *testing.T) {
	f := newRefreshFixture(t)
	a := f.app(f.client.ID)
	if err := f.db.SetAppPolicy(a.ID, "assigned_only", true, a.Revision, nil); err != nil {
		t.Fatal(err)
	}
	until := time.Now().UTC().Add(5 * time.Minute).Truncate(time.Second)
	if err := f.db.SetAppAssignmentUntil(a.ID, "users", f.user.ID, &until, nil); err != nil {
		t.Fatal(err)
	}
	first := f.login("openid")
	var end time.Time
	if err := f.raw.QueryRow(`SELECT t.expires_at FROM issued_tokens t JOIN refresh_families r ON r.jti=t.jti`).Scan(&end); err != nil {
		t.Fatal(err)
	}
	if end.After(until.Add(time.Second)) {
		t.Fatalf("family ends %v, after the access grant %v", end, until)
	}
	second, err := f.refresh(first.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if second.ExpiresIn <= 0 || second.ExpiresIn > 300 {
		t.Fatalf("rotated access token lives %ds, past the grant", second.ExpiresIn)
	}
}

// Refresh is only for an enabled, confidential, known client, and an unknown refresh
// token is ErrRefreshInvalid, not reuse.
func TestExchangeRefreshTokenRefusesIneligibleClients(t *testing.T) {
	f := newRefreshFixture(t)
	first := f.login("openid")
	public := f.newClient("spa", "public")
	for name, clientID := range map[string]string{"unknown client": "nope", "public client": public.ID} {
		if _, _, err := f.e.ExchangeRefreshToken(first.RefreshToken, clientID, f.secret, ""); err == nil || !strings.Contains(err.Error(), "confidential") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, user, err := f.e.ExchangeRefreshToken("unknown-refresh-token", f.client.ID, f.secret, ""); !errors.Is(err, store.ErrRefreshInvalid) || user != "" {
		t.Fatalf("unknown token: user %q err %v", user, err)
	}
	f.exec(`UPDATE oauth_clients SET enabled=0 WHERE id=?`, f.client.ID)
	if _, _, err := f.e.ExchangeRefreshToken(first.RefreshToken, f.client.ID, f.secret, ""); err == nil {
		t.Fatal("disabled client refreshed")
	}
	f.exec(`UPDATE oauth_clients SET enabled=1 WHERE id=?`, f.client.ID)
	// None of the refusals spent the token.
	if _, err := f.refresh(first.RefreshToken); err != nil {
		t.Fatalf("refused refreshes spent the token: %v", err)
	}
}

// Code issuance refuses an unknown or disabled client, a missing session and an app
// policy the session does not satisfy; a forged interaction hash is refused, and
// max_age is recorded so the exchange can re-check it.
func TestCreateAuthorizationCodeForInteractionRefusals(t *testing.T) {
	f := newRefreshFixture(t)
	_, challenge := pkcePair()
	create := func(clientID, session string, req AuthenticationRequest, hash string) (string, error) {
		return f.e.CreateAuthorizationCodeForInteraction(clientID, session, "https://app.example/cb", "openid", challenge, "S256", "", req, hash)
	}
	if _, err := create("nope", f.session, AuthenticationRequest{}, ""); err == nil || !strings.Contains(err.Error(), "disabled client") {
		t.Fatalf("unknown client: %v", err)
	}
	if _, err := create(f.client.ID, uuid.NewString(), AuthenticationRequest{}, ""); err == nil || !strings.Contains(err.Error(), "session") {
		t.Fatalf("unknown session: %v", err)
	}
	// A fresh-login request is unsatisfiable by an existing session...
	if _, err := create(f.client.ID, f.session, AuthenticationRequest{Fresh: true}, ""); !errors.Is(err, store.ErrAppAuthentication) {
		t.Fatalf("fresh request: %v", err)
	}
	// An interaction hash waives the engine's freshness gate only for the store to
	// consume a matching completed interaction; a forged hash is still refused.
	if _, err := create(f.client.ID, f.session, AuthenticationRequest{Fresh: true}, "forged-interaction-hash"); !errors.Is(err, store.ErrAuthorizationInteraction) {
		t.Fatalf("forged interaction hash: %v", err)
	}
	if n := f.covCount(`SELECT COUNT(*) FROM authorization_codes`); n != 0 {
		t.Fatalf("refusals stored %d code(s)", n)
	}
	// Session password is 10 minutes old: max_age 60 refuses, 3600 records a deadline.
	short, long := int64(60), int64(3600)
	if _, err := create(f.client.ID, f.session, AuthenticationRequest{MaxAge: &short}, ""); !errors.Is(err, store.ErrAppAuthentication) {
		t.Fatalf("stale login under max_age: %v", err)
	}
	before := f.covCount(`SELECT COUNT(*) FROM authorization_codes WHERE authentication_expires_at IS NOT NULL`)
	if _, err := create(f.client.ID, f.session, AuthenticationRequest{MaxAge: &long}, ""); err != nil {
		t.Fatal(err)
	}
	if after := f.covCount(`SELECT COUNT(*) FROM authorization_codes WHERE authentication_expires_at IS NOT NULL`); after != before+1 {
		t.Fatal("max_age deadline not recorded on the code")
	}
	f.exec(`UPDATE oauth_clients SET enabled=0 WHERE id=?`, f.client.ID)
	if _, err := create(f.client.ID, f.session, AuthenticationRequest{}, ""); err == nil || !strings.Contains(err.Error(), "disabled client") {
		t.Fatalf("disabled client: %v", err)
	}
}

// GrantedScope refuses an unknown client and a corrupt allowlist instead of granting.
func TestGrantedScopeRefusesUnknownClientAndCorruptAllowlist(t *testing.T) {
	f := newRefreshFixture(t)
	if s, err := f.e.GrantedScope("nope", "openid"); err == nil || s != "" {
		t.Fatalf("unknown client granted %q", s)
	}
	f.exec(`UPDATE oauth_clients SET allowed_scopes_json='not json' WHERE id=?`, f.client.ID)
	if s, err := f.e.GrantedScope(f.client.ID, "openid"); err == nil || s != "" || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("corrupt allowlist granted %q: %v", s, err)
	}
}

// Post-logout redirect URIs match exactly like login redirect URIs: no nil client,
// no empty value, no corrupt registration, blank entries never match.
func TestPostLogoutRedirectURIRequiresExactMatch(t *testing.T) {
	e := &Engine{}
	c := &store.OAuthClient{RedirectURIsJSON: `["https://app/cb"]`, PostLogoutRedirectURIsJSON: `["  ", "https://app/bye"]`}
	cases := []struct {
		client *store.OAuthClient
		uri    string
		ok     bool
	}{
		{c, "https://app/bye", true},
		{c, "https://app/bye/", false},
		{c, "https://app/cb", false},
		{c, "", false},
		{nil, "https://app/bye", false},
		{&store.OAuthClient{PostLogoutRedirectURIsJSON: `{bad`}, "https://app/bye", false},
	}
	for _, tc := range cases {
		if got := e.ValidatePostLogoutRedirectURI(tc.client, tc.uri); got != tc.ok {
			t.Errorf("post-logout %q (client nil=%v): got %v", tc.uri, tc.client == nil, got)
		}
	}
	if e.ValidateRedirectURI(nil, "https://app/cb") {
		t.Fatal("nil client validated a redirect URI")
	}
}

// The published JWKS verifies tokens the engine signs.
func TestJWKSPublishesTheSigningKey(t *testing.T) {
	f := newRefreshFixture(t)
	resp := f.login("openid")
	kid, _ := jwtHeader(t, resp.AccessToken)["kid"].(string)
	found := false
	for _, k := range f.e.GetJWKS().Keys {
		if k.Kid == kid {
			found = true
		}
	}
	if kid == "" || !found {
		t.Fatalf("signing kid %q not in JWKS", kid)
	}
}

// An app that asks for groups gets an empty list, never null, when the user has none.
func TestGroupsClaimIsAnEmptyListNotNull(t *testing.T) {
	e, db, cleanup := setupTestOAuthEngine(t)
	defer cleanup()
	user := testUser(t, db)
	testClient(t, db, "groupsapp", "public", []string{"https://app/cb"}, []string{"openid"})
	a := appFor(t, db, "groupsapp")
	if err := db.SetAppClaimSettings(a.ID, false, true, a.Revision, nil); err != nil {
		t.Fatal(err)
	}
	claims, access := exchangeFor(t, e, db, user, "groupsapp", "openid")
	groups, ok := claims["groups"].([]any)
	if !ok || len(groups) != 0 {
		t.Fatalf("groups claim %#v, want []", claims["groups"])
	}
	info, err := e.GetUserinfo(access)
	if err != nil {
		t.Fatal(err)
	}
	if g, ok := info["groups"].([]string); !ok || len(g) != 0 {
		t.Fatalf("userinfo groups %#v, want []", info["groups"])
	}
}
