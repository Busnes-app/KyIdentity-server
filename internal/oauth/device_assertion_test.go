package oauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

func signDeviceAssertionForTest(t *testing.T, priv *ecdsa.PrivateKey, header map[string]any, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func testHeader(kid string) map[string]any {
	return map[string]any{"alg": "ES256", "typ": "JWT", "kid": kid}
}

func testClaims() map[string]any {
	return map[string]any{
		"iss": "device:dev-1", "sub": "user-1", "aud": "https://id.example/oauth/token",
		"client_id": "kypost", "iat": int64(1000), "exp": int64(1200), "jti": "j-1",
	}
}

func TestParseDeviceAssertionRoundTrip(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	compact := signDeviceAssertionForTest(t, priv, testHeader("dev-1"), testClaims())
	a, input, sig, err := parseDeviceAssertion(compact)
	if err != nil {
		t.Fatal(err)
	}
	if a.DeviceID != "dev-1" || a.Subject != "user-1" || a.ClientID != "kypost" || a.JTI != "j-1" || a.IssuedAt != 1000 || a.ExpiresAt != 1200 || a.Audience != "https://id.example/oauth/token" {
		t.Fatalf("claims: %+v", a)
	}
	if !verifyES256(&priv.PublicKey, input, sig) {
		t.Fatal("valid signature refused")
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if verifyES256(&other.PublicKey, input, sig) {
		t.Fatal("sibling key accepted")
	}
}

func TestParseDeviceAssertionRejectsBadHeaders(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bad := []map[string]any{
		{"alg": "RS256", "typ": "JWT", "kid": "dev-1"},
		{"alg": "none", "typ": "JWT", "kid": "dev-1"},
		{"alg": "ES256", "typ": "JWT"},
		{"alg": "ES256", "typ": "JWT", "kid": "dev-1", "crit": []string{"x"}},
	}
	for _, h := range bad {
		if _, _, _, err := parseDeviceAssertion(signDeviceAssertionForTest(t, priv, h, testClaims())); err == nil {
			t.Fatalf("header %v accepted", h)
		}
	}
	if _, _, _, err := parseDeviceAssertion("a.b"); err == nil {
		t.Fatal("two segments accepted")
	}
	c := testClaims()
	c["iss"] = "device:other"
	if _, _, _, err := parseDeviceAssertion(signDeviceAssertionForTest(t, priv, testHeader("dev-1"), c)); err == nil {
		t.Fatal("iss/kid mismatch accepted")
	}
}

func TestVerifyES256BoundaryAndFormat(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	input := []byte("x.y")
	digest := sha256.Sum256(input)

	// Test DER format rejection (wrong length)
	der, _ := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if verifyES256(&priv.PublicKey, input, der) {
		t.Fatal("DER signature accepted as raw")
	}

	// Test valid signature as control
	r, s, _ := ecdsa.Sign(rand.Reader, priv, digest[:])
	validSig := make([]byte, 64)
	r.FillBytes(validSig[:32])
	s.FillBytes(validSig[32:])
	if !verifyES256(&priv.PublicKey, input, validSig) {
		t.Fatal("valid signature rejected")
	}

	// Boundary cases: test each of r and s at 0, n, n+1 with the other at 1
	n := elliptic.P256().Params().N
	tests := []struct {
		name  string
		r, s  *big.Int
		valid bool
	}{
		{"r=0, s=1", big.NewInt(0), big.NewInt(1), false},
		{"r=1, s=0", big.NewInt(1), big.NewInt(0), false},
		{"r=n, s=1", new(big.Int).Set(n), big.NewInt(1), false},
		{"r=1, s=n", big.NewInt(1), new(big.Int).Set(n), false},
		{"r=n+1, s=1", new(big.Int).Add(n, big.NewInt(1)), big.NewInt(1), false},
		{"r=1, s=n+1", big.NewInt(1), new(big.Int).Add(n, big.NewInt(1)), false},
		{"r=0, s=0", big.NewInt(0), big.NewInt(0), false},
	}
	for _, tt := range tests {
		sig := make([]byte, 64)
		tt.r.FillBytes(sig[:32])
		tt.s.FillBytes(sig[32:])
		if verifyES256(&priv.PublicKey, input, sig) != tt.valid {
			t.Fatalf("%s: expected valid=%v", tt.name, tt.valid)
		}
	}
}

func TestVerifyES256RejectsBadCurve(t *testing.T) {
	// P-256 key as control
	priv256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	input := []byte("x.y")
	digest := sha256.Sum256(input)
	r, s, _ := ecdsa.Sign(rand.Reader, priv256, digest[:])
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	if !verifyES256(&priv256.PublicKey, input, sig) {
		t.Fatal("valid P256 signature rejected")
	}

	// P-384 key should be rejected
	priv384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if verifyES256(&priv384.PublicKey, input, sig) {
		t.Fatal("P384 key accepted")
	}
}

func TestParseDeviceAssertionRejectsInvalidClaims(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Test each claim missing individually
	claimTests := []struct {
		name   string
		modify func(map[string]any)
	}{
		{"missing sub", func(c map[string]any) { delete(c, "sub") }},
		{"missing aud", func(c map[string]any) { delete(c, "aud") }},
		{"missing client_id", func(c map[string]any) { delete(c, "client_id") }},
		{"missing jti", func(c map[string]any) { delete(c, "jti") }},
		{"missing iat", func(c map[string]any) { delete(c, "iat") }},
		{"missing exp", func(c map[string]any) { delete(c, "exp") }},
		{"empty sub", func(c map[string]any) { c["sub"] = "" }},
		{"empty aud", func(c map[string]any) { c["aud"] = "" }},
		{"empty client_id", func(c map[string]any) { c["client_id"] = "" }},
		{"empty jti", func(c map[string]any) { c["jti"] = "" }},
		{"zero iat", func(c map[string]any) { c["iat"] = int64(0) }},
		{"zero exp", func(c map[string]any) { c["exp"] = int64(0) }},
	}
	for _, tt := range claimTests {
		c := testClaims()
		tt.modify(c)
		if _, _, _, err := parseDeviceAssertion(signDeviceAssertionForTest(t, priv, testHeader("dev-1"), c)); err == nil {
			t.Fatalf("%s accepted", tt.name)
		}
	}

	// Test header-side rules
	headerTests := []struct {
		name   string
		modify func(map[string]any)
	}{
		{"typ lowercase jwt", func(h map[string]any) { h["typ"] = "jwt" }},
		{"extra header key jku", func(h map[string]any) { h["jku"] = "https://example.com/keys" }},
	}
	for _, tt := range headerTests {
		h := testHeader("dev-1")
		tt.modify(h)
		if _, _, _, err := parseDeviceAssertion(signDeviceAssertionForTest(t, priv, h, testClaims())); err == nil {
			t.Fatalf("%s accepted", tt.name)
		}
	}

	// Test size limit
	c := testClaims()
	c["jti"] = string(make([]byte, 4096)) // Pad to exceed limit
	if _, _, _, err := parseDeviceAssertion(signDeviceAssertionForTest(t, priv, testHeader("dev-1"), c)); err == nil {
		t.Fatal("oversized assertion accepted")
	}
}

type signOnFixture struct {
	engine *Engine
	db     *store.Store
	user   *store.User
	client *store.OAuthClient
	priv   *ecdsa.PrivateKey
}

func newSignOnFixture(t *testing.T) *signOnFixture {
	t.Helper()
	engine, db, cleanup := setupTestOAuthEngine(t)
	t.Cleanup(cleanup)
	user := &store.User{ID: uuid.NewString(), Username: "alice", DisplayName: "Alice", Email: "alice@example.com", PasswordHash: "x", Role: "user", Status: "active"}
	if err := db.CreateUser(user); err != nil {
		t.Fatal(err)
	}
	client := &store.OAuthClient{ID: uuid.NewString(), ClientName: "KyPost", ClientType: "public",
		RedirectURIsJSON: `["https://kypost.local/callback"]`, AllowedScopesJSON: `["openid","profile","email"]`, Enabled: true}
	if err := db.CreateOAuthClient(client); err != nil {
		t.Fatal(err)
	}
	allowTestAppAccess(t, db, client.ID)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	dev := &store.NativeDevice{ID: "dev-1", UserID: user.ID, DeviceName: "phone", DeviceIdentifier: "ident-1",
		PublicKey: base64.StdEncoding.EncodeToString(spki), IsMFAApprover: true, CanSignOn: true}
	if err := db.UpsertNativeDevice(dev); err != nil {
		t.Fatal(err)
	}
	return &signOnFixture{engine: engine, db: db, user: user, client: client, priv: priv}
}

func (f *signOnFixture) claims(mutate func(map[string]any)) map[string]any {
	now := time.Now().Unix()
	c := map[string]any{
		"iss": "device:dev-1", "sub": f.user.ID, "aud": f.engine.issuerURL + "/oauth/token",
		"client_id": f.client.ID, "iat": now, "exp": now + 120, "jti": uuid.NewString(),
	}
	if mutate != nil {
		mutate(c)
	}
	return c
}

func TestExchangeDeviceAssertionIssuesIDToken(t *testing.T) {
	f := newSignOnFixture(t)
	compact := signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(nil))
	resp, who, err := f.engine.ExchangeDeviceAssertion(compact, f.client.ID, "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	if who.DeviceID != "dev-1" || who.UserID != f.user.ID || who.Username != "alice" || resp.IDToken == "" || resp.AccessToken == "" {
		t.Fatalf("resp %+v who %+v", resp, who)
	}
	claims, err := f.engine.keyManager.VerifyJWT(resp.IDToken)
	if err != nil {
		t.Fatal(err)
	}
	if claims["aud"] != f.client.ID || claims["sub"] != f.user.ID || claims["signon_method"] != "device" || claims["device_id"] != "dev-1" || claims["sid"] == "" || claims["iss"] != f.engine.issuerURL {
		t.Fatalf("claims %v", claims)
	}
	// Single factor: the device key alone must never claim MFA.
	amr, _ := claims["amr"].([]any)
	if len(amr) != 1 || amr[0] != "pop" || claims["acr"] != DeviceACR {
		t.Fatalf("amr %v acr %v", claims["amr"], claims["acr"])
	}
	if at, _ := claims["auth_time"].(float64); at == 0 || time.Since(time.Unix(int64(at), 0)) > time.Minute {
		t.Fatalf("auth_time %v", claims["auth_time"])
	}
}

// requireOrganizationMFA turns on the organization enrollment policy, activated by a
// compliant TOTP administrator.
func (f *signOnFixture) requireOrganizationMFA(t *testing.T, methods []string, grace int64) {
	t.Helper()
	admin := &store.User{ID: uuid.NewString(), Username: "admin", Email: "admin@example.com", PasswordHash: "x", Role: "admin", Status: "active"}
	if err := f.db.CreateUser(admin); err != nil {
		t.Fatal(err)
	}
	if err := f.db.SetMFAMethod(&store.MFAMethod{ID: uuid.NewString(), UserID: admin.ID, MethodType: "totp", EncryptedSecret: "x"}, nil); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	sess := &store.Session{ID: uuid.NewString(), UserID: admin.ID, SessionTokenHash: uuid.NewString(), ExpiresAt: at.Add(time.Hour),
		AuthenticationEvidence: store.AuthenticationEvidence{PrimaryAuthenticatedAt: &at, FactorAuthenticatedAt: &at, FactorMethod: "totp"}}
	if err := f.db.CreateSession(sess); err != nil {
		t.Fatal(err)
	}
	p := store.EnrollmentPolicy{Scope: "organization", Required: true, AllowedMethods: methods, GraceSeconds: grace, Revision: 1}
	if err := f.db.SetEnrollmentPolicy(p, sess.ID, nil); err != nil {
		t.Fatal(err)
	}
}

func TestExchangeDeviceAssertionRefusedWhereMFAIsRequired(t *testing.T) {
	f := newSignOnFixture(t)
	// Push allowed: the device is a compliant factor, so grace does not apply.
	f.requireOrganizationMFA(t, []string{"totp", "push"}, 3600)
	before, err := f.db.ListUserSessions(f.user.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	compact := signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(nil))
	if _, _, err := f.engine.ExchangeDeviceAssertion(compact, f.client.ID, "127.0.0.1", "test"); !errors.Is(err, store.ErrAppAccessDenied) || !errors.Is(err, ErrDeviceSignOnNotPermitted) {
		t.Fatalf("MFA-required user: %v", err)
	}
	after, err := f.db.ListUserSessions(f.user.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("refused sign-on left %d session(s) behind", len(after)-len(before))
	}
}

func TestExchangeDeviceAssertionRefusedByFactorPolicy(t *testing.T) {
	f := newSignOnFixture(t)
	rows, _, err := f.db.ListAppRecords(f.client.ID, 100, 0)
	if err != nil || len(rows) == 0 {
		t.Fatal(err)
	}
	if err := f.db.SetAppAuthenticationPolicy(rows[0].ID, store.AppAuthenticationPolicy{Mode: "reuse", Factor: "mfa"}, rows[0].Revision, nil); err != nil {
		t.Fatal(err)
	}
	compact := signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(nil))
	if _, _, err := f.engine.ExchangeDeviceAssertion(compact, f.client.ID, "127.0.0.1", "test"); !errors.Is(err, ErrDeviceSignOnNotPermitted) {
		t.Fatalf("mfa policy: %v", err)
	}
}

// fresh and max_age mean a recently entered password, which a device sign-on never has.
func TestExchangeDeviceAssertionPasswordPolicyModes(t *testing.T) {
	cases := map[string]struct {
		policy store.AppAuthenticationPolicy
		issued bool
	}{
		"reuse":   {store.AppAuthenticationPolicy{Mode: "reuse", Factor: "password"}, true},
		"fresh":   {store.AppAuthenticationPolicy{Mode: "fresh", Factor: "password"}, false},
		"max_age": {store.AppAuthenticationPolicy{Mode: "max_age", Factor: "password", PrimaryMaxAge: 3600}, false},
	}
	for name, c := range cases {
		f := newSignOnFixture(t)
		rows, _, err := f.db.ListAppRecords(f.client.ID, 100, 0)
		if err != nil || len(rows) == 0 {
			t.Fatal(err)
		}
		if err := f.db.SetAppAuthenticationPolicy(rows[0].ID, c.policy, rows[0].Revision, nil); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		compact := signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(nil))
		_, _, err = f.engine.ExchangeDeviceAssertion(compact, f.client.ID, "127.0.0.1", "test")
		if c.issued && err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if !c.issued && !errors.Is(err, ErrDeviceSignOnNotPermitted) {
			t.Errorf("%s: want ErrDeviceSignOnNotPermitted, got %v", name, err)
		}
	}
}

// Pins the enrollment grace clause: with push outside the allowed methods and no allowed
// factor enrolled, the view admits the device session like a password login until the deadline.
func TestExchangeDeviceAssertionEnrollmentGrace(t *testing.T) {
	for _, c := range []struct {
		name   string
		grace  int64
		issued bool
	}{{"inside grace", 3600, true}, {"deadline passed", 0, false}} {
		f := newSignOnFixture(t)
		f.requireOrganizationMFA(t, []string{"totp"}, c.grace)
		compact := signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(nil))
		resp, _, err := f.engine.ExchangeDeviceAssertion(compact, f.client.ID, "127.0.0.1", "test")
		if !c.issued {
			if !errors.Is(err, ErrDeviceSignOnNotPermitted) {
				t.Errorf("%s: want ErrDeviceSignOnNotPermitted, got %v", c.name, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		claims, err := f.engine.keyManager.VerifyJWT(resp.IDToken)
		if err != nil {
			t.Fatal(err)
		}
		if amr, _ := claims["amr"].([]any); len(amr) != 1 || amr[0] != "pop" || claims["acr"] != DeviceACR {
			t.Fatalf("%s: amr %v acr %v", c.name, claims["amr"], claims["acr"])
		}
	}
}

func (f *signOnFixture) secondClient(t *testing.T) *store.OAuthClient {
	t.Helper()
	c := &store.OAuthClient{ID: uuid.NewString(), ClientName: "Other", ClientType: "public",
		RedirectURIsJSON: `["https://other.local/callback"]`, AllowedScopesJSON: `["openid","profile","email"]`, Enabled: true}
	if err := f.db.CreateOAuthClient(c); err != nil {
		t.Fatal(err)
	}
	allowTestAppAccess(t, f.db, c.ID)
	return c
}

func (f *signOnFixture) secondUser(t *testing.T) *store.User {
	t.Helper()
	u := &store.User{ID: uuid.NewString(), Username: "bob", DisplayName: "Bob", Email: "bob@example.com", PasswordHash: "x", Role: "user", Status: "active"}
	if err := f.db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestExchangeDeviceAssertionRefusals(t *testing.T) {
	f := newSignOnFixture(t)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	clientB := f.secondClient(t)
	userB := f.secondUser(t)
	disabled := f.secondClient(t)
	disabled.Enabled = false
	if err := f.db.UpdateOAuthClient(disabled); err != nil {
		t.Fatal(err)
	}
	if err := f.db.UpsertNativeDevice(&store.NativeDevice{ID: "dev-nokey", UserID: f.user.ID, DeviceName: "k", DeviceIdentifier: "ident-nokey", IsMFAApprover: true, CanSignOn: true}); err != nil {
		t.Fatal(err)
	}
	sign := func(k *ecdsa.PrivateKey, kid string, m func(map[string]any)) string {
		return signDeviceAssertionForTest(t, k, testHeader(kid), f.claims(m))
	}
	type tc struct {
		compact, clientID string
		want              error
	}
	cases := map[string]tc{
		"sibling key":         {sign(other, "dev-1", nil), f.client.ID, errAssertionSignature},
		"form client_id":      {sign(f.priv, "dev-1", nil), clientB.ID, errAssertionClient},
		"claim client_id":     {sign(f.priv, "dev-1", func(c map[string]any) { c["client_id"] = clientB.ID }), f.client.ID, errAssertionClient},
		"unregistered client": {sign(f.priv, "dev-1", func(c map[string]any) { c["client_id"] = "someone-else" }), "someone-else", errUnknownClient},
		"disabled client":     {sign(f.priv, "dev-1", func(c map[string]any) { c["client_id"] = disabled.ID }), disabled.ID, errUnknownClient},
		"wrong aud":           {sign(f.priv, "dev-1", func(c map[string]any) { c["aud"] = "https://evil/oauth/token" }), f.client.ID, errAssertionAudience},
		"wrong sub":           {sign(f.priv, "dev-1", func(c map[string]any) { c["sub"] = userB.ID }), f.client.ID, errUnknownDevice},
		"expired":             {sign(f.priv, "dev-1", func(c map[string]any) { c["iat"] = time.Now().Unix() - 400; c["exp"] = time.Now().Unix() - 100 }), f.client.ID, errAssertionExpired},
		"window too long":     {sign(f.priv, "dev-1", func(c map[string]any) { c["exp"] = time.Now().Unix() + 3600 }), f.client.ID, errAssertionWindow},
		"exp before iat":      {sign(f.priv, "dev-1", func(c map[string]any) { c["exp"] = time.Now().Unix() - 10 }), f.client.ID, errAssertionWindow},
		"future iat":          {sign(f.priv, "dev-1", func(c map[string]any) { c["iat"] = time.Now().Unix() + 300; c["exp"] = time.Now().Unix() + 400 }), f.client.ID, errAssertionFuture},
		"unknown device":      {sign(f.priv, "dev-9", func(c map[string]any) { c["iss"] = "device:dev-9" }), f.client.ID, errUnknownDevice},
		"empty public key":    {sign(f.priv, "dev-nokey", func(c map[string]any) { c["iss"] = "device:dev-nokey" }), f.client.ID, errUnknownDevice},
	}
	for name, c := range cases {
		_, who, err := f.engine.ExchangeDeviceAssertion(c.compact, c.clientID, "127.0.0.1", "test")
		if !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
		if who.DeviceID != "" && c.want != errUnknownClient {
			t.Errorf("%s: unverified device id %q returned", name, who.DeviceID)
		}
	}
}

func TestExchangeDeviceAssertionReplay(t *testing.T) {
	f := newSignOnFixture(t)
	compact := signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(nil))
	if _, _, err := f.engine.ExchangeDeviceAssertion(compact, f.client.ID, "127.0.0.1", "test"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.engine.ExchangeDeviceAssertion(compact, f.client.ID, "127.0.0.1", "test"); !errors.Is(err, errAssertionReplay) {
		t.Fatalf("replayed jti: %v", err)
	}
}

func TestExchangeDeviceAssertionSignOnDisabled(t *testing.T) {
	f := newSignOnFixture(t)
	if err := f.db.SetNativeDeviceCanSignOn("dev-1", f.user.ID, false); err != nil {
		t.Fatal(err)
	}
	compact := signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(nil))
	if _, _, err := f.engine.ExchangeDeviceAssertion(compact, f.client.ID, "127.0.0.1", "test"); !errors.Is(err, ErrDeviceSignOnDisabled) {
		t.Fatalf("want ErrDeviceSignOnDisabled, got %v", err)
	}
}

func TestExchangeDeviceAssertionInactiveUser(t *testing.T) {
	f := newSignOnFixture(t)
	if err := f.db.UpdateUserStatus(f.user.ID, "disabled"); err != nil {
		t.Fatal(err)
	}
	compact := signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(nil))
	if _, _, err := f.engine.ExchangeDeviceAssertion(compact, f.client.ID, "127.0.0.1", "test"); !errors.Is(err, errUserInactive) {
		t.Fatalf("inactive user: %v", err)
	}
}

func TestExchangeDeviceAssertionDoesNotProbeFlags(t *testing.T) {
	f := newSignOnFixture(t)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := f.db.SetNativeDeviceCanSignOn("dev-1", f.user.ID, false); err != nil {
		t.Fatal(err)
	}
	compact := signDeviceAssertionForTest(t, other, testHeader("dev-1"), f.claims(nil))
	if _, _, err := f.engine.ExchangeDeviceAssertion(compact, f.client.ID, "127.0.0.1", "test"); !errors.Is(err, errAssertionSignature) {
		t.Fatalf("want signature error, got %v", err)
	}
}

func TestExchangeDeviceAssertionRequiresApprover(t *testing.T) {
	f := newSignOnFixture(t)
	spki, _ := x509.MarshalPKIXPublicKey(&f.priv.PublicKey)
	dev := &store.NativeDevice{ID: "dev-2", UserID: f.user.ID, DeviceName: "p2", DeviceIdentifier: "ident-2",
		PublicKey: base64.StdEncoding.EncodeToString(spki), IsMFAApprover: false, CanSignOn: true}
	if err := f.db.UpsertNativeDevice(dev); err != nil {
		t.Fatal(err)
	}
	compact := signDeviceAssertionForTest(t, f.priv, testHeader("dev-2"), f.claims(func(c map[string]any) { c["iss"] = "device:dev-2" }))
	if _, _, err := f.engine.ExchangeDeviceAssertion(compact, f.client.ID, "127.0.0.1", "test"); !errors.Is(err, ErrDeviceSignOnDisabled) {
		t.Fatalf("non-approver: %v", err)
	}
}

func TestExchangeDeviceAssertionRefusedAfterMFAReset(t *testing.T) {
	f := newSignOnFixture(t)
	if err := f.db.ResetUserMFA(f.user.ID, nil); err != nil {
		t.Fatal(err)
	}
	compact := signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(nil))
	if _, _, err := f.engine.ExchangeDeviceAssertion(compact, f.client.ID, "127.0.0.1", "test"); !errors.Is(err, ErrDeviceSignOnDisabled) {
		t.Fatalf("after reset: %v", err)
	}
}

func TestExchangeDeviceAssertionHonoursAppPolicy(t *testing.T) {
	f := newSignOnFixture(t)
	rows, _, err := f.db.ListAppRecords(f.client.ID, 100, 0)
	if err != nil || len(rows) == 0 {
		t.Fatal(err)
	}
	if err := f.db.SetAppAuthenticationPolicy(rows[0].ID, store.AppAuthenticationPolicy{Mode: "reuse", Factor: "passkey"}, rows[0].Revision, nil); err != nil {
		t.Fatal(err)
	}
	compact := signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(nil))
	if _, _, err := f.engine.ExchangeDeviceAssertion(compact, f.client.ID, "127.0.0.1", "test"); !errors.Is(err, errAppPolicy) {
		t.Fatalf("passkey policy: %v", err)
	}
}

func TestExchangeDeviceAssertionRefusesUserWithoutAppAccess(t *testing.T) {
	f := newSignOnFixture(t)
	rows, _, err := f.db.ListAppRecords(f.client.ID, 100, 0)
	if err != nil || len(rows) == 0 {
		t.Fatal(err)
	}
	if err := f.db.SetAppPolicy(rows[0].ID, "assigned_only", true, rows[0].Revision, nil); err != nil {
		t.Fatal(err)
	}
	before, err := f.db.ListUserSessions(f.user.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	compact := signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(nil))
	if _, _, err := f.engine.ExchangeDeviceAssertion(compact, f.client.ID, "127.0.0.1", "test"); !errors.Is(err, store.ErrAppAccessDenied) {
		t.Fatalf("unassigned user: %v", err)
	}
	after, err := f.db.ListUserSessions(f.user.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("refused sign-on left %d session(s) behind", len(after)-len(before))
	}
}

func TestExchangeDeviceAssertionRequiresOpenIDScope(t *testing.T) {
	f := newSignOnFixture(t)
	c := &store.OAuthClient{ID: uuid.NewString(), ClientName: "NoOpenID", ClientType: "public",
		RedirectURIsJSON: `["https://noid.local/callback"]`, AllowedScopesJSON: `["profile","email"]`, Enabled: true}
	if err := f.db.CreateOAuthClient(c); err != nil {
		t.Fatal(err)
	}
	allowTestAppAccess(t, f.db, c.ID)
	compact := signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(func(m map[string]any) { m["client_id"] = c.ID }))
	if _, _, err := f.engine.ExchangeDeviceAssertion(compact, c.ID, "127.0.0.1", "test"); !errors.Is(err, errNoOpenIDScope) {
		t.Fatalf("no openid scope: %v", err)
	}
}

// raceAppEdit runs edit between the engine's policy evaluation and token registration,
// then asserts the exchange is refused as app access and leaves no session behind.
func raceAppEdit(t *testing.T, edit func(f *signOnFixture, app store.AppRecord) error) {
	t.Helper()
	f := newSignOnFixture(t)
	rows, _, err := f.db.ListAppRecords(f.client.ID, 100, 0)
	if err != nil || len(rows) == 0 {
		t.Fatal(err)
	}
	beforeDeviceTokenRecord = func() {
		if err := edit(f, rows[0]); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { beforeDeviceTokenRecord = func() {} })
	before, err := f.db.ListUserSessions(f.user.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	compact := signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(nil))
	if _, _, err := f.engine.ExchangeDeviceAssertion(compact, f.client.ID, "127.0.0.1", "test"); !errors.Is(err, store.ErrAppAccessDenied) {
		t.Fatalf("token issued across an app edit: %v", err)
	}
	after, err := f.db.ListUserSessions(f.user.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("refused sign-on left %d session(s) behind", len(after)-len(before))
	}
}

func TestExchangeDeviceAssertionRefusesPolicyTightenedBeforeIssue(t *testing.T) {
	raceAppEdit(t, func(f *signOnFixture, app store.AppRecord) error {
		return f.db.SetAppAuthenticationPolicy(app.ID, store.AppAuthenticationPolicy{Mode: "reuse", Factor: "passkey"}, app.Revision, nil)
	})
}

func TestExchangeDeviceAssertionRefusesRoleRevisionBumpBeforeIssue(t *testing.T) {
	raceAppEdit(t, func(f *signOnFixture, app store.AppRecord) error {
		return f.db.SetAppClaimSettings(app.ID, !app.LegacyRoleClaim, app.GroupsClaim, app.Revision, nil)
	})
}

func TestExchangeDeviceAssertionIssuesWhenPolicyUnchanged(t *testing.T) {
	f := newSignOnFixture(t)
	ran := false
	beforeDeviceTokenRecord = func() { ran = true }
	t.Cleanup(func() { beforeDeviceTokenRecord = func() {} })
	compact := signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(nil))
	if _, _, err := f.engine.ExchangeDeviceAssertion(compact, f.client.ID, "127.0.0.1", "test"); err != nil || !ran {
		t.Fatalf("unchanged policy: err=%v hook ran=%v", err, ran)
	}
}
