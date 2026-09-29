package oauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
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
