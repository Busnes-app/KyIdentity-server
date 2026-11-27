package oauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/hybridsig"
	"github.com/golang-jwt/jwt/v5"
)

func signHybridAssertionForTest(t *testing.T, priv *hybridsig.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(signingMethodHybridSig, claims)
	tok.Header = map[string]any{"alg": deviceAssertionHybridAlg, "typ": "JWT", "kid": kid}
	compact, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("SignedString(hybridsig): %v", err)
	}
	return compact
}

func TestParseDeviceAssertionHybridSigRoundTripAndAlgConfusion(t *testing.T) {
	hPriv, err := hybridsig.Generate()
	if err != nil {
		t.Fatalf("hybridsig.Generate: %v", err)
	}
	compact := signHybridAssertionForTest(t, hPriv, "dev-1", testClaims())

	// Valid hybrid assertion verifies against its enrolled hybrid public key.
	a, err := parseForTest(compact, hPriv.Public())
	if err != nil {
		t.Fatalf("parseForTest(hybridsig): %v", err)
	}
	if a.DeviceID != "dev-1" || a.Subject != "user-1" || a.ClientID != "kypost" {
		t.Fatalf("unexpected claims: %+v", a)
	}

	// Sibling hybrid key fails with errAssertionSignature.
	otherHybrid, _ := hybridsig.Generate()
	if _, err := parseForTest(compact, otherHybrid.Public()); !errors.Is(err, errAssertionSignature) {
		t.Fatalf("sibling hybrid key: got %v want errAssertionSignature", err)
	}

	// Algorithm confusion: hybrid assertion against an enrolled P-256 key MUST fail.
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := parseForTest(compact, &ecPriv.PublicKey); !errors.Is(err, errAssertionSignature) {
		t.Fatalf("hybrid assertion vs P-256 key: got %v want errAssertionSignature", err)
	}

	// Algorithm confusion: ES256 assertion against an enrolled hybrid key MUST fail.
	ecCompact := signDeviceAssertionForTest(t, ecPriv, testHeader("dev-1"), testClaims())
	if _, err := parseForTest(ecCompact, hPriv.Public()); !errors.Is(err, errAssertionSignature) {
		t.Fatalf("ES256 assertion vs hybrid key: got %v want errAssertionSignature", err)
	}

	// Still enforces expiry/audience normally on hybrid assertions.
	if _, err := parseDeviceAssertion(compact, "https://other.example/oauth/token", time.Unix(1100, 0), func(string, string) (any, error) {
		return hPriv.Public(), nil
	}); !errors.Is(err, errAssertionAudience) {
		t.Fatalf("wrong audience on hybrid assertion: got %v want errAssertionAudience", err)
	}
}
