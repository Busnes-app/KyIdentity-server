package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

// A kid must identify the key it belongs to, or clients cannot cache JWKS across a rotation.
func TestKeyIDIsDerivedFromTheKey(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadOrCreateRSAKey(filepath.Join(dir, "a.key"))
	if err != nil {
		t.Fatalf("LoadOrCreateRSAKey(a): %v", err)
	}
	b, err := LoadOrCreateRSAKey(filepath.Join(dir, "b.key"))
	if err != nil {
		t.Fatalf("LoadOrCreateRSAKey(b): %v", err)
	}
	if a.KeyID == b.KeyID {
		t.Errorf("distinct keys share kid %q; key rotation would be invisible to clients", a.KeyID)
	}
}

func TestKeyIDIsStableForTheSameKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k.key")
	first, err := LoadOrCreateRSAKey(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateRSAKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if first.KeyID != second.KeyID {
		t.Errorf("same key reloaded produced different kids %q and %q", first.KeyID, second.KeyID)
	}
}

// An IdP that cannot persist its signing key must not start; silently generating a fresh
// key every boot invalidates every token in the suite with no signal.
func TestKeyPersistenceFailureIsFatal(t *testing.T) {
	dir := t.TempDir()
	unwritable := filepath.Join(dir, "nope")
	if err := os.Mkdir(unwritable, 0500); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateRSAKey(filepath.Join(unwritable, "jwt.key")); err == nil {
		t.Error("LoadOrCreateRSAKey silently ignored an unwritable key path")
	}
}

func TestMalformedExistingKeyIsFatalAndPreserved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jwt.key")
	if err := os.WriteFile(path, []byte("not a PEM"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateRSAKey(path); err == nil {
		t.Fatal("malformed signing key was silently replaced")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != "not a PEM" {
		t.Fatal("malformed signing key was overwritten")
	}
}

func TestVerifyJWTRejectsTokenWithoutExp(t *testing.T) {
	km, err := LoadOrCreateRSAKey(filepath.Join(t.TempDir(), "k.key"))
	if err != nil {
		t.Fatal(err)
	}
	token, err := km.SignJWT(map[string]any{"sub": "u1", "iss": testIss, "token_use": "access_token"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := km.VerifyJWT(token, testIss, "access_token"); err == nil {
		t.Error("a token with no exp claim was accepted; it would never expire")
	}
}

func TestVerifyJWTRejectsExpiredAndAcceptsLive(t *testing.T) {
	km, err := LoadOrCreateRSAKey(filepath.Join(t.TempDir(), "k.key"))
	if err != nil {
		t.Fatal(err)
	}
	expired, _ := km.SignJWT(map[string]any{"sub": "u1", "iss": testIss, "token_use": "access_token", "exp": 1000})
	if _, err := km.VerifyJWT(expired, testIss, "access_token"); err == nil {
		t.Error("expired token accepted")
	}
	live, _ := km.SignJWT(map[string]any{"sub": "u1", "iss": testIss, "token_use": "access_token", "exp": 1 << 40})
	if _, err := km.VerifyJWT(live, testIss, "access_token"); err != nil {
		t.Errorf("live token rejected: %v", err)
	}
}

// b[i]%10 over a uniform byte over-represents 0-5 (26/256 each) and under-represents
// 6-9 (25/256 each). Per-digit that skew is only ~2%, which noise can hide, so this
// asserts on the aggregate {0..5} share where the same bias is ~8 standard errors out.
func TestGenerateRandomPINIsUnbiased(t *testing.T) {
	const draws = 200000
	low := 0 // count of digits 0-5, the ones modulo bias favours
	for i := 0; i < draws; i++ {
		pin, err := GenerateRandomPIN(1)
		if err != nil {
			t.Fatalf("GenerateRandomPIN: %v", err)
		}
		if len(pin) != 1 || pin[0] < '0' || pin[0] > '9' {
			t.Fatalf("malformed PIN %q", pin)
		}
		if pin[0] <= '5' {
			low++
		}
	}

	// Uniform expectation is 0.600. Modulo bias lands at 6*26/256 = 0.609.
	// Standard error at this sample size is ~0.0011, so 0.6045 sits between them.
	share := float64(low) / draws
	if share > 0.6045 {
		t.Errorf("digits 0-5 took %.4f of draws, expected 0.6000; modulo bias (%.4f is the biased value)",
			share, 6*26.0/256.0)
	}
	if share < 0.5955 {
		t.Errorf("digits 0-5 took %.4f of draws, expected 0.6000; generator is skewed", share)
	}
}

func TestRandomGeneratorsReportErrors(t *testing.T) {
	if _, err := GenerateRandomPIN(6); err != nil {
		t.Errorf("GenerateRandomPIN returned an error on the happy path: %v", err)
	}
	if _, err := GenerateRandomAlphanumeric(8); err != nil {
		t.Errorf("GenerateRandomAlphanumeric returned an error on the happy path: %v", err)
	}
}
