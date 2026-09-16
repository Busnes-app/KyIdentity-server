package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAESGCMEncryption(t *testing.T) {
	key, err := GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("GenerateRandomBytes failed: %v", err)
	}

	secretMessage := "my-super-secret-totp-seed-12345"
	encrypted, err := EncryptAESGCM(key, []byte(secretMessage))
	if err != nil {
		t.Fatalf("EncryptAESGCM failed: %v", err)
	}

	decrypted, err := DecryptAESGCM(key, encrypted)
	if err != nil {
		t.Fatalf("DecryptAESGCM failed: %v", err)
	}

	if string(decrypted) != secretMessage {
		t.Fatalf("decrypted mismatch: got %s, want %s", string(decrypted), secretMessage)
	}
}

func TestHMACSHA256(t *testing.T) {
	key := []byte("shared-sync-webhook-secret-key-32b")
	data := []byte(`{"event":"user.created","username":"alice"}`)

	sig := SignHMACSHA256(key, data)
	if !VerifyHMACSHA256(key, data, sig) {
		t.Fatal("HMAC verification failed")
	}

	if VerifyHMACSHA256(key, []byte(`{"tampered":true}`), sig) {
		t.Fatal("HMAC verification should have failed for tampered data")
	}
}

func TestRSAKeyAndJWTSigning(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "kyidentity-key-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	keyPath := filepath.Join(tmpDir, "test_jwt.key")
	km, err := LoadOrCreateRSAKey(keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateRSAKey failed: %v", err)
	}

	jwks := km.GetJWKS()
	if len(jwks.Keys) != 1 || jwks.Keys[0].Alg != "RS256" {
		t.Fatalf("unexpected JWKS output: %+v", jwks)
	}

	claims := map[string]any{
		"sub": "user-uuid-123",
		"iss": "http://localhost:5867",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}

	tokenStr, err := km.SignJWT(claims)
	if err != nil {
		t.Fatalf("SignJWT failed: %v", err)
	}

	parsedClaims, err := km.VerifyJWT(tokenStr)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}

	if parsedClaims["sub"] != "user-uuid-123" {
		t.Fatalf("claims sub mismatch: got %v", parsedClaims["sub"])
	}
}

func TestParseP256PublicKeyRejectsInvalidPoints(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	spki, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	sec1 := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)

	for name, encoded := range map[string]string{
		"spki der":            base64.StdEncoding.EncodeToString(spki),
		"uncompressed sec1":   base64.StdEncoding.EncodeToString(sec1),
		"raw url without pad": base64.RawURLEncoding.EncodeToString(spki),
	} {
		if _, err := ParseP256PublicKey(encoded); err != nil {
			t.Fatalf("%s should parse, got %v", name, err)
		}
	}

	offCurve := append([]byte{}, sec1...)
	offCurve[len(offCurve)-1] ^= 0x01

	for name, encoded := range map[string]string{
		"empty":           "",
		"not base64":      "!!!!",
		"truncated":       base64.StdEncoding.EncodeToString(sec1[:32]),
		"identity":        base64.StdEncoding.EncodeToString(make([]byte, 65)),
		"off-curve point": base64.StdEncoding.EncodeToString(offCurve),
		"random garbage":  base64.StdEncoding.EncodeToString([]byte("this is not a public key at all")),
	} {
		if _, err := ParseP256PublicKey(encoded); err == nil {
			t.Fatalf("%s must be rejected, but parsed successfully", name)
		}
	}
}

func TestVerifyECDSAP256(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pub := base64.StdEncoding.EncodeToString(spki)

	msg := []byte("kysignon-push-v1|challenge|approve|42")
	digest := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("SignASN1 failed: %v", err)
	}
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	if !VerifyECDSAP256(pub, msg, sigB64) {
		t.Fatal("a valid signature failed to verify")
	}
	if VerifyECDSAP256(pub, []byte("kysignon-push-v1|challenge|deny|42"), sigB64) {
		t.Fatal("signature verified against a different message")
	}
	if VerifyECDSAP256(pub, msg, "") {
		t.Fatal("empty signature verified")
	}
	if VerifyECDSAP256("", msg, sigB64) {
		t.Fatal("empty public key verified")
	}

	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherSPKI, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	if VerifyECDSAP256(base64.StdEncoding.EncodeToString(otherSPKI), msg, sigB64) {
		t.Fatal("signature verified against the wrong public key")
	}
}
