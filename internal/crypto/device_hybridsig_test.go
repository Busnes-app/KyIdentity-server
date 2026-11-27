package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/Busnes-app/ky-primitives/hybridsig"
)

func TestParseAndVerifyHybridDeviceKey(t *testing.T) {
	priv, err := hybridsig.Generate()
	if err != nil {
		t.Fatalf("hybridsig.Generate: %v", err)
	}
	pubBytes := priv.Public().Bytes()
	pubB64 := base64.StdEncoding.EncodeToString(pubBytes)

	// Every base64 encoding variant accepted.
	for name, enc := range map[string]string{
		"std":     base64.StdEncoding.EncodeToString(pubBytes),
		"raw_std": base64.RawStdEncoding.EncodeToString(pubBytes),
		"url":     base64.URLEncoding.EncodeToString(pubBytes),
		"raw_url": base64.RawURLEncoding.EncodeToString(pubBytes),
	} {
		parsed, err := ParseDevicePublicKey(enc)
		if err != nil {
			t.Fatalf("%s: ParseDevicePublicKey failed: %v", name, err)
		}
		if parsed.Hybrid == nil || parsed.P256 != nil {
			t.Fatalf("%s: expected hybrid key only", name)
		}
	}

	msg := []byte("kyidentity-push-v2|https://id.example|u|d|c|login|1791331200000|approve|42")
	sig, err := priv.Sign(DevicePushResponseLabel, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	if !VerifyDeviceSignature(pubB64, DevicePushResponseLabel, msg, sigB64) {
		t.Fatal("expected valid hybrid device signature to verify")
	}
	// Wrong label must fail (domain separation).
	if VerifyDeviceSignature(pubB64, DevicePushTokenLabel, msg, sigB64) {
		t.Fatal("signature verified under wrong domain separation label")
	}
	// Tampered message must fail.
	if VerifyDeviceSignature(pubB64, DevicePushResponseLabel, []byte("tampered"), sigB64) {
		t.Fatal("signature verified over tampered message")
	}
	// Tampered ML-DSA byte must fail.
	badSig := append([]byte(nil), sig...)
	badSig[20] ^= 0x01
	if VerifyDeviceSignature(pubB64, DevicePushResponseLabel, msg, base64.StdEncoding.EncodeToString(badSig)) {
		t.Fatal("tampered ML-DSA-65 half verified")
	}
	// Tampered Ed25519 byte must fail.
	badSig2 := append([]byte(nil), sig...)
	badSig2[len(badSig2)-1] ^= 0x01
	if VerifyDeviceSignature(pubB64, DevicePushResponseLabel, msg, base64.StdEncoding.EncodeToString(badSig2)) {
		t.Fatal("tampered Ed25519 half verified")
	}

	// Truncated hybrid key with valid tag prefix must fail.
	trunc := base64.StdEncoding.EncodeToString(pubBytes[:len(pubBytes)-1])
	if _, err := ParseDevicePublicKey(trunc); err == nil {
		t.Fatal("expected truncated hybrid key to fail")
	}
}

func TestParseAndVerifyP256DeviceKeyBackwardCompat(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(spki)

	parsed, err := ParseDevicePublicKey(pubB64)
	if err != nil {
		t.Fatalf("ParseDevicePublicKey(P256): %v", err)
	}
	if parsed.P256 == nil || parsed.Hybrid != nil {
		t.Fatal("expected P-256 key only")
	}

	msg := []byte("kyidentity-push-v2|legacy")
	digest := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}
	if !VerifyDeviceSignature(pubB64, DevicePushResponseLabel, msg, base64.StdEncoding.EncodeToString(sig)) {
		t.Fatal("expected P-256 signature to verify")
	}

	// Cross-algorithm mismatch: hybrid signature against P-256 key must fail.
	hPriv, _ := hybridsig.Generate()
	hSig, _ := hPriv.Sign(DevicePushResponseLabel, msg)
	if VerifyDeviceSignature(pubB64, DevicePushResponseLabel, msg, base64.StdEncoding.EncodeToString(hSig)) {
		t.Fatal("hybrid signature unexpectedly verified against P-256 key")
	}
}
