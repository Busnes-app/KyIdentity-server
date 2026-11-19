package adpass

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestSealBindsConnectorUserAndSequence(t *testing.T) {
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := EncodePublicKey(k.PublicKey())
	secret := []byte("Correct-horse-42")
	ct, err := Seal(pub, "sys-1", "user-a", 7, secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(ct), secret) {
		t.Fatal("ciphertext carries the plaintext")
	}
	got, err := Open(k, "sys-1", "user-a", 7, ct)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("open = %q, %v", got, err)
	}
	for name, try := range map[string]func() ([]byte, error){
		"another user":      func() ([]byte, error) { return Open(k, "sys-1", "user-b", 7, ct) },
		"another connector": func() ([]byte, error) { return Open(k, "sys-2", "user-a", 7, ct) },
		"older sequence":    func() ([]byte, error) { return Open(k, "sys-1", "user-a", 6, ct) },
		"newer sequence":    func() ([]byte, error) { return Open(k, "sys-1", "user-a", 8, ct) },
	} {
		if _, err := try(); err == nil {
			t.Errorf("%s: ciphertext opened", name)
		}
	}
	other, _ := GenerateKey()
	if _, err := Open(other, "sys-1", "user-a", 7, ct); err == nil {
		t.Error("another key opened the ciphertext")
	}
}

func TestParsePublicKeyRefusesMalformedKeys(t *testing.T) {
	k, _ := GenerateKey()
	good := EncodePublicKey(k.PublicKey())
	if _, err := ParsePublicKey(good); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "x25519:", "x25519:AAAA", good[len("x25519:"):], "ed25519:" + good[len("x25519:"):]} {
		if _, err := ParsePublicKey(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := Seal("x25519:AAAA", "s", "u", 1, []byte("p")); err == nil {
		t.Error("sealed to a malformed key")
	}
}

func TestEntrySignatureCoversEveryField(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	sig := SignEntry(priv, "s", "u", 5, 100, "ct")
	if !VerifyEntry(pub, "s", "u", 5, 100, "ct", sig) {
		t.Fatal("valid signature refused")
	}
	for name, ok := range map[string]bool{
		"connector":  VerifyEntry(pub, "x", "u", 5, 100, "ct", sig),
		"user":       VerifyEntry(pub, "s", "x", 5, 100, "ct", sig),
		"seq":        VerifyEntry(pub, "s", "u", 6, 100, "ct", sig),
		"expiry":     VerifyEntry(pub, "s", "u", 5, 101, "ct", sig),
		"ciphertext": VerifyEntry(pub, "s", "u", 5, 100, "cu", sig),
		"no sig":     VerifyEntry(pub, "s", "u", 5, 100, "ct", ""),
	} {
		if ok {
			t.Errorf("signature accepted with a changed %s", name)
		}
	}
	if got, err := ParseSigningKey(EncodeSigningKey(pub)); err != nil || !got.Equal(pub) {
		t.Fatal("signing key round trip", err)
	}
	if _, err := ParseSigningKey("ed25519:AAAA"); err == nil {
		t.Fatal("short signing key accepted")
	}
}
