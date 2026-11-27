package adpass

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"encoding/base64"
	"github.com/Busnes-app/ky-primitives/hybridsig"
	"github.com/Busnes-app/ky-primitives/xwing"
	"strings"
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
	edPub, priv, _ := ed25519.GenerateKey(nil)
	pub, _ := ParseSigningKey(EncodeSigningKey(edPub))
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
	if got, err := ParseSigningKey(EncodeSigningKey(edPub)); err != nil || !bytes.Equal(got.legacy, edPub) {
		t.Fatal("signing key round trip", err)
	}
	if _, err := ParseSigningKey("ed25519:AAAA"); err == nil {
		t.Fatal("short signing key accepted")
	}
}

func TestLegacyHPKEWireCompatibility(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, 32)
	legacy, err := ParsePrivateKey("x25519-private:" + base64.StdEncoding.EncodeToString(seed))
	if err != nil {
		t.Fatal(err)
	}
	ct, err := Seal(EncodePublicKey(legacy.PublicKey()), "s", "u", 9, []byte("legacy-password"))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(ct)
	hk, _ := hpke.NewDHKEMPrivateKey(legacy.legacy)
	// Exact pre-upgrade domain and stdlib wire; no new version byte or signature format.
	oldInfo := []byte("kyidentity-ad-password/1\x00s\x00u\x009")
	plain, err := hpke.Open(hk, hpke.HKDFSHA256(), hpke.AES256GCM(), oldInfo, raw)
	if err != nil || string(plain) != "legacy-password" {
		t.Fatal("legacy reader", err)
	}
	oldCT, err := hpke.Seal(mustLegacyPublic(t, legacy), hpke.HKDFSHA256(), hpke.AES256GCM(), oldInfo, []byte("old-queue"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err = Open(legacy, "s", "u", 9, base64.StdEncoding.EncodeToString(oldCT))
	if err != nil || string(plain) != "old-queue" {
		t.Fatal("legacy writer", err)
	}
	for _, args := range []struct {
		s, u string
		seq  int64
	}{{"x", "u", 9}, {"s", "x", 9}, {"s", "u", 10}} {
		if _, err := Open(legacy, args.s, args.u, args.seq, ct); err == nil {
			t.Fatal("legacy context moved")
		}
	}
	hybrid, _ := GenerateKey()
	if _, err := Open(hybrid, "s", "u", 9, ct); err == nil {
		t.Fatal("X-Wing accepted legacy ciphertext")
	}
	newCT, _ := Seal(EncodePublicKey(hybrid.PublicKey()), "s", "u", 9, []byte("new"))
	if _, err := Open(legacy, "s", "u", 9, newCT); err == nil {
		t.Fatal("legacy accepted X-Wing ciphertext")
	}
}

func mustLegacyPublic(t *testing.T, k *PrivateKey) hpke.PublicKey {
	t.Helper()
	pk, err := hpke.NewDHKEMPublicKey(k.legacy.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

func TestXWingWireAndTampering(t *testing.T) {
	k, _ := GenerateKey()
	pub := EncodePublicKey(k.PublicKey())
	if !strings.HasPrefix(pub, "xwing:") || len(pub) != len("xwing:")+base64.StdEncoding.EncodedLen(xwing.PublicKeyBytes) {
		t.Fatal("new key is not X-Wing")
	}
	restored, err := ParsePrivateKey(EncodePrivateKey(k))
	if err != nil || EncodePublicKey(restored.PublicKey()) != pub {
		t.Fatal("seed round trip", err)
	}
	ct, err := Seal(pub, "s", "u", 1, []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(ct)
	plain, err := xwing.Open(k.hybrid, []byte("kyidentity-ad-password/2\x00s\x00u\x001"), nil, raw)
	if err != nil || string(plain) != "password" {
		t.Fatal("X-Wing v2 wire", err)
	}
	if _, err := xwing.Open(k.hybrid, info("1", "s", "u", 1), nil, raw); err == nil {
		t.Fatal("v1 domain accepted")
	}
	for _, i := range []int{0, 1, xwing.EncapsulationBytes, len(raw) - 1} {
		changed := bytes.Clone(raw)
		changed[i] ^= 1
		if _, err := Open(k, "s", "u", 1, base64.StdEncoding.EncodeToString(changed)); err == nil {
			t.Fatalf("tamper at %d", i)
		}
	}
	for _, bad := range []string{"!", "", base64.StdEncoding.EncodeToString(raw[:len(raw)-1])} {
		if _, err := Open(k, "s", "u", 1, bad); err == nil {
			t.Fatal("malformed ciphertext accepted")
		}
	}
	for _, bad := range []string{"xwing:", "xwing:AAAA", "xwing:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{255}, 1216)), "xwing-private:AAAA", "unknown-private:" + base64.StdEncoding.EncodeToString(make([]byte, 32)), strings.TrimPrefix(EncodePrivateKey(k), "xwing-private:"), pub} {
		if _, err := ParsePrivateKey(bad); err == nil {
			t.Fatal("malformed private key accepted")
		}
	}
	for _, bad := range []string{"xwing:", "xwing:AAAA", "xwing:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{255}, 1216)), EncodePrivateKey(k)} {
		if _, err := ParsePublicKey(bad); err == nil {
			t.Fatal("malformed public key accepted")
		}
	}
}

func TestHybridSignatureRequiresBothHalvesAndEveryField(t *testing.T) {
	k, err := hybridsig.FromSeeds(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParseSigningKey(EncodeHybridSigningKey(k.Public()))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := SignHybridEntry(k, "s", "u", 5, 100, "ct")
	if err != nil || !VerifyEntry(pub, "s", "u", 5, 100, "ct", sig) {
		t.Fatal("hybrid round trip", err)
	}
	for _, v := range []struct {
		s, u     string
		seq, exp int64
		ct       string
	}{{"x", "u", 5, 100, "ct"}, {"s", "x", 5, 100, "ct"}, {"s", "u", 6, 100, "ct"}, {"s", "u", 5, 101, "ct"}, {"s", "u", 5, 100, "cu"}} {
		if VerifyEntry(pub, v.s, v.u, v.seq, v.exp, v.ct, sig) {
			t.Fatal("changed field accepted")
		}
	}
	raw, _ := base64.StdEncoding.DecodeString(sig)
	for _, i := range []int{0, len(hybridsig.Alg) + 1, len(raw) - 1} {
		changed := bytes.Clone(raw)
		changed[i] ^= 1
		if VerifyEntry(pub, "s", "u", 5, 100, "ct", base64.StdEncoding.EncodeToString(changed)) {
			t.Fatalf("signature tamper at %d", i)
		}
	}
	_, edSeed := k.Seeds()
	legacy := ed25519.NewKeyFromSeed(edSeed)
	legacyPin, _ := ParseSigningKey(EncodeSigningKey(legacy.Public().(ed25519.PublicKey)))
	if VerifyEntry(pub, "s", "u", 5, 100, "ct", SignEntry(legacy, "s", "u", 5, 100, "ct")) {
		t.Fatal("hybrid downgraded to Ed25519")
	}
	if VerifyEntry(legacyPin, "s", "u", 5, 100, "ct", sig) {
		t.Fatal("hybrid accepted under legacy pin")
	}
	for _, bad := range []string{"", "!", base64.StdEncoding.EncodeToString(raw[:len(raw)-1])} {
		if VerifyEntry(pub, "s", "u", 5, 100, "ct", bad) {
			t.Fatal("malformed signature accepted")
		}
	}
	for _, bad := range []string{"hybridsig:", "hybridsig:AAAA", "unknown:" + strings.SplitN(EncodeHybridSigningKey(k.Public()), ":", 2)[1]} {
		if _, err := ParseSigningKey(bad); err == nil {
			t.Fatal("malformed signing pin accepted")
		}
	}
}
