package crypto

import (
	"bytes"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// writePEM writes one PEM block to a fresh key file and returns its path.
func writePEM(t *testing.T, typ string, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "jwt.key")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A signing key file that is not an RSA private key stops startup and is left in place;
// generating a replacement would silently invalidate every token the suite issued.
func TestLoadOrCreateRSAKeyRefusesForeignKeyFiles(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalPKCS8PrivateKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		path string
		want string
	}{
		"EC key":           {writePEM(t, "PRIVATE KEY", ecDER), "is not RSA"},
		"garbled PKCS#1":   {writePEM(t, "RSA PRIVATE KEY", []byte("garbage")), "failed to parse signing key"},
		"garbled PKCS#8":   {writePEM(t, "PRIVATE KEY", []byte("garbage")), "failed to parse signing key"},
		"key is directory": {t.TempDir(), "failed to read signing key"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			before, _ := os.ReadFile(c.path)
			if _, err := LoadOrCreateRSAKey(c.path); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			if after, _ := os.ReadFile(c.path); !bytes.Equal(before, after) {
				t.Fatal("the refused key file was changed")
			}
		})
	}
}

// A PKCS#8-encoded RSA key, as openssl genpkey writes it, is accepted and keeps its identity.
func TestLoadOrCreateRSAKeyAcceptsPKCS8(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	m, err := LoadOrCreateRSAKey(writePEM(t, "PRIVATE KEY", der))
	if err != nil {
		t.Fatal(err)
	}
	if !m.PrivateKey.Equal(key) {
		t.Fatal("a PKCS#8 key was replaced by another key")
	}
}

// A key file whose directory cannot be created is an error; nothing is written elsewhere.
func TestCreateKeyFileRefusesAnUncreatableDirectory(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := CreateKeyFile(filepath.Join(file, "sub", "k.key"), []byte("k")); err == nil {
		t.Fatal("created a key under a regular file")
	}
	if _, err := LoadOrCreateRSAKey(filepath.Join(file, "jwt.key")); err == nil || !strings.Contains(err.Error(), "signing key") {
		t.Fatalf("signing key under a regular file: %v", err)
	}
}

// signRaw signs an arbitrary header.claims pair with m's key, for tokens SignJWT would not
// produce.
func signRaw(t *testing.T, m *JWTKeyManager, header, claims string) string {
	t.Helper()
	input := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(claims))
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, m.PrivateKey, stdcrypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

const testIss = "https://id.example"

// A token is accepted only when it has three parts, a valid RS256 signature by this key,
// JSON claims, an exp, and the expected iss and token_use; the expired-tolerant variant
// relaxes exp and nothing else.
func TestVerifyJWTRefusals(t *testing.T) {
	dir := t.TempDir()
	m, err := LoadOrCreateRSAKey(filepath.Join(dir, "a.key"))
	if err != nil {
		t.Fatal(err)
	}
	other, err := LoadOrCreateRSAKey(filepath.Join(dir, "b.key"))
	if err != nil {
		t.Fatal(err)
	}
	claims := func(mutate func(map[string]any)) map[string]any {
		c := map[string]any{"iss": testIss, "sub": "u", "token_use": "access_token", "exp": time.Now().Add(time.Hour).Unix()}
		if mutate != nil {
			mutate(c)
		}
		return c
	}
	sign := func(m *JWTKeyManager, c map[string]any) string {
		token, err := m.SignJWT(c)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	live := sign(m, claims(nil))
	parts := strings.Split(live, ".")
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"`+testIss+`","sub":"admin","token_use":"access_token","exp":9999999999}`)) + "." + parts[2]
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: mustMarshalPKIX(t, m.PublicKey)})
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	es256 := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims(claims(nil)))
	cases := map[string]string{
		"two parts":         parts[0] + "." + parts[1],
		"bad sig encoding":  parts[0] + "." + parts[1] + ".!!!",
		"other key":         sign(other, claims(nil)),
		"tampered claims":   tampered,
		"claims not base64": signRawInput(t, m, parts[0]+".!!!"),
		"claims not JSON":   signRaw(t, m, `{"alg":"RS256"}`, "not json"),
		"string exp":        signRaw(t, m, `{"alg":"RS256"}`, `{"iss":"`+testIss+`","token_use":"access_token","exp":"tomorrow"}`),
		"no exp":            sign(m, claims(func(c map[string]any) { delete(c, "exp") })),
		"wrong iss":         sign(m, claims(func(c map[string]any) { c["iss"] = "https://evil.example" })),
		"no iss":            sign(m, claims(func(c map[string]any) { delete(c, "iss") })),
		"wrong token_use":   sign(m, claims(func(c map[string]any) { c["token_use"] = "id_token" })),
		"no token_use":      sign(m, claims(func(c map[string]any) { delete(c, "token_use") })),
		"alg none":          mustSign(t, jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims(claims(nil))), jwt.UnsafeAllowNoneSignatureType),
		"HS256 with pubkey": mustSign(t, jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims(nil))), pubPEM),
		"ES256":             mustSign(t, es256, ecKey),
		"RS256 header lies": signRaw(t, m, `{"alg":"HS256"}`, `{"iss":"`+testIss+`","token_use":"access_token","exp":9999999999}`),
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			for _, verify := range []func(string, string, string) (map[string]any, error){m.VerifyJWT, m.VerifyExpiredJWT} {
				if claims, err := verify(token, testIss, "access_token"); err == nil || claims != nil {
					t.Fatalf("accepted: claims %v err %v", claims, err)
				}
			}
		})
	}
	for _, verify := range []func(string, string, string) (map[string]any, error){m.VerifyJWT, m.VerifyExpiredJWT} {
		if _, err := verify(live, testIss, "access_token"); err != nil {
			t.Fatalf("live token refused: %v", err)
		}
		if _, err := verify(live, "", "access_token"); err == nil {
			t.Fatal("verified with no expected issuer")
		}
		if _, err := verify(live, testIss, ""); err == nil {
			t.Fatal("verified with no expected token_use")
		}
	}
	expired := sign(m, claims(func(c map[string]any) { c["exp"] = 1 }))
	if _, err := m.VerifyJWT(expired, testIss, "access_token"); !errors.Is(err, jwt.ErrTokenExpired) {
		t.Fatalf("VerifyJWT accepted an expired token: %v", err)
	}
	if claims, err := m.VerifyExpiredJWT(expired, testIss, "access_token"); err != nil || claims["sub"] != "u" {
		t.Fatalf("VerifyExpiredJWT refused a validly signed expired token: %v %v", claims, err)
	}
}

// Tokens must stay byte-identical to the hand-rolled encoding verifiers already accept:
// header {alg,kid,typ} and claims as sorted JSON, RS256 over the raw-url-base64 input.
func TestSignJWTMatchesLegacyEncoding(t *testing.T) {
	m, err := LoadOrCreateRSAKey(filepath.Join(t.TempDir(), "k.key"))
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"iss": testIss, "sub": "u", "aud": "app", "exp": int64(1 << 40), "roles": []string{"a"}, "events": map[string]any{"x": map[string]any{}}}
	for _, typ := range []string{"JWT", "logout+jwt"} {
		got, err := m.SignJWTWithType(typ, claims)
		if err != nil {
			t.Fatal(err)
		}
		h, _ := json.Marshal(map[string]any{"typ": typ, "alg": "RS256", "kid": m.KeyID})
		c, _ := json.Marshal(claims)
		want := signRaw(t, m, string(h), string(c))
		if got != want {
			t.Fatalf("%s token changed encoding:\n got %s\nwant %s", typ, got, want)
		}
	}
}

func mustSign(t *testing.T, tok *jwt.Token, key any) string {
	t.Helper()
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustMarshalPKIX(t *testing.T, pub any) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// signRawInput signs an already-encoded signing input verbatim.
func signRawInput(t *testing.T, m *JWTKeyManager, input string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, m.PrivateKey, stdcrypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// AES-GCM refuses a key of the wrong size in both directions, and ciphertext that is not
// base64, too short to hold a nonce, or altered.
func TestAESGCMRefusesWrongKeysAndMalformedCiphertext(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	if _, err := EncryptAESGCM(key[:16], []byte("x")); err == nil {
		t.Fatal("encrypted under a 16-byte key")
	}
	ct, err := EncryptAESGCM(key, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptAESGCM(key[:31], ct); err == nil {
		t.Fatal("decrypted under a 31-byte key")
	}
	if _, err := DecryptAESGCM(bytes.Repeat([]byte{2}, 32), ct); err == nil {
		t.Fatal("decrypted under the wrong key")
	}
	raw, _ := base64.StdEncoding.DecodeString(ct)
	raw[len(raw)-1] ^= 1
	for name, bad := range map[string]string{
		"not base64": "%%%",
		"short":      base64.StdEncoding.EncodeToString([]byte("tiny")),
		"altered":    base64.StdEncoding.EncodeToString(raw),
	} {
		if _, err := DecryptAESGCM(key, bad); err == nil {
			t.Errorf("%s ciphertext decrypted", name)
		}
	}
	if _, err := Open(key, "p", "r", "v2:%%%"); err == nil {
		t.Fatal("sealed value with a bad body opened")
	}
}

// HMAC verification refuses a signature that is not hex rather than comparing garbage.
func TestVerifyHMACRefusesNonHex(t *testing.T) {
	key := []byte("k")
	sig := SignHMACSHA256(key, []byte("data"))
	if !VerifyHMACSHA256(key, []byte("data"), sig) {
		t.Fatal("valid signature refused")
	}
	if VerifyHMACSHA256(key, []byte("data"), "zz"+sig[2:]) {
		t.Fatal("non-hex signature accepted")
	}
}

// Token digests are stored and compared as lowercase hex SHA-256; the encoding is part of
// every stored session, code and token hash.
func TestHashSHA256IsLowercaseHex(t *testing.T) {
	if got := HashSHA256("abc"); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("HashSHA256(abc) = %s", got)
	}
}

// GenerateRandomHex returns 2n lowercase hex characters, different on each call.
func TestGenerateRandomHex(t *testing.T) {
	a, err := GenerateRandomHex(16)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := GenerateRandomHex(16)
	if len(a) != 32 || a == b || strings.ToLower(a) != a {
		t.Fatalf("GenerateRandomHex: %q %q", a, b)
	}
	if _, err := hex.DecodeString(a); err != nil {
		t.Fatal(err)
	}
}

// A charset that cannot be sampled uniformly from one byte is refused.
func TestRandomStringRefusesUnusableCharsets(t *testing.T) {
	for _, cs := range []string{"", strings.Repeat("a", 257)} {
		if _, err := randomString(cs, 4); err == nil {
			t.Errorf("charset of %d characters accepted", len(cs))
		}
	}
}
