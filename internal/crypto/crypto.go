package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// GenerateRandomBytes returns cryptographically secure random bytes.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// GenerateRandomHex returns a hex-encoded random string.
func GenerateRandomHex(n int) (string, error) {
	b, err := GenerateRandomBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// randomString draws length characters uniformly from charset. Rejection sampling keeps
// every character equally likely for charsets whose size does not divide 256.
func randomString(charset string, length int) (string, error) {
	n := len(charset)
	if n == 0 || n > 256 {
		return "", errors.New("charset must hold between 1 and 256 characters")
	}
	limit := 256 - (256 % n) // largest multiple of n at or below 256; draws at or above it are rejected

	out := make([]byte, length)
	buf := make([]byte, 1)
	for i := range out {
		for {
			if _, err := rand.Read(buf); err != nil {
				return "", fmt.Errorf("random source failed: %w", err)
			}
			if int(buf[0]) < limit {
				out[i] = charset[int(buf[0])%n]
				break
			}
		}
	}
	return string(out), nil
}

// GenerateRandomAlphanumeric returns an alphanumeric code of specified length.
func GenerateRandomAlphanumeric(length int) (string, error) {
	return randomString("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", length)
}

// GenerateRandomPIN returns a numeric PIN of specified digits.
func GenerateRandomPIN(digits int) (string, error) {
	return randomString("0123456789", digits)
}

// HashSHA256 returns hex encoded SHA-256 hash of the input.
func HashSHA256(input string) string {
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])
}

// SignHMACSHA256 produces a hex-encoded HMAC-SHA256 signature.
func SignHMACSHA256(key []byte, data []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyHMACSHA256 verifies HMAC-SHA256 in constant time.
func VerifyHMACSHA256(key []byte, data []byte, expectedHex string) bool {
	sig, err := hex.DecodeString(expectedHex)
	if err != nil {
		return false
	}
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return hmac.Equal(h.Sum(nil), sig)
}

// DeriveKey produces a distinct 32-byte key for a named purpose from a master key.
//
// HMAC-SHA256 keyed by a uniformly random 32-byte master is a PRF, so each label yields
// an independent key (single-block HKDF-Expand without the counter byte). A ciphertext
// encrypted for one label cannot be decrypted, or silently relocated, under another.
// Use a stable label such as "kysignon:setting:kyrecovery_token".
func DeriveKey(master []byte, label string) []byte {
	h := hmac.New(sha256.New, master)
	h.Write([]byte(label))
	return h.Sum(nil)
}

// EncryptAESGCM encrypts plaintext using AES-256-GCM with a prepended nonce.
// Database row secrets use Seal instead.
func EncryptAESGCM(key []byte, plaintext []byte) (string, error) {
	return encryptAESGCM(key, plaintext, nil)
}

// DecryptAESGCM decrypts base64 encoded ciphertext using AES-256-GCM. Under the master
// key it only reads legacy row secrets for migration; row secrets use Open.
func DecryptAESGCM(key []byte, ciphertextBase64 string) ([]byte, error) {
	return decryptAESGCM(key, ciphertextBase64, nil)
}

// sealedPrefix marks Seal output. ':' is outside the standard base64 alphabet, so no
// legacy EncryptAESGCM output can begin with it.
const sealedPrefix = "v2:"

// ErrLegacyCiphertext is returned by Open for ciphertext Seal did not produce.
var ErrLegacyCiphertext = errors.New("ciphertext is not row-bound (pre-v2 format)")

// Seal encrypts a row secret under a key derived for purpose and authenticates purpose
// and row, so the ciphertext opens nowhere else. row must be fixed for the row's lifetime.
func Seal(master []byte, purpose, row string, plaintext []byte) (string, error) {
	out, err := encryptAESGCM(sealKey(master, purpose), plaintext, sealAAD(purpose, row))
	if err != nil {
		return "", err
	}
	return sealedPrefix + out, nil
}

// Open reverses Seal for the same purpose and row. Legacy ciphertext is refused.
func Open(master []byte, purpose, row, sealed string) ([]byte, error) {
	body, ok := strings.CutPrefix(sealed, sealedPrefix)
	if !ok {
		return nil, ErrLegacyCiphertext
	}
	return decryptAESGCM(sealKey(master, purpose), body, sealAAD(purpose, row))
}

// IsSealed reports whether s is Seal output rather than legacy ciphertext.
func IsSealed(s string) bool { return strings.HasPrefix(s, sealedPrefix) }

func sealKey(master []byte, purpose string) []byte {
	return DeriveKey(master, "kyidentity:seal:"+purpose)
}

// Purposes are constants without '|', so purpose and row cannot run together.
func sealAAD(purpose, row string) []byte { return []byte(purpose + "|" + row) }

func encryptAESGCM(key, plaintext, aad []byte) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, plaintext, aad)), nil
}

func decryptAESGCM(key []byte, ciphertextBase64 string, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	data, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, aad)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("AES-256 key must be exactly 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// decodeBase64Any decodes standard, raw-standard, or raw-URL base64.
// Mobile SDKs disagree about padding and alphabet; the server should not care.
func decodeBase64Any(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("value is not valid base64")
}

// ParseP256PublicKey parses a base64 P-256 public key in either SPKI DER or uncompressed
// SEC1 point form. The point is validated as on-curve and non-identity; an invalid encoding
// is always an error and never a usable key.
func ParseP256PublicKey(encoded string) (*ecdsa.PublicKey, error) {
	raw, err := decodeBase64Any(encoded)
	if err != nil {
		return nil, err
	}

	if parsed, err := x509.ParsePKIXPublicKey(raw); err == nil {
		pub, ok := parsed.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return nil, errors.New("public key is not P-256")
		}
		return pub, nil
	}

	// crypto/ecdh rejects off-curve points, the identity, and wrong lengths.
	if _, err := ecdh.P256().NewPublicKey(raw); err != nil {
		return nil, fmt.Errorf("invalid P-256 public key: %w", err)
	}

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(raw[1:33]),
		Y:     new(big.Int).SetBytes(raw[33:65]),
	}, nil
}

// VerifyECDSAP256 verifies an ASN.1 DER ECDSA signature over SHA-256(message) against a
// base64-encoded P-256 public key. Any parse failure is a verification failure.
func VerifyECDSAP256(publicKey string, message []byte, signature string) bool {
	pub, err := ParseP256PublicKey(publicKey)
	if err != nil {
		return false
	}
	sig, err := decodeBase64Any(signature)
	if err != nil {
		return false
	}
	digest := sha256.Sum256(message)
	return ecdsa.VerifyASN1(pub, digest[:], sig)
}

// JWTKeyManager manages RSA keys for OIDC ID Token signing and JWKS.
type JWTKeyManager struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	KeyID      string
}

const minimumRSASigningKeyBits = 2048

// LoadOrCreateRSAKey loads an RSA private key of at least 2048 bits or creates a new one.
func LoadOrCreateRSAKey(keyPath string) (*JWTKeyManager, error) {
	var privKey *rsa.PrivateKey

	data, err := os.ReadFile(keyPath)
	if err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("signing key %s is not PEM", keyPath)
		}
		var parsedKey any
		var parseErr error
		if block.Type == "RSA PRIVATE KEY" {
			parsedKey, parseErr = x509.ParsePKCS1PrivateKey(block.Bytes)
		} else {
			parsedKey, parseErr = x509.ParsePKCS8PrivateKey(block.Bytes)
		}
		if parseErr != nil {
			return nil, fmt.Errorf("failed to parse signing key %s: %w", keyPath, parseErr)
		}
		var ok bool
		if privKey, ok = parsedKey.(*rsa.PrivateKey); !ok {
			return nil, fmt.Errorf("signing key %s is not RSA", keyPath)
		}
		if bits := privKey.N.BitLen(); bits < minimumRSASigningKeyBits {
			return nil, fmt.Errorf("signing key %s has %d bits; RSA signing keys must be at least %d bits", keyPath, bits, minimumRSASigningKeyBits)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read signing key %s: %w", keyPath, err)
	}

	if privKey == nil {
		var err error
		privKey, err = rsa.GenerateKey(rand.Reader, minimumRSASigningKeyBits)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA key: %w", err)
		}
		der := x509.MarshalPKCS1PrivateKey(privKey)
		pemData := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: der,
		})
		// A key that cannot be persisted is regenerated on every restart, silently
		// invalidating every token the suite has issued. Refuse to run that way.
		if err := CreateKeyFile(keyPath, pemData); errors.Is(err, os.ErrExist) {
			return LoadOrCreateRSAKey(keyPath) // a concurrent first start won; use its key
		} else if err != nil {
			return nil, fmt.Errorf("failed to persist signing key to %s: %w", keyPath, err)
		}
	}

	pubKey := &privKey.PublicKey
	pubDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	sum := sha256.Sum256(pubDER)
	kid := hex.EncodeToString(sum[:8])

	return &JWTKeyManager{
		PrivateKey: privKey,
		PublicKey:  pubKey,
		KeyID:      kid,
	}, nil
}

// JWK represents an RFC 7517 JSON Web Key.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// GetJWKS returns the public keys in JWKS format.
func (m *JWTKeyManager) GetJWKS() JWKS {
	nBytes := m.PublicKey.N.Bytes()
	eBytes := big.NewInt(int64(m.PublicKey.E)).Bytes()

	return JWKS{
		Keys: []JWK{
			{
				Kty: "RSA",
				Use: "sig",
				Alg: "RS256",
				Kid: m.KeyID,
				N:   base64.RawURLEncoding.EncodeToString(nBytes),
				E:   base64.RawURLEncoding.EncodeToString(eBytes),
			},
		},
	}
}

// SignJWT creates an RS256 signed JWT string with the given claims.
func (m *JWTKeyManager) SignJWT(claims map[string]any) (string, error) {
	return m.SignJWTWithType("JWT", claims)
}

// SignJWTWithType signs claims under an explicit `typ` header, so tokens with a different
// purpose (logout tokens are `logout+jwt`) are distinguishable before their claims are read.
func (m *JWTKeyManager) SignJWTWithType(typ string, claims map[string]any) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	token.Header["typ"] = typ
	token.Header["kid"] = m.KeyID
	signed, err := token.SignedString(m.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}
	return signed, nil
}

// VerifyJWT verifies an RS256 token signed by this key: exp is required and must not have
// passed, and iss and token_use must equal the given values.
func (m *JWTKeyManager) VerifyJWT(tokenString, issuer, tokenUse string) (map[string]any, error) {
	return m.verifyJWT(tokenString, issuer, tokenUse, false)
}

// VerifyExpiredJWT is VerifyJWT tolerating a past exp. It exists for RP-initiated logout,
// where an ID token hint identifies a login after the token itself has expired; it must
// never gate access.
func (m *JWTKeyManager) VerifyExpiredJWT(tokenString, issuer, tokenUse string) (map[string]any, error) {
	return m.verifyJWT(tokenString, issuer, tokenUse, true)
}

func (m *JWTKeyManager) verifyJWT(tokenString, issuer, tokenUse string, allowExpired bool) (map[string]any, error) {
	if issuer == "" || tokenUse == "" {
		return nil, errors.New("verifier needs an issuer and token_use")
	}
	opts := []jwt.ParserOption{jwt.WithValidMethods([]string{"RS256"}), jwt.WithExpirationRequired(), jwt.WithIssuer(issuer)}
	if allowExpired {
		// This also drops the exp-required and issuer options; both are rechecked below.
		opts = append(opts, jwt.WithoutClaimsValidation())
	}
	claims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(tokenString, claims, func(*jwt.Token) (any, error) { return m.PublicKey, nil }, opts...); err != nil {
		return nil, err
	}
	// A missing exp is not "no expiry", it is a malformed token. Fail closed.
	if exp, err := claims.GetExpirationTime(); err != nil || exp == nil {
		return nil, errors.New("token has no exp claim")
	}
	if claims["iss"] != issuer {
		return nil, errors.New("token was issued by a different issuer")
	}
	if claims["token_use"] != tokenUse {
		return nil, fmt.Errorf("token is not an %s", tokenUse)
	}
	return claims, nil
}

// P256SPKI returns the DER SubjectPublicKeyInfo of a P-256 key in either form
// ParseP256PublicKey accepts.
func P256SPKI(encoded string) ([]byte, error) {
	pub, err := ParseP256PublicKey(encoded)
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKIXPublicKey(pub)
}
