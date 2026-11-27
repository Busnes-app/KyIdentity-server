package crypto

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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

const (
	// AlgRS256 is the RSA PKCS#1 v1.5 SHA-256 JWS algorithm kept for third-party OIDC RPs.
	AlgRS256 = "RS256"
	// AlgMLDSA65 is the RFC 9964 / FIPS 204 post-quantum ML-DSA-65 JWS algorithm.
	AlgMLDSA65 = "ML-DSA-65"

	mldsaPrivateKeyPEMType = "ML-DSA-65 PRIVATE KEY"
)

// SigningMethodMLDSA65 implements jwt.SigningMethod for RFC 9964 ML-DSA-65 (pure ML-DSA
// with an empty context string, matching crypto/mldsa and ky-primitives/oidcverify).
var SigningMethodMLDSA65 = &signingMethodMLDSA65{}

func init() {
	jwt.RegisterSigningMethod(AlgMLDSA65, func() jwt.SigningMethod {
		return SigningMethodMLDSA65
	})
}

type signingMethodMLDSA65 struct{}

func (*signingMethodMLDSA65) Alg() string { return AlgMLDSA65 }

func (*signingMethodMLDSA65) Sign(signingString string, key any) ([]byte, error) {
	priv, ok := key.(*mldsa.PrivateKey)
	if !ok || priv == nil {
		return nil, jwt.ErrInvalidKeyType
	}
	if priv.PublicKey().Parameters() != mldsa.MLDSA65() {
		return nil, jwt.ErrInvalidKey
	}
	return priv.Sign(rand.Reader, []byte(signingString), nil)
}

func (*signingMethodMLDSA65) Verify(signingString string, sig []byte, key any) error {
	pub, ok := key.(*mldsa.PublicKey)
	if !ok || pub == nil {
		return jwt.ErrInvalidKeyType
	}
	if pub.Parameters() != mldsa.MLDSA65() {
		return jwt.ErrInvalidKey
	}
	if err := mldsa.Verify(pub, []byte(signingString), sig, nil); err != nil {
		return jwt.ErrTokenSignatureInvalid
	}
	return nil
}

// VerificationKey is an additional public key published in JWKS and accepted by VerifyJWT
// alongside the active signing keys so key rotation can overlap without invalidating
// in-flight tokens.
type VerificationKey struct {
	Kid       string
	Alg       string
	PublicKey any // *rsa.PublicKey or *mldsa.PublicKey
}

// NormalizeSigningAlg validates an OAuth client's configured id_token_signed_response_alg.
// Empty means "use default" (RS256 for third-party compatibility).
func NormalizeSigningAlg(alg string) (string, error) {
	switch strings.TrimSpace(alg) {
	case "":
		return "", nil
	case AlgRS256:
		return AlgRS256, nil
	case AlgMLDSA65:
		return AlgMLDSA65, nil
	default:
		return "", fmt.Errorf("unsupported signing algorithm %q: must be RS256 or ML-DSA-65", alg)
	}
}

// LoadOrCreateMLDSAKey loads an ML-DSA-65 private seed PEM file or creates a new one.
// Concurrent first starts race safely via CreateKeyFile (O_EXCL) and converge on one key.
func LoadOrCreateMLDSAKey(keyPath string) (*mldsa.PrivateKey, *mldsa.PublicKey, string, error) {
	var priv *mldsa.PrivateKey

	data, err := os.ReadFile(keyPath)
	if err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, nil, "", fmt.Errorf("ML-DSA-65 signing key %s is not PEM", keyPath)
		}
		if block.Type != mldsaPrivateKeyPEMType {
			return nil, nil, "", fmt.Errorf("ML-DSA-65 signing key %s has unexpected PEM type %q", keyPath, block.Type)
		}
		if len(block.Bytes) != mldsa.PrivateKeySize {
			return nil, nil, "", fmt.Errorf("ML-DSA-65 signing key %s has %d seed bytes; expected %d", keyPath, len(block.Bytes), mldsa.PrivateKeySize)
		}
		priv, err = mldsa.NewPrivateKey(mldsa.MLDSA65(), block.Bytes)
		if err != nil {
			return nil, nil, "", fmt.Errorf("failed to parse ML-DSA-65 signing key %s: %w", keyPath, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, nil, "", fmt.Errorf("failed to read ML-DSA-65 signing key %s: %w", keyPath, err)
	}

	if priv == nil {
		priv, err = mldsa.GenerateKey(mldsa.MLDSA65())
		if err != nil {
			return nil, nil, "", fmt.Errorf("failed to generate ML-DSA-65 key: %w", err)
		}
		pemData := pem.EncodeToMemory(&pem.Block{
			Type:  mldsaPrivateKeyPEMType,
			Bytes: priv.Bytes(),
		})
		if err := CreateKeyFile(keyPath, pemData); errors.Is(err, os.ErrExist) {
			return LoadOrCreateMLDSAKey(keyPath)
		} else if err != nil {
			return nil, nil, "", fmt.Errorf("failed to persist ML-DSA-65 signing key to %s: %w", keyPath, err)
		}
	}

	pub := priv.PublicKey()
	sum := sha256.Sum256(pub.Bytes())
	kid := "mldsa65-" + hex.EncodeToString(sum[:8])
	return priv, pub, kid, nil
}

// LoadOrCreateSigningKeys loads or creates both the RS256 and ML-DSA-65 OIDC signing keys.
func LoadOrCreateSigningKeys(rsaKeyPath, mldsaKeyPath string) (*JWTKeyManager, error) {
	km, err := LoadOrCreateRSAKey(rsaKeyPath)
	if err != nil {
		return nil, err
	}
	if mldsaKeyPath != "" {
		priv, pub, kid, err := LoadOrCreateMLDSAKey(mldsaKeyPath)
		if err != nil {
			return nil, err
		}
		km.MLDSAPrivateKey = priv
		km.MLDSAPublicKey = pub
		km.MLDSAKeyID = kid
	}
	return km, nil
}

// HasMLDSA reports whether an active ML-DSA-65 signing key is loaded.
func (m *JWTKeyManager) HasMLDSA() bool {
	return m != nil && m.MLDSAPrivateKey != nil && m.MLDSAPublicKey != nil && m.MLDSAKeyID != ""
}

// SupportedSigningAlgs returns the JWS signing algorithms this key manager can sign with.
func (m *JWTKeyManager) SupportedSigningAlgs() []string {
	if m.HasMLDSA() {
		return []string{AlgMLDSA65, AlgRS256}
	}
	return []string{AlgRS256}
}

// AddVerificationKey registers a retired or rotated public key so it remains published in
// JWKS and accepted during verification while previously issued tokens are still live.
func (m *JWTKeyManager) AddVerificationKey(kid, alg string, pub any) error {
	kid = strings.TrimSpace(kid)
	if kid == "" {
		return errors.New("verification key requires a non-empty kid")
	}
	switch alg {
	case AlgRS256:
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok || rsaPub == nil || rsaPub.N.BitLen() < minimumRSASigningKeyBits {
			return errors.New("RS256 verification key must be an RSA public key of at least 2048 bits")
		}
	case AlgMLDSA65:
		mldsaPub, ok := pub.(*mldsa.PublicKey)
		if !ok || mldsaPub == nil || mldsaPub.Parameters() != mldsa.MLDSA65() {
			return errors.New("ML-DSA-65 verification key must be an ML-DSA-65 public key")
		}
	default:
		return fmt.Errorf("unsupported verification key algorithm %q", alg)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if (kid == m.KeyID && alg != AlgRS256) || (kid == m.MLDSAKeyID && alg != AlgMLDSA65) {
		return fmt.Errorf("verification key kid %q collides with active signing key of a different algorithm", kid)
	}
	for i := range m.extraKeys {
		if m.extraKeys[i].Kid == kid {
			if m.extraKeys[i].Alg != alg {
				return fmt.Errorf("verification key kid %q already registered for %s", kid, m.extraKeys[i].Alg)
			}
			m.extraKeys[i].PublicKey = pub
			return nil
		}
	}
	m.extraKeys = append(m.extraKeys, VerificationKey{Kid: kid, Alg: alg, PublicKey: pub})
	return nil
}

func rsaPublicToJWK(kid string, pub *rsa.PublicKey) JWK {
	nBytes := pub.N.Bytes()
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	return JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: AlgRS256,
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(nBytes),
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
	}
}

func mldsaPublicToJWK(kid string, pub *mldsa.PublicKey) JWK {
	return JWK{
		Kty: "AKP",
		Use: "sig",
		Alg: AlgMLDSA65,
		Kid: kid,
		Pub: base64.RawURLEncoding.EncodeToString(pub.Bytes()),
	}
}

func (m *JWTKeyManager) verificationAlgs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	hasMLDSA := m.MLDSAPublicKey != nil
	if !hasMLDSA {
		for _, k := range m.extraKeys {
			if k.Alg == AlgMLDSA65 {
				hasMLDSA = true
				break
			}
		}
	}
	if hasMLDSA {
		return []string{AlgRS256, AlgMLDSA65}
	}
	return []string{AlgRS256}
}

func (m *JWTKeyManager) resolveVerificationKey(token *jwt.Token) (any, error) {
	alg := token.Method.Alg()
	kid, _ := token.Header["kid"].(string)

	m.mu.RLock()
	defer m.mu.RUnlock()

	switch alg {
	case AlgRS256:
		if kid == "" || kid == m.KeyID {
			if m.PublicKey != nil {
				return m.PublicKey, nil
			}
		}
		for _, k := range m.extraKeys {
			if k.Alg == AlgRS256 && k.Kid == kid {
				return k.PublicKey, nil
			}
		}
		return nil, fmt.Errorf("unknown RS256 signing key %q", kid)

	case AlgMLDSA65:
		if kid == "" {
			return nil, errors.New("ML-DSA-65 JWT requires a non-empty kid header")
		}
		if kid == m.MLDSAKeyID && m.MLDSAPublicKey != nil {
			return m.MLDSAPublicKey, nil
		}
		for _, k := range m.extraKeys {
			if k.Alg == AlgMLDSA65 && k.Kid == kid {
				return k.PublicKey, nil
			}
		}
		return nil, fmt.Errorf("unknown ML-DSA-65 signing key %q", kid)

	default:
		return nil, fmt.Errorf("unsupported JWT signing algorithm %q", alg)
	}
}
