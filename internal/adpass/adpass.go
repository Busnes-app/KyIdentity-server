// Package adpass seals Active Directory passwords to the DC agent and authenticates
// queue entries. New agents use X-Wing HPKE and HybridSig; legacy agents retain
// X25519 HPKE and Ed25519 until the operator re-keys them.
package adpass

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/Busnes-app/ky-primitives/hybridsig"
	"github.com/Busnes-app/ky-primitives/xwing"
)

const (
	keyPrefix   = "x25519:"
	xwingPrefix = "xwing:"
)

var ErrKey = errors.New("agent key must be xwing: (1216-byte public key / 32-byte private seed) or x25519: (32 bytes), base64 encoded")

// PublicKey and PrivateKey keep the selected suite with its key material. Readers
// dispatch by the pinned key, never by attacker-controlled ciphertext or fallback.
type PublicKey struct {
	legacy *ecdh.PublicKey
	hybrid xwing.PublicKey
}
type PrivateKey struct {
	legacy *ecdh.PrivateKey
	hybrid xwing.PrivateKey
}

func (k *PrivateKey) PublicKey() *PublicKey {
	if k.legacy != nil {
		return &PublicKey{legacy: k.legacy.PublicKey()}
	}
	return &PublicKey{hybrid: k.hybrid.Public()}
}

func suite() (hpke.KDF, hpke.AEAD) { return hpke.HKDFSHA256(), hpke.AES256GCM() }

func info(version, systemID, userID string, seq int64) []byte {
	return []byte("kyidentity-ad-password/" + version + "\x00" + systemID + "\x00" + userID + "\x00" + strconv.FormatInt(seq, 10))
}

// ParsePublicKey reads the form EncodePublicKey writes.
func ParsePublicKey(s string) (*PublicKey, error) {
	s = strings.TrimSpace(s)
	prefix, b64, ok := strings.Cut(s, ":")
	raw, err := base64.StdEncoding.DecodeString(b64)
	if !ok || err != nil {
		return nil, ErrKey
	}
	switch prefix {
	case "xwing":
		k, err := xwing.ParsePublicKey(raw)
		if err != nil {
			return nil, ErrKey
		}
		return &PublicKey{hybrid: k}, nil
	case "x25519":
		k, err := ecdh.X25519().NewPublicKey(raw)
		if err != nil {
			return nil, ErrKey
		}
		return &PublicKey{legacy: k}, nil
	default:
		return nil, ErrKey
	}
}

// EncodePublicKey is the text the admin pastes into KyIdentity.
func EncodePublicKey(k *PublicKey) string {
	if k.legacy != nil {
		return keyPrefix + base64.StdEncoding.EncodeToString(k.legacy.Bytes())
	}
	return xwingPrefix + base64.StdEncoding.EncodeToString(k.hybrid.Bytes())
}

// GenerateKey makes a new X-Wing agent key.
func GenerateKey() (*PrivateKey, error) {
	k, err := xwing.Generate()
	if err != nil {
		return nil, err
	}
	return &PrivateKey{hybrid: k}, nil
}

// EncodePrivateKey persists only the seed for X-Wing. Legacy encodings are retained.
func EncodePrivateKey(k *PrivateKey) string {
	if k.legacy != nil {
		return "x25519-private:" + base64.StdEncoding.EncodeToString(k.legacy.Bytes())
	}
	return "xwing-private:" + base64.StdEncoding.EncodeToString(k.hybrid.Seed())
}

// ParsePrivateKey refuses unknown prefixes and wrong lengths, including public keys.
func ParsePrivateKey(s string) (*PrivateKey, error) {
	prefix, b64, ok := strings.Cut(strings.TrimSpace(s), ":")
	raw, err := base64.StdEncoding.DecodeString(b64)
	if !ok || err != nil {
		return nil, ErrKey
	}
	switch prefix {
	case "xwing-private":
		k, err := xwing.FromSeed(raw)
		if err != nil {
			return nil, ErrKey
		}
		return &PrivateKey{hybrid: k}, nil
	case "x25519-private":
		k, err := ecdh.X25519().NewPrivateKey(raw)
		if err != nil {
			return nil, ErrKey
		}
		return &PrivateKey{legacy: k}, nil
	default:
		return nil, ErrKey
	}
}

// Seal encrypts to the suite selected by the registered public key. Connector and
// user IDs are globally unique here; callers carry no separate tenant/org context.
func Seal(publicKey, systemID, userID string, seq int64, plaintext []byte) (string, error) {
	pk, err := ParsePublicKey(publicKey)
	if err != nil {
		return "", err
	}
	var ct []byte
	if pk.legacy != nil {
		hpk, err := hpke.NewDHKEMPublicKey(pk.legacy)
		if err != nil {
			return "", err
		}
		kdf, aead := suite()
		ct, err = hpke.Seal(hpk, kdf, aead, info("1", systemID, userID, seq), plaintext)
		if err != nil {
			return "", err
		}
	} else {
		ct, err = xwing.Seal(pk.hybrid, info("2", systemID, userID, seq), nil, plaintext)
		if err != nil {
			return "", err
		}
	}
	return base64.StdEncoding.EncodeToString(ct), nil
}

// Open fails unless the ciphertext matches the key suite, connector, user and seq.
func Open(k *PrivateKey, systemID, userID string, seq int64, ciphertext string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	if k.legacy == nil {
		return xwing.Open(k.hybrid, info("2", systemID, userID, seq), nil, raw)
	}
	hk, err := hpke.NewDHKEMPrivateKey(k.legacy)
	if err != nil {
		return nil, err
	}
	kdf, aead := suite()
	return hpke.Open(hk, kdf, aead, info("1", systemID, userID, seq), raw)
}

// Marker is the adminDescription value on every directory object a connector created.
func Marker(systemID, kind, localID string) string {
	return "kyidentity:" + systemID + ":" + kind + ":" + localID
}

// UnicodePwd is the unicodePwd value AD takes: the quoted password in UTF-16LE.
func UnicodePwd(password string) string {
	units := utf16.Encode([]rune(`"` + password + `"`))
	out := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(out[2*i:], u)
	}
	return string(out)
}

const signingPrefix = "ed25519:"

// ErrSigningKey reports a malformed or unsupported KyIdentity verification pin.
var ErrSigningKey = errors.New("KyIdentity signing key must be hybridsig: or ed25519: followed by its base64 public key")

// SigningKey selects exactly one verification algorithm; a hybrid pin never falls back.
type SigningKey struct {
	legacy ed25519.PublicKey
	hybrid *hybridsig.PublicKey
}

const hybridEntryLabel = "kyidentity-ad-entry/2"

// SignHybridEntry authenticates every entry field with both ML-DSA-65 and Ed25519.
func SignHybridEntry(k *hybridsig.PrivateKey, systemID, userID string, seq, expires int64, ciphertext string) (string, error) {
	raw, err := k.Sign(hybridEntryLabel, entryMessage(systemID, userID, seq, expires, ciphertext))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

func EncodeHybridSigningKey(pub *hybridsig.PublicKey) string {
	return "hybridsig:" + base64.StdEncoding.EncodeToString(pub.Bytes())
}

func entryMessage(systemID, userID string, seq, expires int64, ciphertext string) []byte {
	return []byte("kyidentity-ad-entry/1\x00" + systemID + "\x00" + userID + "\x00" + strconv.FormatInt(seq, 10) + "\x00" + strconv.FormatInt(expires, 10) + "\x00" + ciphertext)
}

// SignEntry signs a queue entry with KyIdentity's key, which lives outside the database:
// HPKE alone proves nothing about who encrypted, so the agent checks this first.
func SignEntry(k ed25519.PrivateKey, systemID, userID string, seq, expires int64, ciphertext string) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(k, entryMessage(systemID, userID, seq, expires, ciphertext)))
}

// VerifyEntry reports whether sig is KyIdentity's signature over exactly this entry.
func VerifyEntry(pub *SigningKey, systemID, userID string, seq, expires int64, ciphertext, sig string) bool {
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	msg := entryMessage(systemID, userID, seq, expires, ciphertext)
	if pub.hybrid != nil {
		return pub.hybrid.Verify(hybridEntryLabel, msg, raw) == nil
	}
	return ed25519.Verify(pub.legacy, msg, raw)
}

// EncodeSigningKey is the text the admin copies into the agent configuration.
func EncodeSigningKey(pub ed25519.PublicKey) string {
	return signingPrefix + base64.StdEncoding.EncodeToString(pub)
}

// ParseSigningKey reads the form EncodeSigningKey writes.
func ParseSigningKey(s string) (*SigningKey, error) {
	prefix, b64, ok := strings.Cut(strings.TrimSpace(s), ":")
	raw, err := base64.StdEncoding.DecodeString(b64)
	if !ok || err != nil {
		return nil, ErrSigningKey
	}
	switch prefix {
	case "hybridsig":
		pub, err := hybridsig.ParsePublicKey(raw)
		if err != nil {
			return nil, ErrSigningKey
		}
		return &SigningKey{hybrid: pub}, nil
	case "ed25519":
		if len(raw) != ed25519.PublicKeySize {
			return nil, ErrSigningKey
		}
		return &SigningKey{legacy: ed25519.PublicKey(raw)}, nil
	default:
		return nil, ErrSigningKey
	}
}
