// Package adpass seals a password for the Active Directory agent: HPKE (RFC 9180) with
// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM. KyIdentity holds only the
// public key; the agent holds the private key. The info string binds the ciphertext to
// one connector, one user and one sequence number, so it cannot be moved or reordered.
package adpass

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"unicode/utf16"
)

const keyPrefix = "x25519:"

// ErrKey is a public or private key that is not a well-formed X25519 key.
var ErrKey = errors.New("agent key must be x25519: followed by 32 bytes of base64")

func suite() (hpke.KDF, hpke.AEAD) { return hpke.HKDFSHA256(), hpke.AES256GCM() }

func info(systemID, userID string, seq int64) []byte {
	return []byte("kyidentity-ad-password/1\x00" + systemID + "\x00" + userID + "\x00" + strconv.FormatInt(seq, 10))
}

// ParsePublicKey reads the form EncodePublicKey writes.
func ParsePublicKey(s string) (*ecdh.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(strings.TrimSpace(s), keyPrefix))
	if err != nil || !strings.HasPrefix(strings.TrimSpace(s), keyPrefix) {
		return nil, ErrKey
	}
	k, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, ErrKey
	}
	return k, nil
}

// EncodePublicKey is the text the admin pastes into KyIdentity.
func EncodePublicKey(k *ecdh.PublicKey) string {
	return keyPrefix + base64.StdEncoding.EncodeToString(k.Bytes())
}

// GenerateKey makes a new agent key.
func GenerateKey() (*ecdh.PrivateKey, error) { return ecdh.X25519().GenerateKey(rand.Reader) }

// Seal encrypts plaintext to the agent's public key for one user and sequence number.
func Seal(publicKey, systemID, userID string, seq int64, plaintext []byte) (string, error) {
	pk, err := ParsePublicKey(publicKey)
	if err != nil {
		return "", err
	}
	hpk, err := hpke.NewDHKEMPublicKey(pk)
	if err != nil {
		return "", err
	}
	kdf, aead := suite()
	ct, err := hpke.Seal(hpk, kdf, aead, info(systemID, userID, seq), plaintext)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ct), nil
}

// Open decrypts what Seal produced; it fails unless systemID, userID and seq are the ones
// the ciphertext was sealed for.
func Open(k *ecdh.PrivateKey, systemID, userID string, seq int64, ciphertext string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	hk, err := hpke.NewDHKEMPrivateKey(k)
	if err != nil {
		return nil, err
	}
	kdf, aead := suite()
	return hpke.Open(hk, kdf, aead, info(systemID, userID, seq), raw)
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

// ErrSigningKey is a KyIdentity entry-signing key that is not ed25519: and 32 bytes.
var ErrSigningKey = errors.New("KyIdentity signing key must be ed25519: followed by 32 bytes of base64")

func entryMessage(systemID, userID string, seq, expires int64, ciphertext string) []byte {
	return []byte("kyidentity-ad-entry/1\x00" + systemID + "\x00" + userID + "\x00" + strconv.FormatInt(seq, 10) + "\x00" + strconv.FormatInt(expires, 10) + "\x00" + ciphertext)
}

// SignEntry signs a queue entry with KyIdentity's key, which lives outside the database:
// HPKE alone proves nothing about who encrypted, so the agent checks this first.
func SignEntry(k ed25519.PrivateKey, systemID, userID string, seq, expires int64, ciphertext string) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(k, entryMessage(systemID, userID, seq, expires, ciphertext)))
}

// VerifyEntry reports whether sig is KyIdentity's signature over exactly this entry.
func VerifyEntry(pub ed25519.PublicKey, systemID, userID string, seq, expires int64, ciphertext, sig string) bool {
	raw, err := base64.StdEncoding.DecodeString(sig)
	return err == nil && ed25519.Verify(pub, entryMessage(systemID, userID, seq, expires, ciphertext), raw)
}

// EncodeSigningKey is the text the admin copies into the agent configuration.
func EncodeSigningKey(pub ed25519.PublicKey) string {
	return signingPrefix + base64.StdEncoding.EncodeToString(pub)
}

// ParseSigningKey reads the form EncodeSigningKey writes.
func ParseSigningKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, signingPrefix))
	if err != nil || !strings.HasPrefix(s, signingPrefix) || len(raw) != ed25519.PublicKeySize {
		return nil, ErrSigningKey
	}
	return ed25519.PublicKey(raw), nil
}
