package oauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
)

// deviceAssertion is the RFC 7523 assertion a paired KyAuth device signs with its
// enrolled P-256 key to sign in to a suite app. Only the fields the grant checks.
type deviceAssertion struct {
	DeviceID  string
	Subject   string
	Audience  string
	ClientID  string
	JTI       string
	IssuedAt  int64
	ExpiresAt int64
}

const maxAssertionLen = 4096

// parseDeviceAssertion splits a compact JWS and pins the header to exactly what
// KyAuth emits. It verifies nothing about the signature; that needs the device row.
func parseDeviceAssertion(compact string) (*deviceAssertion, []byte, []byte, error) {
	if len(compact) > maxAssertionLen {
		return nil, nil, nil, errors.New("assertion too long")
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, nil, nil, errors.New("assertion is not a compact JWS")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, nil, errors.New("bad header encoding")
	}
	var header map[string]json.RawMessage
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, nil, nil, errors.New("bad header")
	}
	var alg, typ, kid string
	_ = json.Unmarshal(header["alg"], &alg)
	_ = json.Unmarshal(header["typ"], &typ)
	_ = json.Unmarshal(header["kid"], &kid)
	if alg != "ES256" || typ != "JWT" || kid == "" || len(header) != 3 {
		return nil, nil, nil, errors.New("header must be exactly alg=ES256, typ=JWT, kid")
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, nil, errors.New("bad claims encoding")
	}
	var c struct {
		Iss      string `json:"iss"`
		Sub      string `json:"sub"`
		Aud      string `json:"aud"`
		ClientID string `json:"client_id"`
		JTI      string `json:"jti"`
		Iat      int64  `json:"iat"`
		Exp      int64  `json:"exp"`
	}
	if err := json.Unmarshal(claimsJSON, &c); err != nil {
		return nil, nil, nil, errors.New("bad claims")
	}
	if c.Iss != "device:"+kid {
		return nil, nil, nil, errors.New("iss does not name the kid device")
	}
	if c.Sub == "" || c.Aud == "" || c.ClientID == "" || c.JTI == "" || c.Iat == 0 || c.Exp == 0 {
		return nil, nil, nil, errors.New("missing claim")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, nil, errors.New("bad signature encoding")
	}
	a := &deviceAssertion{DeviceID: kid, Subject: c.Sub, Audience: c.Aud, ClientID: c.ClientID, JTI: c.JTI, IssuedAt: c.Iat, ExpiresAt: c.Exp}
	return a, []byte(parts[0] + "." + parts[1]), sig, nil
}

// verifyES256 checks a JWS raw r||s signature over signingInput. DER input is
// refused by length; r and s outside [1, n) are refused before the curve math.
func verifyES256(pub *ecdsa.PublicKey, signingInput, sig []byte) bool {
	if pub == nil || len(sig) != 64 {
		return false
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	n := elliptic.P256().Params().N
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(n) >= 0 || s.Cmp(n) >= 0 {
		return false
	}
	digest := sha256.Sum256(signingInput)
	return ecdsa.Verify(pub, digest[:], r, s)
}
