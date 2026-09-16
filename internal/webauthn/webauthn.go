// Package webauthn implements the subset of WebAuthn Level 2 that KyIdentity needs: verifying
// an ES256 assertion from a registered credential, and reading the authenticator data that
// accompanies registration.
//
// It deliberately parses no CBOR. The browser exposes the credential public key in SPKI form
// (AuthenticatorAttestationResponse.getPublicKey) and the raw authenticator data
// (getAuthenticatorData), both of which the standard library reads. KyIdentity does not verify
// attestation, so re-deriving those two values from the attestation object ourselves would
// buy no property we do not already have.
package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
)

// Authenticator data flag bits (WebAuthn Level 2, section 6.1).
const (
	FlagUserPresent            byte = 0x01
	FlagUserVerified           byte = 0x04
	FlagBackupEligible         byte = 0x08
	FlagBackupState            byte = 0x10
	FlagAttestedCredentialData byte = 0x40
)

// authDataHeaderLen is the fixed prefix: 32-byte RP ID hash, 1 flag byte, 4-byte counter.
const authDataHeaderLen = 37

type AuthenticatorData struct {
	RPIDHash  []byte
	Flags     byte
	SignCount uint32
}

func (a AuthenticatorData) UserPresent() bool    { return a.Flags&FlagUserPresent != 0 }
func (a AuthenticatorData) UserVerified() bool   { return a.Flags&FlagUserVerified != 0 }
func (a AuthenticatorData) BackupEligible() bool { return a.Flags&FlagBackupEligible != 0 }
func (a AuthenticatorData) BackupState() bool    { return a.Flags&FlagBackupState != 0 }

// ParseAuthenticatorData reads the fixed header. Attested credential data and extensions
// follow it during registration; nothing here reads past the header.
func ParseAuthenticatorData(b []byte) (AuthenticatorData, error) {
	if len(b) < authDataHeaderLen {
		return AuthenticatorData{}, fmt.Errorf("authenticator data is %d bytes, need at least %d", len(b), authDataHeaderLen)
	}
	return AuthenticatorData{
		RPIDHash:  b[:32],
		Flags:     b[32],
		SignCount: binary.BigEndian.Uint32(b[33:authDataHeaderLen]),
	}, nil
}

// ParseES256PublicKey reads a DER SPKI public key and rejects anything that is not P-256.
func ParseES256PublicKey(spki []byte) (*ecdsa.PublicKey, error) {
	parsed, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, fmt.Errorf("credential public key is not a valid SPKI key: %w", err)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("credential public key is not an ECDSA key")
	}
	if pub.Curve != elliptic.P256() {
		return nil, errors.New("credential public key is not on P-256")
	}
	return pub, nil
}

type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

// VerifyClientData checks the three fields that bind a ceremony to this server and this
// request. The challenge is compared as the exact base64url string the server issued: a
// re-encoding of the same bytes is a different string, and accepting it would let a caller
// present a challenge the store cannot match.
func VerifyClientData(raw []byte, wantType, wantChallenge, wantOrigin string) error {
	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return fmt.Errorf("client data is not valid JSON: %w", err)
	}
	if cd.Type != wantType {
		return fmt.Errorf("client data type is %q, want %q", cd.Type, wantType)
	}
	if subtle.ConstantTimeCompare([]byte(cd.Challenge), []byte(wantChallenge)) != 1 {
		return errors.New("client data challenge does not match the issued challenge")
	}
	if subtle.ConstantTimeCompare([]byte(cd.Origin), []byte(wantOrigin)) != 1 {
		return fmt.Errorf("client data origin %q is not this server's origin", cd.Origin)
	}
	return nil
}

type RegistrationInput struct {
	AuthenticatorData []byte
	ClientDataJSON    []byte
	PublicKeySPKI     []byte
	Challenge         string
	Origin            string
	RPID              string
}

// VerifyRegistration checks a credential creation response. Attestation is not verified:
// KyIdentity accepts any authenticator, so the statement would be recorded and never acted on.
func VerifyRegistration(in RegistrationInput) (AuthenticatorData, error) {
	if err := VerifyClientData(in.ClientDataJSON, "webauthn.create", in.Challenge, in.Origin); err != nil {
		return AuthenticatorData{}, err
	}
	ad, err := parseAndBind(in.AuthenticatorData, in.RPID)
	if err != nil {
		return AuthenticatorData{}, err
	}
	if _, err := ParseES256PublicKey(in.PublicKeySPKI); err != nil {
		return AuthenticatorData{}, err
	}
	return ad, nil
}

type AssertionInput struct {
	AuthenticatorData []byte
	ClientDataJSON    []byte
	Signature         []byte
	PublicKeySPKI     []byte
	Challenge         string
	Origin            string
	RPID              string
	StoredSignCount   uint32
	BackupEligible    bool
}

// VerifyAssertion checks a credential assertion end to end and returns the authenticator
// data it verified, so the caller can persist the new signature counter and backup state.
func VerifyAssertion(in AssertionInput) (AuthenticatorData, error) {
	if err := VerifyClientData(in.ClientDataJSON, "webauthn.get", in.Challenge, in.Origin); err != nil {
		return AuthenticatorData{}, err
	}
	ad, err := parseAndBind(in.AuthenticatorData, in.RPID)
	if err != nil {
		return AuthenticatorData{}, err
	}

	pub, err := ParseES256PublicKey(in.PublicKeySPKI)
	if err != nil {
		return AuthenticatorData{}, err
	}

	cdHash := sha256.Sum256(in.ClientDataJSON)
	signed := make([]byte, 0, len(in.AuthenticatorData)+len(cdHash))
	signed = append(signed, in.AuthenticatorData...)
	signed = append(signed, cdHash[:]...)
	digest := sha256.Sum256(signed)
	if !ecdsa.VerifyASN1(pub, digest[:], in.Signature) {
		return AuthenticatorData{}, errors.New("assertion signature is not valid for this credential")
	}

	// A counter that fails to advance means the authenticator was cloned, or the response
	// was replayed. Authenticators that never count report zero forever; only those are
	// exempt (WebAuthn Level 2, section 6.1.1). A backup-eligible credential lives on
	// several devices that each keep their own counter, so a sibling reporting a lower
	// value than the one on record is normal, not evidence of cloning — WebAuthn Level 3
	// recommends not enforcing the counter for those credentials at all.
	if !in.BackupEligible && !(ad.SignCount == 0 && in.StoredSignCount == 0) && ad.SignCount <= in.StoredSignCount {
		return AuthenticatorData{}, fmt.Errorf("signature counter did not advance: got %d, stored %d", ad.SignCount, in.StoredSignCount)
	}

	return ad, nil
}

// parseAndBind reads the authenticator data and confirms it was produced for this RP with
// the user physically present.
func parseAndBind(raw []byte, rpID string) (AuthenticatorData, error) {
	ad, err := ParseAuthenticatorData(raw)
	if err != nil {
		return AuthenticatorData{}, err
	}
	want := sha256.Sum256([]byte(rpID))
	if subtle.ConstantTimeCompare(ad.RPIDHash, want[:]) != 1 {
		return AuthenticatorData{}, errors.New("authenticator data was produced for a different relying party")
	}
	if !ad.UserPresent() {
		return AuthenticatorData{}, errors.New("authenticator did not report user presence")
	}
	return ad, nil
}

// RPIDFromIssuer derives the relying party ID and the exact origin from the configured
// issuer URL. The RP ID is the registrable host without the port; the origin keeps it,
// because that is what the browser puts in client data.
func RPIDFromIssuer(issuerURL string) (string, string, error) {
	u, err := url.Parse(issuerURL)
	if err != nil {
		return "", "", fmt.Errorf("issuer URL is not parseable: %w", err)
	}
	if u.Scheme == "" || u.Hostname() == "" {
		return "", "", fmt.Errorf("issuer URL %q has no scheme or host", issuerURL)
	}
	return u.Hostname(), u.Scheme + "://" + u.Host, nil
}
