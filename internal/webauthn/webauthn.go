// Package webauthn adapts github.com/go-webauthn/webauthn to KyIdentity's storage: challenges
// live in the store, and credential public keys are kept as base64url SPKI DER. The library
// does the ceremony verification; this package converts keys and enforces the counter policy.
package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// Authenticator data flag bits (WebAuthn Level 2, section 6.1).
const (
	FlagUserPresent    byte = 0x01
	FlagUserVerified   byte = 0x04
	FlagBackupEligible byte = 0x08
	FlagBackupState    byte = 0x10
)

// AuthenticatorData is what callers persist or audit from a verified ceremony.
type AuthenticatorData struct {
	Flags     byte
	SignCount uint32
}

func (a AuthenticatorData) UserPresent() bool    { return a.Flags&FlagUserPresent != 0 }
func (a AuthenticatorData) UserVerified() bool   { return a.Flags&FlagUserVerified != 0 }
func (a AuthenticatorData) BackupEligible() bool { return a.Flags&FlagBackupEligible != 0 }
func (a AuthenticatorData) BackupState() bool    { return a.Flags&FlagBackupState != 0 }

// ES256 only: every stored key is P-256 SPKI, and every mainstream passkey provider offers it.
var credParams = []protocol.CredentialParameter{{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256}}

// relyingParty is built per ceremony so an issuer the library rejects as an RP ID (a loopback
// IP) fails the ceremony, as browsers would, rather than server startup.
func relyingParty(rpID, origin string) (*gowebauthn.WebAuthn, error) {
	return gowebauthn.New(&gowebauthn.Config{
		RPID:                  rpID,
		RPDisplayName:         "KyIdentity",
		RPOrigins:             []string{origin},
		AttestationPreference: protocol.PreferNoAttestation,
	})
}

type user struct {
	id    []byte
	creds []gowebauthn.Credential
}

func (u user) WebAuthnID() []byte                           { return u.id }
func (u user) WebAuthnName() string                         { return "" }
func (u user) WebAuthnDisplayName() string                  { return "" }
func (u user) WebAuthnCredentials() []gowebauthn.Credential { return u.creds }

type RegistrationInput struct {
	CredentialID      []byte
	AttestationObject []byte
	ClientDataJSON    []byte
	UserHandle        []byte
	Challenge         string
	Origin            string
	RPID              string
}

type Registration struct {
	AuthenticatorData
	PublicKeySPKI []byte
}

// VerifyRegistration checks a credential creation response. Attestation is requested as
// "none"; an authenticator that sends a statement anyway has it checked but not trusted.
func VerifyRegistration(in RegistrationInput) (Registration, error) {
	rp, err := relyingParty(in.RPID, in.Origin)
	if err != nil {
		return Registration{}, err
	}
	parsed, err := protocol.CredentialCreationResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{ID: b64(in.CredentialID), Type: string(protocol.PublicKeyCredentialType)},
			RawID:      in.CredentialID,
		},
		AttestationResponse: protocol.AuthenticatorAttestationResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{ClientDataJSON: in.ClientDataJSON},
			AttestationObject:     in.AttestationObject,
		},
	}.Parse()
	if err != nil {
		return Registration{}, err
	}
	cred, err := rp.CreateCredential(user{id: in.UserHandle}, gowebauthn.SessionData{
		Challenge:        in.Challenge,
		UserID:           in.UserHandle,
		UserVerification: protocol.VerificationPreferred,
		CredParams:       credParams,
	}, parsed)
	if err != nil {
		return Registration{}, err
	}
	spki, err := coseToSPKI(cred.PublicKey)
	if err != nil {
		return Registration{}, err
	}
	return Registration{
		AuthenticatorData: AuthenticatorData{Flags: byte(parsed.Response.AttestationObject.AuthData.Flags), SignCount: cred.Authenticator.SignCount},
		PublicKeySPKI:     spki,
	}, nil
}

type AssertionInput struct {
	CredentialID      []byte
	UserHandle        []byte
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
	rp, err := relyingParty(in.RPID, in.Origin)
	if err != nil {
		return AuthenticatorData{}, err
	}
	publicKey, err := spkiToCOSE(in.PublicKeySPKI)
	if err != nil {
		return AuthenticatorData{}, err
	}
	parsed, err := protocol.CredentialAssertionResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{ID: b64(in.CredentialID), Type: string(protocol.PublicKeyCredentialType)},
			RawID:      in.CredentialID,
		},
		AssertionResponse: protocol.AuthenticatorAssertionResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{ClientDataJSON: in.ClientDataJSON},
			AuthenticatorData:     in.AuthenticatorData,
			Signature:             in.Signature,
		},
	}.Parse()
	if err != nil {
		return AuthenticatorData{}, err
	}
	// The caller resolved the credential within this user, so it is the user's only record here.
	stored := gowebauthn.Credential{
		ID:            in.CredentialID,
		PublicKey:     publicKey,
		Flags:         gowebauthn.CredentialFlags{BackupEligible: in.BackupEligible},
		Authenticator: gowebauthn.Authenticator{SignCount: in.StoredSignCount},
	}
	cred, err := rp.ValidateLogin(user{id: in.UserHandle, creds: []gowebauthn.Credential{stored}}, gowebauthn.SessionData{
		Challenge:            in.Challenge,
		UserID:               in.UserHandle,
		AllowedCredentialIDs: [][]byte{in.CredentialID},
		UserVerification:     protocol.VerificationPreferred,
	}, parsed)
	if err != nil {
		return AuthenticatorData{}, err
	}

	// The library only flags a counter that fails to advance; refusing is our policy. That
	// means a clone or a replay, except for authenticators that never count (both zero,
	// exempted by the library) and backup-eligible credentials, whose synced siblings each
	// keep their own counter (WebAuthn Level 3 recommends not enforcing it for those).
	got := parsed.Response.AuthenticatorData.Counter
	if cred.Authenticator.CloneWarning && !in.BackupEligible {
		return AuthenticatorData{}, fmt.Errorf("signature counter did not advance: got %d, stored %d", got, in.StoredSignCount)
	}
	return AuthenticatorData{Flags: byte(parsed.Response.AuthenticatorData.Flags), SignCount: got}, nil
}

func b64(b []byte) string { return protocol.URLEncodedBase64(b).String() }

// parseES256PublicKey reads a DER SPKI public key and rejects anything that is not P-256.
func parseES256PublicKey(spki []byte) (*ecdsa.PublicKey, error) {
	parsed, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, fmt.Errorf("credential public key is not a valid SPKI key: %w", err)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("credential public key is not a P-256 ECDSA key")
	}
	return pub, nil
}

// spkiToCOSE converts a stored key to the COSE_Key form the library verifies with.
func spkiToCOSE(spki []byte) ([]byte, error) {
	pub, err := parseES256PublicKey(spki)
	if err != nil {
		return nil, err
	}
	point, err := pub.Bytes()
	if err != nil {
		return nil, err
	}
	return webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{KeyType: int64(webauthncose.EllipticKey), Algorithm: int64(webauthncose.AlgES256)},
		Curve:         int64(webauthncose.P256),
		XCoord:        point[1:33],
		YCoord:        point[33:],
	})
}

// coseToSPKI converts a newly registered ES256 COSE_Key to the stored SPKI form.
func coseToSPKI(cose []byte) ([]byte, error) {
	key, err := webauthncose.ParsePublicKey(cose)
	if err != nil {
		return nil, err
	}
	ec, ok := key.(webauthncose.EC2PublicKeyData)
	if !ok || ec.Algorithm != int64(webauthncose.AlgES256) || ec.Curve != int64(webauthncose.P256) {
		return nil, errors.New("credential public key is not ES256")
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, ec.XCoord...), ec.YCoord...))
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKIXPublicKey(pub)
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
