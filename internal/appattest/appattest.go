// Package appattest verifies Apple App Attest attestation objects ("Validating apps that
// connect to your server"). It is pure verification: no database, no HTTP. A pass proves the
// object was produced by a genuine Apple device for one of the configured App IDs; it says
// nothing about any key other than the App Attest key itself.
package appattest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/fxamacker/cbor/v2"
)

//go:embed apple_app_attestation_root_ca.pem
var appleRootPEM []byte

// AppleRootSHA256 pins the Apple App Attestation Root CA (DER, SHA-256, hex).
const AppleRootSHA256 = "1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932"

// Input bounds. A real attestation object is about 5-6 KB with a two-certificate chain.
const (
	MaxAttestationBytes = 16 << 10
	maxKeyIDChars       = 64
	maxCerts            = 4
	maxCertBytes        = 4 << 10
)

// NonceOID is Apple's nonce extension: SEQUENCE { [1] EXPLICIT OCTET STRING }.
var NonceOID = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}

var (
	aaguidProduction  = append([]byte("appattest"), make([]byte, 7)...)
	aaguidDevelopment = []byte("appattestdevelop")
)

// Reason classifies a failed verification for the audit log. It is never sent to the client.
type Reason string

const (
	ReasonTooLarge     Reason = "attestation too large"
	ReasonKeyID        Reason = "key id malformed"
	ReasonDecode       Reason = "attestation object malformed"
	ReasonFormat       Reason = "attestation format is not apple-appattest"
	ReasonCertificate  Reason = "certificate malformed"
	ReasonChain        Reason = "chain does not verify to the Apple App Attestation root"
	ReasonNonce        Reason = "nonce mismatch"
	ReasonKeyMismatch  Reason = "key id does not match the attested key"
	ReasonAuthData     Reason = "authenticator data malformed"
	ReasonAppID        Reason = "app id not configured"
	ReasonSignCount    Reason = "sign count is not zero"
	ReasonAAGUID       Reason = "aaguid not accepted"
	ReasonCredentialID Reason = "credential id does not match key id"
)

// Error is a failed verification: a fixed Reason plus optional detail for the log.
type Error struct {
	Reason Reason
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return "app attest: " + string(e.Reason)
	}
	return "app attest: " + string(e.Reason) + ": " + e.Detail
}

func fail(r Reason, detail string) error { return &Error{Reason: r, Detail: detail} }

// Verifier checks attestation objects against a pinned root and the configured App IDs.
type Verifier struct {
	roots            *x509.CertPool
	rpIDHashes       [][]byte
	allowDevelopment bool
	now              func() time.Time
}

// NewVerifier pins the embedded Apple App Attestation Root CA. appIDs are
// `<TeamID>.<bundleID>` values, validated by the caller's configuration boundary.
func NewVerifier(appIDs []string, allowDevelopment bool) (*Verifier, error) {
	root, err := AppleRoot()
	if err != nil {
		return nil, err
	}
	return NewVerifierWithRoot(root, appIDs, allowDevelopment), nil
}

// NewVerifierWithRoot pins root instead of Apple's; tests use it with a generated CA.
func NewVerifierWithRoot(root *x509.Certificate, appIDs []string, allowDevelopment bool) *Verifier {
	pool := x509.NewCertPool()
	pool.AddCert(root)
	hashes := make([][]byte, 0, len(appIDs))
	for _, id := range appIDs {
		h := sha256.Sum256([]byte(id))
		hashes = append(hashes, h[:])
	}
	return &Verifier{roots: pool, rpIDHashes: hashes, allowDevelopment: allowDevelopment, now: time.Now}
}

// AppleRoot parses the embedded root and refuses it unless it matches AppleRootSHA256.
func AppleRoot() (*x509.Certificate, error) {
	block, _ := pem.Decode(appleRootPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("appattest: embedded root is not a PEM certificate")
	}
	if sum := sha256.Sum256(block.Bytes); hex.EncodeToString(sum[:]) != AppleRootSHA256 {
		return nil, errors.New("appattest: embedded root does not match the pinned fingerprint")
	}
	return x509.ParseCertificate(block.Bytes)
}

type attestationObject struct {
	Fmt     string `cbor:"fmt"`
	AttStmt struct {
		X5C [][]byte `cbor:"x5c"`
	} `cbor:"attStmt"`
	AuthData []byte `cbor:"authData"`
}

var decMode = func() cbor.DecMode {
	dm, err := cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		MaxNestedLevels:  8,
		MaxArrayElements: 16,
		MaxMapPairs:      16,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return dm
}()

// Verify checks attestation (the raw CBOR object) for keyID (standard base64, as
// DCAppAttestService returns it) against clientDataHash = SHA256(clientData). It returns nil
// on a pass and an *Error otherwise.
func (v *Verifier) Verify(keyID string, attestation, clientDataHash []byte) error {
	if len(attestation) > MaxAttestationBytes {
		return fail(ReasonTooLarge, fmt.Sprintf("%d bytes", len(attestation)))
	}
	if len(keyID) > maxKeyIDChars {
		return fail(ReasonKeyID, "too long")
	}
	keyIDRaw, err := base64.StdEncoding.Strict().DecodeString(keyID)
	if err != nil || len(keyIDRaw) != sha256.Size {
		return fail(ReasonKeyID, "not base64 of 32 bytes")
	}

	// 1. Decode.
	var obj attestationObject
	if err := decMode.Unmarshal(attestation, &obj); err != nil {
		return fail(ReasonDecode, err.Error())
	}
	if obj.Fmt != "apple-appattest" {
		return fail(ReasonFormat, "")
	}
	if len(obj.AttStmt.X5C) == 0 || len(obj.AttStmt.X5C) > maxCerts {
		return fail(ReasonCertificate, fmt.Sprintf("%d certificates", len(obj.AttStmt.X5C)))
	}
	certs := make([]*x509.Certificate, 0, len(obj.AttStmt.X5C))
	for i, der := range obj.AttStmt.X5C {
		if len(der) > maxCertBytes {
			return fail(ReasonCertificate, fmt.Sprintf("certificate %d too large", i))
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return fail(ReasonCertificate, fmt.Sprintf("certificate %d: %v", i, err))
		}
		certs = append(certs, c)
	}
	leaf := certs[0]

	// 2. Chain to the pinned root at the current time.
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots: v.roots, Intermediates: inter, CurrentTime: v.now(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fail(ReasonChain, err.Error())
	}
	strongChain := false
	for _, chain := range chains {
		if crypto.CheckCertificateKeys(chain...) == nil {
			strongChain = true
			break
		}
	}
	if !strongChain {
		return fail(ReasonChain, "certificate keys do not meet the strength policy")
	}

	// 3. Nonce = SHA256(authData || clientDataHash) must equal the leaf extension.
	nonce, err := leafNonce(leaf)
	if err != nil {
		return fail(ReasonNonce, err.Error())
	}
	want := sha256.Sum256(append(append([]byte{}, obj.AuthData...), clientDataHash...))
	if !bytes.Equal(nonce, want[:]) {
		return fail(ReasonNonce, "")
	}

	// 4. keyId is SHA256 of the leaf's uncompressed P-256 point.
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return fail(ReasonKeyMismatch, "leaf key is not P-256")
	}
	ek, err := pub.ECDH()
	if err != nil {
		return fail(ReasonKeyMismatch, err.Error())
	}
	if sum := sha256.Sum256(ek.Bytes()); !bytes.Equal(sum[:], keyIDRaw) {
		return fail(ReasonKeyMismatch, "")
	}

	// 5-8. Authenticator data.
	ad, err := parseAuthData(obj.AuthData)
	if err != nil {
		return fail(ReasonAuthData, err.Error())
	}
	if !v.knownRPID(ad.rpIDHash) {
		return fail(ReasonAppID, "")
	}
	if ad.signCount != 0 {
		return fail(ReasonSignCount, fmt.Sprint(ad.signCount))
	}
	switch {
	case bytes.Equal(ad.aaguid, aaguidProduction):
	case v.allowDevelopment && bytes.Equal(ad.aaguid, aaguidDevelopment):
	default:
		return fail(ReasonAAGUID, fmt.Sprintf("%q", ad.aaguid))
	}
	if !bytes.Equal(ad.credentialID, keyIDRaw) {
		return fail(ReasonCredentialID, "")
	}
	return nil
}

func (v *Verifier) knownRPID(h []byte) bool {
	for _, want := range v.rpIDHashes {
		if bytes.Equal(h, want) {
			return true
		}
	}
	return false
}

func leafNonce(leaf *x509.Certificate) ([]byte, error) {
	for _, e := range leaf.Extensions {
		if !e.Id.Equal(NonceOID) {
			continue
		}
		var seq struct {
			Nonce []byte `asn1:"explicit,tag:1"`
		}
		rest, err := asn1.Unmarshal(e.Value, &seq)
		if err != nil || len(rest) != 0 || len(seq.Nonce) != sha256.Size {
			return nil, errors.New("nonce extension malformed")
		}
		return seq.Nonce, nil
	}
	return nil, errors.New("no nonce extension")
}

type authData struct {
	rpIDHash     []byte
	signCount    uint32
	aaguid       []byte
	credentialID []byte
}

// parseAuthData reads the WebAuthn authenticator data layout: rpIdHash(32) flags(1)
// signCount(4) and, with the AT flag, aaguid(16) credIdLen(2) credId. The COSE key that
// follows is not needed: the key is bound through keyId and the certificate.
func parseAuthData(b []byte) (authData, error) {
	const fixed = 32 + 1 + 4
	if len(b) < fixed+16+2 {
		return authData{}, errors.New("too short")
	}
	if b[32]&0x40 == 0 {
		return authData{}, errors.New("no attested credential data")
	}
	n := int(binary.BigEndian.Uint16(b[fixed+16:]))
	start := fixed + 16 + 2
	if len(b) < start+n {
		return authData{}, errors.New("credential id truncated")
	}
	return authData{
		rpIDHash:     b[:32],
		signCount:    binary.BigEndian.Uint32(b[33:37]),
		aaguid:       b[fixed : fixed+16],
		credentialID: b[start : start+n],
	}, nil
}
