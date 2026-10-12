// Package appattesttest builds App Attest attestation objects under a generated CA, so tests
// can exercise appattest.Verifier without a real Apple device. It is imported only by tests.
package appattesttest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

var nonceOID = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}

// ProductionAAGUID and DevelopmentAAGUID are the two App Attest environments.
var (
	ProductionAAGUID  = append([]byte("appattest"), make([]byte, 7)...)
	DevelopmentAAGUID = []byte("appattestdevelop")
)

// CA is a generated root and intermediate standing in for Apple's.
type CA struct {
	Root     *x509.Certificate
	inter    *x509.Certificate
	interKey *ecdsa.PrivateKey
	interDER []byte
}

func NewCA(t testing.TB) *CA {
	t.Helper()
	rk, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	root := mkCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test app attestation root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, nil, &rk.PublicKey, rk)
	ik, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	interDER := mkDER(t, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test app attestation ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, root, &ik.PublicKey, rk)
	inter, _ := x509.ParseCertificate(interDER)
	return &CA{Root: root, inter: inter, interKey: ik, interDER: interDER}
}

// Options describe one attestation; the zero value of each field yields a valid object.
type Options struct {
	AppID          string
	ClientDataHash []byte
	SignCount      uint32
	AAGUID         []byte    // nil: production
	CredentialID   []byte    // nil: the key id
	KeyID          string    // empty: the real key id
	Fmt            string    // empty: apple-appattest
	Nonce          []byte    // nil: the correct nonce
	OmitNonce      bool      // leaf without the nonce extension
	OmitAT         bool      // clear the attested-credential-data flag
	LeafNotAfter   time.Time // zero: a day from now
	OmitIntermed   bool      // x5c carries only the leaf
}

// Attest returns a key id (standard base64) and the CBOR attestation object.
func (c *CA) Attest(t testing.TB, o Options) (keyID string, object []byte) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ek, _ := k.PublicKey.ECDH()
	kid := sha256.Sum256(ek.Bytes())
	keyID = base64.StdEncoding.EncodeToString(kid[:])
	if o.KeyID != "" {
		keyID = o.KeyID
	}
	aaguid := o.AAGUID
	if aaguid == nil {
		aaguid = ProductionAAGUID
	}
	cred := o.CredentialID
	if cred == nil {
		cred = kid[:]
	}
	rp := sha256.Sum256([]byte(o.AppID))
	ad := append([]byte{}, rp[:]...)
	flags := byte(0x40)
	if o.OmitAT {
		flags = 0
	}
	ad = append(ad, flags)
	ad = binary.BigEndian.AppendUint32(ad, o.SignCount)
	ad = append(ad, aaguid...)
	ad = binary.BigEndian.AppendUint16(ad, uint16(len(cred)))
	ad = append(ad, cred...)
	ad = append(ad, 0xa0) // stand-in COSE key; the verifier does not read it

	nonce := o.Nonce
	if nonce == nil {
		n := sha256.Sum256(append(append([]byte{}, ad...), o.ClientDataHash...))
		nonce = n[:]
	}
	notAfter := o.LeafNotAfter
	if notAfter.IsZero() {
		notAfter = time.Now().Add(24 * time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "test app attest leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if !o.OmitNonce {
		ext, err := asn1.Marshal(struct {
			Nonce []byte `asn1:"explicit,tag:1"`
		}{nonce})
		if err != nil {
			t.Fatal(err)
		}
		tmpl.ExtraExtensions = []pkix.Extension{{Id: nonceOID, Value: ext}}
	}
	leaf := mkDER(t, tmpl, c.inter, &k.PublicKey, c.interKey)
	x5c := [][]byte{leaf, c.interDER}
	if o.OmitIntermed {
		x5c = x5c[:1]
	}
	format := o.Fmt
	if format == "" {
		format = "apple-appattest"
	}
	obj, err := cbor.Marshal(map[string]any{
		"fmt":      format,
		"attStmt":  map[string]any{"x5c": x5c, "receipt": []byte("receipt")},
		"authData": ad,
	})
	if err != nil {
		t.Fatal(err)
	}
	return keyID, obj
}

func mkDER(t testing.TB, tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) []byte {
	t.Helper()
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func mkCert(t testing.TB, tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(mkDER(t, tmpl, parent, pub, signer))
	if err != nil {
		t.Fatal(err)
	}
	return c
}
