package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

type testCA struct {
	root, inter       *x509.Certificate
	rootKey, interKey *ecdsa.PrivateKey
	rootDER, interDER []byte
}

func newTestCA(t *testing.T, rootSubjectSerial string, notAfter time.Time) *testCA {
	t.Helper()
	rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root", SerialNumber: rootSubjectSerial},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rk.PublicKey, rk)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)
	ik, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	interTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test intermediate"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, root, &ik.PublicKey, rk)
	if err != nil {
		t.Fatal(err)
	}
	inter, _ := x509.ParseCertificate(interDER)
	return &testCA{root, inter, rk, ik, rootDER, interDER}
}

// leaf signs a device key with the attestation extension carrying kdDER. serial distinguishes leaves.
func (c *testCA) leaf(t *testing.T, devicePub *ecdsa.PublicKey, kdDER []byte, serial int64, notAfter time.Time) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "Android Keystore Key"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		ExtraExtensions: []pkix.Extension{{Id: ExtensionOID, Value: kdDER}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.inter, devicePub, c.interKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

type staticStatus map[string]bool

func (s staticStatus) Revoked(serial string) (bool, bool) { return s[serial], true }

func spki(t *testing.T, pub *ecdsa.PublicKey) []byte {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// reissueIntermediateWithExtension re-signs the intermediate (same key) with the attestation
// extension added, so the existing leaf still chains.
func (c *testCA) reissueIntermediateWithExtension(t *testing.T, kdDER []byte) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test intermediate"},
		NotBefore: c.inter.NotBefore, NotAfter: c.inter.NotAfter, IsCA: true, BasicConstraintsValid: true,
		KeyUsage:        x509.KeyUsageCertSign,
		ExtraExtensions: []pkix.Extension{{Id: ExtensionOID, Value: kdDER}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.root, &c.interKey.PublicKey, c.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
