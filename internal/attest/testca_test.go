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

// leafNB is leaf with an explicit NotBefore; a nil kdDER yields a plain certificate.
func (c *testCA) leafNB(t *testing.T, devicePub *ecdsa.PublicKey, kdDER []byte, serial int64, notBefore, notAfter time.Time) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "Android Keystore Key"},
		NotBefore: notBefore, NotAfter: notAfter,
	}
	if kdDER != nil {
		tmpl.ExtraExtensions = []pkix.Extension{{Id: ExtensionOID, Value: kdDER}}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.inter, devicePub, c.interKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// lookalike returns a CA pair whose top certificate names subjectSerial but is signed by c.root.
func (c *testCA) lookalike(t *testing.T, subjectSerial string, notAfter time.Time) *testCA {
	t.Helper()
	mk := func(serial int64, cn, sn string, parent *x509.Certificate, pk *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn, SerialNumber: sn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &k.PublicKey, pk)
		if err != nil {
			t.Fatal(err)
		}
		cert, _ := x509.ParseCertificate(der)
		return cert, k, der
	}
	top, topKey, topDER := mk(3, "lookalike", subjectSerial, c.root, c.rootKey)
	inter, interKey, interDER := mk(4, "lookalike inter", "", top, topKey)
	return &testCA{top, inter, topKey, interKey, topDER, interDER}
}
