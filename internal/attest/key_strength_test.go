package attest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"testing"
	"time"
)

func TestAttestationCertificateKeyFloor(t *testing.T) {
	for _, role := range []string{"root", "intermediate"} {
		for _, bits := range []int{1024, 2047, 2048} {
			t.Run(fmt.Sprintf("%s/RSA%d", role, bits), func(t *testing.T) {
				ca, device, _, want := good(t)
				key, err := rsa.GenerateKey(rand.Reader, bits)
				if err != nil {
					t.Fatal(err)
				}
				var rootKey, interKey crypto.Signer = ca.rootKey, ca.interKey
				if role == "root" {
					rootKey = key
				} else {
					interKey = key
				}
				issue := func(template, parent *x509.Certificate, public crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
					t.Helper()
					copy := *template
					copy.SignatureAlgorithm = 0
					copy.ExtraExtensions = template.Extensions
					if template == parent {
						copy.PublicKey = public
						parent = &copy
					}
					der, err := x509.CreateCertificate(rand.Reader, &copy, parent, public, signer)
					if err != nil {
						t.Fatal(err)
					}
					cert, err := x509.ParseCertificate(der)
					if err != nil {
						t.Fatal(err)
					}
					return cert
				}
				root := issue(ca.root, ca.root, rootKey.Public(), rootKey)
				inter := issue(ca.inter, root, interKey.Public(), rootKey)
				kd := keyDescriptionDER(t, kdOpts{attLevel: 2, kmLevel: 2, challenge: want.Challenge, hardware: goodHardware(t), software: goodSoftware(t, digest)})
				// Keep the real P-256 device key and attestation policy while varying
				// the CA key. The presented chain deliberately omits the trust root.
				leafDER := ca.leaf(t, &device.PublicKey, kd, 100, time.Now().Add(time.Hour))
				leaf, err := x509.ParseCertificate(leafDER)
				if err != nil {
					t.Fatal(err)
				}
				leaf = issue(leaf, inter, device.Public(), interKey)
				got := Verify([][]byte{leaf.Raw, inter.Raw}, want, &StaticRoots{certs: []*x509.Certificate{root}}, staticStatus{})
				if bits < 2048 {
					if got.Level != "none" {
						t.Fatalf("accepted RSA-%d %s: %+v", bits, role, got)
					}
				} else if got.Level != "strongbox" {
					t.Fatalf("strong chain failed: %+v", got)
				}
			})
		}
	}
}
