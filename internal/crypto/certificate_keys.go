package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

// CheckCertificateKeys enforces key floors on a verified attestation chain,
// including its trust anchor. Go's TLS policy does not cover raw X.509 checks.
func CheckCertificateKeys(chain ...*x509.Certificate) error {
	for _, cert := range chain {
		switch key := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			if key.N.BitLen() < 2048 {
				return fmt.Errorf("RSA certificate keys must be at least 2048 bits")
			}
		case *ecdsa.PublicKey:
			if key.Curve.Params().BitSize < 224 {
				return fmt.Errorf("EC certificate keys must be at least 224 bits")
			}
		case ed25519.PublicKey:
		default:
			return fmt.Errorf("unsupported certificate key type %T", key)
		}
	}
	return nil
}
