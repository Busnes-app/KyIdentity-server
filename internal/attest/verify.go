package attest

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"time"
)

type Expectation struct {
	Challenge               []byte
	PublicKeySPKI           []byte
	AppPackage              string
	AppDigests              [][]byte
	RequireLockedBootloader bool
	Now                     time.Time
}

type Result struct {
	Level     string
	Reason    string
	BootState string
	Serials   []string
}

func none(reason string, serials []string) Result {
	return Result{Level: "none", Reason: reason, BootState: "unknown", Serials: serials}
}

// Verify grades an attestation chain (leaf first). It never returns an error: every failure is a
// Result with Level "none" and a Reason for the audit log.
func Verify(chainDER [][]byte, want Expectation, roots Roots, status Status) Result {
	if len(chainDER) == 0 {
		return none("no chain", nil)
	}
	certs := make([]*x509.Certificate, 0, len(chainDER))
	for i, der := range chainDER {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return none(fmt.Sprintf("certificate %d: %v", i, err), nil)
		}
		certs = append(certs, c)
	}
	serials := make([]string, 0, len(certs))
	for _, c := range certs {
		serials = append(serials, fmt.Sprintf("%x", c.SerialNumber))
	}
	// 1. Chain to a trusted root.
	_, trusted := roots.Pool()
	root, err := chainToTrustedRoot(certs, trusted)
	if err != nil {
		return none(err.Error(), serials)
	}
	legacy := root.Subject.SerialNumber == LegacyRSARootSerialNumber
	if !legacy {
		for i, c := range certs {
			if want.Now.Before(c.NotBefore) || want.Now.After(c.NotAfter) {
				return none(fmt.Sprintf("certificate %d outside validity", i), serials)
			}
		}
	}
	// 2. Revocation.
	for _, s := range serials {
		revoked, known := status.Revoked(s)
		if !known {
			return none("status list unavailable", serials)
		}
		if revoked {
			return none("certificate "+s+" revoked", serials)
		}
	}
	// 3. First extension walking from the root; any later one rejects.
	var attCert *x509.Certificate
	for i := len(certs) - 1; i >= 0; i-- {
		if ext := findExt(certs[i]); ext != nil {
			if attCert != nil {
				return none("attestation extension appears more than once", serials)
			}
			attCert = certs[i]
		}
	}
	if attCert == nil {
		return none("no attestation extension", serials)
	}
	// 4. Key binding.
	if !bytes.Equal(attCert.RawSubjectPublicKeyInfo, want.PublicKeySPKI) {
		return none("attested key differs from registered key", serials)
	}
	kd, err := ParseKeyDescription(findExt(attCert))
	if err != nil {
		return none(err.Error(), serials)
	}
	// 5. Levels and challenge.
	lvl := kd.AttestationSecurityLevel
	if lvl != kd.KeyMintSecurityLevel || (lvl != SecurityLevelTEE && lvl != SecurityLevelStrongBox) {
		return none(fmt.Sprintf("security level %d/%d", kd.AttestationSecurityLevel, kd.KeyMintSecurityLevel), serials)
	}
	if !bytes.Equal(kd.Challenge, want.Challenge) {
		return none("challenge mismatch", serials)
	}
	// 6. Hardware-enforced key policy.
	hw := kd.Hardware
	if !contains(hw.Purpose, 2) || hw.Algorithm == nil || *hw.Algorithm != 3 || hw.ECCurve == nil || *hw.ECCurve != 1 {
		return none("key is not an EC P-256 signing key", serials)
	}
	if hw.Origin == nil || *hw.Origin != 0 {
		return none("key was not generated in hardware", serials)
	}
	if hw.NoAuthRequired || hw.UserAuthType == nil || *hw.UserAuthType == 0 || hw.AuthTimeout != nil {
		return none("key does not require per-use user authentication", serials)
	}
	boot := bootState(hw.RootOfTrust)
	// 7. Application identity.
	app := kd.Software.AppID
	if app == nil {
		return none("no attestation application id", serials)
	}
	if _, ok := app.Packages[want.AppPackage]; !ok {
		return none("attested app is not "+want.AppPackage, serials)
	}
	if !anyDigest(app.SignatureDigests, want.AppDigests) {
		return none("attested app signature not pinned", serials)
	}
	// 8. Locked bootloader policy.
	if want.RequireLockedBootloader && boot != "locked-verified" && boot != "locked-selfsigned" {
		return Result{Level: "none", Reason: "bootloader not locked (" + boot + ")", BootState: boot, Serials: serials}
	}
	level := "tee"
	if lvl == SecurityLevelStrongBox {
		level = "strongbox"
	}
	return Result{Level: level, BootState: boot, Serials: serials}
}

func chainToTrustedRoot(certs []*x509.Certificate, trusted []*x509.Certificate) (*x509.Certificate, error) {
	for i := 0; i+1 < len(certs); i++ {
		if err := certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
			return nil, fmt.Errorf("certificate %d not signed by certificate %d", i, i+1)
		}
	}
	last := certs[len(certs)-1]
	for _, r := range trusted {
		if bytes.Equal(r.Raw, last.Raw) {
			return r, nil
		}
		if err := last.CheckSignatureFrom(r); err == nil {
			return r, nil
		}
	}
	return nil, fmt.Errorf("chain does not end at a trusted root")
}

func findExt(c *x509.Certificate) []byte {
	for _, e := range c.Extensions {
		if e.Id.Equal(ExtensionOID) {
			return e.Value
		}
	}
	return nil
}

func bootState(r *RootOfTrust) string {
	switch {
	case r == nil:
		return "unknown"
	case r.DeviceLocked && r.VerifiedBootState == 0:
		return "locked-verified"
	case r.DeviceLocked && r.VerifiedBootState == 1:
		return "locked-selfsigned"
	case !r.DeviceLocked:
		return "unlocked"
	default:
		return "unknown"
	}
}

func contains(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func anyDigest(have, want [][]byte) bool {
	for _, h := range have {
		for _, w := range want {
			if bytes.Equal(h, w) {
				return true
			}
		}
	}
	return false
}
