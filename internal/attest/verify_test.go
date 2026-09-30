package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

var digest = bytes.Repeat([]byte{0xab}, 32)

func good(t *testing.T) (*testCA, *ecdsa.PrivateKey, [][]byte, Expectation) {
	ca := newTestCA(t, "testroot", time.Now().Add(time.Hour))
	dev, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	chal := []byte("challenge-1")
	kd := keyDescriptionDER(t, kdOpts{attLevel: 2, kmLevel: 2, challenge: chal, hardware: goodHardware(t), software: goodSoftware(t, digest)})
	leaf := ca.leaf(t, &dev.PublicKey, kd, 100, time.Now().Add(time.Hour))
	want := Expectation{Challenge: chal, PublicKeySPKI: spki(t, &dev.PublicKey), AppPackage: "org.kysecurity.authenticator", AppDigests: [][]byte{digest}, Now: time.Now()}
	return ca, dev, [][]byte{leaf, ca.interDER, ca.rootDER}, want
}

func roots(ca *testCA) *StaticRoots { return &StaticRoots{certs: []*x509.Certificate{ca.root}} }

func TestVerifyStrongBoxChain(t *testing.T) {
	ca, _, chain, want := good(t)
	r := Verify(chain, want, roots(ca), staticStatus{})
	if r.Level != "strongbox" || r.Reason != "" || r.BootState != "locked-verified" || len(r.Serials) != 3 {
		t.Fatalf("%+v", r)
	}
}

func TestVerifyRefusals(t *testing.T) {
	type mut func(t *testing.T, ca *testCA, dev *ecdsa.PrivateKey, chain [][]byte, want *Expectation) ([][]byte, Roots, Status)
	cases := map[string]mut{
		"untrusted root": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			other := newTestCA(t, "other", time.Now().Add(time.Hour))
			return c, roots(other), staticStatus{}
		},
		"broken signature": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			bad := append([]byte{}, c[0]...)
			bad[len(bad)-1] ^= 0x01
			return [][]byte{bad, c[1], c[2]}, roots(ca), staticStatus{}
		},
		"revoked intermediate": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			return c, roots(ca), staticStatus{"2": true}
		},
		"status unknown": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			return c, roots(ca), unknownStatus{}
		},
		"challenge mismatch": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			w.Challenge = []byte("other")
			return c, roots(ca), staticStatus{}
		},
		"key mismatch": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			o, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			w.PublicKeySPKI = spki(t, &o.PublicKey)
			return c, roots(ca), staticStatus{}
		},
		"software level": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			kd := keyDescriptionDER(t, kdOpts{attLevel: 0, kmLevel: 0, challenge: w.Challenge, hardware: goodHardware(t), software: goodSoftware(t, digest)})
			return [][]byte{ca.leaf(t, &d.PublicKey, kd, 101, time.Now().Add(time.Hour)), c[1], c[2]}, roots(ca), staticStatus{}
		},
		"levels differ": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			kd := keyDescriptionDER(t, kdOpts{attLevel: 2, kmLevel: 1, challenge: w.Challenge, hardware: goodHardware(t), software: goodSoftware(t, digest)})
			return [][]byte{ca.leaf(t, &d.PublicKey, kd, 102, time.Now().Add(time.Hour)), c[1], c[2]}, roots(ca), staticStatus{}
		},
		"auth timeout": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			hw := authList(t, setOfIntTag(t, 1, 2), intTag(t, 2, 3), intTag(t, 10, 1), intTag(t, 504, 3), intTag(t, 505, 30), intTag(t, 702, 0))
			kd := keyDescriptionDER(t, kdOpts{attLevel: 1, kmLevel: 1, challenge: w.Challenge, hardware: hw, software: goodSoftware(t, digest)})
			return [][]byte{ca.leaf(t, &d.PublicKey, kd, 103, time.Now().Add(time.Hour)), c[1], c[2]}, roots(ca), staticStatus{}
		},
		"no auth required": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			hw := authList(t, setOfIntTag(t, 1, 2), intTag(t, 2, 3), intTag(t, 10, 1), nullTag(t, 503), intTag(t, 702, 0))
			kd := keyDescriptionDER(t, kdOpts{attLevel: 1, kmLevel: 1, challenge: w.Challenge, hardware: hw, software: goodSoftware(t, digest)})
			return [][]byte{ca.leaf(t, &d.PublicKey, kd, 104, time.Now().Add(time.Hour)), c[1], c[2]}, roots(ca), staticStatus{}
		},
		"user auth only in software list": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			hw := authList(t, setOfIntTag(t, 1, 2), intTag(t, 2, 3), intTag(t, 10, 1), intTag(t, 702, 0))
			sw := authList(t, appIDTag(t, "org.kysecurity.authenticator", digest), intTag(t, 504, 3))
			kd := keyDescriptionDER(t, kdOpts{attLevel: 1, kmLevel: 1, challenge: w.Challenge, hardware: hw, software: sw})
			return [][]byte{ca.leaf(t, &d.PublicKey, kd, 105, time.Now().Add(time.Hour)), c[1], c[2]}, roots(ca), staticStatus{}
		},
		"imported origin": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			hw := authList(t, setOfIntTag(t, 1, 2), intTag(t, 2, 3), intTag(t, 10, 1), intTag(t, 504, 3), intTag(t, 702, 2))
			kd := keyDescriptionDER(t, kdOpts{attLevel: 1, kmLevel: 1, challenge: w.Challenge, hardware: hw, software: goodSoftware(t, digest)})
			return [][]byte{ca.leaf(t, &d.PublicKey, kd, 106, time.Now().Add(time.Hour)), c[1], c[2]}, roots(ca), staticStatus{}
		},
		"wrong package": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			kd := keyDescriptionDER(t, kdOpts{attLevel: 1, kmLevel: 1, challenge: w.Challenge, hardware: goodHardware(t), software: goodSoftware(t, digest)})
			w.AppPackage = "com.evil"
			return [][]byte{ca.leaf(t, &d.PublicKey, kd, 107, time.Now().Add(time.Hour)), c[1], c[2]}, roots(ca), staticStatus{}
		},
		"wrong digest": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			w.AppDigests = [][]byte{bytes.Repeat([]byte{0xcd}, 32)}
			return c, roots(ca), staticStatus{}
		},
		"extension twice": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			// Put the extension on the intermediate too: the first occurrence from the root is the
			// intermediate, whose key is not the device key, and a second occurrence must reject.
			inter2 := ca.reissueIntermediateWithExtension(t, keyDescriptionDER(t, kdOpts{attLevel: 2, kmLevel: 2, challenge: w.Challenge, hardware: goodHardware(t), software: goodSoftware(t, digest)}))
			return [][]byte{c[0], inter2, c[2]}, roots(ca), staticStatus{}
		},
		"expired leaf under non-legacy root": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			kd := keyDescriptionDER(t, kdOpts{attLevel: 2, kmLevel: 2, challenge: w.Challenge, hardware: goodHardware(t), software: goodSoftware(t, digest)})
			return [][]byte{ca.leaf(t, &d.PublicKey, kd, 108, time.Now().Add(-time.Minute)), c[1], c[2]}, roots(ca), staticStatus{}
		},
		"unlocked with setting on": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			hw := authList(t, setOfIntTag(t, 1, 2), intTag(t, 2, 3), intTag(t, 10, 1), intTag(t, 504, 3), intTag(t, 702, 0), rootOfTrustTag(t, false, 2))
			kd := keyDescriptionDER(t, kdOpts{attLevel: 2, kmLevel: 2, challenge: w.Challenge, hardware: hw, software: goodSoftware(t, digest)})
			w.RequireLockedBootloader = true
			return [][]byte{ca.leaf(t, &d.PublicKey, kd, 109, time.Now().Add(time.Hour)), c[1], c[2]}, roots(ca), staticStatus{}
		},
		"empty chain": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			return nil, roots(ca), staticStatus{}
		},
		"wrong algorithm": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			return withHW(t, ca, d, c, w, authList(t, setOfIntTag(t, 1, 2), intTag(t, 2, 1), intTag(t, 10, 1), intTag(t, 504, 3), intTag(t, 702, 0)))
		},
		"wrong curve": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			return withHW(t, ca, d, c, w, authList(t, setOfIntTag(t, 1, 2), intTag(t, 2, 3), intTag(t, 10, 2), intTag(t, 504, 3), intTag(t, 702, 0)))
		},
		"wrong purpose": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			return withHW(t, ca, d, c, w, authList(t, setOfIntTag(t, 1, 0), intTag(t, 2, 3), intTag(t, 10, 1), intTag(t, 504, 3), intTag(t, 702, 0)))
		},
		"user auth type zero": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			return withHW(t, ca, d, c, w, authList(t, setOfIntTag(t, 1, 2), intTag(t, 2, 3), intTag(t, 10, 1), intTag(t, 504, 0), intTag(t, 702, 0)))
		},
		"origin absent": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			return withHW(t, ca, d, c, w, authList(t, setOfIntTag(t, 1, 2), intTag(t, 2, 3), intTag(t, 10, 1), intTag(t, 504, 3)))
		},
		"root of trust absent with setting on": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			w.RequireLockedBootloader = true
			return withHW(t, ca, d, c, w, authList(t, setOfIntTag(t, 1, 2), intTag(t, 2, 3), intTag(t, 10, 1), intTag(t, 504, 3), intTag(t, 702, 0)))
		},
		"locked but unverified": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			w.RequireLockedBootloader = true
			return withHW(t, ca, d, c, w, authList(t, setOfIntTag(t, 1, 2), intTag(t, 2, 3), intTag(t, 10, 1), intTag(t, 504, 3), intTag(t, 702, 0), rootOfTrustTag(t, true, 2)))
		},
		"locked but failed": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			w.RequireLockedBootloader = true
			return withHW(t, ca, d, c, w, authList(t, setOfIntTag(t, 1, 2), intTag(t, 2, 3), intTag(t, 10, 1), intTag(t, 504, 3), intTag(t, 702, 0), rootOfTrustTag(t, true, 3)))
		},
		"leaf not yet valid": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			kd := keyDescriptionDER(t, kdOpts{attLevel: 2, kmLevel: 2, challenge: w.Challenge, hardware: goodHardware(t), software: goodSoftware(t, digest)})
			return [][]byte{ca.leafNB(t, &d.PublicKey, kd, 112, time.Now().Add(time.Hour), time.Now().Add(2*time.Hour)), c[1], c[2]}, roots(ca), staticStatus{}
		},
		"no attestation extension": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			return [][]byte{ca.leafNB(t, &d.PublicKey, nil, 113, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)), c[1], c[2]}, roots(ca), staticStatus{}
		},
		"no application id": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			kd := keyDescriptionDER(t, kdOpts{attLevel: 2, kmLevel: 2, challenge: w.Challenge, hardware: goodHardware(t), software: authList(t)})
			return [][]byte{ca.leaf(t, &d.PublicKey, kd, 114, time.Now().Add(time.Hour)), c[1], c[2]}, roots(ca), staticStatus{}
		},
		"expired intermediate": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			old := newTestCA(t, "testroot", time.Now().Add(-time.Minute))
			kd := keyDescriptionDER(t, kdOpts{attLevel: 2, kmLevel: 2, challenge: w.Challenge, hardware: goodHardware(t), software: goodSoftware(t, digest)})
			return [][]byte{old.leaf(t, &d.PublicKey, kd, 115, time.Now().Add(time.Hour)), old.interDER}, roots(old), staticStatus{}
		},
		"legacy subject on untrusted-legacy chain cert": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			fake := ca.lookalike(t, LegacyRSARootSerialNumber, time.Now().Add(-time.Minute))
			kd := keyDescriptionDER(t, kdOpts{attLevel: 2, kmLevel: 2, challenge: w.Challenge, hardware: goodHardware(t), software: goodSoftware(t, digest)})
			return [][]byte{fake.leaf(t, &d.PublicKey, kd, 116, time.Now().Add(-time.Minute)), fake.interDER, fake.rootDER}, roots(ca), staticStatus{}
		},
		"non-CA intermediate": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			tmpl := &x509.Certificate{
				SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test intermediate"},
				NotBefore: ca.inter.NotBefore, NotAfter: ca.inter.NotAfter, IsCA: false, BasicConstraintsValid: true,
				KeyUsage: x509.KeyUsageCertSign,
			}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.root, &ca.interKey.PublicKey, ca.rootKey)
			if err != nil {
				t.Fatal(err)
			}
			return [][]byte{c[0], der, c[2]}, roots(ca), staticStatus{}
		},
		"leaf as issuer": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			leaf, err := x509.ParseCertificate(c[0])
			if err != nil {
				t.Fatal(err)
			}
			sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			kd := keyDescriptionDER(t, kdOpts{attLevel: 2, kmLevel: 2, challenge: w.Challenge, hardware: goodHardware(t), software: goodSoftware(t, digest)})
			tmpl := &x509.Certificate{
				SerialNumber: big.NewInt(130), Subject: pkix.Name{CommonName: "sub leaf"},
				NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
				ExtraExtensions: []pkix.Extension{{Id: ExtensionOID, Value: kd}},
			}
			sub, err := x509.CreateCertificate(rand.Reader, tmpl, leaf, &sk.PublicKey, d)
			if err != nil {
				t.Fatal(err)
			}
			w.PublicKeySPKI = spki(t, &sk.PublicKey)
			return [][]byte{sub, c[0], c[1], c[2]}, roots(ca), staticStatus{}
		},
	}
	reasonList := []struct{ name, want string }{
		{"untrusted root", "trusted root"},
		{"broken signature", "not signed by"},
		{"revoked intermediate", "revoked"},
		{"status unknown", "status list unavailable"},
		{"challenge mismatch", "challenge mismatch"},
		{"key mismatch", "attested key differs"},
		{"software level", "security level"},
		{"levels differ", "security level"},
		{"auth timeout", "per-use user authentication"},
		{"no auth required", "per-use user authentication"},
		{"user auth only in software list", "per-use user authentication"},
		{"imported origin", "generated in hardware"},
		{"wrong package", "attested app is not"},
		{"wrong digest", "signature not pinned"},
		{"extension twice", "more than once"},
		{"expired leaf under non-legacy root", "outside validity"},
		{"unlocked with setting on", "bootloader not locked"},
		{"empty chain", "no chain"},
		{"wrong algorithm", "EC P-256"},
		{"wrong curve", "EC P-256"},
		{"wrong purpose", "EC P-256"},
		{"user auth type zero", "per-use user authentication"},
		{"origin absent", "generated in hardware"},
		{"root of trust absent with setting on", "bootloader not locked (unknown)"},
		{"locked but unverified", "bootloader not locked (unknown)"},
		{"locked but failed", "bootloader not locked (unknown)"},
		{"leaf not yet valid", "certificate 0 outside validity"},
		{"no attestation extension", "no attestation extension"},
		{"no application id", "no attestation application id"},
		{"expired intermediate", "certificate 1 outside validity"},
		{"legacy subject on untrusted-legacy chain cert", "outside validity"},
	}
	reasons := make(map[string]string, len(reasonList))
	for _, r := range reasonList {
		reasons[r.name] = r.want
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			ca, dev, chain, want := good(t)
			chain, rs, st := m(t, ca, dev, chain, &want)
			r := Verify(chain, want, rs, st)
			if r.Level != "none" || !strings.Contains(r.Reason, reasons[name]) || r.Reason == "" {
				t.Fatalf("%s: want reason containing %q: %+v", name, reasons[name], r)
			}
		})
	}
}

func TestVerifyUnlockedRecordedWhenSettingOff(t *testing.T) {
	ca, dev, chain, want := good(t)
	hw := authList(t, setOfIntTag(t, 1, 2), intTag(t, 2, 3), intTag(t, 10, 1), intTag(t, 504, 3), intTag(t, 702, 0), rootOfTrustTag(t, false, 2))
	kd := keyDescriptionDER(t, kdOpts{attLevel: 1, kmLevel: 1, challenge: want.Challenge, hardware: hw, software: goodSoftware(t, digest)})
	chain = [][]byte{ca.leaf(t, &dev.PublicKey, kd, 110, time.Now().Add(time.Hour)), chain[1], chain[2]}
	r := Verify(chain, want, roots(ca), staticStatus{})
	if r.Level != "tee" || r.BootState != "unlocked" {
		t.Fatalf("%+v", r)
	}
	selfSigned := authList(t, setOfIntTag(t, 1, 2), intTag(t, 2, 3), intTag(t, 10, 1), intTag(t, 504, 3), intTag(t, 702, 0), rootOfTrustTag(t, true, 1))
	kd = keyDescriptionDER(t, kdOpts{attLevel: 1, kmLevel: 1, challenge: want.Challenge, hardware: selfSigned, software: goodSoftware(t, digest)})
	want.RequireLockedBootloader = true
	r = Verify([][]byte{ca.leaf(t, &dev.PublicKey, kd, 111, time.Now().Add(time.Hour)), chain[1], chain[2]}, want, roots(ca), staticStatus{})
	if r.Level != "tee" || r.BootState != "locked-selfsigned" {
		t.Fatalf("self-signed locked must pass: %+v", r)
	}
}

func TestVerifyLegacyRootAcceptsExpiredChain(t *testing.T) {
	ca := newTestCA(t, LegacyRSARootSerialNumber, time.Now().Add(-time.Minute)) // root and intermediate already expired
	dev, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	chal := []byte("c")
	kd := keyDescriptionDER(t, kdOpts{attLevel: 1, kmLevel: 1, challenge: chal, hardware: goodHardware(t), software: goodSoftware(t, digest)})
	leaf := ca.leaf(t, &dev.PublicKey, kd, 200, time.Now().Add(-time.Minute))
	want := Expectation{Challenge: chal, PublicKeySPKI: spki(t, &dev.PublicKey), AppPackage: "org.kysecurity.authenticator", AppDigests: [][]byte{digest}, Now: time.Now()}
	if r := Verify([][]byte{leaf, ca.interDER, ca.rootDER}, want, roots(ca), staticStatus{}); r.Level != "tee" {
		t.Fatalf("%+v", r)
	}
}

func TestVerifyChainWithoutRootCert(t *testing.T) {
	ca, _, chain, want := good(t)
	if r := Verify(chain[:2], want, roots(ca), staticStatus{}); r.Level != "strongbox" {
		t.Fatalf("chain ending at intermediate signed by a trusted root must pass: %+v", r)
	}
}

type unknownStatus struct{}

func (unknownStatus) Revoked(string) (bool, bool) { return false, false }

func TestEmbeddedRootsParse(t *testing.T) {
	r, err := LoadEmbeddedRoots()
	if err != nil {
		t.Fatal(err)
	}
	_, certs := r.Pool()
	found := false
	for _, c := range certs {
		if c.Subject.SerialNumber == LegacyRSARootSerialNumber {
			found = true
		}
	}
	if !found {
		t.Fatalf("legacy RSA root not embedded; subjects: %v", certs)
	}
}

// withHW re-issues the leaf at security level TEE with the given hardware list.
func withHW(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation, hw []byte) ([][]byte, Roots, Status) {
	kd := keyDescriptionDER(t, kdOpts{attLevel: 1, kmLevel: 1, challenge: w.Challenge, hardware: hw, software: goodSoftware(t, digest)})
	return [][]byte{ca.leaf(t, &d.PublicKey, kd, 120, time.Now().Add(time.Hour)), c[1], c[2]}, roots(ca), staticStatus{}
}
