package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
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
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			ca, dev, chain, want := good(t)
			chain, rs, st := m(t, ca, dev, chain, &want)
			r := Verify(chain, want, rs, st)
			if r.Level != "none" || r.Reason == "" {
				t.Fatalf("%s: %+v", name, r)
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
