package appattesttest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// The verifier's negative tests are only meaningful if each fixture knob breaks exactly the
// property it names and nothing else. These tests decode the object independently of
// appattest.Verifier, so a fixture drifting into always-invalid output is caught here rather
// than by a refusal test passing for the wrong reason.

type decoded struct {
	fmt      string
	x5c      [][]byte
	authData []byte
	leaf     *x509.Certificate
}

func decode(t *testing.T, obj []byte) decoded {
	t.Helper()
	var raw struct {
		Fmt     string `cbor:"fmt"`
		AttStmt struct {
			X5C     [][]byte `cbor:"x5c"`
			Receipt []byte   `cbor:"receipt"`
		} `cbor:"attStmt"`
		AuthData []byte `cbor:"authData"`
	}
	if err := cbor.Unmarshal(obj, &raw); err != nil {
		t.Fatalf("attestation is not CBOR: %v", err)
	}
	if len(raw.AttStmt.X5C) == 0 {
		t.Fatal("no x5c")
	}
	leaf, err := x509.ParseCertificate(raw.AttStmt.X5C[0])
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}
	return decoded{fmt: raw.Fmt, x5c: raw.AttStmt.X5C, authData: raw.AuthData, leaf: leaf}
}

func leafNonce(t *testing.T, leaf *x509.Certificate) ([]byte, bool) {
	t.Helper()
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(nonceOID) {
			var v struct {
				Nonce []byte `asn1:"explicit,tag:1"`
			}
			if _, err := asn1.Unmarshal(ext.Value, &v); err != nil {
				t.Fatalf("nonce extension: %v", err)
			}
			return v.Nonce, true
		}
	}
	return nil, false
}

// The zero Options must describe a fully valid attestation: correct format, a leaf chaining
// to the CA root through the intermediate, the RP ID hash, AT flag, zero counter, production
// AAGUID, the key id as credential id, and the nonce over authData||clientDataHash.
func TestZeroOptionsYieldValidObject(t *testing.T) {
	ca := NewCA(t)
	cdh := sha256.Sum256([]byte("client data"))
	keyID, obj := ca.Attest(t, Options{AppID: "TEAM.org.example", ClientDataHash: cdh[:]})
	d := decode(t, obj)

	if d.fmt != "apple-appattest" || len(d.x5c) != 2 {
		t.Fatalf("fmt=%q x5c=%d", d.fmt, len(d.x5c))
	}
	inter, err := x509.ParseCertificate(d.x5c[1])
	if err != nil {
		t.Fatal(err)
	}
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(ca.Root)
	inters.AddCert(inter)
	if _, err := d.leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("leaf does not chain to the CA root: %v", err)
	}

	pub, ok := d.leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("leaf key %T", d.leaf.PublicKey)
	}
	ek, err := pub.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	kid := sha256.Sum256(ek.Bytes())
	if keyID != base64.StdEncoding.EncodeToString(kid[:]) {
		t.Fatal("key id is not the hash of the leaf public key")
	}

	ad := d.authData
	rp := sha256.Sum256([]byte("TEAM.org.example"))
	if !bytes.Equal(ad[:32], rp[:]) {
		t.Fatal("rpIdHash is not the app id hash")
	}
	if ad[32] != 0x40 {
		t.Fatalf("flags %#x, want AT only", ad[32])
	}
	if binary.BigEndian.Uint32(ad[33:37]) != 0 {
		t.Fatal("sign count not zero")
	}
	if !bytes.Equal(ad[37:53], ProductionAAGUID) {
		t.Fatalf("aaguid %q", ad[37:53])
	}
	n := int(binary.BigEndian.Uint16(ad[53:55]))
	if !bytes.Equal(ad[55:55+n], kid[:]) {
		t.Fatal("credential id is not the key id")
	}

	nonce, ok := leafNonce(t, d.leaf)
	want := sha256.Sum256(append(append([]byte{}, ad...), cdh[:]...))
	if !ok || !bytes.Equal(nonce, want[:]) {
		t.Fatal("leaf nonce is not sha256(authData||clientDataHash)")
	}
	if d.leaf.NotAfter.Before(time.Now().Add(23 * time.Hour)) {
		t.Fatalf("default leaf expiry %v", d.leaf.NotAfter)
	}
}

// Each knob changes the one property it names.
func TestOptionsChangeOnlyTheirProperty(t *testing.T) {
	ca := NewCA(t)
	other := sha256.Sum256([]byte("other"))
	expired := time.Now().Add(-time.Minute)

	keyID, obj := ca.Attest(t, Options{KeyID: "forced", Fmt: "packed", SignCount: 7, AAGUID: DevelopmentAAGUID, CredentialID: []byte{1, 2, 3}, OmitAT: true})
	d := decode(t, obj)
	if keyID != "forced" || d.fmt != "packed" {
		t.Fatalf("keyID=%q fmt=%q", keyID, d.fmt)
	}
	ad := d.authData
	if ad[32] != 0 || binary.BigEndian.Uint32(ad[33:37]) != 7 || !bytes.Equal(ad[37:53], DevelopmentAAGUID) {
		t.Fatalf("flags=%#x count=%d aaguid=%q", ad[32], binary.BigEndian.Uint32(ad[33:37]), ad[37:53])
	}
	if binary.BigEndian.Uint16(ad[53:55]) != 3 || !bytes.Equal(ad[55:58], []byte{1, 2, 3}) {
		t.Fatal("credential id override not applied")
	}

	_, obj = ca.Attest(t, Options{Nonce: other[:]})
	if nonce, ok := leafNonce(t, decode(t, obj).leaf); !ok || !bytes.Equal(nonce, other[:]) {
		t.Fatal("nonce override not applied")
	}

	_, obj = ca.Attest(t, Options{OmitNonce: true})
	if _, ok := leafNonce(t, decode(t, obj).leaf); ok {
		t.Fatal("OmitNonce left the nonce extension in place")
	}

	_, obj = ca.Attest(t, Options{OmitIntermed: true, LeafNotAfter: expired})
	d = decode(t, obj)
	if len(d.x5c) != 1 {
		t.Fatalf("OmitIntermed left %d certificates", len(d.x5c))
	}
	if !d.leaf.NotAfter.Before(time.Now()) {
		t.Fatalf("LeafNotAfter not applied: %v", d.leaf.NotAfter)
	}
}

// Two CAs must not trust each other's leaves, or a "wrong root" test would prove nothing.
func TestSeparateCAsAreDistinct(t *testing.T) {
	a, b := NewCA(t), NewCA(t)
	_, obj := a.Attest(t, Options{})
	d := decode(t, obj)
	inter, _ := x509.ParseCertificate(d.x5c[1])
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(b.Root)
	inters.AddCert(inter)
	if _, err := d.leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err == nil {
		t.Fatal("a leaf from one CA verified under another CA's root")
	}
}
