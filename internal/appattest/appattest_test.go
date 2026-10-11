package appattest

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/appattest/appattesttest"
	"github.com/fxamacker/cbor/v2"
)

const appID = "TATYN4X57D.org.kysecurity.authenticator"

func TestEmbeddedRootIsPinnedApple(t *testing.T) {
	root, err := AppleRoot()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(root.Raw)
	if got := strings.ToUpper(hex.EncodeToString(sum[:])); got != "1CB9823BA28BA6AD2D33A006941DE2AE4F513EF1D4E831B9F7E0FA7B6242C932" {
		t.Fatalf("fingerprint %s", got)
	}
	if root.Subject.CommonName != "Apple App Attestation Root CA" {
		t.Fatalf("subject %v", root.Subject)
	}
	if _, err := NewVerifier([]string{appID}, false); err != nil {
		t.Fatal(err)
	}
}

func TestEmbeddedRootTamperIsRefused(t *testing.T) {
	saved := appleRootPEM
	defer func() { appleRootPEM = saved }()
	appleRootPEM = bytes.Replace(saved, []byte("MIIC"), []byte("MIID"), 1)
	if _, err := AppleRoot(); err == nil {
		t.Fatal("altered root accepted")
	}
}

func reason(t *testing.T, err error) Reason {
	t.Helper()
	if err == nil {
		return ""
	}
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("untyped error %v", err)
	}
	return e.Reason
}

func TestVerify(t *testing.T) {
	ca := appattesttest.NewCA(t)
	cdh := sha256.Sum256([]byte("client data"))
	base := appattesttest.Options{AppID: appID, ClientDataHash: cdh[:]}
	other := sha256.Sum256([]byte("other"))
	cases := []struct {
		name   string
		edit   func(*appattesttest.Options)
		dev    bool
		hash   []byte // overrides the hash the verifier is given
		want   Reason
		mutObj func([]byte) []byte
	}{
		{name: "production passes"},
		{name: "development refused by default", edit: func(o *appattesttest.Options) { o.AAGUID = appattesttest.DevelopmentAAGUID }, want: ReasonAAGUID},
		{name: "development allowed", edit: func(o *appattesttest.Options) { o.AAGUID = appattesttest.DevelopmentAAGUID }, dev: true},
		{name: "production still passes with development on", dev: true},
		{name: "unknown aaguid", edit: func(o *appattesttest.Options) { o.AAGUID = bytes.Repeat([]byte{1}, 16) }, dev: true, want: ReasonAAGUID},
		{name: "wrong client data", hash: other[:], want: ReasonNonce},
		{name: "wrong nonce", edit: func(o *appattesttest.Options) { o.Nonce = other[:] }, want: ReasonNonce},
		{name: "no nonce extension", edit: func(o *appattesttest.Options) { o.OmitNonce = true }, want: ReasonNonce},
		{name: "short nonce", edit: func(o *appattesttest.Options) { o.Nonce = []byte{1, 2} }, want: ReasonNonce},
		{name: "other app id", edit: func(o *appattesttest.Options) { o.AppID = "ABCDE12345.org.example.other" }, want: ReasonAppID},
		{name: "sign count", edit: func(o *appattesttest.Options) { o.SignCount = 1 }, want: ReasonSignCount},
		{name: "credential id", edit: func(o *appattesttest.Options) { o.CredentialID = other[:] }, want: ReasonCredentialID},
		{name: "key id of another key", edit: func(o *appattesttest.Options) { o.KeyID = base64.StdEncoding.EncodeToString(other[:]) }, want: ReasonKeyMismatch},
		{name: "key id not base64", edit: func(o *appattesttest.Options) { o.KeyID = "!!" }, want: ReasonKeyID},
		{name: "key id wrong length", edit: func(o *appattesttest.Options) { o.KeyID = base64.StdEncoding.EncodeToString([]byte("short")) }, want: ReasonKeyID},
		{name: "key id too long", edit: func(o *appattesttest.Options) { o.KeyID = strings.Repeat("A", 100) }, want: ReasonKeyID},
		{name: "format", edit: func(o *appattesttest.Options) { o.Fmt = "packed" }, want: ReasonFormat},
		{name: "no attested credential data", edit: func(o *appattesttest.Options) { o.OmitAT = true }, want: ReasonAuthData},
		{name: "expired leaf", edit: func(o *appattesttest.Options) { o.LeafNotAfter = time.Now().Add(-time.Minute) }, want: ReasonChain},
		{name: "missing intermediate", edit: func(o *appattesttest.Options) { o.OmitIntermed = true }, want: ReasonChain},
		{name: "garbage", mutObj: func([]byte) []byte { return []byte("garbage") }, want: ReasonDecode},
		{name: "truncated", mutObj: func(b []byte) []byte { return b[:len(b)/2] }, want: ReasonDecode},
		{name: "oversized", mutObj: func([]byte) []byte { return make([]byte, MaxAttestationBytes+1) }, want: ReasonTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := base
			if tc.edit != nil {
				tc.edit(&o)
			}
			keyID, obj := ca.Attest(t, o)
			if tc.mutObj != nil {
				obj = tc.mutObj(obj)
			}
			h := cdh[:]
			if tc.hash != nil {
				h = tc.hash
			}
			v := NewVerifierWithRoot(ca.Root, []string{"ABCDE12345.org.example.unused", appID}, tc.dev)
			err := v.Verify(keyID, obj, h)
			if got := reason(t, err); got != tc.want {
				t.Fatalf("reason %q (%v), want %q", got, err, tc.want)
			}
		})
	}
}

func TestVerifyRefusesForeignRoot(t *testing.T) {
	ca, foreign := appattesttest.NewCA(t), appattesttest.NewCA(t)
	cdh := sha256.Sum256([]byte("c"))
	keyID, obj := ca.Attest(t, appattesttest.Options{AppID: appID, ClientDataHash: cdh[:]})
	if r := reason(t, NewVerifierWithRoot(foreign.Root, []string{appID}, false).Verify(keyID, obj, cdh[:])); r != ReasonChain {
		t.Fatalf("foreign root: %q", r)
	}
	// The production verifier trusts only Apple.
	v, err := NewVerifier([]string{appID}, false)
	if err != nil {
		t.Fatal(err)
	}
	if r := reason(t, v.Verify(keyID, obj, cdh[:])); r != ReasonChain {
		t.Fatalf("apple root: %q", r)
	}
}

func TestVerifyChainCheckedAtCurrentTime(t *testing.T) {
	ca := appattesttest.NewCA(t)
	cdh := sha256.Sum256([]byte("c"))
	keyID, obj := ca.Attest(t, appattesttest.Options{AppID: appID, ClientDataHash: cdh[:]})
	v := NewVerifierWithRoot(ca.Root, []string{appID}, false)
	v.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	if r := reason(t, v.Verify(keyID, obj, cdh[:])); r != ReasonChain {
		t.Fatalf("future: %q", r)
	}
}

func TestVerifyRejectsDuplicateKeysAndExtraCerts(t *testing.T) {
	ca := appattesttest.NewCA(t)
	cdh := sha256.Sum256([]byte("c"))
	keyID, obj := ca.Attest(t, appattesttest.Options{AppID: appID, ClientDataHash: cdh[:]})
	v := NewVerifierWithRoot(ca.Root, []string{appID}, false)

	var m map[string]cbor.RawMessage
	if err := cbor.Unmarshal(obj, &m); err != nil {
		t.Fatal(err)
	}
	// A map that repeats "fmt": hand-encode a 4-pair map with the key twice.
	dup := []byte{0xa4}
	for _, k := range []string{"fmt", "attStmt", "authData"} {
		kb, _ := cbor.Marshal(k)
		dup = append(append(dup, kb...), m[k]...)
	}
	kb, _ := cbor.Marshal("fmt")
	vb, _ := cbor.Marshal("apple-appattest")
	dup = append(append(dup, kb...), vb...)
	if r := reason(t, v.Verify(keyID, dup, cdh[:])); r != ReasonDecode {
		t.Fatalf("duplicate key: %q", r)
	}

	var stmt struct {
		X5C [][]byte `cbor:"x5c"`
	}
	if err := cbor.Unmarshal(m["attStmt"], &stmt); err != nil {
		t.Fatal(err)
	}
	many := append(stmt.X5C, stmt.X5C[1], stmt.X5C[1], stmt.X5C[1])
	var ad []byte
	_ = cbor.Unmarshal(m["authData"], &ad)
	big, _ := cbor.Marshal(map[string]any{"fmt": "apple-appattest", "attStmt": map[string]any{"x5c": many}, "authData": ad})
	if r := reason(t, v.Verify(keyID, big, cdh[:])); r != ReasonCertificate {
		t.Fatalf("five certificates: %q", r)
	}
	empty, _ := cbor.Marshal(map[string]any{"fmt": "apple-appattest", "attStmt": map[string]any{}, "authData": ad})
	if r := reason(t, v.Verify(keyID, empty, cdh[:])); r != ReasonCertificate {
		t.Fatalf("no certificates: %q", r)
	}
}

func TestParseAuthDataBounds(t *testing.T) {
	ok := append(make([]byte, 32), 0x40, 0, 0, 0, 0)
	ok = append(ok, make([]byte, 16)...)
	ok = append(ok, 0, 2, 9, 9)
	if ad, err := parseAuthData(ok); err != nil || !bytes.Equal(ad.credentialID, []byte{9, 9}) {
		t.Fatalf("%v %+v", err, ad)
	}
	for i := 0; i < len(ok); i++ {
		if _, err := parseAuthData(ok[:i]); err == nil {
			t.Fatalf("truncated at %d accepted", i)
		}
	}
	long := append(append([]byte{}, ok[:len(ok)-4]...), 0xff, 0xff, 1)
	if _, err := parseAuthData(long); err == nil {
		t.Fatal("overlong credential id accepted")
	}
}

// FuzzVerify asserts the decoder and checks never panic on arbitrary input. Mutations can
// legitimately still verify (the receipt is not checked), so acceptance is not asserted.
func FuzzVerify(f *testing.F) {
	ca := appattesttest.NewCA(f)
	cdh := sha256.Sum256([]byte("c"))
	keyID, obj := ca.Attest(f, appattesttest.Options{AppID: appID, ClientDataHash: cdh[:]})
	v := NewVerifierWithRoot(ca.Root, []string{appID}, false)
	f.Add(obj)
	f.Add([]byte{0xa1, 0x63, 'f', 'm', 't', 0x9f})
	f.Add([]byte{0xbf, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) { _ = v.Verify(keyID, b, cdh[:]) })
}
