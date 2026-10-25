package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

const (
	testRPID      = "auth.example.com"
	testOrigin    = "https://auth.example.com"
	testChallenge = "Q0hBTExFTkdFLUNIQUxMRU5HRS0zMg" // 22 bytes, above the library's 16-byte floor
)

var testCredID = []byte("credential-0001")

// authData builds the 37-byte authenticator data header for rpID.
func authData(rpID string, flags byte, count uint32) []byte {
	h := sha256.Sum256([]byte(rpID))
	b := make([]byte, 37)
	copy(b, h[:])
	b[32] = flags
	binary.BigEndian.PutUint32(b[33:37], count)
	return b
}

func clientDataJSON(t *testing.T, typ, challenge, origin string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": origin, "crossOrigin": false})
	if err != nil {
		t.Fatalf("marshal client data: %v", err)
	}
	return b
}

func testKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return key, spki
}

// signAssertion signs authenticator data concatenated with the client data hash.
func signAssertion(t *testing.T, key *ecdsa.PrivateKey, ad, cdj []byte) []byte {
	t.Helper()
	cdHash := sha256.Sum256(cdj)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}
	return sig
}

// attestationObject is a "none" attestation carrying cose as attested credential data.
func attestationObject(t *testing.T, rpID string, flags byte, cose []byte) []byte {
	t.Helper()
	ad := append(authData(rpID, flags|0x40, 0), make([]byte, 16)...)
	ad = binary.BigEndian.AppendUint16(ad, uint16(len(testCredID)))
	ad = append(append(ad, testCredID...), cose...)
	obj, err := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": ad})
	if err != nil {
		t.Fatalf("marshal attestation object: %v", err)
	}
	return obj
}

func assertion(t *testing.T, key *ecdsa.PrivateKey, spki []byte, flags byte, count, stored uint32) AssertionInput {
	t.Helper()
	ad := authData(testRPID, flags, count)
	cdj := clientDataJSON(t, "webauthn.get", testChallenge, testOrigin)
	return AssertionInput{
		CredentialID:      testCredID,
		UserHandle:        []byte("user-1"),
		AuthenticatorData: ad,
		ClientDataJSON:    cdj,
		Signature:         signAssertion(t, key, ad, cdj),
		PublicKeySPKI:     spki,
		Challenge:         testChallenge,
		Origin:            testOrigin,
		RPID:              testRPID,
		StoredSignCount:   stored,
	}
}

// A row written before go-webauthn stores the browser's getPublicKey() SPKI, base64url. This
// literal is such a row for the RFC 6979 P-256 test key; it must still authenticate.
func TestVerifyAssertionAcceptsLegacyStoredCredential(t *testing.T) {
	const storedRow = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYP7UuiVanTHJYet0xjVtaMBJuJI7Yfps5mliLmDyn7Z5A_4QCLi8maQa6elWKLxk8vGyDC1-n1F3o8KU1EYimQ"
	d, _ := hex.DecodeString("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		t.Fatalf("ParseRawPrivateKey: %v", err)
	}
	spki, err := base64.RawURLEncoding.DecodeString(storedRow)
	if err != nil {
		t.Fatalf("decode stored row: %v", err)
	}
	got, err := VerifyAssertion(assertion(t, key, spki, FlagUserPresent|FlagUserVerified, 5, 4))
	if err != nil {
		t.Fatalf("legacy SPKI credential must authenticate: %v", err)
	}
	if got.SignCount != 5 || !got.UserVerified() {
		t.Fatalf("verified data = %+v", got)
	}
}

func TestVerifyAssertionRejects(t *testing.T) {
	key, spki := testKey(t)
	otherKey, otherSPKI := testKey(t)

	cases := map[string]func(*AssertionInput){
		"wrong challenge": func(in *AssertionInput) { in.Challenge = "T1RIRVItQ0hBTExFTkdFLU9USEVSUw" },
		"wrong origin":    func(in *AssertionInput) { in.Origin = "https://evil.example.com" },
		"wrong rp id":     func(in *AssertionInput) { in.RPID = "evil.example.com" },
		"wrong key":       func(in *AssertionInput) { in.PublicKeySPKI = otherSPKI },
		"bad signature": func(in *AssertionInput) {
			in.Signature = signAssertion(t, otherKey, in.AuthenticatorData, in.ClientDataJSON)
		},
		"tampered authenticator data": func(in *AssertionInput) {
			in.AuthenticatorData = authData(testRPID, FlagUserPresent|FlagUserVerified, 5)
		},
		"replayed sign count":  func(in *AssertionInput) { in.StoredSignCount = 5 },
		"regressed sign count": func(in *AssertionInput) { in.StoredSignCount = 9 },
		"user not present": func(in *AssertionInput) {
			in.AuthenticatorData = authData(testRPID, 0x00, 5)
			in.Signature = signAssertion(t, key, in.AuthenticatorData, in.ClientDataJSON)
		},
		"wrong ceremony type": func(in *AssertionInput) {
			in.ClientDataJSON = clientDataJSON(t, "webauthn.create", testChallenge, testOrigin)
			in.Signature = signAssertion(t, key, in.AuthenticatorData, in.ClientDataJSON)
		},
		"non-P-256 stored key":       func(in *AssertionInput) { in.PublicKeySPKI = []byte("not a key") },
		"backup eligibility changed": func(in *AssertionInput) { in.BackupEligible = true },
		"cross-origin client data": func(in *AssertionInput) {
			in.ClientDataJSON = []byte(`{"type":"webauthn.get","challenge":"` + testChallenge + `","origin":"` + testOrigin + `","crossOrigin":true}`)
			in.Signature = signAssertion(t, key, in.AuthenticatorData, in.ClientDataJSON)
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := assertion(t, key, spki, FlagUserPresent, 5, 4)
			mutate(&in)
			if _, err := VerifyAssertion(in); err == nil {
				t.Fatalf("expected VerifyAssertion to reject %s", name)
			}
		})
	}
}

func TestVerifyAssertionAcceptsBothCountersZero(t *testing.T) {
	key, spki := testKey(t)
	if _, err := VerifyAssertion(assertion(t, key, spki, FlagUserPresent, 0, 0)); err != nil {
		t.Fatalf("an authenticator that never increments its counter must be accepted: %v", err)
	}
}

// A synced sibling of a backup-eligible credential may report a lower counter than the one
// on record; a device-bound credential doing the same is a clone or replay.
func TestVerifyAssertionBackupEligibleCounterExemption(t *testing.T) {
	key, spki := testKey(t)

	synced := assertion(t, key, spki, FlagUserPresent|FlagBackupEligible|FlagBackupState, 2, 9)
	synced.BackupEligible = true
	if _, err := VerifyAssertion(synced); err != nil {
		t.Fatalf("a backup-eligible credential must authenticate despite a non-advancing counter: %v", err)
	}

	deviceBound := assertion(t, key, spki, FlagUserPresent, 2, 9)
	if _, err := VerifyAssertion(deviceBound); err == nil {
		t.Fatal("a device-bound credential must still be rejected when its counter fails to advance")
	}
}

func TestVerifyRegistration(t *testing.T) {
	key, spki := testKey(t)
	point, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	es256, err := webauthncbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: point[1:33], -3: point[33:]})
	if err != nil {
		t.Fatalf("marshal COSE key: %v", err)
	}
	base := func() RegistrationInput {
		return RegistrationInput{
			CredentialID:      testCredID,
			AttestationObject: attestationObject(t, testRPID, FlagUserPresent|FlagBackupEligible, es256),
			ClientDataJSON:    clientDataJSON(t, "webauthn.create", testChallenge, testOrigin),
			UserHandle:        []byte("user-1"),
			Challenge:         testChallenge,
			Origin:            testOrigin,
			RPID:              testRPID,
		}
	}

	got, err := VerifyRegistration(base())
	if err != nil {
		t.Fatalf("VerifyRegistration: %v", err)
	}
	if string(got.PublicKeySPKI) != string(spki) || !got.BackupEligible() || got.UserVerified() {
		t.Fatalf("registration = %+v", got)
	}

	// The key registered here verifies an assertion, so storage round-trips through SPKI.
	if _, err := VerifyAssertion(assertion(t, key, got.PublicKeySPKI, FlagUserPresent, 1, got.SignCount)); err != nil {
		t.Fatalf("registered key does not verify: %v", err)
	}

	ed25519 := []byte{0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20}
	ed25519 = append(ed25519, make([]byte, 32)...)
	cases := map[string]func(*RegistrationInput){
		"wrong challenge": func(in *RegistrationInput) { in.Challenge = "T1RIRVItQ0hBTExFTkdFLU9USEVSUw" },
		"wrong origin":    func(in *RegistrationInput) { in.Origin = "https://evil.example.com" },
		"wrong rp id":     func(in *RegistrationInput) { in.RPID = "evil.example.com" },
		"user not present": func(in *RegistrationInput) {
			in.AttestationObject = attestationObject(t, testRPID, 0x00, es256)
		},
		"credential id not attested": func(in *RegistrationInput) { in.CredentialID = []byte("credential-0002") },
		"wrong ceremony type": func(in *RegistrationInput) {
			in.ClientDataJSON = clientDataJSON(t, "webauthn.get", testChallenge, testOrigin)
		},
		"non-ES256 key": func(in *RegistrationInput) {
			in.AttestationObject = attestationObject(t, testRPID, FlagUserPresent, ed25519)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := base()
			mutate(&in)
			if _, err := VerifyRegistration(in); err == nil {
				t.Fatalf("expected VerifyRegistration to reject %s", name)
			}
		})
	}
}

func TestRPIDFromIssuer(t *testing.T) {
	cases := []struct {
		issuer, rpID, origin string
	}{
		{"https://auth.example.com", "auth.example.com", "https://auth.example.com"},
		{"https://auth.example.com/", "auth.example.com", "https://auth.example.com"},
		{"http://localhost:5867", "localhost", "http://localhost:5867"},
	}
	for _, c := range cases {
		rpID, origin, err := RPIDFromIssuer(c.issuer)
		if err != nil {
			t.Fatalf("RPIDFromIssuer(%q): %v", c.issuer, err)
		}
		if rpID != c.rpID || origin != c.origin {
			t.Fatalf("RPIDFromIssuer(%q) = %q, %q; want %q, %q", c.issuer, rpID, origin, c.rpID, c.origin)
		}
	}

	if _, _, err := RPIDFromIssuer("not a url"); err == nil {
		t.Fatal("expected an error for an issuer URL with no host")
	}
}
