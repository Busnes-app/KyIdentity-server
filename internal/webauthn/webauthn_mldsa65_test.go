package webauthn

import (
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

func testMLDSA65Key(t *testing.T) (*mldsa.PrivateKey, []byte, []byte) {
	t.Helper()
	priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("mldsa.GenerateKey(MLDSA65): %v", err)
	}
	cose, err := webauthncbor.Marshal(webauthncose.AKPPublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.AKP),
			Algorithm: int64(webauthncose.AlgMLDSA65),
		},
		PublicKey: priv.PublicKey().Bytes(),
	})
	if err != nil {
		t.Fatalf("marshal ML-DSA-65 COSE key: %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(priv.PublicKey())
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey(ML-DSA-65): %v", err)
	}
	return priv, cose, spki
}

func signMLDSA65Assertion(t *testing.T, priv *mldsa.PrivateKey, ad, cdj []byte) []byte {
	t.Helper()
	cdHash := sha256.Sum256(cdj)
	signed := append(append([]byte{}, ad...), cdHash[:]...)
	sig, err := priv.Sign(nil, signed, nil)
	if err != nil {
		t.Fatalf("ML-DSA-65 Sign: %v", err)
	}
	return sig
}

func TestMLDSA65RegistrationAndAssertionRoundTrip(t *testing.T) {
	priv, cose, wantSPKI := testMLDSA65Key(t)

	reg, err := VerifyRegistration(RegistrationInput{
		CredentialID:      testCredID,
		AttestationObject: attestationObject(t, testRPID, FlagUserPresent|FlagUserVerified, cose),
		ClientDataJSON:    clientDataJSON(t, "webauthn.create", testChallenge, testOrigin),
		UserHandle:        []byte("user-1"),
		Challenge:         testChallenge,
		Origin:            testOrigin,
		RPID:              testRPID,
	})
	if err != nil {
		t.Fatalf("VerifyRegistration(ML-DSA-65): %v", err)
	}
	if !reg.UserPresent() || !reg.UserVerified() {
		t.Fatalf("unexpected registration flags: %+v", reg.AuthenticatorData)
	}
	if string(reg.PublicKeySPKI) != string(wantSPKI) {
		t.Fatalf("stored SPKI length=%d want=%d (mismatch)", len(reg.PublicKeySPKI), len(wantSPKI))
	}

	parsed, err := x509.ParsePKIXPublicKey(reg.PublicKeySPKI)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	pub, ok := parsed.(*mldsa.PublicKey)
	if !ok || pub.Parameters() != mldsa.MLDSA65() {
		t.Fatalf("parsed key is %T, want *mldsa.PublicKey(MLDSA65)", parsed)
	}

	// Valid assertion authenticates and advances sign count.
	ad := authData(testRPID, FlagUserPresent|FlagUserVerified, 2)
	cdj := clientDataJSON(t, "webauthn.get", testChallenge, testOrigin)
	sig := signMLDSA65Assertion(t, priv, ad, cdj)
	got, err := VerifyAssertion(AssertionInput{
		CredentialID:      testCredID,
		UserHandle:        []byte("user-1"),
		AuthenticatorData: ad,
		ClientDataJSON:    cdj,
		Signature:         sig,
		PublicKeySPKI:     reg.PublicKeySPKI,
		Challenge:         testChallenge,
		Origin:            testOrigin,
		RPID:              testRPID,
		StoredSignCount:   1,
	})
	if err != nil {
		t.Fatalf("VerifyAssertion(ML-DSA-65): %v", err)
	}
	if got.SignCount != 2 || !got.UserVerified() {
		t.Fatalf("verified data = %+v", got)
	}

	// Tampered signature must fail.
	badSig := append([]byte(nil), sig...)
	badSig[0] ^= 0xff
	if _, err := VerifyAssertion(AssertionInput{
		CredentialID:      testCredID,
		UserHandle:        []byte("user-1"),
		AuthenticatorData: ad,
		ClientDataJSON:    cdj,
		Signature:         badSig,
		PublicKeySPKI:     reg.PublicKeySPKI,
		Challenge:         testChallenge,
		Origin:            testOrigin,
		RPID:              testRPID,
		StoredSignCount:   1,
	}); err == nil {
		t.Fatal("expected tampered ML-DSA-65 assertion signature to fail")
	}
}

func TestMLDSAOtherParameterSetsRejected(t *testing.T) {
	priv44, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("GenerateKey(MLDSA44): %v", err)
	}
	spki44, err := x509.MarshalPKIXPublicKey(priv44.PublicKey())
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey(MLDSA44): %v", err)
	}
	if _, err := spkiToCOSE(spki44); err == nil {
		t.Fatal("expected ML-DSA-44 SPKI to be rejected")
	}

	cose44, err := webauthncbor.Marshal(webauthncose.AKPPublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.AKP),
			Algorithm: int64(webauthncose.AlgMLDSA44),
		},
		PublicKey: priv44.PublicKey().Bytes(),
	})
	if err != nil {
		t.Fatalf("marshal ML-DSA-44 COSE: %v", err)
	}
	if _, err := coseToSPKI(cose44); err == nil {
		t.Fatal("expected ML-DSA-44 COSE key to be rejected")
	}
}
