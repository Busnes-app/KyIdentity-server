package mfa

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// Golden vector shared with KyAuth Android, iOS and Linux (pairing proof v1).
func TestPairingProofGoldenVector(t *testing.T) {
	const token = "00112233445566778899aabbccddeeff0011223344556677"
	key := pairingProofKey(token)
	if got := hex.EncodeToString(key); got != "8f7bb6e4f056bb6d1846aa7544964867c93afdd56ec29c73c46aac8ebd8f8d76" {
		t.Fatalf("K = %s", got)
	}
	if sum := sha256.Sum256([]byte(token)); bytes.Equal(sum[:], key) {
		t.Fatal("K must not be the stored token_hash")
	}
	body := []byte(`{"userId":"user-1","deviceName":"Pixel","deviceIdentifier":"inst-1","platform":"android","publicKey":"BAAA","pushToken":"tok","pushTransport":"fcm"}`)
	p := &PairingProof{Header: "mJoloQsGw4y-mlo2Lo3pMsesJrVna3FPQN4DuV5HaTs", Body: body}
	if !p.matches(key, "https://id.example.com") {
		t.Fatal("request proof did not verify")
	}
	e := &Engine{issuerOrigin: "https://id.example.com"}
	if got := e.ReplyProof(p, []byte("{\"success\":true,\"deviceId\":\"dev-1\",\"device\":{\"id\":\"dev-1\"}}\n")); got != "QsV0h3Srdjg805wx19o-D3Ee1KhzmKAz1RqP4Zu0Q-Y" {
		t.Fatalf("reply proof %s", got)
	}
	req := &NativeDeviceRegisterRequest{UserID: "user-1", PublicKey: "BAAA", Proof: p}
	if got := hex.EncodeToString(ExpectedChallenge(req)); got != "d15e7280b1406114c113bd5019d7b8a11f06f575938872fa2bb82a450208e4e7" {
		t.Fatalf("challenge %s", got)
	}
	if got := string(AppAttestClientData(req)); got != "kyidentity-appattest-v1|pair1:"+hex.EncodeToString(key)+"|BAAA" {
		t.Fatalf("clientData %s", got)
	}
}

func TestPairingProofRefusesOtherOriginOrBody(t *testing.T) {
	key := pairingProofKey("00112233445566778899aabbccddeeff0011223344556677")
	body := []byte(`{"userId":"user-1","deviceName":"Pixel","deviceIdentifier":"inst-1","platform":"android","publicKey":"BAAA","pushToken":"tok","pushTransport":"fcm"}`)
	const proof = "mJoloQsGw4y-mlo2Lo3pMsesJrVna3FPQN4DuV5HaTs"
	if (&PairingProof{Header: proof, Body: body}).matches(key, "https://evil.example.com") {
		t.Fatal("proof verified for another origin")
	}
	tampered := append([]byte{}, body...)
	tampered[len(tampered)-3] = 'x'
	if (&PairingProof{Header: proof, Body: tampered}).matches(key, "https://id.example.com") {
		t.Fatal("proof verified a changed body")
	}
	if (&PairingProof{Header: proof, Body: body}).matches(make([]byte, 32), "https://id.example.com") {
		t.Fatal("proof verified under another key")
	}
}
