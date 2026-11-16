package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Busnes-app/kyidentity-server/internal/mfa"
)

// proofFor builds a KyAuth pairing proof v1 independently of the server code.
func proofKeyFor(token string) []byte {
	m := hmac.New(sha256.New, []byte(token))
	m.Write([]byte("kyidentity-pair-key/1"))
	return m.Sum(nil)
}

func proofFor(token, origin, body string) string {
	m := hmac.New(sha256.New, proofKeyFor(token))
	m.Write([]byte("kyidentity-pair/1\n" + origin + "\n" + body))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func replyFor(token, origin, reqBody, respBody string) string {
	h := sha256.Sum256([]byte(reqBody))
	m := hmac.New(sha256.New, proofKeyFor(token))
	m.Write([]byte("kyidentity-pair-reply/1\n" + origin + "\n" + base64.RawURLEncoding.EncodeToString(h[:]) + "\n" + respBody))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func postProofRegister(server *Server, body, proof string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/notifications/native/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(mfa.PairingProofHeader, proof)
	server.httpServer.Handler.ServeHTTP(rec, req)
	return rec
}

func TestRegisterWithPairingProof(t *testing.T) {
	server, dbStore, _, mfaEngine, _, cleanup := setupTestServer(t)
	defer cleanup()
	user := newUser(t, dbStore, "user")
	token, _, _, err := mfaEngine.GenerateDevicePairingToken(user.ID, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	body := registerBody(t, mfa.NativeDeviceRegisterRequest{
		UserID: user.ID, DeviceName: "p", DeviceIdentifier: "i", PublicKey: testSPKI(t), PushToken: "fcm",
	})

	// A proof made with another token, or for another origin, spends nothing.
	for _, bad := range []string{proofFor("wrong-token", testIssuerOrigin, body), proofFor(token, "https://evil.example", body)} {
		if rec := postProofRegister(server, body, bad); rec.Code != http.StatusBadRequest || rec.Header().Get(mfa.PairingProofHeader) != "" {
			t.Fatalf("bad proof: status %d header %q", rec.Code, rec.Header().Get(mfa.PairingProofHeader))
		}
	}

	rec := postProofRegister(server, body, proofFor(token, testIssuerOrigin, body))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if got, want := rec.Header().Get(mfa.PairingProofHeader), replyFor(token, testIssuerOrigin, body, rec.Body.String()); got != want {
		t.Fatalf("reply proof %q, want %q", got, want)
	}

	// Spent: the same proof cannot pair a second device.
	if rec := postProofRegister(server, body, proofFor(token, testIssuerOrigin, body)); rec.Code != http.StatusBadRequest {
		t.Fatalf("replayed proof: status %d", rec.Code)
	}
}

func TestPairingProofRefusesTokenOrPINInBody(t *testing.T) {
	server, dbStore, _, mfaEngine, _, cleanup := setupTestServer(t)
	defer cleanup()
	user := newUser(t, dbStore, "user")
	token, pin, _, err := mfaEngine.GenerateDevicePairingToken(user.ID, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, req := range []mfa.NativeDeviceRegisterRequest{
		{UserID: user.ID, PairingToken: token},
		{UserID: user.ID, PINCode: pin},
		{},
	} {
		req.DeviceName, req.DeviceIdentifier, req.PublicKey, req.PushToken = "p", "i", testSPKI(t), "fcm"
		body := registerBody(t, req)
		if rec := postProofRegister(server, body, proofFor(token, testIssuerOrigin, body)); rec.Code != http.StatusBadRequest {
			t.Fatalf("body %s: status %d", body, rec.Code)
		}
	}
	// None of those spent the token: a legacy registration still succeeds.
	if rec := postRegister(server, registerBody(t, mfa.NativeDeviceRegisterRequest{
		PairingToken: token, DeviceName: "p", DeviceIdentifier: "i", PublicKey: testSPKI(t), PushToken: "fcm",
	})); rec.Code != http.StatusOK || rec.Header().Get(mfa.PairingProofHeader) != "" {
		t.Fatalf("legacy: status %d header %q", rec.Code, rec.Header().Get(mfa.PairingProofHeader))
	}
}
