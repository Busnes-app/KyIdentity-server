package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Busnes-app/kyidentity-server/internal/attest"
	"github.com/Busnes-app/kyidentity-server/internal/mfa"
)

type stubAttestor struct{ result attest.Result }

func (s stubAttestor) Verify([][]byte, attest.Expectation) attest.Result { return s.result }

func registerBody(t *testing.T, req mfa.NativeDeviceRegisterRequest) string {
	t.Helper()
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func postRegister(server *Server, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/notifications/native/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	server.httpServer.Handler.ServeHTTP(rec, req)
	return rec
}

func testSPKI(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	return base64.StdEncoding.EncodeToString(spki)
}

func TestRegisterHandlerReturnsAttestedLevelAndCapsBody(t *testing.T) {
	server, dbStore, _, mfaEngine, _, cleanup := setupTestServer(t)
	defer cleanup()
	user := newUser(t, dbStore, "user")
	mfaEngine.SetAttestor(stubAttestor{attest.Result{Level: "tee", BootState: "locked-verified"}})

	token, _, _, err := mfaEngine.GenerateDevicePairingToken(user.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	rec := postRegister(server, registerBody(t, mfa.NativeDeviceRegisterRequest{
		PairingToken: token, DeviceName: "p", DeviceIdentifier: "i", PublicKey: testSPKI(t), PushToken: "fcm",
		Attestation: []string{base64.StdEncoding.EncodeToString([]byte("cert"))},
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	var out struct {
		DeviceID string `json:"deviceId"`
		Device   struct {
			AttestedLevel string `json:"attestedLevel"`
			BootState     string `json:"bootState"`
		} `json:"device"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Device.AttestedLevel != "tee" || out.Device.BootState != "locked-verified" {
		t.Fatalf("body %s", rec.Body.String())
	}

	// An oversize body is refused before any pairing token is spent or device created.
	token2, _, _, err := mfaEngine.GenerateDevicePairingToken(user.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	big := registerBody(t, mfa.NativeDeviceRegisterRequest{
		PairingToken: token2, DeviceName: "q", DeviceIdentifier: "j", PublicKey: testSPKI(t), PushToken: "fcm",
		Attestation: []string{strings.Repeat("A", 70*1024)},
	})
	if rec := postRegister(server, big); rec.Code != http.StatusBadRequest {
		t.Fatalf("oversize status %d body %s", rec.Code, rec.Body.String())
	}
	devs, err := dbStore.ListUserNativeDevices(user.ID)
	if err != nil || len(devs) != 1 || devs[0].DeviceIdentifier != "i" {
		t.Fatalf("oversize request created a device: %v %+v", err, devs)
	}
}

func TestRepairingResetsAttestation(t *testing.T) {
	_, dbStore, _, mfaEngine, _, cleanup := setupTestServer(t)
	defer cleanup()
	user := newUser(t, dbStore, "user")
	mfaEngine.SetAttestor(stubAttestor{attest.Result{Level: "tee", BootState: "locked-verified"}})
	pub := testSPKI(t)

	token, _, _, _ := mfaEngine.GenerateDevicePairingToken(user.ID, true)
	first, err := mfaEngine.RegisterNativeDevice(&mfa.NativeDeviceRegisterRequest{PairingToken: token, DeviceName: "p", DeviceIdentifier: "i", PublicKey: pub, PushToken: "fcm", Attestation: []string{base64.StdEncoding.EncodeToString([]byte("cert"))}})
	if err != nil || first.AttestedLevel != "tee" {
		t.Fatalf("%v %+v", err, first)
	}
	if stored, _ := dbStore.GetNativeDevice(first.ID); stored.AttestedLevel != "tee" || stored.AttestedAt == nil {
		t.Fatalf("setup: %+v", stored)
	}

	token2, _, _, _ := mfaEngine.GenerateDevicePairingToken(user.ID, true)
	second, err := mfaEngine.RegisterNativeDevice(&mfa.NativeDeviceRegisterRequest{PairingToken: token2, DeviceName: "p", DeviceIdentifier: "i", PublicKey: pub, PushToken: "fcm"})
	if err != nil || second.ID != first.ID {
		t.Fatalf("%v %+v", err, second)
	}
	stored, _ := dbStore.GetNativeDevice(second.ID)
	if stored.AttestedLevel != "none" || stored.AttestedAt != nil {
		t.Fatalf("re-pair must reset attestation: %+v", stored)
	}
}
