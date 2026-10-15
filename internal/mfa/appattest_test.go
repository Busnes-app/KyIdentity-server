package mfa

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/appattest"
	"github.com/Busnes-app/kyidentity-server/internal/appattest/appattesttest"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

const testAppID = "TATYN4X57D.org.kysecurity.authenticator"

// iosEvidence attests the clientData KyAuth iOS would build for req.
func iosEvidence(t *testing.T, ca *appattesttest.CA, req *NativeDeviceRegisterRequest) *AppAttestEvidence {
	t.Helper()
	sum := sha256.Sum256(AppAttestClientData(req))
	keyID, obj := ca.Attest(t, appattesttest.Options{AppID: testAppID, ClientDataHash: sum[:]})
	return &AppAttestEvidence{KeyID: keyID, Attestation: base64.StdEncoding.EncodeToString(obj)}
}

func TestAppAttestClientDataMatchesKyAuthIOS(t *testing.T) {
	tok := &NativeDeviceRegisterRequest{PairingToken: "abc", PublicKey: "MFkw+/=="}
	if got := string(AppAttestClientData(tok)); got != "kyidentity-appattest-v1|abc|MFkw+/==" {
		t.Fatal(got)
	}
	pin := &NativeDeviceRegisterRequest{UserID: "u1", PINCode: "123456", PublicKey: "pk"}
	if got := string(AppAttestClientData(pin)); got != "kyidentity-appattest-v1|u1|123456|pk" {
		t.Fatal(got)
	}
}

func TestRegisterIOSWithAppAttest(t *testing.T) {
	engine, dbStore, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	ca := appattesttest.NewCA(t)
	engine.SetAppAttestor(appattest.NewVerifierWithRoot(ca.Root, []string{testAppID}, false))
	android := &fakeAttestor{}
	engine.SetAttestor(android)
	token, _, _, _ := engine.GenerateDevicePairingToken(user.ID, true, nil)
	_, pub := signingKey(t)
	req := &NativeDeviceRegisterRequest{PairingToken: token, DeviceName: "iPhone", DeviceIdentifier: "i", Platform: "ios", PublicKey: pub, PushToken: "apns",
		Attestation: []string{base64.StdEncoding.EncodeToString([]byte("cert"))}}
	req.AppAttest = iosEvidence(t, ca, req)
	dev, err := engine.RegisterNativeDevice(req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if dev.AttestedLevel != "appattest" || dev.BootState != "unknown" || dev.AttestedAt == nil || dev.AttestationReason != "" {
		t.Fatalf("%+v", dev)
	}
	if android.calls != 0 {
		t.Fatal("android chain graded for an ios registration")
	}
	if stored, _ := dbStore.GetNativeDevice(dev.ID); stored.AttestedLevel != "appattest" || stored.Platform != "ios" {
		t.Fatalf("stored %+v", stored)
	}
}

func TestRegisterIOSAppAttestBoundToPublicKey(t *testing.T) {
	engine, _, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	ca := appattesttest.NewCA(t)
	engine.SetAppAttestor(appattest.NewVerifierWithRoot(ca.Root, []string{testAppID}, false))
	token, _, _, _ := engine.GenerateDevicePairingToken(user.ID, true, nil)
	_, pub := signingKey(t)
	_, other := signingKey(t)
	req := &NativeDeviceRegisterRequest{PairingToken: token, DeviceName: "iPhone", DeviceIdentifier: "i", Platform: "ios", PublicKey: other, PushToken: "apns"}
	req.AppAttest = iosEvidence(t, ca, req)
	req.PublicKey = pub // swapped after attesting
	dev, err := engine.RegisterNativeDevice(req, nil)
	if err != nil || dev.AttestedLevel != "none" || dev.AttestationReason == "" {
		t.Fatalf("%v %+v", err, dev)
	}
}

func TestRegisterIOSGarbageAppAttestStillPairs(t *testing.T) {
	engine, dbStore, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	v, err := appattest.NewVerifier([]string{testAppID}, false)
	if err != nil {
		t.Fatal(err)
	}
	engine.SetAppAttestor(v)
	for _, ev := range []*AppAttestEvidence{
		{KeyID: "k", Attestation: "!!not base64!!"},
		{KeyID: base64.StdEncoding.EncodeToString(make([]byte, 32)), Attestation: base64.StdEncoding.EncodeToString([]byte("garbage"))},
	} {
		token, _, _, _ := engine.GenerateDevicePairingToken(user.ID, true, nil)
		_, pub := signingKey(t)
		dev, err := engine.RegisterNativeDevice(&NativeDeviceRegisterRequest{PairingToken: token, DeviceName: "iPhone", DeviceIdentifier: "i", Platform: "ios", PublicKey: pub, PushToken: "apns", AppAttest: ev}, nil)
		if err != nil || dev.AttestedLevel != "none" || dev.BootState != "unknown" || dev.AttestationReason == "" {
			t.Fatalf("%v %+v", err, dev)
		}
		if stored, _ := dbStore.GetNativeDevice(dev.ID); stored == nil || stored.AttestedLevel != "none" {
			t.Fatalf("stored %+v", stored)
		}
	}
}

func TestRegisterIOSWithoutAppAttestOrVerifierIsNone(t *testing.T) {
	engine, _, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	ca := appattesttest.NewCA(t)
	token, _, _, _ := engine.GenerateDevicePairingToken(user.ID, true, nil)
	_, pub := signingKey(t)
	req := &NativeDeviceRegisterRequest{PairingToken: token, DeviceName: "iPhone", DeviceIdentifier: "i", Platform: "ios", PublicKey: pub, PushToken: "apns"}
	req.AppAttest = iosEvidence(t, ca, req)
	dev, err := engine.RegisterNativeDevice(req, nil) // no App Attest verifier configured
	if err != nil || dev.AttestedLevel != "none" || dev.AttestationReason != "app attest not configured" {
		t.Fatalf("%v %+v", err, dev)
	}
	engine.SetAppAttestor(appattest.NewVerifierWithRoot(ca.Root, []string{testAppID}, false))
	token, _, _, _ = engine.GenerateDevicePairingToken(user.ID, true, nil)
	dev, err = engine.RegisterNativeDevice(&NativeDeviceRegisterRequest{PairingToken: token, DeviceName: "iPhone", DeviceIdentifier: "i", Platform: "ios", PublicKey: pub, PushToken: "apns"}, nil)
	if err != nil || dev.AttestedLevel != "none" || dev.AttestationReason != "" {
		t.Fatalf("%v %+v", err, dev)
	}
}

func TestRegisterAndroidIgnoresAppAttest(t *testing.T) {
	engine, _, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	ca := appattesttest.NewCA(t)
	engine.SetAppAttestor(appattest.NewVerifierWithRoot(ca.Root, []string{testAppID}, false))
	fa := &fakeAttestor{}
	engine.SetAttestor(fa)
	for _, platform := range []string{"android", ""} {
		token, _, _, _ := engine.GenerateDevicePairingToken(user.ID, true, nil)
		_, pub := signingKey(t)
		req := &NativeDeviceRegisterRequest{PairingToken: token, DeviceName: "p", DeviceIdentifier: "i", Platform: platform, PublicKey: pub, PushToken: "fcm"}
		req.AppAttest = iosEvidence(t, ca, req)
		dev, err := engine.RegisterNativeDevice(req, nil)
		if err != nil || dev.AttestedLevel != "none" || dev.AttestationReason != "" {
			t.Fatalf("%q: valid app attest graded an android device: %v %+v", platform, err, dev)
		}
	}
	if fa.calls != 0 {
		t.Fatalf("android attestor called without a chain: %d", fa.calls)
	}
}

func TestSweepSkipsAppAttestDevices(t *testing.T) {
	engine, dbStore, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	dev := &store.NativeDevice{ID: "ios", UserID: user.ID, DeviceName: "ios", DeviceIdentifier: "ios", Platform: "ios", PublicKey: "pk", IsMFAApprover: true}
	if err := dbStore.UpsertNativeDevice(dev); err != nil {
		t.Fatal(err)
	}
	if ok, err := dbStore.SetNativeDeviceAttestation("ios", "pk", "appattest", "unknown", []string{"bb"}, time.Now()); err != nil || !ok {
		t.Fatalf("attest: %v %v", ok, err)
	}
	n, err := engine.SweepAttestations(staticStatus{"bb": true}, true, func(string, string, string) { t.Fatal("audited an app attest device") })
	if err != nil || n != 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if d, _ := dbStore.GetNativeDevice("ios"); d.AttestedLevel != "appattest" {
		t.Fatalf("downgraded: %s", d.AttestedLevel)
	}
}

// The audit row keeps the fixed classification, never the error's detail.
func TestRegisterIOSDevelopmentEvidenceRefusedWithClassifiedReason(t *testing.T) {
	engine, _, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	ca := appattesttest.NewCA(t)
	engine.SetAppAttestor(appattest.NewVerifierWithRoot(ca.Root, []string{testAppID}, false))
	token, _, _, _ := engine.GenerateDevicePairingToken(user.ID, true, nil)
	_, pub := signingKey(t)
	req := &NativeDeviceRegisterRequest{PairingToken: token, DeviceName: "iPhone", DeviceIdentifier: "i", Platform: "ios", PublicKey: pub, PushToken: "apns"}
	sum := sha256.Sum256(AppAttestClientData(req))
	keyID, obj := ca.Attest(t, appattesttest.Options{AppID: testAppID, ClientDataHash: sum[:], AAGUID: []byte("appattestdevelop")})
	req.AppAttest = &AppAttestEvidence{KeyID: keyID, Attestation: base64.StdEncoding.EncodeToString(obj)}
	dev, err := engine.RegisterNativeDevice(req, nil)
	if err != nil {
		t.Fatalf("pairing must still succeed: %v", err)
	}
	if dev.AttestedLevel != "none" || dev.AttestationReason != string(appattest.ReasonAAGUID) {
		t.Fatalf("level %q reason %q", dev.AttestedLevel, dev.AttestationReason)
	}
}

func TestRefusedAppAttestLogsStructuredFields(t *testing.T) {
	engine, _, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	ca := appattesttest.NewCA(t)
	engine.SetAppAttestor(appattest.NewVerifierWithRoot(ca.Root, []string{testAppID}, false))
	var buf bytes.Buffer
	engine.logger = slog.New(slog.NewJSONHandler(&buf, nil))

	register := func(ev func(*NativeDeviceRegisterRequest) *AppAttestEvidence) map[string]string {
		t.Helper()
		buf.Reset()
		token, _, _, _ := engine.GenerateDevicePairingToken(user.ID, true, nil)
		_, pub := signingKey(t)
		req := &NativeDeviceRegisterRequest{PairingToken: token, DeviceName: "iPhone", DeviceIdentifier: "i", Platform: "ios", PublicKey: pub, PushToken: "apns"}
		req.AppAttest = ev(req)
		if _, err := engine.RegisterNativeDevice(req, nil); err != nil {
			t.Fatalf("pairing must still succeed: %v", err)
		}
		var rec map[string]string
		if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
			t.Fatalf("log is not one JSON record: %q", buf.String())
		}
		return rec
	}
	check := func(rec map[string]string, reason appattest.Reason) {
		t.Helper()
		if rec["level"] != "WARN" || rec["msg"] != "ios pairing graded none" || rec["user"] != user.ID ||
			rec["reason"] != string(reason) || rec["detail"] == "" || rec["detail"] == rec["reason"] {
			t.Fatalf("record %v", rec)
		}
	}

	check(register(func(req *NativeDeviceRegisterRequest) *AppAttestEvidence {
		sum := sha256.Sum256(AppAttestClientData(req))
		keyID, obj := ca.Attest(t, appattesttest.Options{AppID: testAppID, ClientDataHash: sum[:], AAGUID: []byte("appattestdevelop")})
		return &AppAttestEvidence{KeyID: keyID, Attestation: base64.StdEncoding.EncodeToString(obj)}
	}), appattest.ReasonAAGUID)
	check(register(func(*NativeDeviceRegisterRequest) *AppAttestEvidence {
		return &AppAttestEvidence{KeyID: "k", Attestation: "!!not base64!!"}
	}), appattest.ReasonDecode)
}
