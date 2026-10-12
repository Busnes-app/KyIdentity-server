package mfa

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// RFC 8291 section 5 and appendix A.
func TestSealAES128GCMMatchesRFC8291Example(t *testing.T) {
	b64 := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(strings.ReplaceAll(s, " ", ""))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	uaPriv, err := ecdh.P256().NewPrivateKey(b64("q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94"))
	if err != nil {
		t.Fatal(err)
	}
	asPriv, err := ecdh.P256().NewPrivateKey(b64("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"))
	if err != nil {
		t.Fatal(err)
	}
	auth := b64("BTBZMqHH6r4Tts7J_aSIgg")
	want := b64("DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml" +
		"mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT" +
		"pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN")
	plain := []byte("When I grow up, I want to be a watermelon")

	got, err := sealAES128GCM(plain, uaPriv.PublicKey(), auth, b64("DGv6ra1nlYgDCS1FRnbzlw"), asPriv, 4096, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("body =\n%x\nwant\n%x", got, want)
	}
	// The same vector proves the test decrypter the sender tests rely on.
	if out := decryptRFC8291(t, receiverKeys{priv: uaPriv, auth: auth}, want); !bytes.Equal(out, plain) {
		t.Fatalf("decrypted %q", out)
	}
}

func newTestUbuntuPushSender(t *testing.T, ps *pushServer) *UbuntuPushSender {
	t.Helper()
	s := NewUbuntuPushSender(ps.URL+"/notify", "kyauth.busnes_kyauth")
	s.client.Transport.(*http.Transport).TLSClientConfig = ps.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	return s
}

func TestUbuntuPushSenderRequest(t *testing.T) {
	ps := newPushServer(t, http.StatusOK)
	s := newTestUbuntuPushSender(t, ps)
	rk := newReceiver(t)
	dev := store.NativeDevice{
		ID: "device-5b1d07", UserID: "user-9c2e41", Platform: "linux", PushTransport: "ubuntupush",
		PushToken: "NQq1Ox+9Ah/lOM=:tok", PushP256dh: rk.p256dh, PushAuth: rk.a64,
	}
	expires := time.Date(2026, 10, 11, 12, 0, 30, 500e6, time.UTC)
	if err := s.SendPush(dev, MFAChallengePush{ChallengeID: "challenge-7f3a9c", Purpose: "step_up", ExpiresAtMS: expires.UnixMilli()}); err != nil {
		t.Fatal(err)
	}

	body, h := ps.received()
	ps.mu.Lock()
	target := ps.target
	ps.mu.Unlock()
	if target != "POST /notify" || h.Get("Content-Type") != "application/json" {
		t.Fatalf("request %q content-type %q", target, h.Get("Content-Type"))
	}
	var req map[string]json.RawMessage
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatal(err)
	}
	var appID, token, expireOn, replaceTag string
	_ = json.Unmarshal(req["appid"], &appID)
	_ = json.Unmarshal(req["token"], &token)
	_ = json.Unmarshal(req["expire_on"], &expireOn)
	_ = json.Unmarshal(req["replace_tag"], &replaceTag)
	if len(req) != 5 || appID != "kyauth.busnes_kyauth" || token != dev.PushToken ||
		expireOn != "2026-10-11T12:00:30Z" || replaceTag != "kyauth-mfa" {
		t.Fatalf("request = %s", body)
	}
	data := req["data"]
	if len(data) > 4096 {
		t.Fatalf("data is %d bytes, over the 4096 MaxUnicastPayload", len(data))
	}
	var d struct {
		Message      map[string]string `json:"message"`
		Notification json.RawMessage   `json:"notification"`
	}
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatal(err)
	}
	const wantNotification = `{"card":{"body":"Open KyAuth to approve or deny.","persist":true,"popup":true,"summary":"Sign-in request"},"sound":true,"tag":"kyauth-mfa","vibrate":true}`
	if string(d.Notification) != wantNotification {
		t.Fatalf("notification = %s", d.Notification)
	}
	if bytes.Contains(body, []byte("challenge-7f3a9c")) || bytes.Contains(body, []byte("user-9c2e41")) {
		t.Fatal("challenge details visible to the push service")
	}
	if len(d.Message) != 1 {
		t.Fatalf("message = %v", d.Message)
	}
	sealed, err := base64.RawURLEncoding.DecodeString(d.Message["kyauth"])
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) != 86+ubuntuPushRecordSize {
		t.Fatalf("sealed body is %d bytes, want the fixed %d", len(sealed), 86+ubuntuPushRecordSize)
	}
	var got map[string]string
	if err := json.Unmarshal(decryptRFC8291(t, rk, sealed), &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"type": "mfa_challenge", "title": "Sign-in request", "body": "Open KySecurity Authenticator to review.",
		"challengeId": "challenge-7f3a9c", "deviceId": "device-5b1d07", "deviceUserId": "user-9c2e41", "purpose": "step_up",
		"expiresAtEpochMs": strconv.FormatInt(expires.UnixMilli(), 10), "devicePlatform": "linux",
	}
	if len(got) != len(want) {
		t.Fatalf("payload = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("payload[%s] = %q, want %q", k, got[k], v)
		}
	}
}

// Replies are lomiri-push-service APIError bodies (server/api/handlers.go).
func TestUbuntuPushSenderResponses(t *testing.T) {
	rk := newReceiver(t)
	for _, tc := range []struct {
		status    int
		reply     string
		ok, stale bool
	}{
		{http.StatusOK, `{}`, true, false},
		{http.StatusBadRequest, `{"error":"unknown-token","message":"Unknown token"}`, false, true},
		{http.StatusBadRequest, `{"error":"invalid-request","message":"Past expiration date"}`, false, false},
		{http.StatusUnauthorized, `{"error":"unauthorized","message":"Unauthorized"}`, false, false},
		{http.StatusRequestEntityTooLarge, `{"error":"too-many-pending"}`, false, false},
		{http.StatusServiceUnavailable, `{"error":"unavailable"}`, false, false},
		{http.StatusInternalServerError, `not json`, false, false},
	} {
		ps := newPushServer(t, tc.status)
		ps.reply = tc.reply
		s := newTestUbuntuPushSender(t, ps)
		dev := store.NativeDevice{ID: "d", Platform: "linux", PushToken: "secret-token", PushP256dh: rk.p256dh, PushAuth: rk.a64}
		err := s.SendPush(dev, MFAChallengePush{ChallengeID: "c", Purpose: "login", ExpiresAtMS: time.Now().Add(time.Minute).UnixMilli()})
		if tc.ok != (err == nil) || tc.stale != errors.Is(err, ErrStalePushToken) {
			t.Errorf("%d %s: err = %v", tc.status, tc.reply, err)
		}
		if err != nil && strings.Contains(err.Error(), "secret-token") {
			t.Errorf("error leaks the token: %v", err)
		}
	}
}

func TestUbuntuPushSenderRequiresKeys(t *testing.T) {
	ps := newPushServer(t, http.StatusOK)
	s := newTestUbuntuPushSender(t, ps)
	if err := s.SendPush(store.NativeDevice{ID: "d", PushToken: "tok"}, MFAChallengePush{ChallengeID: "c", Purpose: "login"}); err == nil {
		t.Fatal("sent without encryption keys")
	}
	if body, _ := ps.received(); body != nil {
		t.Fatal("a plaintext request was made")
	}
}

func TestLinuxPlatformTransports(t *testing.T) {
	e, db, _, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	u := mfaUser(t, db)
	rk := newReceiver(t)
	keys := NativeDeviceRegisterRequest{PushP256dh: rk.p256dh, PushAuth: rk.a64}

	for _, tc := range []struct{ name, platform, transport, token string }{
		{"linux ubuntupush", "linux", "ubuntupush", "ubports-token"},
		{"linux unifiedpush", "Linux", "unifiedpush", "https://push.example.net/up1"},
	} {
		req := keys
		req.Platform, req.PushTransport, req.PushToken = tc.platform, tc.transport, tc.token
		dev := registerTestDevice(t, e, u.ID, tc.name, req)
		stored, err := db.GetNativeDevice(dev.ID)
		if err != nil || stored.Platform != "linux" || stored.PushTransport != tc.transport {
			t.Fatalf("%s: stored %+v, %v", tc.name, stored, err)
		}
	}

	_, pub := signingKey(t)
	for _, tc := range []struct{ name, platform, transport, token, p256dh, auth string }{
		{"linux fcm", "linux", "fcm", "fcm-token", "", ""},
		{"linux default transport", "linux", "", "fcm-token", "", ""},
		{"android ubuntupush", "android", "ubuntupush", "ubports-token", rk.p256dh, rk.a64},
		{"default platform ubuntupush", "", "ubuntupush", "ubports-token", rk.p256dh, rk.a64},
		{"ios ubuntupush", "ios", "ubuntupush", "ubports-token", rk.p256dh, rk.a64},
	} {
		token, _, _, err := e.GenerateDevicePairingToken(u.ID, true)
		if err != nil {
			t.Fatal(err)
		}
		_, err = e.RegisterNativeDevice(&NativeDeviceRegisterRequest{
			PairingToken: token, DeviceName: tc.name, DeviceIdentifier: tc.name, Platform: tc.platform, PublicKey: pub,
			PushTransport: tc.transport, PushToken: tc.token, PushP256dh: tc.p256dh, PushAuth: tc.auth,
		})
		if !errors.Is(err, errInvalidPushTarget) {
			t.Errorf("%s: err = %v, want invalid push target", tc.name, err)
		}
		if spent, _ := db.GetValidDevicePairingToken(crypto.HashSHA256(token)); spent == nil {
			t.Errorf("%s: a refused registration consumed the pairing token", tc.name)
		}
	}
}

func TestUnknownUbuntuPushTokenIsCleared(t *testing.T) {
	e, db, _, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	u := mfaUser(t, db)
	ps := newPushServer(t, http.StatusBadRequest)
	ps.reply = `{"error":"unknown-token","message":"Unknown token"}`
	rk := newReceiver(t)
	dev := registerTestDevice(t, e, u.ID, "ut-phone", NativeDeviceRegisterRequest{
		Platform: "linux", PushTransport: "ubuntupush", PushToken: "ubports-token", PushP256dh: rk.p256dh, PushAuth: rk.a64,
	})
	e.SetUnifiedPushSender(&fakePushSender{})
	e.SetUbuntuPushSender(newTestUbuntuPushSender(t, ps))
	if _, err := e.CreatePushChallenge(u.ID, "login"); err != nil {
		t.Fatal(err)
	}
	if body, _ := ps.received(); body == nil {
		t.Fatal("push service was not contacted")
	}
	stored, err := db.GetNativeDevice(dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.PushToken != "" || stored.PushP256dh != "" || stored.PushAuth != "" || !stored.IsMFAApprover {
		t.Fatalf("stored device = %+v", stored)
	}
}
