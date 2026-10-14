package api

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/mfa"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

func signPushTokenRefresh(t *testing.T, key *ecdsa.PrivateKey, issuer, deviceID, token string, issuedAt int64) string {
	t.Helper()
	return signPushTarget(t, key, issuer, deviceID, issuedAt, pushTokenRefreshRequest{PushTransport: "fcm", PushToken: token})
}

func signPushTarget(t *testing.T, key *ecdsa.PrivateKey, issuer, deviceID string, issuedAt int64, r pushTokenRefreshRequest) string {
	t.Helper()
	msg, err := mfa.PushTokenRefreshMessage(issuer, deviceID, issuedAt, r.PushTransport, r.PushToken, r.PushP256dh, r.PushAuth)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func TestNativeDeviceCanRefreshRotatedPushTokenOnce(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	user := newUser(t, db, "user")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	device := &store.NativeDevice{
		ID: uuid.New().String(), UserID: user.ID, DeviceName: "phone", DeviceIdentifier: "phone-1",
		PublicKey: base64.StdEncoding.EncodeToString(der), PushToken: "old-token", IsMFAApprover: true,
	}
	if err := db.UpsertNativeDevice(device); err != nil {
		t.Fatal(err)
	}

	issuedAt := time.Now().UnixMilli()
	call := func(token, signature string, at int64) *httptest.ResponseRecorder {
		body, _ := json.Marshal(pushTokenRefreshRequest{PushToken: token, IssuedAt: at, Signature: signature})
		req := httptest.NewRequest(http.MethodPut, "/api/notifications/native/devices/"+device.ID+"/push-token", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)
		return rec
	}

	signature := signPushTokenRefresh(t, key, "http://localhost:5867", device.ID, "new-token", issuedAt)
	if rec := call("new-token", signature, issuedAt); rec.Code != http.StatusNoContent {
		t.Fatalf("refresh = %d %s", rec.Code, rec.Body.String())
	} else if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	stored, err := db.GetNativeDevice(device.ID)
	if err != nil || stored.PushToken != "new-token" || stored.PushTokenUpdatedAtMS != issuedAt {
		t.Fatalf("stored device = %+v, err = %v", stored, err)
	}
	if rec := call("new-token", signature, issuedAt); rec.Code != http.StatusConflict {
		t.Fatalf("replay = %d, want 409", rec.Code)
	}

	wrongTokenAt := issuedAt + 1
	wrongTokenSignature := signPushTokenRefresh(t, key, "http://localhost:5867", device.ID, "signed-token", wrongTokenAt)
	if rec := call("substituted-token", wrongTokenSignature, wrongTokenAt); rec.Code != http.StatusUnauthorized {
		t.Fatalf("token substitution = %d, want 401", rec.Code)
	}
	wrongOriginSignature := signPushTokenRefresh(t, key, "https://attacker.test", device.ID, "next-token", wrongTokenAt)
	if rec := call("next-token", wrongOriginSignature, wrongTokenAt); rec.Code != http.StatusUnauthorized {
		t.Fatalf("origin substitution = %d, want 401", rec.Code)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherDeviceSignature := signPushTokenRefresh(t, otherKey, "http://localhost:5867", device.ID, "next-token", wrongTokenAt)
	if rec := call("next-token", otherDeviceSignature, wrongTokenAt); rec.Code != http.StatusUnauthorized {
		t.Fatalf("another device's signature = %d, want 401", rec.Code)
	}
	if rec := call("late-token", "ignored", time.Now().Add(-pushTokenClockSkew-time.Second).UnixMilli()); rec.Code != http.StatusBadRequest {
		t.Fatalf("stale request = %d, want 400", rec.Code)
	}

	events, _, err := db.ListAuditEvents(10, 0)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, event := range events {
		if event.Action == "device.push_token_refreshed" {
			count++
			if event.DetailsJSON != `{"pushTransport":"fcm"}` {
				t.Fatalf("token refresh audit details may leak a token: %s", event.DetailsJSON)
			}
		}
	}
	if count != 1 {
		t.Fatalf("refresh audit count = %d, want 1", count)
	}
}

// A device moves from FCM to UnifiedPush with a v2 refresh; the keys are signed with the endpoint.
func TestNativeDeviceRefreshSwitchesToUnifiedPush(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	user := newUser(t, db, "user")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	device := &store.NativeDevice{
		ID: uuid.New().String(), UserID: user.ID, DeviceName: "phone", DeviceIdentifier: "phone-1",
		PublicKey: base64.StdEncoding.EncodeToString(der), PushToken: "old-token", IsMFAApprover: true,
	}
	if err := db.UpsertNativeDevice(device); err != nil {
		t.Fatal(err)
	}
	receiver, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	target := pushTokenRefreshRequest{
		PushTransport: "unifiedpush",
		PushToken:     "https://push.example.net/upAbC123?up=1",
		PushP256dh:    base64.RawURLEncoding.EncodeToString(receiver.PublicKey().Bytes()),
		PushAuth:      base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef")),
	}
	call := func(r pushTokenRefreshRequest) int {
		body, _ := json.Marshal(r)
		req := httptest.NewRequest(http.MethodPut, "/api/notifications/native/devices/"+device.ID+"/push-token", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)
		return rec.Code
	}

	at := time.Now().UnixMilli()
	// A signature over other keys must not authorise these ones.
	swapped := target
	swapped.IssuedAt = at
	otherAuth := target
	otherAuth.PushAuth = base64.RawURLEncoding.EncodeToString([]byte("fedcba9876543210"))
	swapped.Signature = signPushTarget(t, key, "http://localhost:5867", device.ID, at, otherAuth)
	if code := call(swapped); code != http.StatusUnauthorized {
		t.Fatalf("key substitution = %d, want 401", code)
	}

	target.IssuedAt = at
	target.Signature = signPushTarget(t, key, "http://localhost:5867", device.ID, at, target)
	if code := call(target); code != http.StatusNoContent {
		t.Fatalf("refresh = %d", code)
	}
	stored, err := db.GetNativeDevice(device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.PushTransport != "unifiedpush" || stored.PushToken != target.PushToken ||
		stored.PushP256dh != target.PushP256dh || stored.PushAuth != target.PushAuth || stored.PushTokenUpdatedAtMS != at {
		t.Fatalf("stored device = %+v", stored)
	}

	// An unvalidated target is refused before the signature is checked.
	bad := target
	bad.PushToken = "https://10.0.0.5/x"
	bad.IssuedAt = at + 1
	bad.Signature = signPushTarget(t, key, "http://localhost:5867", device.ID, at+1, bad)
	if code := call(bad); code != http.StatusBadRequest {
		t.Fatalf("private endpoint = %d, want 400", code)
	}

	// Back to FCM clears the keys in the same write.
	fcm := pushTokenRefreshRequest{PushTransport: "fcm", PushToken: "fcm-token-2", IssuedAt: at + 2}
	fcm.Signature = signPushTarget(t, key, "http://localhost:5867", device.ID, at+2, fcm)
	if code := call(fcm); code != http.StatusNoContent {
		t.Fatalf("refresh to fcm = %d", code)
	}
	stored, err = db.GetNativeDevice(device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.PushTransport != "fcm" || stored.PushToken != "fcm-token-2" || stored.PushP256dh != "" || stored.PushAuth != "" {
		t.Fatalf("stored device = %+v", stored)
	}

	// The relay with keys (KyAuth iOS) keeps them, so its pushes stay sealed.
	sealed := pushTokenRefreshRequest{PushTransport: "fcm", PushToken: "fcm-token-3", PushP256dh: target.PushP256dh, PushAuth: target.PushAuth, IssuedAt: at + 3}
	sealed.Signature = signPushTarget(t, key, "http://localhost:5867", device.ID, at+3, sealed)
	if code := call(sealed); code != http.StatusNoContent {
		t.Fatalf("refresh to fcm with keys = %d", code)
	}
	stored, err = db.GetNativeDevice(device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.PushTransport != "fcm" || stored.PushToken != "fcm-token-3" || stored.PushP256dh != sealed.PushP256dh || stored.PushAuth != sealed.PushAuth {
		t.Fatalf("stored device = %+v", stored)
	}
}

// A linux device refreshes to ubuntupush; fcm is refused for it, and ubuntupush for android.
func TestNativeDeviceRefreshUbuntuPushIsLinuxOnly(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	user := newUser(t, db, "user")
	receiver, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p256dh := base64.RawURLEncoding.EncodeToString(receiver.PublicKey().Bytes())
	auth := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	enrol := func(ident, platform string) (*store.NativeDevice, *ecdsa.PrivateKey) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		d := &store.NativeDevice{
			ID: uuid.New().String(), UserID: user.ID, DeviceName: ident, DeviceIdentifier: ident, Platform: platform,
			PublicKey: base64.StdEncoding.EncodeToString(der), PushTransport: "unifiedpush",
			PushToken: "https://push.example.net/up1", PushP256dh: p256dh, PushAuth: auth, IsMFAApprover: true,
		}
		if err := db.UpsertNativeDevice(d); err != nil {
			t.Fatal(err)
		}
		return d, key
	}
	at := time.Now().UnixMilli()
	call := func(d *store.NativeDevice, key *ecdsa.PrivateKey, r pushTokenRefreshRequest) int {
		at++ // each refresh must be newer than the last
		r.IssuedAt = at
		r.Signature = signPushTarget(t, key, "http://localhost:5867", d.ID, r.IssuedAt, r)
		body, _ := json.Marshal(r)
		req := httptest.NewRequest(http.MethodPut, "/api/notifications/native/devices/"+d.ID+"/push-token", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)
		return rec.Code
	}
	ubuntu := pushTokenRefreshRequest{PushTransport: "ubuntupush", PushToken: "NQq1Ox+9Ah/lOM=:tok", PushP256dh: p256dh, PushAuth: auth}

	linux, linuxKey := enrol("pinephone", "linux")
	if code := call(linux, linuxKey, ubuntu); code != http.StatusNoContent {
		t.Fatalf("linux ubuntupush refresh = %d", code)
	}
	stored, err := db.GetNativeDevice(linux.ID)
	if err != nil || stored.Platform != "linux" || stored.PushTransport != "ubuntupush" || stored.PushToken != ubuntu.PushToken {
		t.Fatalf("stored = %+v, %v", stored, err)
	}
	if code := call(linux, linuxKey, pushTokenRefreshRequest{PushTransport: "fcm", PushToken: "fcm-token"}); code != http.StatusBadRequest {
		t.Fatalf("linux fcm refresh = %d, want 400", code)
	}
	if stored, _ := db.GetNativeDevice(linux.ID); stored.PushTransport != "ubuntupush" {
		t.Fatalf("refused refresh changed the target: %+v", stored)
	}

	android, androidKey := enrol("pixel", "android")
	if code := call(android, androidKey, ubuntu); code != http.StatusBadRequest {
		t.Fatalf("android ubuntupush refresh = %d, want 400", code)
	}
}
