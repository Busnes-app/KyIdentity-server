package api

import (
	"bytes"
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

	"github.com/Busness-app/kyidentity-server/internal/mfa"
	"github.com/Busness-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

func signPushTokenRefresh(t *testing.T, key *ecdsa.PrivateKey, issuer, deviceID, token string, issuedAt int64) string {
	t.Helper()
	digest := sha256.Sum256(mfa.PushTokenRefreshMessage(issuer, deviceID, token, issuedAt))
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
			if event.DetailsJSON != "" {
				t.Fatalf("token refresh audit details may leak a token: %s", event.DetailsJSON)
			}
		}
	}
	if count != 1 {
		t.Fatalf("refresh audit count = %d, want 1", count)
	}
}
