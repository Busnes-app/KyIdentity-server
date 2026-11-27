package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/hybridsig"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/mfa"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

func TestNativeHybridDeviceCanRefreshPushToken(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	user := newUser(t, db, "user")
	priv, err := hybridsig.Generate()
	if err != nil {
		t.Fatal(err)
	}
	device := &store.NativeDevice{
		ID:               uuid.New().String(),
		UserID:           user.ID,
		DeviceName:       "KyAuth Linux",
		DeviceIdentifier: "linux-hybrid-1",
		PublicKey:        base64.StdEncoding.EncodeToString(priv.Public().Bytes()),
		PushToken:        "old-token",
		IsMFAApprover:    true,
	}
	if err := db.UpsertNativeDevice(device); err != nil {
		t.Fatal(err)
	}

	issuedAt := time.Now().UnixMilli()
	const newToken = "new-token"
	msg, err := mfa.PushTokenRefreshMessage("http://localhost:5867", device.ID, issuedAt, "fcm", newToken, "", "")
	if err != nil {
		t.Fatal(err)
	}

	call := func(sig []byte) *httptest.ResponseRecorder {
		body, _ := json.Marshal(pushTokenRefreshRequest{
			PushToken: newToken,
			IssuedAt:  issuedAt,
			Signature: base64.StdEncoding.EncodeToString(sig),
		})
		req := httptest.NewRequest(http.MethodPut, "/api/notifications/native/devices/"+device.ID+"/push-token", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)
		return rec
	}

	// Wrong domain-separation label must be refused.
	wrongLabelSig, err := priv.Sign(crypto.DevicePushResponseLabel, msg)
	if err != nil {
		t.Fatal(err)
	}
	if rec := call(wrongLabelSig); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong label = %d %s, want 401", rec.Code, rec.Body.String())
	}

	// Valid label updates the push token.
	goodSig, err := priv.Sign(crypto.DevicePushTokenLabel, msg)
	if err != nil {
		t.Fatal(err)
	}
	if rec := call(goodSig); rec.Code != http.StatusNoContent {
		t.Fatalf("hybrid push-token refresh = %d %s, want 204", rec.Code, rec.Body.String())
	}
}
