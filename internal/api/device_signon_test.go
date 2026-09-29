package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/mfa"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

func TestSetDeviceSignOnTogglesOwnDeviceOnly(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	u := newUser(t, db, "user")
	cookie := newSession(t, db, u, time.Now().UTC().Add(time.Hour))
	if err := db.UpsertNativeDevice(&store.NativeDevice{ID: "dev-1", UserID: u.ID, DeviceName: "p", DeviceIdentifier: "i", CanSignOn: true}); err != nil {
		t.Fatal(err)
	}
	other := newUser(t, db, "user")
	if err := db.UpsertNativeDevice(&store.NativeDevice{ID: "dev-2", UserID: other.ID, DeviceName: "q", DeviceIdentifier: "j"}); err != nil {
		t.Fatal(err)
	}
	do := func(id, body string) int {
		return adminRequestNoStepUp(t, srv, http.MethodPut, "/api/notifications/native/devices/"+id+"/sign-on", cookie, body).Code
	}

	if c := do("dev-1", `{"canSignOn":false}`); c != http.StatusOK {
		t.Fatalf("own device: status %d", c)
	}
	if got, _ := db.GetNativeDevice("dev-1"); got.CanSignOn {
		t.Fatal("toggle off did not persist")
	}
	if c := do("dev-2", `{"canSignOn":true}`); c != http.StatusNotFound {
		t.Fatalf("foreign device: status %d", c)
	}
	if got, _ := db.GetNativeDevice("dev-2"); got.CanSignOn {
		t.Fatal("foreign toggle changed the row")
	}
	if c := do("dev-1", `{"canSignOn":`); c != http.StatusBadRequest {
		t.Fatalf("malformed: status %d", c)
	}

	for _, want := range []string{"success", "failure"} {
		evs, _, err := db.SearchAuditEvents(store.AuditFilter{Action: "device.sign_on_changed", Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, e := range evs {
			if e.Outcome == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("no %s audit event", want)
		}
	}
}

func signAssertion(t *testing.T, priv *ecdsa.PrivateKey, deviceID string, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "JWT", "kid": deviceID})
	c, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestTokenEndpointDeviceSignOnGrant(t *testing.T) {
	server, dbStore, _, mfaEngine, _, cleanup := setupTestServer(t)
	defer cleanup()
	user := newUser(t, dbStore, "user")
	client := &store.OAuthClient{ID: uuid.NewString(), ClientName: "KyPost", ClientType: "public", RedirectURIsJSON: `["https://kypost.example/cb"]`, AllowedScopesJSON: `["openid","profile","email"]`, Enabled: true}
	if err := dbStore.CreateOAuthClient(client); err != nil {
		t.Fatal(err)
	}
	allowTestAppAccess(t, dbStore, client.ID)

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	token, _, _, err := mfaEngine.GenerateDevicePairingToken(user.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	dev, err := mfaEngine.RegisterNativeDevice(&mfa.NativeDeviceRegisterRequest{PairingToken: token, DeviceName: "p", DeviceIdentifier: "i", PublicKey: base64.StdEncoding.EncodeToString(spki), PushToken: "fcm"})
	if err != nil {
		t.Fatal(err)
	}

	post := func(assertion string) *httptest.ResponseRecorder {
		form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {assertion}, "client_id": {client.ID}}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		server.httpServer.Handler.ServeHTTP(rec, req)
		return rec
	}
	now := time.Now().Unix()
	claims := map[string]any{"iss": "device:" + dev.ID, "sub": user.ID, "aud": server.cfg.IssuerURL + "/oauth/token", "client_id": client.ID, "iat": now, "exp": now + 120, "jti": uuid.NewString()}
	rec := post(signAssertion(t, priv, dev.ID, claims))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("token response must be no-store")
	}
	var body struct {
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.IDToken == "" || body.RefreshToken != "" {
		t.Fatalf("body %s", rec.Body.String())
	}

	rec = post("not-a-jwt")
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"invalid_grant"`) ||
		strings.Contains(rec.Body.String(), "device_signon_disabled") || strings.Contains(rec.Body.String(), "id_token") {
		t.Fatalf("garbage: status %d body %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("error response must be no-store")
	}

	if err := dbStore.SetNativeDeviceCanSignOn(dev.ID, user.ID, false); err != nil {
		t.Fatal(err)
	}
	claims["jti"] = uuid.NewString()
	rec = post(signAssertion(t, priv, dev.ID, claims))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "device_signon_disabled") {
		t.Fatalf("disabled: status %d body %s", rec.Code, rec.Body.String())
	}
}
