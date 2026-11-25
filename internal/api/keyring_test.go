package api

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

func TestKeyringHTTPAccountAndAppBoundaries(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()
	token := f.cookie.Value
	encoded := func(v byte, size int) string {
		return base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(string(v), size)))
	}
	device, recovery, ring := uuid.NewString(), uuid.NewString(), uuid.NewString()
	capability := encoded('c', 32)
	wrapped := encoded('w', 60)
	init := map[string]any{
		"keyring_version": ring, "org_id": f.store.DefaultOrg().ID().String(), "user_id": f.user.ID,
		"device":   map[string]string{"id": device, "kind": "device", "sealed": wrapped, "device_hash": crypto.HashSHA256(capability)},
		"recovery": map[string]string{"id": recovery, "kind": "recovery", "sealed": wrapped},
	}
	call := func(want int, method, path, cookie, grant string, body any, headers ...[2]string) string {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		req := httptest.NewRequest(method, path, strings.NewReader(string(raw)))
		if cookie != "" {
			csrf := f.srv.middleware.IssueCSRFToken(cookie)
			req.AddCookie(&http.Cookie{Name: "kyidentity_session", Value: cookie})
			req.AddCookie(&http.Cookie{Name: "kyidentity_csrf", Value: csrf})
			req.Header.Set("X-CSRF-Token", csrf)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(StepUpHeader, grant)
		for _, h := range headers {
			req.Header.Set(h[0], h[1])
		}
		w := httptest.NewRecorder()
		f.srv.httpServer.Handler.ServeHTTP(w, req)
		if w.Code != want || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s %s: %d (want %d), headers=%v body=%s", method, path, w.Code, want, w.Header(), w.Body.String())
		}
		return w.Body.String()
	}

	call(401, "GET", keyringPath, "", "", nil)
	other := newUser(t, f.store, "user")
	otherToken := newSession(t, f.store, other, time.Now().UTC().Add(time.Hour))
	administrator := newUser(t, f.store, "admin")
	adminToken := newSession(t, f.store, administrator, time.Now().UTC().Add(time.Hour))
	call(403, "GET", keyringPath, adminToken, "", nil)
	call(403, "POST", keyringPath, token, "", init)
	grant := f.grant(t, "POST "+keyringPath)
	call(403, "POST", keyringPath, token, grant, init, [2]string{"X-CSRF-Token", "wrong"})
	init["unknown"] = "refuse"
	call(400, "POST", keyringPath, token, grant, init)
	delete(init, "unknown")
	call(400, "POST", keyringPath, otherToken, grant, init)
	call(204, "POST", keyringPath, token, grant, init)
	if got := call(200, "GET", keyringPath, token, "", nil); strings.Contains(got, wrapped) || strings.Contains(got, "device_hash") {
		t.Fatal("status exposed ciphertext or device capability hash")
	}
	call(404, "GET", keyringPath+"/wrappers/"+recovery, otherToken, "", nil)
	call(404, "GET", keyringPath+"/wrappers/"+device, token, "", nil)
	call(200, "GET", keyringPath+"/wrappers/"+device, token, "", nil, [2]string{"X-Ky-Keyring-Device", capability})
	call(403, "DELETE", keyringPath+"/wrappers/"+device, token, grant, nil)

	transfer := keyringPath + "/transfers"
	requestID := uuid.NewString()
	point, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	req := map[string]string{"keyring_version": ring, "id": requestID, "recipient_key": encoded('z', 65), "request_mac": encoded('m', 32)}
	call(400, "POST", transfer, token, "", req)
	req["recipient_key"] = base64.RawURLEncoding.EncodeToString(point.PublicKey().Bytes())
	call(200, "POST", transfer, token, "", req)
	call(404, "GET", transfer+"/"+requestID, token, "", nil)
	second := newSession(t, f.store, f.user, time.Now().UTC().Add(time.Hour))
	call(200, "GET", transfer+"/"+requestID, second, "", nil)
	call(404, "POST", transfer+"/"+requestID+"/claim", second, "", nil)
	call(204, "DELETE", transfer+"/"+requestID, token, "", nil)

	clients := []string{"keyring-app-a", "keyring-app-b"}
	appID := func(client string) string {
		t.Helper()
		apps, _, err := f.store.ListAppRecords(client, 2, 0)
		if err != nil || len(apps) != 1 || apps[0].ClientID != client {
			t.Fatalf("app lookup for %q: %v, %v", client, apps, err)
		}
		return apps[0].ID
	}
	org := f.store.DefaultOrg()
	for _, client := range clients {
		if err := f.store.CreateOAuthClient(&store.OAuthClient{ID: client, ClientName: client, ClientType: "public",
			RedirectURIsJSON: `["https://app.example/callback"]`, AllowedScopesJSON: `["openid"]`, Enabled: true}, nil); err != nil {
			t.Fatal(err)
		}
		if err := org.SetAppAssignment(appID(client), "users", f.user.ID, true, nil); err != nil {
			t.Fatal(err)
		}
	}
	appPath := keyringPath + "/apps/" + clients[0]
	put := func(version int, sealed string) map[string]any {
		return map[string]any{"keyring_version": ring, "key_version": version, "sealed": sealed}
	}
	g := f.grant(t, "PUT "+appPath)
	call(204, "PUT", appPath, token, g, put(1, wrapped))
	call(403, "GET", appPath, otherToken, "", nil)
	call(403, "GET", appPath, adminToken, "", nil)

	expires := time.Now().UTC().Add(time.Hour)
	signed := func(jti, audience, purpose string) [2]string {
		t.Helper()
		jwt, err := f.srv.keyManager.SignJWT(map[string]any{"iss": f.srv.cfg.IssuerURL, "sub": f.user.ID,
			"aud": audience, "exp": expires.Unix(), "jti": jti, "token_use": purpose})
		if err != nil {
			t.Fatal(err)
		}
		return [2]string{"Authorization", "Bearer " + jwt}
	}
	audienceTokens := []string{uuid.NewString(), uuid.NewString()}
	for i, client := range clients {
		if err := f.store.RecordIssuedToken(&store.IssuedToken{JTI: audienceTokens[i], UserID: f.user.ID, ClientID: client,
			SessionID: f.session.ID, ExpiresAt: expires}); err != nil {
			t.Fatal(err)
		}
	}
	bearerPath := "/api/keyring/app"
	bearer := signed(audienceTokens[0], clients[0], "access_token")
	if got := call(200, "GET", bearerPath, "", "", nil, bearer); !strings.Contains(got, wrapped) {
		t.Fatal("authorized app did not receive its envelope")
	}
	call(404, "GET", bearerPath+"?client="+clients[0], "", "", nil, signed(audienceTokens[1], clients[1], "access_token"))
	call(403, "GET", bearerPath, "", "", nil, signed(audienceTokens[1], clients[0], "access_token"))
	call(401, "GET", bearerPath, "", "", nil, signed(audienceTokens[0], clients[0], "id_token"))
	call(401, "GET", keyringPath, "", "", nil, bearer)
	g = f.grant(t, "PUT "+appPath)
	call(409, "PUT", appPath, token, g, put(3, wrapped))
	call(400, "PUT", appPath, token, g, map[string]any{"keyring_version": ring, "key_version": 2})
	rotated := encoded('r', 60)
	call(204, "PUT", appPath, token, g, put(2, rotated))
	if got := call(200, "GET", bearerPath, "", "", nil, bearer); !strings.Contains(got, rotated) || strings.Contains(got, wrapped) {
		t.Fatalf("rotation did not replace the prior envelope: %s", got)
	}
	g = f.grant(t, "PUT "+appPath)
	call(204, "PUT", appPath, token, g, put(3, ""))
	if got := call(200, "GET", bearerPath, "", "", nil, bearer); strings.Contains(got, rotated) || !strings.Contains(got, `"key_version":3`) {
		t.Fatalf("revoked version: %s", got)
	}
	if err := org.SetAppAssignment(appID(clients[0]), "users", f.user.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	call(403, "GET", bearerPath, "", "", nil, bearer)
}
