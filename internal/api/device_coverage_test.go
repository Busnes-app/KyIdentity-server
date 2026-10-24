package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// The device list shows the caller's own devices only, and an empty list as [] not null.
func TestListUserDevicesIsScopedToCaller(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	alice, bob := newUser(t, db, "user"), newUser(t, db, "user")
	aliceCookie := newSession(t, db, alice, time.Now().UTC().Add(time.Hour))
	bobCookie := newSession(t, db, bob, time.Now().UTC().Add(time.Hour))
	if err := db.UpsertNativeDevice(&store.NativeDevice{ID: uuid.NewString(), UserID: alice.ID, DeviceName: "alice-phone", DeviceIdentifier: "a-1"}); err != nil {
		t.Fatal(err)
	}

	rr := call(t, srv, aliceCookie, "GET", "/api/user/devices")
	var got struct {
		Devices []store.NativeDevice `json:"devices"`
	}
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &got) != nil || len(got.Devices) != 1 || got.Devices[0].DeviceName != "alice-phone" {
		t.Fatalf("alice's devices: %d %s", rr.Code, rr.Body.String())
	}
	rr = call(t, srv, bobCookie, "GET", "/api/user/devices")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"devices":[]`) {
		t.Fatalf("bob sees: %d %s", rr.Code, rr.Body.String())
	}
}

// Enabling TOTP needs a body, a step-up grant and a code that matches the secret; a wrong
// code spends the grant and saves nothing.
func TestEnableTOTPRefusals(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()
	secret, _, err := f.srv.mfaEngine.GenerateTOTPSecret(f.user.Username, "test")
	if err != nil {
		t.Fatal(err)
	}
	const op = "POST /api/user/mfa/totp/enable"
	covRefused(t, f.post(t, "/api/user/mfa/totp/enable", map[string]string{"secret": secret}, f.grant(t, op)), 400, "invalid_request")
	if rr := f.post(t, "/api/user/mfa/totp/enable", map[string]string{"secret": secret, "code": testTOTPCode(t, secret)}, ""); rr.Code != http.StatusForbidden {
		t.Fatalf("enable without step-up: %d", rr.Code)
	}
	grant := f.grant(t, op)
	covRefused(t, f.post(t, "/api/user/mfa/totp/enable", map[string]string{"secret": secret, "code": "000000x"}, grant), 400, "invalid_code")
	if rr := f.post(t, "/api/user/mfa/totp/enable", map[string]string{"secret": secret, "code": testTOTPCode(t, secret)}, grant); rr.Code != http.StatusForbidden {
		t.Fatalf("a grant spent on a wrong code was reused: %d", rr.Code)
	}
	methods, err := f.store.ListUserMFAMethods(f.user.ID)
	if err != nil || len(methods) != 0 {
		t.Fatalf("refused enrolment saved a factor: %v %v", methods, err)
	}
}

// Device writes refuse malformed bodies before checking signatures or grants.
func TestDeviceWritesRefuseMalformedBodies(t *testing.T) {
	f, cleanup := newStepUpFixture(t)
	defer cleanup()
	covRefused(t, adminRequestNoStepUp(t, f.srv, "PUT", "/api/notifications/native/devices/x/mfa", f.cookie.Value, "{"), 400, "invalid_request")
	rr := covRawRequest(t, f.srv, "PUT", "/api/notifications/native/devices/x/push-token", "{")
	body := covRefused(t, rr, 400, "invalid_request")
	if !strings.Contains(body["error_description"], "Malformed JSON") {
		t.Fatalf("push-token refusal: %v", body)
	}
}

// covRawRequest sends a raw body with a self-consistent CSRF pair and no session, as a
// native device or an anonymous browser would.
func covRawRequest(t *testing.T, srv *Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "192.0.2.77:1234"
	req.Header.Set("Content-Type", "application/json")
	csrf := "test-csrf-" + uuid.NewString()
	req.AddCookie(&http.Cookie{Name: "kyidentity_csrf", Value: csrf})
	req.Header.Set("X-CSRF-Token", csrf)
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)
	return rr
}

// A client with no launch URL launches at its redirect origin; one whose only redirect is
// a custom scheme launches at that URI; one with no redirect at all is not on the launcher.
// Cards are ordered by sort order, then name.
func TestLauncherDerivesClientURLsAndOrdersCards(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	cookie := newSession(t, db, newUser(t, db, "user"), time.Now().UTC().Add(time.Hour))
	newClient(t, db, "web", []string{"http://localhost:3000/cb", "https://web.example/cb"}, []string{"openid"})
	newClient(t, db, "native", []string{"com.example.app:/oauth"}, []string{"openid"})
	newClient(t, db, "nowhere", []string{}, []string{"openid"})
	for _, a := range []*store.Application{
		{ID: uuid.NewString(), Name: "Zeta", URL: "https://zeta.example", IconName: "favicon", SortOrder: -1, Enabled: true},
		{ID: uuid.NewString(), Name: "Alpha", URL: "https://alpha.example", IconName: "favicon", SortOrder: 5, Enabled: true},
	} {
		if err := db.CreateApplication(a, nil); err != nil {
			t.Fatal(err)
		}
		allowTestAppAccess(t, db, a.ID)
	}

	cards := launcherCards(t, srv, cookie)
	if c := cardByID(cards, "web"); c == nil || c.URL != "https://web.example" {
		t.Fatalf("web card: %+v", c)
	}
	if c := cardByID(cards, "native"); c == nil || c.URL != "com.example.app:/oauth" {
		t.Fatalf("native card: %+v", c)
	}
	if c := cardByID(cards, "nowhere"); c != nil {
		t.Fatalf("a client with nowhere to launch is on the launcher: %+v", c)
	}
	if len(cards) < 2 || cards[0].Name != "Zeta" || cards[len(cards)-1].Name != "Alpha" {
		names := []string{}
		for _, c := range cards {
			names = append(names, c.Name)
		}
		t.Fatalf("card order: %v", names)
	}
}
