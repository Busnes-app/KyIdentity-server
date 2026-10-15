package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/config"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// A borrowed session must not be able to remove, demote, or re-scope a phone factor.
func TestDeviceMutationsRequireStepUp(t *testing.T) {
	cases := []struct {
		name, method, path, body, action string
		changed                          func(*store.NativeDevice) bool
	}{
		{"delete", http.MethodDelete, "/api/user/devices/dev-1", "", "device.deleted",
			func(d *store.NativeDevice) bool { return d == nil }},
		{"approver", http.MethodPut, "/api/notifications/native/devices/dev-1/mfa", `{"isMfaApprover":false}`, "device.mfa_approver_changed",
			func(d *store.NativeDevice) bool { return !d.IsMFAApprover }},
		{"sign-on", http.MethodPut, "/api/notifications/native/devices/dev-1/sign-on", `{"canSignOn":false}`, "device.sign_on_changed",
			func(d *store.NativeDevice) bool { return !d.CanSignOn }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, db, _, _, _, cleanup := setupTestServer(t)
			defer cleanup()
			u := newUser(t, db, "user")
			cookie := newSession(t, db, u, time.Now().UTC().Add(time.Hour))
			if err := db.UpsertNativeDevice(&store.NativeDevice{ID: "dev-1", UserID: u.ID, DeviceName: "p", DeviceIdentifier: "i", IsMFAApprover: true, CanSignOn: true}); err != nil {
				t.Fatal(err)
			}
			device := func() *store.NativeDevice {
				d, err := db.GetNativeDevice("dev-1")
				if err != nil {
					t.Fatal(err)
				}
				return d
			}

			if r := adminRequestNoStepUp(t, srv, tc.method, tc.path, cookie, tc.body); r.Code != http.StatusForbidden {
				t.Fatalf("without step-up: status %d %s", r.Code, r.Body.String())
			}
			// A grant for another device's path must not spend here either.
			other := mintStepUp(t, srv, cookie, tc.method+" /api/user/devices/dev-2")
			if r := adminRequestWithStepUp(t, srv, tc.method, tc.path, cookie, tc.body, other); r.Code != http.StatusForbidden {
				t.Fatalf("with a foreign grant: status %d", r.Code)
			}
			if tc.changed(device()) {
				t.Fatal("device changed without step-up")
			}

			grant := mintStepUp(t, srv, cookie, tc.method+" "+tc.path)
			if r := adminRequestWithStepUp(t, srv, tc.method, tc.path, cookie, tc.body, grant); r.Code != http.StatusOK {
				t.Fatalf("with step-up: status %d %s", r.Code, r.Body.String())
			}
			if !tc.changed(device()) {
				t.Fatal("device unchanged with step-up")
			}
			events, _, err := db.SearchAuditEvents(store.AuditFilter{Action: tc.action, Outcome: "success", Limit: 10})
			if err != nil || len(events) != 1 || events[0].TargetID != "dev-1" || events[0].ActorID != u.ID {
				t.Fatalf("audit %+v err=%v", events, err)
			}
		})
	}
}

func TestDeleteUnknownDeviceIsNotFound(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	u := newUser(t, db, "user")
	cookie := newSession(t, db, u, time.Now().UTC().Add(time.Hour))
	other := newUser(t, db, "user")
	if err := db.UpsertNativeDevice(&store.NativeDevice{ID: "theirs", UserID: other.ID, DeviceName: "p", DeviceIdentifier: "i"}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"missing", "theirs"} {
		path := "/api/user/devices/" + id
		r := adminRequestWithStepUp(t, srv, http.MethodDelete, path, cookie, "", mintStepUp(t, srv, cookie, "DELETE "+path))
		if r.Code != http.StatusNotFound {
			t.Fatalf("delete %s: status %d %s", id, r.Code, r.Body.String())
		}
	}
	if d, _ := db.GetNativeDevice("theirs"); d == nil {
		t.Fatal("another user's device was deleted")
	}
	if events, _, _ := db.SearchAuditEvents(store.AuditFilter{Action: "device.deleted", Limit: 10}); len(events) != 0 {
		t.Fatalf("a delete that matched nothing was audited as success: %+v", events)
	}
}

func TestRateLimitPrefix(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.8":                      "203.0.113.8",
		"::ffff:203.0.113.8":               "203.0.113.8",
		"2001:db8:1:2:3:4:5:6":             "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff:ffff:ffff:ffff": "2001:db8:1:2::/64",
		"2001:db8:1:3::1":                  "2001:db8:1:3::/64",
		"not-an-ip":                        "not-an-ip",
	} {
		if got := rateLimitPrefix(in); got != want {
			t.Errorf("rateLimitPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

// Rotating through a /64 must not mint fresh buckets, and ClientIP must stay exact for audit.
func TestRateLimitSharesIPv6Prefix(t *testing.T) {
	mm := NewMiddlewareManager(nil, nil, config.DefaultForwardedHeader, testCSRFKey)
	limited := mm.RateLimit("probe", 2, 0)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	codes := []int{}
	for _, addr := range []string{"[2001:db8::1]:1", "[2001:db8::2]:1", "[2001:db8::3]:1", "[2001:db8:0:1::1]:1"} {
		req, _ := http.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		limited.ServeHTTP(rec, req)
		codes = append(codes, rec.Code)
		if addr == "[2001:db8::2]:1" && mm.ClientIP(req) != "2001:db8::2" {
			t.Fatalf("ClientIP = %q, want the exact address", mm.ClientIP(req))
		}
	}
	want := []int{200, 200, 429, 200}
	for i := range want {
		if codes[i] != want[i] {
			t.Fatalf("statuses %v, want %v", codes, want)
		}
	}
}
