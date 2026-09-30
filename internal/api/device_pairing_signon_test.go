package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/mfa"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

func TestPairingTokenHandlerSignOnBody(t *testing.T) {
	path := "/api/user/devices/pairing-token"
	cases := []struct {
		name string
		body string
		code int
		want bool
	}{
		{"no body", "", 200, true},
		{"empty object", `{}`, 200, true},
		{"explicit true", `{"signOn":true}`, 200, true},
		{"explicit false", `{"signOn":false}`, 200, false},
		{"malformed", `{"signOn":`, 400, false},
		{"wrong type", `{"signOn":"no"}`, 400, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, db, _, _, _, cleanup := setupTestServer(t)
			defer cleanup()
			u := newUser(t, db, "user")
			cookie := newSession(t, db, u, time.Now().UTC().Add(time.Hour))
			grant := mintStepUp(t, srv, cookie, "POST "+path)
			r := adminRequestWithStepUp(t, srv, "POST", path, cookie, tc.body, grant)
			if r.Code != tc.code {
				t.Fatalf("status %d, want %d: %s", r.Code, tc.code, r.Body.String())
			}
			if tc.code != 200 {
				// A rejected body must not burn the step-up grant.
				if r := adminRequestWithStepUp(t, srv, "POST", path, cookie, `{}`, grant); r.Code != 200 {
					t.Fatalf("grant burned by malformed body: %d", r.Code)
				}
				return
			}
			var resp struct {
				SignOn       bool   `json:"signOn"`
				PairingToken string `json:"pairingToken"`
			}
			if err := json.Unmarshal(r.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			if resp.SignOn != tc.want {
				t.Fatalf("response signOn=%v, want %v", resp.SignOn, tc.want)
			}

			events, _, err := db.SearchAuditEvents(store.AuditFilter{Action: "device.pairing_token_generated", Limit: 10})
			if err != nil || len(events) != 1 {
				t.Fatalf("audit events=%d err=%v", len(events), err)
			}
			var details map[string]any
			if err := json.Unmarshal([]byte(events[0].DetailsJSON), &details); err != nil || details["signOn"] != tc.want {
				t.Fatalf("audit details %q, want signOn=%v", events[0].DetailsJSON, tc.want)
			}

			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			pub := base64.StdEncoding.EncodeToString(elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y))
			dev, err := srv.mfaEngine.RegisterNativeDevice(&mfa.NativeDeviceRegisterRequest{
				PairingToken: resp.PairingToken, DeviceName: "phone", DeviceIdentifier: "ident", PublicKey: pub, PushToken: "fcm",
			})
			if err != nil {
				t.Fatal(err)
			}
			stored, err := db.GetNativeDevice(dev.ID)
			if err != nil || stored == nil || stored.CanSignOn != tc.want {
				t.Fatalf("stored device %+v err=%v, want CanSignOn=%v", stored, err, tc.want)
			}
		})
	}
}
