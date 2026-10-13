package mfa

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

const (
	vectorP256dh = "BLO9a5hWe8nCmwQX1aEnHLLnt8zkEd8orUdvm7-T9G4iMCY1nFt6ZzoFQA9EFaeHLGtbLcxSsDi0zCgJqaMqF6k"
	vectorAuth   = "MDEyMzQ1Njc4OWFiY2RlZg"
)

// The Android client asserts the same strings.
func TestPushTokenRefreshMessageGoldenVectors(t *testing.T) {
	for _, tc := range []struct {
		name, transport, token, p256dh, auth, tokenSHA, want string
	}{
		{
			name: "unifiedpush", transport: "unifiedpush", token: "https://ntfy.example.net/upAbC123?up=1",
			p256dh: vectorP256dh, auth: vectorAuth,
			tokenSHA: "8148d101f0613cac03f05c9530160b99c97e54841c0858e6a07b6deb9ab7ee2f",
			want:     "kyidentity-push-token-v2|https://id.example.com|d-456|1791331200000|unifiedpush|8148d101f0613cac03f05c9530160b99c97e54841c0858e6a07b6deb9ab7ee2f|" + vectorP256dh + "|" + vectorAuth,
		},
		{
			name: "ubuntupush", transport: "ubuntupush", token: "NQq1Ox+9Ah/lOM=:ubports_kyauth.-1",
			p256dh: vectorP256dh, auth: vectorAuth,
			tokenSHA: "2fc9f793cda3f150612f317c41b146738a3eba4b1dc16a80b43c5ec229552875",
			want:     "kyidentity-push-token-v2|https://id.example.com|d-456|1791331200000|ubuntupush|2fc9f793cda3f150612f317c41b146738a3eba4b1dc16a80b43c5ec229552875|" + vectorP256dh + "|" + vectorAuth,
		},
		{
			name: "fcm", transport: "fcm", token: "fcm-token-1",
			tokenSHA: "3cfaa3f1d62d114805029366153fbb440a2d4e4b56406a04830579ac65db6a5c",
			want:     "kyidentity-push-token-v2|https://id.example.com|d-456|1791331200000|fcm|3cfaa3f1d62d114805029366153fbb440a2d4e4b56406a04830579ac65db6a5c||",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sum := sha256.Sum256([]byte(tc.token))
			if got := hex.EncodeToString(sum[:]); got != tc.tokenSHA {
				t.Fatalf("sha256(%q) = %s, want %s", tc.token, got, tc.tokenSHA)
			}
			if _, err := ValidatePushTarget(tc.transport, tc.token, tc.p256dh, tc.auth); err != nil {
				t.Fatalf("vector target rejected: %v", err)
			}
			msg, err := PushTokenRefreshMessage("https://id.example.com", "d-456", 1791331200000, tc.transport, tc.token, tc.p256dh, tc.auth)
			if err != nil {
				t.Fatal(err)
			}
			if string(msg) != tc.want {
				t.Fatalf("message =\n%s\nwant\n%s", msg, tc.want)
			}
		})
	}
}

func TestPushTokenRefreshMessageRefusesSeparators(t *testing.T) {
	for _, f := range []func() ([]byte, error){
		func() ([]byte, error) { return PushTokenRefreshMessage("https://a|b", "d", 1, "fcm", "t", "", "") },
		func() ([]byte, error) { return PushTokenRefreshMessage("https://a", "d|e", 1, "fcm", "t", "", "") },
		func() ([]byte, error) { return PushTokenRefreshMessage("https://a", "d", 1, "fcm|x", "t", "", "") },
		func() ([]byte, error) {
			return PushTokenRefreshMessage("https://a", "d", 1, "unifiedpush", "t", "a|b", "c")
		},
		func() ([]byte, error) {
			return PushTokenRefreshMessage("https://a", "d", 1, "unifiedpush", "t", "a", "b|c")
		},
		func() ([]byte, error) { return PushTokenRefreshMessage("", "d", 1, "fcm", "t", "", "") },
	} {
		if msg, err := f(); err == nil {
			t.Errorf("accepted %q", msg)
		}
	}
}

func TestRegistrationValidatesPushTarget(t *testing.T) {
	e, _, _, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	_, pub := signingKey(t)

	receiver, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	point := receiver.PublicKey().Bytes()
	offCurve := append([]byte(nil), point...)
	offCurve[64] ^= 1
	compressed := append([]byte{2 + point[64]&1}, point[1:33]...)
	b64 := base64.RawURLEncoding.EncodeToString
	p256dh, auth := b64(point), b64([]byte("0123456789abcdef"))
	endpoint := "https://push.example.net/upAbC123"

	for _, tc := range []struct {
		name, transport, token, p256dh, auth string
	}{
		{"http endpoint", "unifiedpush", "http://push.example.net/x", p256dh, auth},
		{"private ip endpoint", "unifiedpush", "https://10.0.0.5/x", p256dh, auth},
		{"loopback endpoint", "unifiedpush", "https://127.0.0.1/x", p256dh, auth},
		{"endpoint too long", "unifiedpush", endpoint + strings.Repeat("a", MaxPushTokenBytes), p256dh, auth},
		{"fcm token too long", "fcm", strings.Repeat("a", MaxPushTokenBytes+1), "", ""},
		{"p256dh compressed", "unifiedpush", endpoint, b64(compressed), auth},
		{"p256dh short", "unifiedpush", endpoint, b64(point[:64]), auth},
		{"p256dh off curve", "unifiedpush", endpoint, b64(offCurve), auth},
		{"p256dh not base64url", "unifiedpush", endpoint, base64.StdEncoding.EncodeToString(point) + "+/", auth},
		{"p256dh missing", "unifiedpush", endpoint, "", auth},
		{"auth 15 bytes", "unifiedpush", endpoint, p256dh, b64([]byte("0123456789abcde"))},
		{"auth 17 bytes", "unifiedpush", endpoint, p256dh, b64([]byte("0123456789abcdefg"))},
		{"auth missing", "unifiedpush", endpoint, p256dh, ""},
		{"keys with fcm", "fcm", "fcm-token", p256dh, auth},
		{"auth with default transport", "", "fcm-token", "", auth},
		{"unknown transport", "apns", "token", "", ""},
		{"transport case", "UnifiedPush", endpoint, p256dh, auth},
		{"ubuntupush token 513 bytes", "ubuntupush", strings.Repeat("a", 513), p256dh, auth},
		{"ubuntupush token space", "ubuntupush", "abc def", p256dh, auth},
		{"ubuntupush token pipe", "ubuntupush", "abc|def", p256dh, auth},
		{"ubuntupush token newline", "ubuntupush", "abc\ndef", p256dh, auth},
		{"ubuntupush token url", "ubuntupush", "https://push.example.net/x?y", p256dh, auth},
		{"ubuntupush p256dh missing", "ubuntupush", "tok", "", auth},
		{"ubuntupush p256dh off curve", "ubuntupush", "tok", b64(offCurve), auth},
		{"ubuntupush auth missing", "ubuntupush", "tok", p256dh, ""},
		{"ubuntupush auth 15 bytes", "ubuntupush", "tok", p256dh, b64([]byte("0123456789abcde"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := e.RegisterNativeDevice(&NativeDeviceRegisterRequest{
				PairingToken: "unused", DeviceName: "p", DeviceIdentifier: "i", PublicKey: pub,
				PushToken: tc.token, PushTransport: tc.transport, PushP256dh: tc.p256dh, PushAuth: tc.auth,
			})
			if !errors.Is(err, errInvalidPushTarget) {
				t.Fatalf("err = %v, want invalid push target", err)
			}
		})
	}

	for _, tc := range []struct{ name, transport, token, p256dh, auth, want string }{
		{"default fcm", "", "fcm-token", "", "", "fcm"},
		{"fcm", "fcm", "fcm-token", "", "", "fcm"},
		{"unifiedpush", "unifiedpush", endpoint, p256dh, auth, "unifiedpush"},
		{"ubuntupush", "ubuntupush", "NQq1Ox+9Ah/lOM=:ubports_kyauth.-1", p256dh, auth, "ubuntupush"},
		{"ubuntupush 512 bytes", "ubuntupush", strings.Repeat("A", 512), p256dh, auth, "ubuntupush"},
		{"ubuntupush 1 byte", "ubuntupush", "A", p256dh, auth, "ubuntupush"},
		{"padded keys", "unifiedpush", endpoint, base64.URLEncoding.EncodeToString(point), base64.URLEncoding.EncodeToString([]byte("0123456789abcdef")), "unifiedpush"},
	} {
		got, err := ValidatePushTarget(tc.transport, tc.token, tc.p256dh, tc.auth)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %q, %v; want %q", tc.name, got, err, tc.want)
		}
	}
}
