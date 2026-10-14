package mfa

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
)

func TestRelaySenderRegistersAndPersistsKey(t *testing.T) {
	var registered bool
	var sentAuth string
	var sentPayload map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/register":
			registered = true
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"key": "relay-key"})
		case "/send":
			sentAuth = r.Header.Get("Authorization")
			if err := json.NewDecoder(r.Body).Decode(&sentPayload); err != nil {
				t.Fatalf("decode send payload: %v", err)
			}
			w.Header().Set("X-Request-Id", "req-ok")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	keyFile := filepath.Join(t.TempDir(), "relay.key")
	sender, err := NewRelaySender(RelayConfig{
		URL:     srv.URL,
		KeyFile: keyFile,
		Label:   "test",
	}, RelayConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !registered {
		t.Fatal("relay key was not registered")
	}
	key, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(key) != "relay-key\n" {
		t.Fatalf("unexpected persisted key: %q", key)
	}

	expires := time.Now().UTC().Add(5 * time.Minute).Truncate(time.Second)
	err = sender.SendPush(store.NativeDevice{
		ID: "dev1", UserID: "u1", Platform: "android", PushToken: "token",
	}, MFAChallengePush{ChallengeID: "challenge", Purpose: "login", ExpiresAtMS: expires.UnixMilli()})
	if err != nil {
		t.Fatal(err)
	}
	if sentAuth != "Bearer relay-key" {
		t.Fatalf("unexpected Authorization header: %q", sentAuth)
	}
	for _, field := range []string{"title", "body"} {
		if strings.Contains(fmt.Sprint(sentPayload[field]), "42") {
			t.Fatalf("%s leaked match digits: %v", field, sentPayload[field])
		}
	}
	data, ok := sentPayload["data"].(map[string]any)
	if !ok {
		t.Fatalf("unexpected data payload: %#v", sentPayload["data"])
	}
	for _, field := range []string{"matchDigits", "decoyDigits"} {
		if _, ok := data[field]; ok {
			t.Fatalf("push data leaked %s", field)
		}
	}
	for _, field := range []string{"title", "body"} {
		if strings.Contains(fmt.Sprint(data[field]), "42") {
			t.Fatalf("data.%s leaked match digits: %v", field, data[field])
		}
	}
	if data["purpose"] != "login" || data["expiresAtEpochMs"] != strconv.FormatInt(expires.UnixMilli(), 10) {
		t.Fatalf("purpose/expiry = %v / %v", data["purpose"], data["expiresAtEpochMs"])
	}
	if data["challengeId"] != "challenge" {
		t.Fatalf("challengeId = %v, want challenge", data["challengeId"])
	}
}

func TestRelaySenderReturnsStaleTokenOnGone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone)
	}))
	defer srv.Close()

	sender, err := NewRelaySender(RelayConfig{URL: srv.URL, Key: "key"}, RelayConfig{})
	if err != nil {
		t.Fatal(err)
	}
	err = sender.SendPush(store.NativeDevice{
		ID: "dev1", UserID: "u1", Platform: "android", PushToken: "token",
	}, MFAChallengePush{ChallengeID: "challenge"})
	if err != ErrStalePushToken {
		t.Fatalf("error = %v, want ErrStalePushToken", err)
	}
}

func TestRelaySenderRequiresOKBodyOnSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-Id", "req-bad")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "queued nowhere"})
	}))
	defer srv.Close()

	sender, err := NewRelaySender(RelayConfig{URL: srv.URL, Key: "key"}, RelayConfig{})
	if err != nil {
		t.Fatal(err)
	}
	err = sender.SendPush(store.NativeDevice{
		ID: "dev1", UserID: "u1", Platform: "android", PushToken: "token",
	}, MFAChallengePush{ChallengeID: "challenge"})
	if err == nil {
		t.Fatal("expected relay success without ok=true to fail")
	}
	if !strings.Contains(err.Error(), "req-bad") {
		t.Fatalf("error did not include relay request id: %v", err)
	}
}

// A device with keys gets the challenge sealed: the relay sees the fixed alert, the type and
// one fixed-size ciphertext, and no identifier.
func TestRelaySenderSealsChallengeForDeviceKeys(t *testing.T) {
	var raw []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ = io.ReadAll(r.Body)
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}))
	defer srv.Close()
	sender, err := NewRelaySender(RelayConfig{}, RelayConfig{URL: srv.URL, Key: "key"})
	if err != nil {
		t.Fatal(err)
	}
	rk := newReceiver(t)
	dev := store.NativeDevice{
		ID: "3f9d6a1e-7c2b-4e58-9a0d-5b1c8e2f4a67", UserID: "c81e728d-9d4c-4f63-8b2a-0e5d7f9a1b3c",
		Platform: "ios", PushToken: strings.Repeat("ab", 32), PushP256dh: rk.p256dh, PushAuth: rk.a64,
	}
	ch := MFAChallengePush{ChallengeID: "e4da3b7f-bbce-4345-8d1f-6c2a9e0b7d58", Purpose: "step_up", ExpiresAtMS: time.Now().Add(5 * time.Minute).UnixMilli()}
	if err := sender.SendPush(dev, ch); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{dev.ID, dev.UserID, ch.ChallengeID, "step_up"} {
		if strings.Contains(string(raw), id) {
			t.Fatalf("relay request carries %q: %s", id, raw)
		}
	}
	var sent struct {
		Title, Body string
		Data        map[string]string
	}
	if err := json.Unmarshal(raw, &sent); err != nil {
		t.Fatal(err)
	}
	if sent.Title != pushTitle || sent.Body != pushBody || len(sent.Data) != 2 || sent.Data["type"] != "mfa_challenge" {
		t.Fatalf("relay request = %s", raw)
	}
	if n := len(sent.Data["kyauth"]); n != 968 {
		t.Fatalf("kyauth is %d characters, want the fixed 968 (relay cap 1024)", n)
	}
	sealed, err := base64.RawURLEncoding.DecodeString(sent.Data["kyauth"])
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal(decryptRFC8291(t, rk, sealed), &got); err != nil {
		t.Fatal(err)
	}
	if want := challengeData(dev, ch); !maps.Equal(got, want) {
		t.Fatalf("decrypted %v, want %v", got, want)
	}
}

func TestRelaySenderRefusesBadDeviceKeys(t *testing.T) {
	sender, err := NewRelaySender(RelayConfig{}, RelayConfig{URL: "https://relay.invalid", Key: "key"})
	if err != nil {
		t.Fatal(err)
	}
	err = sender.SendPush(store.NativeDevice{ID: "d", Platform: "ios", PushToken: "t", PushP256dh: "AAAA", PushAuth: "AAAA"},
		MFAChallengePush{ChallengeID: "c", Purpose: "login"})
	if err == nil || !strings.Contains(err.Error(), "encrypt") {
		t.Fatalf("err = %v, want an encryption failure before any send", err)
	}
}
