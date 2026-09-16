package mfa

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

	err = sender.SendPush(store.NativeDevice{
		ID: "dev1", UserID: "u1", Platform: "android", PushToken: "token",
	}, MFAChallengePush{ChallengeID: "challenge"})
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
