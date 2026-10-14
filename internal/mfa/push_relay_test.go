package mfa

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

// supersedingRelay accepts only its newest key; older keys get the relay's key_superseded 401,
// or a plain 401 when superseded is false.
func supersedingRelay(t *testing.T, superseded bool) (*httptest.Server, *atomic.Int32) {
	var registrations atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/register":
			n := registrations.Add(1)
			time.Sleep(20 * time.Millisecond) // widen the window concurrent senders could stampede in
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"key": fmt.Sprintf("key-%d", n)})
		case "/send":
			if n := registrations.Load(); n > 0 && r.Header.Get("Authorization") == fmt.Sprintf("Bearer key-%d", n) {
				_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			body := map[string]string{"error": "invalid api key"}
			if superseded {
				body = map[string]string{"error": "api key superseded", "code": "key_superseded"}
			}
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &registrations
}

var relayTestDevice = store.NativeDevice{ID: "dev1", UserID: "u1", Platform: "android", PushToken: "token"}

func TestRelaySenderReRegistersOnceWhenKeySuperseded(t *testing.T) {
	srv, registrations := supersedingRelay(t, true)
	keyFile := filepath.Join(t.TempDir(), "relay.key")
	if err := os.WriteFile(keyFile, []byte("key-0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	sender, err := NewRelaySender(RelayConfig{URL: srv.URL, KeyFile: keyFile, Label: "test"}, RelayConfig{})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- sender.SendPush(relayTestDevice, MFAChallengePush{ChallengeID: "c"})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("send after supersession: %v", err)
		}
	}
	if n := registrations.Load(); n != 1 {
		t.Fatalf("registrations = %d, want 1: concurrent senders must share one renewal", n)
	}
	if key, _ := os.ReadFile(keyFile); string(key) != "key-1\n" {
		t.Fatalf("key file = %q, want the renewed key", key)
	}
}

func TestRelaySenderKeepsRefusedKeysRefused(t *testing.T) {
	// A plain 401 is an operator revocation, and an operator key is not ours to replace.
	plain, plainRegs := supersedingRelay(t, false)
	keyFile := filepath.Join(t.TempDir(), "relay.key")
	if err := os.WriteFile(keyFile, []byte("key-0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	superseded, operatorRegs := supersedingRelay(t, true)
	for name, cfg := range map[string]RelayConfig{
		"plain 401":    {URL: plain.URL, KeyFile: keyFile},
		"operator key": {URL: superseded.URL, Key: "key-0"},
	} {
		sender, err := NewRelaySender(cfg, RelayConfig{})
		if err != nil {
			t.Fatal(err)
		}
		if err := sender.SendPush(relayTestDevice, MFAChallengePush{ChallengeID: "c"}); err == nil {
			t.Fatalf("%s: send with a refused key succeeded", name)
		}
	}
	if plainRegs.Load()+operatorRegs.Load() != 0 {
		t.Fatalf("re-registered on a refusal that was not key_superseded")
	}
}
