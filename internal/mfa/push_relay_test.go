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
	}, MFAChallengePush{ChallengeID: "challenge", Purpose: "login", ExpiresAtMS: expires.UnixMilli(), Username: "alice.unsealed"})
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
	for _, field := range []string{"matchDigits", "decoyDigits", "username"} {
		if _, ok := data[field]; ok {
			t.Fatalf("push data leaked %s", field)
		}
	}
	// A keyless device's push is readable by the relay and Google: it never names the account.
	if strings.Contains(fmt.Sprint(sentPayload), "alice.unsealed") {
		t.Fatalf("unsealed push carries the username: %v", sentPayload)
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
	ch := MFAChallengePush{ChallengeID: "e4da3b7f-bbce-4345-8d1f-6c2a9e0b7d58", Purpose: "step_up", ExpiresAtMS: time.Now().Add(5 * time.Minute).UnixMilli(), Username: "alice.sealed"}
	if err := sender.SendPush(dev, ch); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{dev.ID, dev.UserID, ch.ChallengeID, "step_up", ch.Username} {
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
	want := challengeData(dev, ch)
	want["username"] = "alice.sealed"
	if !maps.Equal(got, want) {
		t.Fatalf("decrypted %v, want %v", got, want)
	}
}

// The username rides only in the sealed payload, so it must leave the relay record at its
// fixed 640 bytes (968 characters, under the relay's 1024). A longest-case challenge (UUID
// identifiers, step_up, a 13-digit expiry) still has room for a long username; one that would
// overflow the record is left out rather than breaking the cap.
func TestSealedChallengeUsernameFitsTheRelayRecord(t *testing.T) {
	dev := store.NativeDevice{
		ID: "3f9d6a1e-7c2b-4e58-9a0d-5b1c8e2f4a67", UserID: "c81e728d-9d4c-4f63-8b2a-0e5d7f9a1b3c", Platform: "android",
	}
	ch := MFAChallengePush{ChallengeID: "e4da3b7f-bbce-4345-8d1f-6c2a9e0b7d58", Purpose: "step_up", ExpiresAtMS: 9_999_999_999_999}
	bare, err := json.Marshal(challengeData(dev, ch))
	if err != nil {
		t.Fatal(err)
	}
	rk := newReceiver(t)
	room := maxRecordPlaintext(relayRecordSize) - len(bare) - len(`,"username":""`)
	if room < 200 {
		t.Fatalf("only %d bytes left for a username in the relay record", room)
	}
	for _, tc := range []struct {
		name string
		kept bool
	}{
		{strings.Repeat("a", room), true},
		{strings.Repeat("a", room+1), false},
		{strings.Repeat("<", room/6), true}, // json escapes each to \u003c: six bytes
		{strings.Repeat("<", room/6+1), false},
		{strings.Repeat("é", room/2), true},
	} {
		ch.Username = tc.name
		plain, err := sealedChallenge(dev, ch, relayRecordSize)
		if err != nil {
			t.Fatal(err)
		}
		if len(plain) > maxRecordPlaintext(relayRecordSize) {
			t.Fatalf("%d-byte username: plaintext is %d bytes, over one record", len(tc.name), len(plain))
		}
		var got map[string]string
		if err := json.Unmarshal(plain, &got); err != nil {
			t.Fatal(err)
		}
		if kept := got["username"] == tc.name; kept != tc.kept {
			t.Fatalf("%d-byte username kept = %v, want %v", len(tc.name), kept, tc.kept)
		}
		if sealed, err := webPushEncrypt(plain, rk.p256dh, rk.a64, relayRecordSize); err != nil {
			t.Fatal(err)
		} else if n := len(base64.RawURLEncoding.EncodeToString(sealed)); n != 968 {
			t.Fatalf("kyauth is %d characters, want 968", n)
		}
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

// A key belongs to the relay host that issued it: a server moved to another relay registers
// there instead of presenting the old relay's key, which the new one refuses as revoked.
func TestRelayKeyFilePerHost(t *testing.T) {
	dir := "/data"
	for _, c := range []struct{ transport, url, want string }{
		{"fcm", "https://fcm.relay.kyauth.busnes.app", "/data/push-relay-fcm-fcm.relay.kyauth.busnes.app.key"},
		{"apns", "https://APN.relay.kyauth.busnes.app:443/", "/data/push-relay-apns-apn.relay.kyauth.busnes.app.key"},
		{"fcm", "", "/data/push-relay-fcm.key"},
		{"fcm", "https://../evil/", "/data/push-relay-fcm-...key"},
	} {
		if got := RelayKeyFile(dir, c.transport, c.url); got != c.want {
			t.Errorf("RelayKeyFile(%q, %q) = %q, want %q", c.transport, c.url, got, c.want)
		}
		if filepath.Dir(RelayKeyFile(dir, c.transport, c.url)) != dir {
			t.Errorf("RelayKeyFile(%q) leaves %s", c.url, dir)
		}
	}
	if RelayKeyFile(dir, "fcm", "https://a.example") == RelayKeyFile(dir, "fcm", "https://b.example") {
		t.Fatal("two relays share one key file")
	}
}
