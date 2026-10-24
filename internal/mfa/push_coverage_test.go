package mfa

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/netguard"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// covRelayHit is one request a fake relay received.
type covRelayHit struct {
	method, path, auth, contentType string
	body                            map[string]any
}

// covRelay is a plain-HTTP push relay whose /register and /send replies a test scripts.
type covRelay struct {
	*httptest.Server
	mu       sync.Mutex
	hits     []covRelayHit
	register func(w http.ResponseWriter)
	send     func(w http.ResponseWriter)
}

func newCovRelay(t *testing.T) *covRelay {
	t.Helper()
	cr := &covRelay{
		register: func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"key":"fresh-key"}`)
		},
		send: func(w http.ResponseWriter) { _, _ = io.WriteString(w, `{"ok":true}`) },
	}
	cr.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		cr.mu.Lock()
		cr.hits = append(cr.hits, covRelayHit{r.Method, r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type"), body})
		register, send := cr.register, cr.send
		cr.mu.Unlock()
		if r.URL.Path == "/register" {
			register(w)
			return
		}
		send(w)
	}))
	t.Cleanup(cr.Close)
	return cr
}

func (cr *covRelay) recorded() []covRelayHit {
	cr.mu.Lock()
	defer cr.mu.Unlock()
	return append([]covRelayHit(nil), cr.hits...)
}

// Relay registration accepts only a 200/201 carrying a key; every other answer fails
// startup instead of running with no key.
func TestRelayRegistrationRefusesBadAnswers(t *testing.T) {
	for name, reply := range map[string]func(w http.ResponseWriter){
		"server error": func(w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError) },
		"rate limited": func(w http.ResponseWriter) { w.WriteHeader(http.StatusTooManyRequests) },
		"not json":     func(w http.ResponseWriter) { _, _ = io.WriteString(w, "<html>") },
		"no key":       func(w http.ResponseWriter) { _, _ = io.WriteString(w, `{"key":""}`) },
	} {
		t.Run(name, func(t *testing.T) {
			cr := newCovRelay(t)
			cr.register = reply
			keyFile := filepath.Join(t.TempDir(), "relay.key")
			sender, err := NewRelaySender(RelayConfig{URL: cr.URL, KeyFile: keyFile, Label: "kyid"}, RelayConfig{})
			if err == nil || sender != nil {
				t.Fatalf("sender=%v err=%v", sender, err)
			}
			hits := cr.recorded()
			if len(hits) != 1 || hits[0].method != http.MethodPost || hits[0].path != "/register" ||
				hits[0].contentType != "application/json" || hits[0].body["label"] != "kyid" {
				t.Fatalf("register request = %+v", hits)
			}
			if _, err := os.Stat(keyFile); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a key file was written after a failed registration: %v", err)
			}
		})
	}
}

// A failure on the APNs relay fails construction even when FCM succeeded, and no relay
// configured at all yields no sender rather than an empty one.
func TestNewRelaySenderConfigOutcomes(t *testing.T) {
	if s, err := NewRelaySender(RelayConfig{}, RelayConfig{}); s != nil || err != nil {
		t.Fatalf("no relays: %v %v", s, err)
	}
	if s, err := NewRelaySender(RelayConfig{URL: "http://bad host"}, RelayConfig{}); s != nil || err == nil {
		t.Fatalf("unparseable fcm url: %v %v", s, err)
	}
	cr := newCovRelay(t)
	cr.register = func(w http.ResponseWriter) { w.WriteHeader(http.StatusForbidden) }
	if s, err := NewRelaySender(RelayConfig{URL: "https://fcm.invalid", Key: "k"}, RelayConfig{URL: cr.URL}); s != nil || err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("apns registration refused: %v %v", s, err)
	}
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	if s, err := NewRelaySender(RelayConfig{URL: closed.URL}, RelayConfig{}); s != nil || err == nil {
		t.Fatalf("unreachable relay: %v %v", s, err)
	}
}

// A key that cannot be persisted fails startup: otherwise every restart would register a
// new key and supersede the last.
func TestRelayKeyPersistFailureFailsStartup(t *testing.T) {
	cr := newCovRelay(t)
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := NewRelaySender(RelayConfig{URL: cr.URL, KeyFile: filepath.Join(blocker, "relay.key")}, RelayConfig{})
	if s != nil || err == nil {
		t.Fatalf("sender=%v err=%v", s, err)
	}
}

// Devices route by platform: an unknown platform is an error, and an iOS device with no
// APNs relay configured is skipped without contacting the FCM relay.
func TestRelaySendPushRoutesByPlatform(t *testing.T) {
	cr := newCovRelay(t)
	s, err := NewRelaySender(RelayConfig{URL: cr.URL, Key: "op-key"}, RelayConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SendPush(store.NativeDevice{ID: "d", Platform: "linux", PushToken: "t"}, MFAChallengePush{ChallengeID: "c"}); err == nil || !strings.Contains(err.Error(), "unsupported push platform") {
		t.Fatalf("linux via relay: %v", err)
	}
	if err := s.SendPush(store.NativeDevice{ID: "d", Platform: "ios", PushToken: "t"}, MFAChallengePush{ChallengeID: "c"}); err != nil {
		t.Fatalf("ios without apns relay: %v", err)
	}
	if hits := cr.recorded(); len(hits) != 0 {
		t.Fatalf("relay was contacted: %+v", hits)
	}

	if err := s.SendPush(store.NativeDevice{ID: "d", UserID: "u", Platform: "android", PushToken: "fcm-tok"},
		MFAChallengePush{ChallengeID: "c1", Purpose: "login", ExpiresAtMS: 1700000000000}); err != nil {
		t.Fatal(err)
	}
	hits := cr.recorded()
	if len(hits) != 1 || hits[0].method != http.MethodPost || hits[0].path != "/send" || hits[0].auth != "Bearer op-key" || hits[0].body["token"] != "fcm-tok" {
		t.Fatalf("send = %+v", hits)
	}
	data, _ := hits[0].body["data"].(map[string]any)
	if data["challengeId"] != "c1" || data["expiresAtEpochMs"] != "1700000000000" || data["deviceId"] != "d" {
		t.Fatalf("data = %v", data)
	}
}

// Relay send failures are classified: non-200 is an error carrying the relay's request id
// from the body (preferred) or header; 410 is a stale token; transport errors surface.
func TestRelaySendFailureClassification(t *testing.T) {
	cr := newCovRelay(t)
	s, err := NewRelaySender(RelayConfig{URL: cr.URL, Key: "op-key"}, RelayConfig{})
	if err != nil {
		t.Fatal(err)
	}
	dev := store.NativeDevice{ID: "d", Platform: "android", PushToken: "t"}
	for _, tc := range []struct {
		name      string
		reply     func(w http.ResponseWriter)
		want      string
		wantStale bool
	}{
		{"5xx with body request id", func(w http.ResponseWriter) {
			w.Header().Set("X-Request-Id", "hdr-id")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, `{"error":"fcm down","requestId":"body-id"}`)
		}, "requestId=body-id", false},
		{"429 with header request id", func(w http.ResponseWriter) {
			w.Header().Set("X-Request-Id", "hdr-id")
			w.WriteHeader(http.StatusTooManyRequests)
		}, "429", false},
		{"plain 401 is not a superseded key", func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"invalid api key"}`)
		}, "401", false},
		{"gone", func(w http.ResponseWriter) { w.WriteHeader(http.StatusGone) }, "", true},
	} {
		cr.mu.Lock()
		cr.send = tc.reply
		cr.mu.Unlock()
		err := s.SendPush(dev, MFAChallengePush{ChallengeID: "c"})
		if tc.wantStale != errors.Is(err, ErrStalePushToken) || err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v", tc.name, err)
		}
	}
	// An operator key is never re-registered, so a 401 above made no /register call.
	for _, h := range cr.recorded() {
		if h.path == "/register" {
			t.Fatal("operator-supplied key was re-registered")
		}
	}

	cr.Close()
	if err := s.SendPush(dev, MFAChallengePush{ChallengeID: "c"}); err == nil {
		t.Fatal("send to a closed relay succeeded")
	}
}

// When the relay supersedes our key and re-registration then fails, the push fails with
// a clear error and the old key is not reused for a second send.
func TestRelayRenewalFailureFailsThePush(t *testing.T) {
	cr := newCovRelay(t)
	keyFile := filepath.Join(t.TempDir(), "relay.key")
	if err := os.WriteFile(keyFile, []byte("old-key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := NewRelaySender(RelayConfig{URL: cr.URL, KeyFile: keyFile}, RelayConfig{})
	if err != nil {
		t.Fatal(err)
	}
	cr.mu.Lock()
	cr.send = func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"code":"key_superseded"}`)
	}
	cr.register = func(w http.ResponseWriter) { w.WriteHeader(http.StatusServiceUnavailable) }
	cr.mu.Unlock()

	err = s.SendPush(store.NativeDevice{ID: "d", Platform: "android", PushToken: "t"}, MFAChallengePush{ChallengeID: "c"})
	if err == nil || !strings.Contains(err.Error(), "re-registration failed") {
		t.Fatalf("err = %v", err)
	}
	var paths []string
	for _, h := range cr.recorded() {
		paths = append(paths, h.path)
	}
	if strings.Join(paths, ",") != "/send,/register" {
		t.Fatalf("requests = %v, want one send then one register", paths)
	}
	if got, _ := os.ReadFile(keyFile); strings.TrimSpace(string(got)) != "old-key" {
		t.Fatalf("key file = %q", got)
	}
}

// A renewed key is used even when it cannot be written to disk: the relay has already
// revoked the old one, so falling back to it would fail every push.
func TestRelayRenewedKeyUsedWhenPersistFails(t *testing.T) {
	var renewedSends atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/register":
			_, _ = io.WriteString(w, `{"key":"fresh-key"}`)
		case r.Header.Get("Authorization") == "Bearer fresh-key":
			renewedSends.Add(1)
			_, _ = io.WriteString(w, `{"ok":true}`)
		default:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"code":"key_superseded"}`)
		}
	}))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "relay.key")
	if err := os.WriteFile(keyFile, []byte("old-key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := NewRelaySender(RelayConfig{URL: srv.URL, KeyFile: keyFile}, RelayConfig{})
	if err != nil {
		t.Fatal(err)
	}
	// Point persistence at a path whose parent is a file, so the write fails.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	s.fcm.keyFile = filepath.Join(blocker, "relay.key")

	if err := s.SendPush(store.NativeDevice{ID: "d", Platform: "android", PushToken: "t"}, MFAChallengePush{ChallengeID: "c"}); err != nil {
		t.Fatalf("send after renewal: %v", err)
	}
	if renewedSends.Load() != 1 || s.fcm.currentKey() != "fresh-key" {
		t.Fatalf("renewed sends=%d key=%q", renewedSends.Load(), s.fcm.currentKey())
	}
}

// Ubuntu push refuses malformed device keys and an oversized payload before any request
// leaves the server.
func TestUbuntuPushRefusesBadKeysAndOversize(t *testing.T) {
	ps := newPushServer(t, http.StatusOK)
	s := newTestUbuntuPushSender(t, ps)
	rk := newReceiver(t)
	future := time.Now().Add(time.Minute).UnixMilli()
	for name, tc := range map[string]struct {
		dev store.NativeDevice
		ch  MFAChallengePush
	}{
		"p256dh not base64url": {store.NativeDevice{ID: "d", PushToken: "t", PushP256dh: "!!!", PushAuth: rk.a64}, MFAChallengePush{ChallengeID: "c", ExpiresAtMS: future}},
		"auth wrong length":    {store.NativeDevice{ID: "d", PushToken: "t", PushP256dh: rk.p256dh, PushAuth: "AAAA"}, MFAChallengePush{ChallengeID: "c", ExpiresAtMS: future}},
		"auth not base64url":   {store.NativeDevice{ID: "d", PushToken: "t", PushP256dh: rk.p256dh, PushAuth: "@@@@"}, MFAChallengePush{ChallengeID: "c", ExpiresAtMS: future}},
		"payload over record":  {store.NativeDevice{ID: "d", PushToken: "t", PushP256dh: rk.p256dh, PushAuth: rk.a64}, MFAChallengePush{ChallengeID: strings.Repeat("c", ubuntuPushRecordSize), ExpiresAtMS: future}},
	} {
		if err := s.SendPush(tc.dev, tc.ch); err == nil || !strings.Contains(err.Error(), "encrypt") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if body, _ := ps.received(); body != nil {
		t.Fatal("a request was sent for a refused push")
	}
}

// Ubuntu push transport failures are errors, never success, and a refused loopback dial
// (the outbound guard) stops the request.
func TestUbuntuPushTransportFailures(t *testing.T) {
	rk := newReceiver(t)
	dev := store.NativeDevice{ID: "d", PushToken: "tok", PushP256dh: rk.p256dh, PushAuth: rk.a64}
	ch := MFAChallengePush{ChallengeID: "c", Purpose: "login", ExpiresAtMS: time.Now().Add(time.Minute).UnixMilli()}

	ps := newPushServer(t, http.StatusOK)
	s := newTestUbuntuPushSender(t, ps)
	prevLoopback := netguard.AllowLoopback
	t.Cleanup(func() { netguard.AllowLoopback = prevLoopback })
	netguard.AllowLoopback = false
	err := s.SendPush(dev, ch)
	if err == nil || !strings.HasPrefix(err.Error(), "ubuntupush send failed") || !strings.Contains(err.Error(), "non-public") {
		t.Fatalf("guarded dial: %v", err)
	}
	if body, _ := ps.received(); body != nil {
		t.Fatal("the guard let a request through to loopback")
	}

	bad := NewUbuntuPushSender("http://bad host/notify", "app")
	if err := bad.SendPush(dev, ch); err == nil {
		t.Fatal("unparseable notify URL accepted")
	}
}

// The VAPID key file is refused when group/world readable, unparseable, or not a P-256
// scalar; a refused key never yields a sender.
func TestUnifiedPushVAPIDKeyFileRefusals(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	zero := strings.Repeat("A", 43) // 32 zero bytes: not a valid P-256 private scalar
	for name, path := range map[string]string{
		"world readable": write("open.key", zero, 0o644),
		"not base64":     write("garbage.key", "not*base64", 0o600),
		"zero scalar":    write("zero.key", zero, 0o600),
		"parent is file": filepath.Join(write("plain", "", 0o600), "vapid.key"),
	} {
		if s, err := NewUnifiedPushSender(path, "https://id.example.com"); s != nil || err == nil {
			t.Errorf("%s: sender=%v err=%v", name, s, err)
		}
	}
	if os.Geteuid() != 0 {
		unreadable := write("unreadable.key", zero, 0o000)
		if _, err := NewUnifiedPushSender(unreadable, "https://id.example.com"); err == nil {
			t.Error("unreadable key accepted")
		}
	}
}
