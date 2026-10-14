package mfa

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/netguard"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// pushServer is a TLS UnifiedPush endpoint that records what it was sent.
type pushServer struct {
	*httptest.Server
	mu      sync.Mutex
	status  int
	reply   string
	target  string // method and request URI
	body    []byte
	headers http.Header
}

func newPushServer(t *testing.T, status int) *pushServer {
	t.Helper()
	allow := netguard.AllowLoopback
	netguard.AllowLoopback = true
	t.Cleanup(func() { netguard.AllowLoopback = allow })
	ps := &pushServer{status: status}
	ps.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ps.mu.Lock()
		ps.body, ps.headers, ps.target = body, r.Header.Clone(), r.Method+" "+r.URL.RequestURI()
		status, reply := ps.status, ps.reply
		ps.mu.Unlock()
		w.WriteHeader(status)
		_, _ = io.WriteString(w, reply)
	}))
	t.Cleanup(ps.Close)
	return ps
}

func (ps *pushServer) received() ([]byte, http.Header) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.body, ps.headers
}

// newTestUnifiedPushSender keeps the netguard client and only trusts the test certificate.
func newTestUnifiedPushSender(t *testing.T, ps *pushServer) *UnifiedPushSender {
	t.Helper()
	s, err := NewUnifiedPushSender(filepath.Join(t.TempDir(), "vapid.key"), "https://id.example.com")
	if err != nil {
		t.Fatal(err)
	}
	s.client.Transport.(*http.Transport).TLSClientConfig = ps.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	return s
}

type receiverKeys struct {
	priv        *ecdh.PrivateKey
	auth        []byte
	p256dh, a64 string
}

func newReceiver(t *testing.T) receiverKeys {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth := make([]byte, 16)
	if _, err := rand.Read(auth); err != nil {
		t.Fatal(err)
	}
	return receiverKeys{priv, auth, base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()), base64.RawURLEncoding.EncodeToString(auth)}
}

// decryptRFC8291 opens an aes128gcm Web Push body, written from RFC 8291 section 3.4 and
// RFC 8188 rather than from the sender's library.
func decryptRFC8291(t *testing.T, rk receiverKeys, body []byte) []byte {
	t.Helper()
	if len(body) < 21 {
		t.Fatalf("body too short: %d", len(body))
	}
	salt, rs, idlen := body[:16], binary.BigEndian.Uint32(body[16:20]), int(body[20])
	if idlen != 65 || rs < 18 {
		t.Fatalf("header idlen=%d rs=%d", idlen, rs)
	}
	asPublic, ciphertext := body[21:21+idlen], body[21+idlen:]
	if len(ciphertext) > int(rs) {
		t.Fatalf("more than one record: %d > %d", len(ciphertext), rs)
	}
	as, err := ecdh.P256().NewPublicKey(asPublic)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := rk.priv.ECDH(as)
	if err != nil {
		t.Fatal(err)
	}
	prkKey, _ := hkdf.Extract(sha256.New, secret, rk.auth)
	keyInfo := "WebPush: info\x00" + string(rk.priv.PublicKey().Bytes()) + string(asPublic)
	ikm, _ := hkdf.Expand(sha256.New, prkKey, keyInfo, 32)
	prk, _ := hkdf.Extract(sha256.New, ikm, salt)
	cek, _ := hkdf.Expand(sha256.New, prk, "Content-Encoding: aes128gcm\x00", 16)
	nonce, _ := hkdf.Expand(sha256.New, prk, "Content-Encoding: nonce\x00", 12)
	block, _ := aes.NewCipher(cek)
	gcm, _ := cipher.NewGCM(block)
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	plain = bytes.TrimRight(plain, "\x00")
	if len(plain) == 0 || plain[len(plain)-1] != 2 { // last-record delimiter
		t.Fatalf("missing last-record delimiter")
	}
	return plain[:len(plain)-1]
}

func TestUnifiedPushSenderEncryptsChallenge(t *testing.T) {
	ps := newPushServer(t, http.StatusCreated)
	s := newTestUnifiedPushSender(t, ps)
	rk := newReceiver(t)
	dev := store.NativeDevice{
		ID: "dev1", UserID: "u1", Platform: "android", PushTransport: "unifiedpush",
		PushToken: ps.URL + "/upAbC123?up=1", PushP256dh: rk.p256dh, PushAuth: rk.a64,
	}
	expires := time.Now().Add(90 * time.Second).UnixMilli()
	if err := s.SendPush(dev, MFAChallengePush{ChallengeID: "ch1", Purpose: "login", ExpiresAtMS: expires}); err != nil {
		t.Fatal(err)
	}

	body, h := ps.received()
	if h.Get("Content-Encoding") != "aes128gcm" || h.Get("Urgency") != "high" {
		t.Fatalf("headers = %v", h)
	}
	if ttl := h.Get("TTL"); ttl != "90" && ttl != "89" {
		t.Fatalf("TTL = %q, want the challenge's remaining seconds", ttl)
	}
	if auth := h.Get("Authorization"); !strings.HasPrefix(auth, "vapid t=") || !strings.HasSuffix(auth, ", k="+s.vapidPublic) {
		t.Fatalf("Authorization = %q", auth)
	}
	if bytes.Contains(body, []byte("ch1")) {
		t.Fatal("challenge id visible to the distributor")
	}
	var got map[string]string
	if err := json.Unmarshal(decryptRFC8291(t, rk, body), &got); err != nil {
		t.Fatal(err)
	}
	// Spelled out, not built with challengeData: KyAuth's parser needs every one of these.
	want := map[string]string{
		"type": "mfa_challenge", "title": "Sign-in request", "body": "Open KyAuth to review.",
		"challengeId": "ch1", "deviceId": "dev1", "deviceUserId": "u1", "purpose": "login",
		"expiresAtEpochMs": strconv.FormatInt(expires, 10), "devicePlatform": "android",
	}
	if len(got) != len(want) {
		t.Fatalf("payload = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("payload[%s] = %q, want %q", k, got[k], v)
		}
	}
	if got["type"] != "mfa_challenge" || got["deviceId"] != "dev1" {
		t.Fatalf("payload = %v", got)
	}
}

func TestUnifiedPushSenderResponses(t *testing.T) {
	rk := newReceiver(t)
	for _, tc := range []struct {
		status int
		stale  bool
		ok     bool
	}{
		{http.StatusCreated, false, true},
		{http.StatusNotFound, true, false},
		{http.StatusGone, true, false},
		{http.StatusTooManyRequests, false, false},
		{http.StatusInternalServerError, false, false},
	} {
		ps := newPushServer(t, tc.status)
		s := newTestUnifiedPushSender(t, ps)
		dev := store.NativeDevice{ID: "d", PushToken: ps.URL + "/secret-topic", PushP256dh: rk.p256dh, PushAuth: rk.a64}
		err := s.SendPush(dev, MFAChallengePush{ChallengeID: "c", Purpose: "login", ExpiresAtMS: time.Now().UnixMilli() - 1000})
		if tc.ok != (err == nil) || tc.stale != (err == ErrStalePushToken) {
			t.Errorf("status %d: err = %v", tc.status, err)
		}
		if _, h := ps.received(); h.Get("TTL") != "1" {
			t.Errorf("expired challenge TTL = %q, want 1", h.Get("TTL"))
		}
	}
}

// The sender dials through the device guard, which AllowPrivate does not open, and its
// errors never carry the capability URL.
func TestUnifiedPushSenderRefusesPrivateDialWithoutLeakingEndpoint(t *testing.T) {
	ps := newPushServer(t, http.StatusCreated)
	s := newTestUnifiedPushSender(t, ps)
	netguard.AllowLoopback, netguard.AllowPrivate = false, true
	t.Cleanup(func() { netguard.AllowPrivate = false })
	rk := newReceiver(t)
	dev := store.NativeDevice{ID: "d", PushToken: ps.URL + "/secret-topic", PushP256dh: rk.p256dh, PushAuth: rk.a64}
	err := s.SendPush(dev, MFAChallengePush{ChallengeID: "c", Purpose: "login", ExpiresAtMS: time.Now().Add(time.Minute).UnixMilli()})
	if err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Fatalf("err = %v, want a refused private dial", err)
	}
	if strings.Contains(err.Error(), "secret-topic") {
		t.Fatalf("error leaks the endpoint: %v", err)
	}
	if body, _ := ps.received(); body != nil {
		t.Fatal("request reached the private endpoint")
	}
}

func TestUnifiedPushSenderRequiresKeys(t *testing.T) {
	ps := newPushServer(t, http.StatusCreated)
	s := newTestUnifiedPushSender(t, ps)
	if err := s.SendPush(store.NativeDevice{ID: "d", PushToken: ps.URL}, MFAChallengePush{ChallengeID: "c", Purpose: "login"}); err == nil {
		t.Fatal("sent without encryption keys")
	}
	if body, _ := ps.received(); body != nil {
		t.Fatal("a plaintext request was made")
	}
}

func TestVAPIDKeyIsCreatedOnceWithPrivateMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "push-vapid-private.key")
	priv, pub, err := loadOrCreateVAPIDKey(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %v, want 0600", info.Mode().Perm())
	}
	priv2, pub2, err := loadOrCreateVAPIDKey(path)
	if err != nil || priv2 != priv || pub2 != pub {
		t.Fatalf("reload changed the key: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}
	if err := os.WriteFile(path, []byte("garbage\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadOrCreateVAPIDKey(path); err == nil {
		t.Fatal("a corrupt key was accepted")
	}
}

func registerTestDevice(t *testing.T, e *Engine, userID, ident string, req NativeDeviceRegisterRequest) *store.NativeDevice {
	t.Helper()
	token, _, _, err := e.GenerateDevicePairingToken(userID, true)
	if err != nil {
		t.Fatal(err)
	}
	_, pub := signingKey(t)
	req.PairingToken, req.DeviceName, req.DeviceIdentifier, req.PublicKey = token, ident, ident, pub
	dev, err := e.RegisterNativeDevice(&req)
	if err != nil {
		t.Fatal(err)
	}
	return dev
}

func TestDispatchRoutesByTransport(t *testing.T) {
	e, db, _, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	u := mfaUser(t, db)
	rk := newReceiver(t)
	fcmDev := registerTestDevice(t, e, u.ID, "fcm-phone", NativeDeviceRegisterRequest{PushToken: "fcm-token"})
	upDev := registerTestDevice(t, e, u.ID, "up-phone", NativeDeviceRegisterRequest{
		PushTransport: "unifiedpush", PushToken: "https://push.example.net/up1", PushP256dh: rk.p256dh, PushAuth: rk.a64,
	})

	// No FCM relay configured: UnifiedPush still delivers.
	up := &fakePushSender{}
	e.SetUnifiedPushSender(up)
	if _, err := e.CreatePushChallenge(u.ID, "login"); err != nil {
		t.Fatal(err)
	}
	if len(up.sent) != 1 || up.sent[0].ID != upDev.ID || up.sent[0].PushP256dh != rk.p256dh || up.sent[0].PushAuth != rk.a64 {
		t.Fatalf("unifiedpush sends = %+v", up.sent)
	}

	fcm := &fakePushSender{}
	e.SetPushSender(fcm)
	up.sent = nil
	if _, err := e.CreatePushChallenge(u.ID, "login"); err != nil {
		t.Fatal(err)
	}
	if len(fcm.sent) != 1 || fcm.sent[0].ID != fcmDev.ID || len(up.sent) != 1 || up.sent[0].ID != upDev.ID {
		t.Fatalf("fcm sends = %+v, unifiedpush sends = %+v", fcm.sent, up.sent)
	}
}

func TestGoneUnifiedPushEndpointIsCleared(t *testing.T) {
	e, db, _, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	u := mfaUser(t, db)
	ps := newPushServer(t, http.StatusGone)
	rk := newReceiver(t)
	dev := registerTestDevice(t, e, u.ID, "up-phone", NativeDeviceRegisterRequest{
		PushTransport: "unifiedpush", PushToken: ps.URL + "/up1", PushP256dh: rk.p256dh, PushAuth: rk.a64,
	})
	e.SetUnifiedPushSender(newTestUnifiedPushSender(t, ps))
	if _, err := e.CreatePushChallenge(u.ID, "login"); err != nil {
		t.Fatal(err)
	}
	if body, _ := ps.received(); body == nil {
		t.Fatal("endpoint was not contacted")
	}
	stored, err := db.GetNativeDevice(dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.PushToken != "" || stored.PushP256dh != "" || stored.PushAuth != "" || !stored.IsMFAApprover {
		t.Fatalf("stored device = %+v", stored)
	}
}
