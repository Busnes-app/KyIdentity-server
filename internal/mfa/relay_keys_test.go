package mfa

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

var relaySealKey = bytes.Repeat([]byte{9}, 32)

func relayKeyStore(t *testing.T) *store.Store {
	t.Helper()
	return openRelayKeyStore(t, filepath.Join(t.TempDir(), "relay.db"))
}

func openRelayKeyStore(t *testing.T, path string) *store.Store {
	t.Helper()
	s, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func sharedRelay(keys RelayKeys, url, keyFile string) RelayConfig {
	return RelayConfig{URL: url, KeyFile: keyFile, Keys: keys, SealKey: relaySealKey, Label: "test"}
}

// storedRelayKey opens the key stored for keyFile's name, or returns "".
func storedRelayKey(t *testing.T, keys RelayKeys, keyFile string) string {
	t.Helper()
	name := filepath.Base(keyFile)
	sealed, _, err := keys.RelayKey(name)
	if err != nil {
		t.Fatal(err)
	}
	if sealed == "" {
		return ""
	}
	if bytes.Contains([]byte(sealed), []byte("key")) {
		t.Fatalf("relay key stored unsealed: %q", sealed)
	}
	key, err := crypto.Open(relaySealKey, store.SealRelayKey, name, sealed)
	if err != nil {
		t.Fatal(err)
	}
	return string(key)
}

// brokenRelayKeys fails every store while fail is set.
type brokenRelayKeys struct {
	RelayKeys
	fail atomic.Bool
}

func (b *brokenRelayKeys) SetRelayKey(name, sealed string, version int64) (bool, error) {
	if b.fail.Load() {
		return false, errors.New("database is read-only")
	}
	return b.RelayKeys.SetRelayKey(name, sealed, version)
}

// evictingRelay behaves as the real relay does: each /register returns a new key and
// drops the one before it, and /send accepts only the newest.
func evictingRelay(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var registrations atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/register" {
			_, _ = io.WriteString(w, `{"key":"key-`+strconv.Itoa(int(registrations.Add(1)))+`"}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer key-"+strconv.Itoa(int(registrations.Load())) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"code":"key_superseded"}`)
			return
		}
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(srv.Close)
	return srv, &registrations
}

// Replicas are separate processes on one database. Each registering for itself would
// supersede the others' keys for good; they must end up presenting one key, registered once.
func TestReplicasShareOneRelayRegistration(t *testing.T) {
	srv, registrations := evictingRelay(t)
	db := filepath.Join(t.TempDir(), "relay.db")
	const replicas = 6
	stores := make([]*store.Store, replicas)
	for i := range stores {
		stores[i] = openRelayKeyStore(t, db)
	}
	senders := make([]*RelaySender, replicas)
	each := func(fn func(i int) error) {
		t.Helper()
		var wg sync.WaitGroup
		errs := make([]error, replicas)
		for i := range replicas {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[i] = fn(i)
			}()
		}
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("replica %d: %v", i, err)
			}
		}
	}
	send := func(i int) error {
		return senders[i].SendPush(relayTestDevice, MFAChallengePush{ChallengeID: "c"})
	}

	each(func(i int) (err error) {
		senders[i], err = NewRelaySender(sharedRelay(stores[i], srv.URL, "push-relay-fcm.key"), RelayConfig{})
		return err
	})
	if n := registrations.Load(); n != 1 {
		t.Fatalf("first start registered %d times, want 1", n)
	}
	each(send)

	// The relay drops the key (another server registered from this address): every
	// replica sees key_superseded at once and exactly one of them registers again.
	registrations.Add(1)
	each(send)
	if n := registrations.Load(); n != 3 {
		t.Fatalf("after one supersession the relay saw %d registrations in all, want 3 (ours, the stranger's, one renewal)", n)
	}
	for i, s := range senders {
		if got := s.fcm.currentKey(); got != "key-3" {
			t.Fatalf("replica %d presents %q, want key-3", i, got)
		}
	}
	each(send)
	if n := registrations.Load(); n != 3 {
		t.Fatalf("replicas kept re-registering: %d", n)
	}
}

// A key stored in the database wins over a leftover file; the file seeds an empty database.
func TestRelayKeyFileSeedsTheDatabaseOnce(t *testing.T) {
	srv, registrations := evictingRelay(t)
	registrations.Store(1) // the relay's current key is key-1
	keys, keyFile := relayKeyStore(t), filepath.Join(t.TempDir(), "push-relay-fcm.key")
	writeKey := func(k string) {
		t.Helper()
		if err := os.WriteFile(keyFile, []byte(k+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeKey("key-1")
	if _, err := NewRelaySender(sharedRelay(keys, srv.URL, keyFile), RelayConfig{}); err != nil {
		t.Fatal(err)
	}
	writeKey("stale")
	s, err := NewRelaySender(sharedRelay(keys, srv.URL, keyFile), RelayConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.fcm.currentKey(); got != "key-1" || registrations.Load() != 1 {
		t.Fatalf("key %q after %d registrations, want the stored key-1 and no new registration", got, registrations.Load())
	}
}
