package mfa

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

var ErrStalePushToken = errors.New("push token is stale")

// errKeyRenewable is the relay's 401 for a key it no longer honours but that we may replace by
// registering again: one a later /register from our address superseded (key_superseded), or
// one the relay has no record of (key_unknown). A revoked key gets a plain 401 and stays refused.
var errKeyRenewable = errors.New("push relay key superseded or unknown")

const relayResponseLimit = 2048

type RelayConfig struct {
	URL string
	Key string
	// KeyFile names the key: its base name is the row in Keys. A file found there (an
	// install from before the key moved to the database, or a restored capsule) is copied
	// into Keys when Keys has none.
	KeyFile string
	// Keys holds the self-registered key, sealed under SealKey. Nil keeps it in memory only.
	Keys    RelayKeys
	SealKey []byte
	Label   string
	// Optional leaves this transport off when self-registration fails, instead of failing
	// startup. For the built-in relays, whose outage must not stop the server.
	Optional bool
}

// RelayKeys is the shared home of self-registered relay keys: the database, so every
// replica presents the same key and exactly one of them registers a new one.
// store.Store implements it.
type RelayKeys interface {
	RelayKey(name string) (sealed string, version int64, err error)
	SetRelayKey(name, sealed string, version int64) (bool, error)
	AcquireLease(name string, ttl time.Duration) (release func(), ok bool, err error)
}

// A registration is one HTTP call with a 10 s timeout; the lease outlives it, and a
// replica that did not get the lease waits a little longer than that for the key.
var (
	relayRegisterLease = 30 * time.Second
	relayRegisterWait  = 15 * time.Second
	relayRegisterPoll  = 250 * time.Millisecond
)

type RelaySender struct {
	fcm    *relayEndpoint
	apns   *relayEndpoint
	client *http.Client
}

type relayEndpoint struct {
	url   string
	label string
	// renewable is false for an operator-supplied key, which re-registering would discard.
	renewable bool
	keys      RelayKeys
	name      string
	sealKey   []byte

	mu  sync.Mutex
	key string
}

type relayRegisterResponse struct {
	Key string `json:"key"`
}

type relaySendResponse struct {
	OK        bool   `json:"ok"`
	Stale     bool   `json:"stale"`
	Error     string `json:"error"`
	Code      string `json:"code"`
	RequestID string `json:"requestId"`
}

func NewRelaySender(fcm, apns RelayConfig) (*RelaySender, error) {
	fcmEndpoint, err := prepareRelay(fcm)
	if err != nil {
		return nil, err
	}
	apnsEndpoint, err := prepareRelay(apns)
	if err != nil {
		return nil, err
	}
	if fcmEndpoint == nil && apnsEndpoint == nil {
		return nil, nil
	}
	return &RelaySender{
		fcm:    fcmEndpoint,
		apns:   apnsEndpoint,
		client: &http.Client{Timeout: 5 * time.Second},
	}, nil
}

func prepareRelay(cfg RelayConfig) (*relayEndpoint, error) {
	if cfg.URL == "" {
		return nil, nil
	}
	e := &relayEndpoint{url: cfg.URL, label: cfg.Label, key: cfg.Key, renewable: cfg.Key == "", sealKey: cfg.SealKey}
	if e.key != "" {
		return e, nil
	}
	if cfg.Keys != nil && cfg.KeyFile != "" {
		e.keys, e.name = cfg.Keys, filepath.Base(cfg.KeyFile)
		if err := e.importKeyFile(cfg.KeyFile); err != nil && !errors.Is(err, errStoredFirst) {
			return nil, err
		}
	}
	key, err := e.register("")
	if err != nil {
		if cfg.Optional {
			log.Printf("mfa push relay: %s unavailable, push over it stays off until restart: %v", cfg.URL, err)
			return nil, nil
		}
		return nil, err
	}
	e.key = key
	return e, nil
}

// importKeyFile copies a key file into Keys when Keys has none: an install from before the
// key moved to the database, or a restored capsule. A stored key always wins, so the file,
// which nothing updates any more, is left alone.
func (e *relayEndpoint) importKeyFile(path string) error {
	raw, err := os.ReadFile(path)
	key := strings.TrimSpace(string(raw))
	if err != nil || key == "" {
		return nil // as before the database: an unreadable file means register afresh
	}
	if sealed, _, err := e.keys.RelayKey(e.name); err != nil || sealed != "" {
		return err
	}
	return e.store(key, 0)
}

// RelayKeyFile is where a self-registered key for relayURL was kept, and whose base name
// still names it: one per relay host, so a server moved to another relay registers there
// instead of presenting the old relay's key, which the new one refuses with the plain 401
// a revocation gets (never re-registered).
func RelayKeyFile(dataDir, transport, relayURL string) string {
	host := ""
	if u, err := url.Parse(relayURL); err == nil {
		host = strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' {
				return r
			}
			return '_'
		}, strings.ToLower(u.Hostname()))
	}
	if host == "" {
		return filepath.Join(dataDir, "push-relay-"+transport+".key")
	}
	return filepath.Join(dataDir, "push-relay-"+transport+"-"+host+".key")
}

// stored is the shared key and its version; "" when there is none.
func (e *relayEndpoint) stored() (string, int64, error) {
	if e.keys == nil {
		return "", 0, nil
	}
	sealed, version, err := e.keys.RelayKey(e.name)
	if err != nil || sealed == "" {
		return "", version, err
	}
	key, err := crypto.Open(e.sealKey, store.SealRelayKey, e.name, sealed)
	if err != nil {
		return "", 0, fmt.Errorf("stored push relay key %s does not open: %w", e.name, err)
	}
	return string(key), version, nil
}

func (e *relayEndpoint) store(key string, version int64) error {
	if e.keys == nil {
		return nil
	}
	sealed, err := crypto.Seal(e.sealKey, store.SealRelayKey, e.name, []byte(key))
	if err != nil {
		return err
	}
	if ok, err := e.keys.SetRelayKey(e.name, sealed, version); err != nil {
		return err
	} else if !ok {
		return errStoredFirst
	}
	return nil
}

var errStoredFirst = errors.New("another replica stored a push relay key first")

// register returns a key to use in place of stale ("" at first start). Registering makes
// the relay drop the previous key for this address, so replicas that each registered would
// knock each other out for good: one registers under a lease and stores the key, the
// others take the stored one.
func (e *relayEndpoint) register(stale string) (string, error) {
	deadline := time.Now().Add(relayRegisterWait)
	for {
		key, done, err := e.registerOnce(stale)
		if err != nil || done {
			return key, err
		}
		if time.Now().After(deadline) {
			return "", errors.New("another replica holds the push relay registration and stored no key")
		}
		time.Sleep(relayRegisterPoll)
	}
}

// registerOnce reports done=false when another replica is registering right now.
func (e *relayEndpoint) registerOnce(stale string) (key string, done bool, err error) {
	if key, _, err = e.stored(); err != nil || (key != "" && key != stale) {
		return key, true, err
	}
	release := func() {}
	if e.keys != nil {
		var ok bool
		if release, ok, err = e.keys.AcquireLease("relay-register:"+e.name, relayRegisterLease); err != nil || !ok {
			return "", false, err
		}
	}
	defer release()
	// The previous holder may have stored its key between the read and the lease.
	key, version, err := e.stored()
	if err != nil || (key != "" && key != stale) {
		return key, true, err
	}
	if key, err = registerRelayKey(e.url, e.label); err != nil {
		return "", true, err
	}
	switch err = e.store(key, version); {
	case errors.Is(err, errStoredFirst):
		return "", false, nil // our lease ran out mid-registration; take the newer key
	case err != nil && stale == "":
		// At first start an unstored key would be registered again, and supersede this
		// one, on every restart.
		return "", true, err
	case err != nil:
		// The relay already dropped the old key, so use the new one even though it is not stored.
		log.Printf("mfa push relay: store renewed key: %v", err)
	}
	return key, true, nil
}

func (e *relayEndpoint) currentKey() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.key
}

// renew replaces a superseded or unknown key once. Senders that saw the same stale key wait
// here and reuse the winner's key; each registering would supersede the last.
func (e *relayEndpoint) renew(stale string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.key != stale {
		return e.key, nil
	}
	key, err := e.register(stale)
	if err != nil {
		return "", err
	}
	e.key = key
	return key, nil
}

func registerRelayKey(relayURL, label string) (string, error) {
	body, _ := json.Marshal(map[string]string{"label": label})
	req, err := http.NewRequest(http.MethodPost, relayURL+"/register", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("relay registration failed: %s", resp.Status)
	}
	var parsed relayRegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", err
	}
	if parsed.Key == "" {
		return "", errors.New("relay registration response did not include a key")
	}
	return parsed.Key, nil
}

const (
	pushTitle = "Sign-in request"
	pushBody  = "Open KyAuth to review."
)

// challengeData is the push payload every transport carries. The browser displays the
// number and the authenticator asks the user to enter it, so neither the answer nor decoys
// belong here.
func challengeData(dev store.NativeDevice, ch MFAChallengePush) map[string]string {
	return map[string]string{
		"type":             "mfa_challenge",
		"title":            pushTitle,
		"body":             pushBody,
		"challengeId":      ch.ChallengeID,
		"deviceId":         dev.ID,
		"deviceUserId":     dev.UserID,
		"purpose":          ch.Purpose,
		"expiresAtEpochMs": strconv.FormatInt(ch.ExpiresAtMS, 10),
		"devicePlatform":   dev.Platform,
	}
}

// sealedChallenge is the plaintext of a sealed push: challengeData plus the account's
// username. The username goes only here, never in challengeData, because an unsealed push
// crosses the relay and the push provider readable. One that would not fit a record of
// recordSize is left out and logged rather than overflowing it; the authenticator then shows
// the username saved at pairing.
func sealedChallenge(dev store.NativeDevice, ch MFAChallengePush, recordSize int) ([]byte, error) {
	data := challengeData(dev, ch)
	plain, err := json.Marshal(data)
	if err != nil || ch.Username == "" {
		return plain, err
	}
	data["username"] = ch.Username
	named, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	if len(named) > maxRecordPlaintext(recordSize) {
		log.Printf("mfa push: username left out of challenge %s for device %s: %d bytes do not fit a %d-byte record", ch.ChallengeID, dev.ID, len(named), recordSize)
		return plain, nil
	}
	return named, nil
}

// relayRecordSize pads every sealed relay payload to 86+640 bytes, 968 base64url characters:
// under the relay's 1024-character cap on one data value (MAX_DATA_VALUE_LENGTH), past which
// it truncates.
const relayRecordSize = 640

func (s *RelaySender) SendPush(dev store.NativeDevice, ch MFAChallengePush) error {
	endpoint, err := s.endpointFor(dev.Platform)
	if err != nil {
		return err
	}
	if endpoint == nil {
		return nil
	}
	data := challengeData(dev, ch)
	if dev.PushP256dh != "" {
		// The relay and the push provider then see only this ciphertext and the fixed alert.
		plain, err := sealedChallenge(dev, ch, relayRecordSize)
		if err != nil {
			return err
		}
		sealed, err := webPushEncrypt(plain, dev.PushP256dh, dev.PushAuth, relayRecordSize)
		if err != nil {
			return fmt.Errorf("relay push encrypt: %w", err)
		}
		data = map[string]string{"type": "mfa_challenge", "kyauth": base64.RawURLEncoding.EncodeToString(sealed)}
	}
	body, _ := json.Marshal(map[string]any{
		"token":    dev.PushToken,
		"title":    pushTitle,
		"body":     pushBody,
		"platform": dev.Platform,
		"data":     data,
	})
	key := endpoint.currentKey()
	err = s.send(endpoint.url, key, body, dev)
	if !errors.Is(err, errKeyRenewable) || !endpoint.renewable {
		return err
	}
	if key, err = endpoint.renew(key); err != nil {
		return fmt.Errorf("push relay key superseded or unknown, re-registration failed: %w", err)
	}
	return s.send(endpoint.url, key, body, dev)
}

func (s *RelaySender) send(url, key string, body []byte, dev store.NativeDevice) error {
	req, err := http.NewRequest(http.MethodPost, url+"/send", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, relayResponseLimit))
	responseText := strings.TrimSpace(string(responseBody))
	requestID := resp.Header.Get("X-Request-Id")
	var parsed relaySendResponse
	if responseText != "" {
		_ = json.Unmarshal(responseBody, &parsed)
	}
	if parsed.RequestID != "" {
		requestID = parsed.RequestID
	}
	if resp.StatusCode == http.StatusOK && parsed.OK {
		if requestID != "" {
			log.Printf("mfa push relay: relay accepted device %s platform %s requestId=%s", dev.ID, dev.Platform, requestID)
		}
		return nil
	}
	if resp.StatusCode == http.StatusGone {
		return ErrStalePushToken
	}
	if resp.StatusCode == http.StatusUnauthorized && (parsed.Code == "key_superseded" || parsed.Code == "key_unknown") {
		return fmt.Errorf("%w (%s) requestId=%s", errKeyRenewable, parsed.Code, requestID)
	}
	if resp.StatusCode == http.StatusOK {
		return fmt.Errorf("push relay send returned %s without ok=true body=%q requestId=%s", resp.Status, responseText, requestID)
	}
	return fmt.Errorf("push relay send failed: %s body=%q requestId=%s", resp.Status, responseText, requestID)
}

func (s *RelaySender) endpointFor(platform string) (*relayEndpoint, error) {
	switch platform {
	case "", "android":
		return s.fcm, nil
	case "ios", "macos":
		return s.apns, nil
	default:
		return nil, fmt.Errorf("unsupported push platform %q", platform)
	}
}
