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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
)

var ErrStalePushToken = errors.New("push token is stale")

// errKeySuperseded is the relay's 401 for a key a later /register from our address replaced.
var errKeySuperseded = errors.New("push relay key superseded")

const relayResponseLimit = 2048

type RelayConfig struct {
	URL     string
	Key     string
	KeyFile string
	Label   string
}

type RelaySender struct {
	fcm    *relayEndpoint
	apns   *relayEndpoint
	client *http.Client
}

type relayEndpoint struct {
	url     string
	label   string
	keyFile string
	// renewable is false for an operator-supplied key, which re-registering would discard.
	renewable bool

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
	e := &relayEndpoint{url: cfg.URL, label: cfg.Label, keyFile: cfg.KeyFile, key: cfg.Key, renewable: cfg.Key == ""}
	if e.key != "" {
		return e, nil
	}
	if cfg.KeyFile != "" {
		key, err := os.ReadFile(cfg.KeyFile)
		if err == nil && strings.TrimSpace(string(key)) != "" {
			e.key = strings.TrimSpace(string(key))
			return e, nil
		}
	}
	key, err := registerRelayKey(cfg.URL, cfg.Label)
	if err != nil {
		return nil, err
	}
	if cfg.KeyFile != "" {
		if err := writeRelayKey(cfg.KeyFile, key); err != nil {
			return nil, err
		}
	}
	e.key = key
	return e, nil
}

// writeRelayKey replaces path through a synced temp file and a rename, so a crash never
// leaves a truncated key.
func writeRelayKey(path, key string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".push-relay-*") // mode 0600
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.WriteString(key + "\n")
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (e *relayEndpoint) currentKey() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.key
}

// renew replaces a superseded key once. Senders that saw the same stale key wait here and
// reuse the winner's key; each registering would supersede the last.
func (e *relayEndpoint) renew(stale string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.key != stale {
		return e.key, nil
	}
	key, err := registerRelayKey(e.url, e.label)
	if err != nil {
		return "", err
	}
	// The relay already revoked the old key, so keep the new one even if persisting fails.
	e.key = key
	if e.keyFile != "" {
		if err := writeRelayKey(e.keyFile, key); err != nil {
			log.Printf("mfa push relay: persist renewed key: %v", err)
		}
	}
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
		plain, err := json.Marshal(data)
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
	if !errors.Is(err, errKeySuperseded) || !endpoint.renewable {
		return err
	}
	if key, err = endpoint.renew(key); err != nil {
		return fmt.Errorf("push relay key superseded, re-registration failed: %w", err)
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
	if resp.StatusCode == http.StatusUnauthorized && parsed.Code == "key_superseded" {
		return fmt.Errorf("%w requestId=%s", errKeySuperseded, requestID)
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
