package mfa

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/netguard"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	webpush "github.com/SherClockHolmes/webpush-go"
)

// UnifiedPushSender posts RFC 8291 encrypted Web Push straight to a device's UnifiedPush
// endpoint. There is no plaintext path: a device without keys is refused at registration.
type UnifiedPushSender struct {
	client       *http.Client
	subscriber   string
	vapidPublic  string
	vapidPrivate string
}

// NewUnifiedPushSender loads the VAPID key at keyFile, creating it on first start.
// subscriber is the issuer origin, sent as the VAPID JWT subject.
func NewUnifiedPushSender(keyFile, subscriber string) (*UnifiedPushSender, error) {
	private, public, err := loadOrCreateVAPIDKey(keyFile)
	if err != nil {
		return nil, fmt.Errorf("vapid key %s: %w", keyFile, err)
	}
	return &UnifiedPushSender{
		client:       netguard.Client(5 * time.Second),
		subscriber:   subscriber,
		vapidPublic:  public,
		vapidPrivate: private,
	}, nil
}

func (s *UnifiedPushSender) SendPush(dev store.NativeDevice, ch MFAChallengePush) error {
	if dev.PushP256dh == "" || dev.PushAuth == "" {
		return errors.New("unifiedpush device has no encryption keys")
	}
	body, err := json.Marshal(challengeData(dev, ch))
	if err != nil {
		return err
	}
	ttl := int((time.Until(time.UnixMilli(ch.ExpiresAtMS)) + time.Second - 1) / time.Second)
	resp, err := webpush.SendNotificationWithContext(context.Background(), body, &webpush.Subscription{
		Endpoint: dev.PushToken,
		Keys:     webpush.Keys{P256dh: dev.PushP256dh, Auth: dev.PushAuth},
	}, &webpush.Options{
		HTTPClient:      s.client,
		Subscriber:      s.subscriber,
		VAPIDPublicKey:  s.vapidPublic,
		VAPIDPrivateKey: s.vapidPrivate,
		TTL:             max(ttl, 1),
		Urgency:         webpush.UrgencyHigh,
	})
	if err != nil {
		// url.Error names the endpoint, which is a capability URL; keep it out of logs.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("unifiedpush send failed: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		return ErrStalePushToken
	default:
		return fmt.Errorf("unifiedpush send failed: %s", resp.Status)
	}
}

// loadOrCreateVAPIDKey returns the base64url private scalar and uncompressed public key.
func loadOrCreateVAPIDKey(path string) (private, public string, err error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		raw, err = createVAPIDKey(path)
	}
	if err != nil {
		return "", "", err
	}
	private = strings.TrimSpace(string(raw))
	scalar, err := base64.RawURLEncoding.DecodeString(private)
	if err != nil {
		return "", "", err
	}
	key, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		return "", "", err
	}
	return private, base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

// createVAPIDKey writes a new key through a temp file and rename, so a run that dies
// halfway never leaves a truncated key at path.
func createVAPIDKey(path string) ([]byte, error) {
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	data := []byte(base64.RawURLEncoding.EncodeToString(key.Bytes()) + "\n")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".push-vapid-*") // mode 0600
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return nil, err
	}
	return data, nil
}
