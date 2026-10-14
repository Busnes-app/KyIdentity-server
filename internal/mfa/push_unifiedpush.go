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
	"strings"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
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
		// Padded to a fixed 2 KiB rather than 4 KiB, so a distributor that re-encodes the
		// body (FCM-backed ones base64 it) stays under its own 4 KiB limit.
		RecordSize: 2048,
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
	if err := createVAPIDKey(path); err != nil {
		return "", "", err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", "", err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", "", fmt.Errorf("permissions %v are too open; chmod 600 it", info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
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

// createVAPIDKey writes a key to path unless one exists; a concurrent first start that
// wins leaves its key, which the caller then reads.
func createVAPIDKey(path string) error {
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	err = crypto.CreateKeyFile(path, []byte(base64.RawURLEncoding.EncodeToString(key.Bytes())+"\n"))
	if errors.Is(err, fs.ErrExist) {
		return nil
	}
	return err
}
