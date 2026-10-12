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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/netguard"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

const (
	// ubuntuPushRecordSize pads every message to one fixed RFC 8188 record. Its base64 inside
	// the notification stays under ubuntuPushMaxData.
	ubuntuPushRecordSize = 2048
	// ubuntuPushMaxData is lomiri-push-service's MaxUnicastPayload for the serialized data.
	ubuntuPushMaxData = 4096
)

// ubuntuPushNotification is fixed text: it carries no user, server or challenge details.
var ubuntuPushNotification = map[string]any{
	"tag": "kyauth-mfa",
	"card": map[string]any{
		"summary": "Sign-in request",
		"body":    "Open KyAuth to approve or deny.",
		"popup":   true,
		"persist": true,
	},
	"vibrate": true,
	"sound":   true,
}

// UbuntuPushSender posts RFC 8291 encrypted challenges to the UBports (Lomiri) push service.
// The service sees only ciphertext, the token and the timing.
type UbuntuPushSender struct {
	client *http.Client
	url    string
	appID  string
}

// NewUbuntuPushSender sends to notifyURL as appID; both are validated configuration.
func NewUbuntuPushSender(notifyURL, appID string) *UbuntuPushSender {
	return &UbuntuPushSender{client: netguard.Client(5 * time.Second), url: notifyURL, appID: appID}
}

func (s *UbuntuPushSender) SendPush(dev store.NativeDevice, ch MFAChallengePush) error {
	plain, err := json.Marshal(challengeData(dev, ch))
	if err != nil {
		return err
	}
	sealed, err := webPushEncrypt(plain, dev.PushP256dh, dev.PushAuth, ubuntuPushRecordSize)
	if err != nil {
		return fmt.Errorf("ubuntupush encrypt: %w", err)
	}
	data, err := json.Marshal(map[string]any{
		"message":      map[string]string{"kyauth": base64.RawURLEncoding.EncodeToString(sealed)},
		"notification": ubuntuPushNotification,
	})
	if err != nil {
		return err
	}
	if len(data) > ubuntuPushMaxData {
		return fmt.Errorf("ubuntupush data is %d bytes, over %d", len(data), ubuntuPushMaxData)
	}
	body, err := json.Marshal(struct {
		AppID    string          `json:"appid"`
		Token    string          `json:"token"`
		ExpireOn string          `json:"expire_on"`
		Data     json.RawMessage `json:"data"`
	}{s.appID, dev.PushToken, time.UnixMilli(ch.ExpiresAtMS).UTC().Format(time.RFC3339), data})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("ubuntupush send failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	var apiErr struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, relayResponseLimit)).Decode(&apiErr)
	// lomiri-push-service server/api/handlers.go: ErrUnknownToken. "unauthorized" means the
	// token belongs to another appid, a configuration fault, so it does not clear the target.
	if resp.StatusCode == http.StatusBadRequest && apiErr.Error == "unknown-token" {
		return ErrStalePushToken
	}
	return fmt.Errorf("ubuntupush send failed: %s %q", resp.Status, apiErr.Error)
}

// webPushEncrypt seals plaintext for the device keys as one RFC 8291 aes128gcm record of
// exactly recordSize bytes.
func webPushEncrypt(plaintext []byte, p256dh, auth string, recordSize int) ([]byte, error) {
	pub, err := decodeBase64URL(p256dh)
	if err != nil {
		return nil, err
	}
	ua, err := ecdh.P256().NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	secret, err := decodeBase64URL(auth)
	if err != nil || len(secret) != 16 {
		return nil, errInvalidPushTarget
	}
	pad := recordSize - 16 - 1 - len(plaintext) // tag, delimiter
	if pad < 0 {
		return nil, errors.New("payload does not fit one record")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	as, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return sealAES128GCM(plaintext, ua, secret, salt, as, uint32(recordSize), pad)
}

// sealAES128GCM is RFC 8291 section 3.4 over RFC 8188, single record, with pad zero bytes
// after the last-record delimiter. Split from webPushEncrypt so the RFC 8291 vector can fix
// the salt and sender key.
func sealAES128GCM(plaintext []byte, ua *ecdh.PublicKey, auth, salt []byte, as *ecdh.PrivateKey, rs uint32, pad int) ([]byte, error) {
	shared, err := as.ECDH(ua)
	if err != nil {
		return nil, err
	}
	asPublic := as.PublicKey().Bytes()
	ikm, err := hkdf.Key(sha256.New, shared, auth, "WebPush: info\x00"+string(ua.Bytes())+string(asPublic), 32)
	if err != nil {
		return nil, err
	}
	cek, err := hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: aes128gcm\x00", 16)
	if err != nil {
		return nil, err
	}
	nonce, err := hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: nonce\x00", 12)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	header := append([]byte{}, salt...)
	header = binary.BigEndian.AppendUint32(header, rs)
	header = append(header, byte(len(asPublic)))
	header = append(header, asPublic...)
	record := append(append(append([]byte{}, plaintext...), 2), make([]byte, pad)...) // 2: last-record delimiter
	return gcm.Seal(header, nonce, record, nil), nil
}
