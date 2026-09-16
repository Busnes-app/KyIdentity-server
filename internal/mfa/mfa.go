package mfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

type Engine struct {
	store         *store.Store
	encryptionKey []byte
	pushSender    PushSender
}

func NewEngine(s *store.Store, encryptionKey []byte) *Engine {
	return &Engine{
		store:         s,
		encryptionKey: encryptionKey,
	}
}

type PushSender interface {
	SendPush(dev store.NativeDevice, ch MFAChallengePush) error
}

type MFAChallengePush struct {
	ChallengeID string
}

func (e *Engine) SetPushSender(sender PushSender) {
	e.pushSender = sender
}

// GenerateTOTPSecret generates a random 20-byte base32 TOTP secret and returns an otpauth URL.
func (e *Engine) GenerateTOTPSecret(username, issuer string) (secretBase32, otpAuthURL string, err error) {
	b, err := crypto.GenerateRandomBytes(20)
	if err != nil {
		return "", "", err
	}
	secretBase32 = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	if issuer == "" {
		issuer = "KyIdentity"
	}

	uri := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		url.PathEscape(issuer),
		url.PathEscape(username),
		secretBase32,
		url.QueryEscape(issuer),
	)

	return secretBase32, uri, nil
}

// ValidateTOTP verifies a 6-digit TOTP code against a base32 secret with a +/- 1 step
// grace window.
func ValidateTOTP(secretBase32, code string) bool {
	_, ok := matchTOTP(secretBase32, code)
	return ok
}

// matchTOTP returns the time step a code belongs to, so the caller can spend that step and
// stop the same code being replayed inside its window.
func matchTOTP(secretBase32, code string) (int64, bool) {
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secretBase32)))
	if err != nil {
		return 0, false
	}

	currentCounter := time.Now().Unix() / 30
	trimmed := strings.TrimSpace(code)
	for i := int64(-1); i <= 1; i++ {
		counter := currentCounter + i
		if subtle.ConstantTimeCompare([]byte(calculateTOTPCode(secret, counter)), []byte(trimmed)) == 1 {
			return counter, true
		}
	}
	return 0, false
}

func calculateTOTPCode(secret []byte, counter int64) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(counter))

	h := hmac.New(sha1.New, secret)
	h.Write(buf)
	sum := h.Sum(nil)

	offset := sum[len(sum)-1] & 0x0F
	truncated := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7FFFFFFF
	codeInt := truncated % 1000000

	return fmt.Sprintf("%06d", codeInt)
}

// SaveUserTOTP encrypts and saves a user's TOTP secret.
func (e *Engine) SaveUserTOTP(userID, secretBase32 string, audit *store.AuditEvent) error {
	encrypted, err := crypto.EncryptAESGCM(e.encryptionKey, []byte(secretBase32))
	if err != nil {
		return fmt.Errorf("failed to encrypt TOTP secret: %w", err)
	}

	method := &store.MFAMethod{
		ID:              uuid.New().String(),
		UserID:          userID,
		MethodType:      "totp",
		EncryptedSecret: encrypted,
		IsPrimary:       true,
	}

	return e.store.SetMFAMethod(method, audit)
}

// VerifyUserTOTP verifies a TOTP code for an enrolled user.
func (e *Engine) VerifyUserTOTP(userID, code string) (bool, error) {
	method, err := e.store.GetMFAMethod(userID, "totp")
	if err != nil {
		return false, err
	}
	if method == nil || method.EncryptedSecret == "" {
		return false, errors.New("TOTP not enrolled for this user")
	}

	decrypted, err := crypto.DecryptAESGCM(e.encryptionKey, method.EncryptedSecret)
	if err != nil {
		return false, fmt.Errorf("failed to decrypt TOTP secret: %w", err)
	}

	counter, ok := matchTOTP(string(decrypted), code)
	if !ok {
		return false, nil
	}

	// Spend the time step. A code that is merely "correct" is still a replay if it has
	// already been used, and its window is up to 90 seconds wide.
	return e.store.ConsumeTOTPCounter(userID, counter)
}

// GenerateRecoveryCodes creates 8 one-time recovery codes for a user.
func (e *Engine) GenerateRecoveryCodes(userID string, audit *store.AuditEvent) ([]string, error) {
	var plainCodes []string
	var recoveryCodes []store.RecoveryCode

	for i := 0; i < 8; i++ {
		left, err := crypto.GenerateRandomAlphanumeric(4)
		if err != nil {
			return nil, err
		}
		right, err := crypto.GenerateRandomAlphanumeric(4)
		if err != nil {
			return nil, err
		}
		code := fmt.Sprintf("%s-%s", left, right)
		plainCodes = append(plainCodes, code)
		recoveryCodes = append(recoveryCodes, store.RecoveryCode{
			ID:       uuid.New().String(),
			UserID:   userID,
			CodeHash: crypto.HashSHA256(strings.ToUpper(strings.ReplaceAll(code, "-", ""))),
		})
	}

	if err := e.store.ReplaceRecoveryCodes(userID, recoveryCodes, audit); err != nil {
		return nil, err
	}

	return plainCodes, nil
}

// VerifyAndConsumeRecoveryCode validates and consumes a recovery code.
func (e *Engine) VerifyAndConsumeRecoveryCode(userID, code string) (bool, error) {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	codeHash := crypto.HashSHA256(normalized)

	return e.store.ConsumeRecoveryCode(userID, codeHash)
}

// GenerateDevicePairingToken generates a 90s ephemeral PIN & token for registering a native mobile device.
func (e *Engine) GenerateDevicePairingToken(userID string) (token string, pin string, expiresAt time.Time, err error) {
	rawToken, err := crypto.GenerateRandomHex(24)
	if err != nil {
		return "", "", time.Time{}, err
	}

	pin, err = crypto.GenerateRandomPIN(6)
	if err != nil {
		return "", "", time.Time{}, err
	}
	tokenHash := crypto.HashSHA256(rawToken)
	expiresAt = time.Now().UTC().Add(90 * time.Second)

	item := &store.DevicePairingToken{
		ID:        uuid.New().String(),
		UserID:    userID,
		TokenHash: tokenHash,
		PINHash:   crypto.HashSHA256(pin),
		ExpiresAt: expiresAt,
	}

	if err := e.store.CreateDevicePairingToken(item); err != nil {
		return "", "", time.Time{}, err
	}

	return rawToken, pin, expiresAt, nil
}

type NativeDeviceRegisterRequest struct {
	PairingToken     string `json:"pairingToken,omitempty"`
	PINCode          string `json:"pinCode,omitempty"`
	UserID           string `json:"userId,omitempty"`
	DeviceName       string `json:"deviceName"`
	DeviceIdentifier string `json:"deviceIdentifier"`
	Platform         string `json:"platform,omitempty"`
	PublicKey        string `json:"publicKey,omitempty"`
	PushToken        string `json:"pushToken,omitempty"`
}

// RegisterNativeDevice registers a device presented with a valid 90s pairing token, or a
// PIN scoped to the user who generated it.
//
// A device must present a usable P-256 public key. Pairing one without a key enrols push
// MFA that no response can ever satisfy, which locks the user out of every later login.
func (e *Engine) RegisterNativeDevice(req *NativeDeviceRegisterRequest) (*store.NativeDevice, error) {
	if req.PublicKey == "" {
		return nil, errors.New("a device public key is required to pair an authenticator")
	}
	if strings.TrimSpace(req.PushToken) == "" {
		return nil, errors.New("a push token is required to pair an authenticator")
	}
	if _, err := crypto.ParseP256PublicKey(req.PublicKey); err != nil {
		return nil, fmt.Errorf("device public key is not a valid P-256 key: %w", err)
	}

	var validToken *store.DevicePairingToken
	var err error

	switch {
	case req.PairingToken != "":
		validToken, err = e.store.GetValidDevicePairingToken(crypto.HashSHA256(req.PairingToken))
	case req.PINCode != "" && req.UserID != "":
		validToken, err = e.store.GetDevicePairingTokenByUserPIN(req.UserID, crypto.HashSHA256(req.PINCode))
	case req.PINCode != "":
		return nil, errors.New("a userId is required when pairing with a PIN")
	default:
		return nil, errors.New("pairingToken or pinCode is required")
	}

	if err != nil {
		return nil, err
	}
	if validToken == nil {
		return nil, errors.New("invalid or expired pairing token")
	}

	name := req.DeviceName
	if name == "" {
		name = "KySecurity Authenticator Device"
	}
	platform, err := normalizeDevicePlatform(req.Platform)
	if err != nil {
		return nil, err
	}

	device := &store.NativeDevice{
		ID:               uuid.New().String(),
		UserID:           validToken.UserID,
		DeviceName:       name,
		DeviceIdentifier: req.DeviceIdentifier,
		Platform:         platform,
		PublicKey:        req.PublicKey,
		PushToken:        strings.TrimSpace(req.PushToken),
		IsMFAApprover:    true, // Enrolled devices are default approvers
	}

	enrolled, err := e.store.RegisterNativeDeviceWithPairingToken(validToken.ID, device, &store.MFAMethod{
		ID:         uuid.New().String(),
		UserID:     validToken.UserID,
		MethodType: "push",
		IsPrimary:  false,
	})
	if err != nil {
		return nil, err
	}
	if !enrolled {
		return nil, errors.New("pairing token has already been redeemed or expired")
	}

	return device, nil
}

func normalizeDevicePlatform(platform string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(platform)) {
	case "", "android":
		return "android", nil
	case "ios", "macos":
		return strings.ToLower(strings.TrimSpace(platform)), nil
	default:
		return "", errors.New("unsupported device platform")
	}
}

// randomMatchNumber returns a uniformly distributed number in [10, 99].
func randomMatchNumber() (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(90))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()) + 10, nil
}

// CreatePushChallenge creates a push challenge with a 2-digit match and 3 decoys.
func (e *Engine) CreatePushChallenge(userID string) (*store.MFAChallenge, error) {
	matchNum, err := randomMatchNumber()
	if err != nil {
		return nil, err
	}
	matchDigits := strconv.Itoa(matchNum)

	// Generate 3 unique decoys. The attempt cap keeps this bounded even if the
	// entropy source misbehaves; 90 candidates for 3 slots makes 200 tries ample.
	seen := map[int]bool{matchNum: true}
	decoys := make([]string, 0, 3)
	for attempts := 0; len(decoys) < 3; attempts++ {
		if attempts > 200 {
			return nil, errors.New("failed to generate distinct decoy digits")
		}
		decoyNum, err := randomMatchNumber()
		if err != nil {
			return nil, err
		}
		if seen[decoyNum] {
			continue
		}
		seen[decoyNum] = true
		decoys = append(decoys, strconv.Itoa(decoyNum))
	}

	decoysJSON, err := json.Marshal(decoys)
	if err != nil {
		return nil, err
	}

	challenge := &store.MFAChallenge{
		ID:              uuid.New().String(),
		UserID:          userID,
		MethodType:      "push",
		MatchDigits:     matchDigits,
		DecoyDigitsJSON: string(decoysJSON),
		Status:          "pending",
		ExpiresAt:       time.Now().UTC().Add(5 * time.Minute),
	}

	if err := e.store.CreateMFAChallenge(challenge); err != nil {
		return nil, err
	}

	e.dispatchPushChallenge(challenge, decoys)

	return challenge, nil
}

func (e *Engine) dispatchPushChallenge(challenge *store.MFAChallenge, decoys []string) {
	if e.pushSender == nil {
		log.Printf("mfa push relay: no sender configured for challenge %s user %s", challenge.ID, challenge.UserID)
		return
	}
	devices, err := e.store.ListUserNativeDevices(challenge.UserID)
	if err != nil {
		log.Printf("mfa push relay: failed to list devices for challenge %s user %s: %v", challenge.ID, challenge.UserID, err)
		return
	}
	push := MFAChallengePush{
		ChallengeID: challenge.ID,
	}
	dispatched := 0
	for _, dev := range devices {
		if !dev.IsMFAApprover || dev.PushToken == "" {
			log.Printf("mfa push relay: skipping device %s platform %s approver=%v hasToken=%v", dev.ID, dev.Platform, dev.IsMFAApprover, dev.PushToken != "")
			continue
		}
		if err := e.pushSender.SendPush(dev, push); errors.Is(err, ErrStalePushToken) {
			_ = e.store.ClearNativeDevicePushToken(dev.ID, dev.UserID)
			log.Printf("mfa push relay: stale token cleared for device %s platform %s", dev.ID, dev.Platform)
		} else if err != nil {
			log.Printf("mfa push relay: send failed for device %s platform %s: %v", dev.ID, dev.Platform, err)
		} else {
			dispatched++
			log.Printf("mfa push relay: sent challenge %s to device %s platform %s", challenge.ID, dev.ID, dev.Platform)
		}
	}
	if dispatched == 0 {
		log.Printf("mfa push relay: no pushes sent for challenge %s user %s across %d device(s)", challenge.ID, challenge.UserID, len(devices))
	}
}

// ErrUnsignedDevice reports that no paired device is able to sign push responses, so no
// response can be authenticated. The user must re-pair an authenticator.
var ErrUnsignedDevice = errors.New("no paired device is enrolled for response signing")

// PushResponseMessage builds the exact byte string a device must sign to answer a challenge.
// The version prefix domain-separates this from future payloads that carry key material.
func PushResponseMessage(challengeID string, approve bool, selectedDigits string) []byte {
	verb := "deny"
	if approve {
		verb = "approve"
	}
	return []byte(strings.Join([]string{"kysignon-push-v1", challengeID, verb, selectedDigits}, "|"))
}

// PushTokenRefreshMessage is the exact domain-separated payload an enrolled device signs
// when FCM rotates its delivery address. The token digest keeps the canonical message small.
func PushTokenRefreshMessage(issuerOrigin, deviceID, pushToken string, issuedAtMS int64) []byte {
	return []byte(strings.Join([]string{
		"kysignon-push-token-v1",
		issuerOrigin,
		deviceID,
		strconv.FormatInt(issuedAtMS, 10),
		crypto.HashSHA256(pushToken),
	}, "|"))
}

// verifyDeviceSignature finds the paired approver device whose key signed this response.
// A response that no enrolled device signed is not a response.
func (e *Engine) verifyDeviceSignature(userID string, message []byte, signature string) (*store.NativeDevice, error) {
	devices, err := e.store.ListUserNativeDevices(userID)
	if err != nil {
		return nil, err
	}

	enrolled := false
	for i := range devices {
		dev := &devices[i]
		if !dev.IsMFAApprover || dev.PublicKey == "" {
			continue
		}
		enrolled = true
		if crypto.VerifyECDSAP256(dev.PublicKey, message, signature) {
			return dev, nil
		}
	}

	if !enrolled {
		return nil, ErrUnsignedDevice
	}
	return nil, errors.New("signature does not match any paired device")
}

// RespondPushChallenge processes a signed response from a paired mobile authenticator.
// The signature is the authentication for this endpoint: it is verified before the
// challenge is touched, and an unsigned response is always rejected.
func (e *Engine) RespondPushChallenge(challengeID, selectedDigits string, approve bool, signature string) (approved bool, deviceID string, err error) {
	ch, err := e.store.GetMFAChallenge(challengeID)
	if err != nil {
		return false, "", err
	}
	if ch == nil {
		return false, "", errors.New("challenge not found")
	}
	if ch.Status != "pending" {
		return false, "", errors.New("challenge is no longer pending")
	}
	if time.Now().UTC().After(ch.ExpiresAt) {
		_, _ = e.store.TransitionMFAChallengeStatus(ch.ID, "pending", "expired")
		return false, "", errors.New("challenge expired")
	}

	device, err := e.verifyDeviceSignature(ch.UserID, PushResponseMessage(challengeID, approve, selectedDigits), signature)
	if err != nil {
		return false, "", err
	}

	if !approve || subtle.ConstantTimeCompare([]byte(selectedDigits), []byte(ch.MatchDigits)) != 1 {
		ok, err := e.store.TransitionMFAChallengeStatus(ch.ID, "pending", "denied")
		if err != nil {
			return false, device.ID, err
		}
		if !ok {
			return false, device.ID, errors.New("challenge is no longer pending")
		}
		return false, device.ID, nil
	}

	ok, err := e.store.TransitionMFAChallengeStatus(ch.ID, "pending", "approved")
	if err != nil {
		return false, device.ID, err
	}
	if !ok {
		return false, device.ID, errors.New("challenge is no longer pending")
	}
	return true, device.ID, nil
}

// CheckPushChallenge returns the current status of a push challenge along with its owner,
// so callers can confirm the challenge belongs to the user they think it does.
func (e *Engine) CheckPushChallenge(challengeID string) (status, userID string, err error) {
	ch, err := e.store.GetMFAChallenge(challengeID)
	if err != nil {
		return "", "", err
	}
	if ch == nil {
		return "", "", errors.New("challenge not found")
	}

	if ch.Status == "pending" && time.Now().UTC().After(ch.ExpiresAt) {
		if ok, err := e.store.TransitionMFAChallengeStatus(ch.ID, "pending", "expired"); err == nil && ok {
			return "expired", ch.UserID, nil
		}
	}

	return ch.Status, ch.UserID, nil
}

// MFATokenTTL bounds how long a second factor may be completed after the password step.
const MFATokenTTL = 5 * time.Minute

// IssueMFAToken mints a single-use token recording that the primary factor passed for this
// user. Only the hash is stored, so a leaked database cannot be used to complete a login.
func (e *Engine) IssueMFAToken(userID, challengeID string, primaryAt time.Time) (string, error) {
	return e.IssueMFATokenForInteraction(userID, challengeID, primaryAt, "")
}

func (e *Engine) IssueMFATokenForInteraction(userID, challengeID string, primaryAt time.Time, interactionHash string) (string, error) {
	raw, err := crypto.GenerateRandomHex(32)
	if err != nil {
		return "", err
	}

	token := &store.MFAToken{
		InteractionHash:        interactionHash,
		PrimaryAuthenticatedAt: &primaryAt,
		ID:                     uuid.New().String(),
		UserID:                 userID,
		TokenHash:              crypto.HashSHA256(raw),
		ChallengeID:            challengeID,
		ExpiresAt:              time.Now().UTC().Add(MFATokenTTL),
	}
	if err := e.store.CreateMFAToken(token); err != nil {
		return "", err
	}

	return raw, nil
}

// MaxMFAAttempts bounds how many wrong second factors a single login attempt may fund.
// Without it, one token allows unlimited guesses for its whole five-minute lifetime.
const MaxMFAAttempts = 5

// RegisterMFAFailure counts a wrong second-factor guess against the token.
func (e *Engine) RegisterMFAFailure(tokenID string) (int, error) {
	return e.store.RecordMFAFailure(tokenID)
}

// ValidateMFAToken resolves a raw token to its stored record without consuming it.
// The user identity comes from the record, never from the client-supplied string.
func (e *Engine) ValidateMFAToken(rawToken string) (*store.MFAToken, error) {
	if rawToken == "" || len(rawToken) > 256 {
		return nil, errors.New("invalid mfa token")
	}
	token, err := e.store.GetValidMFAToken(crypto.HashSHA256(strings.TrimSpace(rawToken)), MaxMFAAttempts)
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, errors.New("invalid or expired mfa token")
	}
	return token, nil
}

// ConsumeMFAToken spends a token. It reports false if another request spent it first.
func (e *Engine) ConsumeMFAToken(tokenID string) (bool, error) {
	return e.store.ConsumeMFAToken(tokenID)
}
