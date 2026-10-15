package mfa

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/attest"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/netguard"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

type Engine struct {
	store         *store.Store
	encryptionKey []byte
	pushSender    PushSender
	unifiedPush   PushSender
	ubuntuPush    PushSender
	attestor      Attestor
	appAttestor   AppAttestor
	issuerOrigin  string
	logger        *slog.Logger // nil: slog.Default()
}

// Attestor grades a device key attestation chain.
type Attestor interface {
	Verify(chain [][]byte, want attest.Expectation) attest.Result
}

// SetAttestor installs the chain verifier; nil grades every registration none.
func (e *Engine) SetAttestor(a Attestor) { e.attestor = a }

// SetIssuerOrigin sets the origin push approvals are bound to; empty refuses every response.
func (e *Engine) SetIssuerOrigin(o string) { e.issuerOrigin = o }

// ExpectedChallenge is the attestation challenge KyAuth binds to the credential it redeems.
func ExpectedChallenge(req *NativeDeviceRegisterRequest) []byte {
	cred := req.PairingToken
	if cred == "" {
		cred = req.UserID + "|" + req.PINCode
	}
	sum := sha256.Sum256([]byte("kyidentity-attest-v1|" + cred))
	return sum[:]
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
	Purpose     string
	ExpiresAtMS int64
}

// SetPushSender installs the FCM/APNs relay sender.
func (e *Engine) SetPushSender(sender PushSender) {
	e.pushSender = sender
}

// SetUnifiedPushSender installs the sender for unifiedpush devices.
func (e *Engine) SetUnifiedPushSender(sender PushSender) {
	e.unifiedPush = sender
}

// SetUbuntuPushSender installs the sender for ubuntupush devices.
func (e *Engine) SetUbuntuPushSender(sender PushSender) {
	e.ubuntuPush = sender
}

func (e *Engine) senderFor(dev store.NativeDevice) PushSender {
	switch dev.PushTransport {
	case store.PushTransportUnifiedPush:
		return e.unifiedPush
	case store.PushTransportUbuntuPush:
		return e.ubuntuPush
	}
	return e.pushSender
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
	encrypted, err := crypto.Seal(e.encryptionKey, store.SealTOTP, userID, []byte(secretBase32))
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

	decrypted, err := crypto.Open(e.encryptionKey, store.SealTOTP, method.UserID, method.EncryptedSecret)
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
			CodeHash: e.recoveryCodeHash(userID, normalizeRecoveryCode(code)),
		})
	}

	if err := e.store.ReplaceRecoveryCodes(userID, recoveryCodes, audit); err != nil {
		return nil, err
	}

	return plainCodes, nil
}

func normalizeRecoveryCode(code string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
}

// recoveryCodeHash keys the hash to this server's key and the user: a code holds only 40
// bits, which a bare SHA-256 from a leaked database gives up in seconds.
func (e *Engine) recoveryCodeHash(userID, normalized string) string {
	key := crypto.DeriveKey(e.encryptionKey, "kyidentity:recovery-code")
	return store.RecoveryCodeHMACPrefix + crypto.SignHMACSHA256(key, []byte(userID+"|"+normalized))
}

// VerifyAndConsumeRecoveryCode validates and consumes a recovery code. Codes issued before
// keyed hashing still redeem until the user regenerates (store.HasLegacyRecoveryCodes).
// A spent code commits with audit.
func (e *Engine) VerifyAndConsumeRecoveryCode(userID, code string, audit *store.AuditEvent) (bool, error) {
	normalized := normalizeRecoveryCode(code)
	return e.store.ConsumeRecoveryCode(userID, e.recoveryCodeHash(userID, normalized), crypto.HashSHA256(normalized), audit)
}

// GenerateDevicePairingToken generates a 90s ephemeral PIN & token for registering a native
// mobile device, committing audit with the token.
func (e *Engine) GenerateDevicePairingToken(userID string, signOn bool, audit *store.AuditEvent) (token string, pin string, expiresAt time.Time, err error) {
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
		SignOn:    signOn,
		ExpiresAt: expiresAt,
	}

	if err := e.store.CreateDevicePairingToken(item, audit); err != nil {
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
	// PushTransport is fcm (default), unifiedpush or ubuntupush; the last two need the RFC 8291
	// keys, which are optional on fcm.
	PushTransport string `json:"pushTransport,omitempty"`
	PushP256dh    string `json:"pushP256dh,omitempty"`
	PushAuth      string `json:"pushAuth,omitempty"`
	// Attestation is the base64 DER Android key attestation chain, leaf first.
	Attestation []string `json:"attestation,omitempty"`
	// AppAttest is KyAuth iOS's App Attest evidence, graded only for platform "ios".
	AppAttest *AppAttestEvidence `json:"appAttest,omitempty"`
}

// RegisterNativeDevice registers a device presented with a valid 90s pairing token, or a
// PIN scoped to the user who generated it.
//
// A device must present a usable P-256 public key. Pairing one without a key enrols push
// MFA that no response can ever satisfy, which locks the user out of every later login.
// audit builds the audit row from the stored device; it commits with the enrolment.
func (e *Engine) RegisterNativeDevice(req *NativeDeviceRegisterRequest, audit func(*store.NativeDevice) *store.AuditEvent) (*store.NativeDevice, error) {
	if req.PublicKey == "" {
		return nil, store.InputError("a device public key is required to pair an authenticator")
	}
	if strings.TrimSpace(req.PushToken) == "" {
		return nil, store.InputError("a push token is required to pair an authenticator")
	}
	transport, err := ValidatePushTarget(req.PushTransport, strings.TrimSpace(req.PushToken), req.PushP256dh, req.PushAuth)
	if err != nil {
		return nil, err
	}
	platform, err := normalizeDevicePlatform(req.Platform)
	if err != nil {
		return nil, err
	}
	if !PlatformAllowsTransport(platform, transport) {
		return nil, errInvalidPushTarget
	}
	if _, err := crypto.ParseP256PublicKey(req.PublicKey); err != nil {
		return nil, store.InputError("device public key is not a valid P-256 key")
	}

	var validToken *store.DevicePairingToken

	switch {
	case req.PairingToken != "":
		validToken, err = e.store.GetValidDevicePairingToken(crypto.HashSHA256(req.PairingToken))
	case req.PINCode != "" && req.UserID != "":
		validToken, err = e.store.MatchDevicePairingPIN(req.UserID, crypto.HashSHA256(req.PINCode))
	case req.PINCode != "":
		return nil, store.InputError("a userId is required when pairing with a PIN")
	default:
		return nil, store.InputError("pairingToken or pinCode is required")
	}

	if err != nil {
		return nil, err
	}
	if validToken == nil {
		return nil, store.InputError("invalid or expired pairing token")
	}

	name := req.DeviceName
	if name == "" {
		name = "KySecurity Authenticator Device"
	}
	device := &store.NativeDevice{
		ID:               uuid.New().String(),
		UserID:           validToken.UserID,
		DeviceName:       name,
		DeviceIdentifier: req.DeviceIdentifier,
		Platform:         platform,
		PublicKey:        req.PublicKey,
		PushToken:        strings.TrimSpace(req.PushToken),
		PushTransport:    transport,
		PushP256dh:       req.PushP256dh,
		PushAuth:         req.PushAuth,
		IsMFAApprover:    true, // Enrolled devices are default approvers
		CanSignOn:        validToken.SignOn,
	}
	// Graded before the enrolment write, which stores the grade with the key it graded.
	e.gradeAttestation(req, device)

	enrolled, err := e.store.RegisterNativeDeviceWithPairingToken(validToken.ID, device, &store.MFAMethod{
		ID:         uuid.New().String(),
		UserID:     validToken.UserID,
		MethodType: "push",
		IsPrimary:  false,
	}, audit)
	if err != nil {
		return nil, err
	}
	if !enrolled {
		return nil, store.InputError("pairing token has already been redeemed or expired")
	}
	return device, nil
}

// gradeAttestation grades the request's attestation onto device: App Attest for iOS, the
// Keystore chain for Android. Grading never fails a registration; missing or bad evidence is none.
func (e *Engine) gradeAttestation(req *NativeDeviceRegisterRequest, device *store.NativeDevice) {
	if device.Platform == "ios" {
		e.gradeAppAttest(req, device)
		return
	}
	if device.Platform != "android" || len(req.Attestation) == 0 || e.attestor == nil {
		return
	}
	chain := make([][]byte, 0, len(req.Attestation))
	for _, b64 := range req.Attestation {
		der, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			chain = nil
			break
		}
		chain = append(chain, der)
	}
	spki, _ := crypto.P256SPKI(req.PublicKey)
	res := e.attestor.Verify(chain, attest.Expectation{Challenge: ExpectedChallenge(req), PublicKeySPKI: spki})
	device.AttestedLevel, device.BootState, device.AttestationSerials, device.AttestationReason = res.Level, res.BootState, res.Serials, res.Reason
}

func normalizeDevicePlatform(platform string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(platform)) {
	case "", "android":
		return "android", nil
	case "ios", "macos", "linux":
		return strings.ToLower(strings.TrimSpace(platform)), nil
	default:
		return "", store.InputError("unsupported device platform")
	}
}

// PlatformAllowsTransport reports whether a device platform may use a push transport.
// Linux has no FCM, and the Lomiri push service exists only on Linux (Ubuntu Touch).
func PlatformAllowsTransport(platform, transport string) bool {
	switch transport {
	case store.PushTransportFCM:
		return platform != "linux"
	case store.PushTransportUbuntuPush:
		return platform == "linux"
	}
	return true
}

// randomMatchNumber returns a uniformly distributed number in [10, 99].
func randomMatchNumber() (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(90))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()) + 10, nil
}

// ErrPushPending means the user already has a live login push. Sharing it with a second
// login would let one approval sign in both, so no new push is sent until it settles.
var ErrPushPending = errors.New("a login push is already pending")

// CreatePushChallenge creates a push challenge with a 2-digit match and 3 decoys. A user
// has at most one pending login push (ErrPushPending).
func (e *Engine) CreatePushChallenge(userID, purpose string) (*store.MFAChallenge, error) {
	if purpose != "login" && purpose != "step_up" {
		return nil, errors.New("unknown push purpose")
	}
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
		Purpose:         purpose,
		// Whole seconds: the signed message carries milliseconds, so storage must not hold more.
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute).Truncate(time.Second),
	}

	if purpose == "login" {
		created, err := e.store.CreateLoginPushChallenge(challenge)
		if err != nil {
			return nil, err
		}
		if !created {
			return nil, ErrPushPending
		}
	} else if err := e.store.CreateMFAChallenge(challenge); err != nil {
		return nil, err
	}

	e.dispatchPushChallenge(challenge, decoys)

	return challenge, nil
}

func (e *Engine) dispatchPushChallenge(challenge *store.MFAChallenge, decoys []string) {
	devices, err := e.store.ListUserNativeDevices(challenge.UserID)
	if err != nil {
		log.Printf("mfa push relay: failed to list devices for challenge %s user %s: %v", challenge.ID, challenge.UserID, err)
		return
	}
	push := MFAChallengePush{
		ChallengeID: challenge.ID,
		Purpose:     challenge.Purpose,
		ExpiresAtMS: challenge.ExpiresAt.UnixMilli(),
	}
	// Concurrent, so an unreachable distributor costs the login one send timeout, not one per
	// device. Logs name the device and transport only: a UnifiedPush endpoint is a capability URL.
	var dispatched atomic.Int32
	var wg sync.WaitGroup
	for _, dev := range devices {
		sender := e.senderFor(dev)
		if !dev.IsMFAApprover || dev.PushToken == "" || sender == nil {
			log.Printf("mfa push: skipping device %s transport %s approver=%v hasToken=%v hasSender=%v", dev.ID, dev.PushTransport, dev.IsMFAApprover, dev.PushToken != "", sender != nil)
			continue
		}
		wg.Add(1)
		go func(dev store.NativeDevice) {
			defer wg.Done()
			if err := sender.SendPush(dev, push); errors.Is(err, ErrStalePushToken) {
				_ = e.store.ClearNativeDevicePushToken(dev)
				log.Printf("mfa push: stale token cleared for device %s transport %s", dev.ID, dev.PushTransport)
			} else if err != nil {
				log.Printf("mfa push: send failed for device %s transport %s: %v", dev.ID, dev.PushTransport, err)
			} else {
				dispatched.Add(1)
				log.Printf("mfa push: sent challenge %s to device %s transport %s", challenge.ID, dev.ID, dev.PushTransport)
			}
		}(dev)
	}
	wg.Wait()
	if dispatched.Load() == 0 {
		log.Printf("mfa push: no pushes sent for challenge %s user %s across %d device(s)", challenge.ID, challenge.UserID, len(devices))
	}
}

// ErrUnsignedDevice reports that no paired device is able to sign push responses, so no
// response can be authenticated. The user must re-pair an authenticator.
var ErrUnsignedDevice = errors.New("no paired device is enrolled for response signing")

// PushBinding is everything a push approval states: which server, account, device, challenge,
// purpose and deadline the user saw. Every value comes from the server's own records.
type PushBinding struct {
	Origin, UserID, DeviceID, ChallengeID, Purpose string
	ExpiresAtMS                                    int64
}

// PushResponseMessage builds the exact byte string a device signs to answer a challenge.
func PushResponseMessage(b PushBinding, approve bool, selectedDigits string) ([]byte, error) {
	if b.Purpose != "login" && b.Purpose != "step_up" {
		return nil, errors.New("unknown push purpose")
	}
	for _, f := range []string{b.Origin, b.UserID, b.DeviceID, b.ChallengeID} {
		if f == "" || strings.Contains(f, "|") {
			return nil, errors.New("invalid push binding field")
		}
	}
	if strings.Contains(selectedDigits, "|") {
		return nil, errors.New("invalid digits")
	}
	verb := "deny"
	if approve {
		verb = "approve"
	}
	return []byte(strings.Join([]string{
		"kyidentity-push-v2", b.Origin, b.UserID, b.DeviceID, b.ChallengeID, b.Purpose,
		strconv.FormatInt(b.ExpiresAtMS, 10), verb, selectedDigits,
	}, "|")), nil
}

// IssuerOrigin normalizes an issuer URL to scheme://host[:port], dropping the default port.
func IssuerOrigin(issuerURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(issuerURL))
	if err != nil || u.Scheme == "" || u.Hostname() == "" {
		return "", errors.New("issuer URL has no origin")
	}
	scheme, host, port := strings.ToLower(u.Scheme), strings.ToLower(u.Hostname()), u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return scheme + "://" + host, nil
}

// MaxPushTokenBytes caps a push token or UnifiedPush endpoint.
const MaxPushTokenBytes = 4096

// ubuntuPushToken is a Lomiri PushClient token.
var ubuntuPushToken = regexp.MustCompile(`^[A-Za-z0-9+/=_.:-]{1,512}$`)

var errInvalidPushTarget error = store.InputError("invalid push target")

// ValidatePushTarget checks a device's push address and keys, and returns the effective
// transport. A UnifiedPush endpoint is device-chosen and server-contacted, so it gets the strict
// device URL policy.
// UnifiedPush and ubuntupush require RFC 8291 keys: payloads are never sent in plaintext.
// On fcm (the relay) keys are optional; a device that sends them gets sealed pushes.
func ValidatePushTarget(transport, pushToken, p256dh, auth string) (string, error) {
	if pushToken == "" || len(pushToken) > MaxPushTokenBytes {
		return "", errInvalidPushTarget
	}
	switch transport {
	case "", store.PushTransportFCM:
		if p256dh == "" && auth == "" {
			return store.PushTransportFCM, nil
		}
		transport = store.PushTransportFCM
	case store.PushTransportUnifiedPush:
		if netguard.ValidateDeviceURL(pushToken, "push endpoint") != nil {
			return "", errInvalidPushTarget
		}
	case store.PushTransportUbuntuPush:
		if !ubuntuPushToken.MatchString(pushToken) {
			return "", errInvalidPushTarget
		}
	default:
		return "", errInvalidPushTarget
	}
	pub, err := decodeBase64URL(p256dh)
	if err != nil {
		return "", errInvalidPushTarget
	}
	if _, err := ecdh.P256().NewPublicKey(pub); err != nil { // uncompressed and on the curve
		return "", errInvalidPushTarget
	}
	if secret, err := decodeBase64URL(auth); err != nil || len(secret) != 16 {
		return "", errInvalidPushTarget
	}
	return transport, nil
}

// decodeBase64URL accepts base64url with or without padding, and nothing else.
func decodeBase64URL(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, errInvalidPushTarget
	}
	if strings.HasSuffix(s, "=") {
		return base64.URLEncoding.DecodeString(s)
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// PushTokenRefreshMessage builds the exact string a device signs to replace its push target.
// p256dh and auth are the strings the device sent, empty when it has no keys.
func PushTokenRefreshMessage(origin, deviceID string, issuedAtMS int64, transport, pushToken, p256dh, auth string) ([]byte, error) {
	for _, f := range []string{origin, deviceID, transport} {
		if f == "" {
			return nil, errInvalidPushTarget
		}
	}
	for _, f := range []string{origin, deviceID, transport, p256dh, auth} {
		if strings.Contains(f, "|") {
			return nil, errInvalidPushTarget
		}
	}
	return []byte(strings.Join([]string{
		"kyidentity-push-token-v2", origin, deviceID, strconv.FormatInt(issuedAtMS, 10),
		transport, crypto.HashSHA256(pushToken), p256dh, auth,
	}, "|")), nil
}

// verifyDeviceSignature checks the response against the one device it names. Every failure
// after the enrollment check is the same error, so a caller learns nothing about which part failed.
func (e *Engine) verifyDeviceSignature(ch *store.MFAChallenge, deviceID string, approve bool, selectedDigits, signature string) (*store.NativeDevice, error) {
	devices, err := e.store.ListUserNativeDevices(ch.UserID)
	if err != nil {
		return nil, err
	}
	enrolled := false
	for _, d := range devices {
		if d.IsMFAApprover && d.PublicKey != "" {
			enrolled = true
			break
		}
	}
	if !enrolled {
		return nil, ErrUnsignedDevice
	}
	errBad := errors.New("signature does not match any paired device")
	dev, err := e.store.GetNativeDevice(deviceID)
	if err != nil {
		return nil, err
	}
	if dev == nil || dev.UserID != ch.UserID || !dev.IsMFAApprover || dev.PublicKey == "" {
		return nil, errBad
	}
	msg, err := PushResponseMessage(PushBinding{
		Origin: e.issuerOrigin, UserID: ch.UserID, DeviceID: dev.ID, ChallengeID: ch.ID,
		Purpose: ch.Purpose, ExpiresAtMS: ch.ExpiresAt.UnixMilli(),
	}, approve, selectedDigits)
	if err != nil || !crypto.VerifyECDSAP256(dev.PublicKey, msg, signature) {
		return nil, errBad
	}
	return dev, nil
}

// RespondPushChallenge processes a signed response from a paired mobile authenticator.
// The signature is the authentication for this endpoint: it is verified before the
// challenge is touched, and an unsigned response is always rejected.
func (e *Engine) RespondPushChallenge(challengeID, namedDeviceID, selectedDigits string, approve bool, signature string) (approved bool, deviceID string, err error) {
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

	device, err := e.verifyDeviceSignature(ch, namedDeviceID, approve, selectedDigits, signature)
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

// ErrMFAAttemptsExhausted means the token has no attempt left to spend.
var ErrMFAAttemptsExhausted = errors.New("mfa token has no attempts left")

// ReserveMFAAttempt spends one attempt before the proof is checked, so parallel guesses
// on one token cannot exceed MaxMFAAttempts. It returns the attempts used so far.
func (e *Engine) ReserveMFAAttempt(tokenID string) (int, error) {
	n, err := e.store.ReserveMFAAttempt(tokenID, MaxMFAAttempts)
	if err == nil && n == 0 {
		err = ErrMFAAttemptsExhausted
	}
	return n, err
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
