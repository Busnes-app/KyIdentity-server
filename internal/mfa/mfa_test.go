package mfa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

func setupTestMFAEngine(t *testing.T) (*Engine, *store.Store, *store.User, func()) {
	tmpDir, err := os.MkdirTemp("", "kyidentity-mfa-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	dbStore, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("store.New failed: %v", err)
	}

	encKey, _ := crypto.GenerateRandomBytes(32)
	engine := NewEngine(dbStore, encKey)

	user := &store.User{
		ID:           uuid.New().String(),
		Username:     "alice",
		DisplayName:  "Alice",
		Email:        "alice@example.com",
		PasswordHash: "mock-hash",
		Role:         "user",
		Status:       "active",
	}
	if err := dbStore.CreateUser(user); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	cleanup := func() {
		_ = dbStore.Close()
		_ = os.RemoveAll(tmpDir)
	}

	return engine, dbStore, user, cleanup
}

func TestTOTPEnrollmentAndVerification(t *testing.T) {
	engine, _, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()

	secret, uri, err := engine.GenerateTOTPSecret(user.Username, "KyIdentity")
	if err != nil {
		t.Fatalf("GenerateTOTPSecret failed: %v", err)
	}

	if len(secret) < 16 || uri == "" {
		t.Fatalf("unexpected secret or uri: %s, %s", secret, uri)
	}

	if err := engine.SaveUserTOTP(user.ID, secret, nil); err != nil {
		t.Fatalf("SaveUserTOTP failed: %v", err)
	}

	// Calculate valid code for current counter
	timeStep := time.Now().Unix() / 30

	// Validate TOTP algorithm with calculated code
	code := calculateTOTPCode([]byte("12345678901234567890"), timeStep)
	if !ValidateTOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", code) {
		t.Fatal("ValidateTOTP failed for RFC 6238 sample secret")
	}
}

func TestRecoveryCodesGenerationAndSingleUse(t *testing.T) {
	engine, _, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()

	codes, err := engine.GenerateRecoveryCodes(user.ID, nil)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes failed: %v", err)
	}

	if len(codes) != 8 {
		t.Fatalf("expected 8 recovery codes, got %d", len(codes))
	}

	firstCode := codes[0]

	// 1. Consume first code
	valid, err := engine.VerifyAndConsumeRecoveryCode(user.ID, firstCode)
	if err != nil || !valid {
		t.Fatalf("first recovery code verification failed: %v", err)
	}

	// 2. Replay of same code must fail
	valid, err = engine.VerifyAndConsumeRecoveryCode(user.ID, firstCode)
	if err != nil || valid {
		t.Fatal("expected already consumed recovery code to fail")
	}
}

func TestDevicePairingAndRegistration(t *testing.T) {
	engine, dbStore, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()

	// 1. Generate 90s device pairing PIN/token
	token, pin, expiresAt, err := engine.GenerateDevicePairingToken(user.ID)
	if err != nil {
		t.Fatalf("GenerateDevicePairingToken failed: %v", err)
	}

	if len(pin) != 6 || token == "" {
		t.Fatalf("unexpected token or pin format: %s, %s", token, pin)
	}
	if expiresAt.Before(time.Now().UTC().Add(80 * time.Second)) {
		t.Fatalf("TTL too short: %v", expiresAt)
	}

	// 2. Register native device using PIN. The PIN is scoped to the user who generated
	// it, and a device must present the P-256 key it will sign push responses with.
	_, devicePub := signingKey(t)
	regReq := &NativeDeviceRegisterRequest{
		PINCode:          pin,
		UserID:           user.ID,
		DeviceName:       "Yoshi's Pixel Phone",
		DeviceIdentifier: "pixel-9-pro-uuid",
		PublicKey:        devicePub,
		PushToken:        "fcm-mock-token-12345",
	}

	dev, err := engine.RegisterNativeDevice(regReq)
	if err != nil {
		t.Fatalf("RegisterNativeDevice failed: %v", err)
	}

	if dev.UserID != user.ID || dev.DeviceName != "Yoshi's Pixel Phone" || !dev.IsMFAApprover {
		t.Fatalf("unexpected registered device: %+v", dev)
	}

	// 3. Check store
	devices, err := dbStore.ListUserNativeDevices(user.ID)
	if err != nil || len(devices) != 1 {
		t.Fatalf("expected 1 device in store, got %d", len(devices))
	}

	// 4. Token replay must fail
	_, err = engine.RegisterNativeDevice(regReq)
	if err == nil {
		t.Fatal("expected device pairing PIN replay to fail")
	}
}

// testDevice is a paired authenticator that can sign push responses.
type testDevice struct {
	id   string
	priv *ecdsa.PrivateKey
}

func (d *testDevice) sign(t *testing.T, challengeID string, approve bool, digits string) string {
	t.Helper()
	digest := sha256.Sum256(PushResponseMessage(challengeID, approve, digits))
	sig, err := ecdsa.SignASN1(rand.Reader, d.priv, digest[:])
	if err != nil {
		t.Fatalf("SignASN1 failed: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func pairSigningDevice(t *testing.T, s *store.Store, userID, name string) *testDevice {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey failed: %v", err)
	}

	dev := &store.NativeDevice{
		ID:               uuid.New().String(),
		UserID:           userID,
		DeviceName:       name,
		DeviceIdentifier: name,
		PublicKey:        base64.StdEncoding.EncodeToString(der),
		IsMFAApprover:    true,
	}
	if err := s.UpsertNativeDevice(dev); err != nil {
		t.Fatalf("UpsertNativeDevice failed: %v", err)
	}

	return &testDevice{id: dev.ID, priv: priv}
}

func TestPushChallengeNumberMatching(t *testing.T) {
	engine, dbStore, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()

	device := pairSigningDevice(t, dbStore, user.ID, "phone-1")

	challenge, err := engine.CreatePushChallenge(user.ID)
	if err != nil {
		t.Fatalf("CreatePushChallenge failed: %v", err)
	}
	if len(challenge.MatchDigits) != 2 {
		t.Fatalf("expected 2-digit match number, got %s", challenge.MatchDigits)
	}

	status, owner, err := engine.CheckPushChallenge(challenge.ID)
	if err != nil || status != "pending" {
		t.Fatalf("expected pending status, got %s (err=%v)", status, err)
	}
	if owner != user.ID {
		t.Fatalf("expected challenge owner %s, got %s", user.ID, owner)
	}

	// Wrong match number, correctly signed: denied.
	ok, _, err := engine.RespondPushChallenge(challenge.ID, "99", true, device.sign(t, challenge.ID, true, "99"))
	if err != nil || ok {
		t.Fatalf("expected incorrect number response to fail, got ok=%v err=%v", ok, err)
	}
	if status, _, _ = engine.CheckPushChallenge(challenge.ID); status != "denied" {
		t.Fatalf("expected denied status after incorrect number, got %s", status)
	}

	// Correct match number, correctly signed: approved.
	ch2, err := engine.CreatePushChallenge(user.ID)
	if err != nil {
		t.Fatalf("CreatePushChallenge failed: %v", err)
	}
	ok, deviceID, err := engine.RespondPushChallenge(ch2.ID, ch2.MatchDigits, true, device.sign(t, ch2.ID, true, ch2.MatchDigits))
	if err != nil || !ok {
		t.Fatalf("expected correct number response to succeed, got ok=%v err=%v", ok, err)
	}
	if deviceID != device.id {
		t.Fatalf("expected responding device %s, got %s", device.id, deviceID)
	}
	if status, _, _ = engine.CheckPushChallenge(ch2.ID); status != "approved" {
		t.Fatalf("expected approved status, got %s", status)
	}
}

func TestPushResponseRequiresValidDeviceSignature(t *testing.T) {
	engine, dbStore, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()

	device := pairSigningDevice(t, dbStore, user.ID, "phone-1")

	t.Run("unsigned response is rejected", func(t *testing.T) {
		ch, _ := engine.CreatePushChallenge(user.ID)
		if ok, _, err := engine.RespondPushChallenge(ch.ID, ch.MatchDigits, true, ""); ok || err == nil {
			t.Fatalf("expected unsigned response to be rejected, got ok=%v err=%v", ok, err)
		}
		if status, _, _ := engine.CheckPushChallenge(ch.ID); status != "pending" {
			t.Fatalf("rejected response must not move the challenge, got %s", status)
		}
	})

	t.Run("signature from an unpaired key is rejected", func(t *testing.T) {
		ch, _ := engine.CreatePushChallenge(user.ID)
		attacker := &testDevice{}
		attacker.priv, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

		if ok, _, err := engine.RespondPushChallenge(ch.ID, ch.MatchDigits, true, attacker.sign(t, ch.ID, true, ch.MatchDigits)); ok || err == nil {
			t.Fatalf("expected foreign signature to be rejected, got ok=%v err=%v", ok, err)
		}
		if status, _, _ := engine.CheckPushChallenge(ch.ID); status != "pending" {
			t.Fatalf("rejected response must not move the challenge, got %s", status)
		}
	})

	t.Run("signature bound to another challenge is rejected", func(t *testing.T) {
		chA, _ := engine.CreatePushChallenge(user.ID)
		chB, _ := engine.CreatePushChallenge(user.ID)

		// A valid signature for challenge A, replayed against challenge B.
		replay := device.sign(t, chA.ID, true, chB.MatchDigits)
		if ok, _, err := engine.RespondPushChallenge(chB.ID, chB.MatchDigits, true, replay); ok || err == nil {
			t.Fatalf("expected cross-challenge replay to be rejected, got ok=%v err=%v", ok, err)
		}
	})

	t.Run("flipping approve invalidates the signature", func(t *testing.T) {
		ch, _ := engine.CreatePushChallenge(user.ID)
		denial := device.sign(t, ch.ID, false, ch.MatchDigits)
		if ok, _, err := engine.RespondPushChallenge(ch.ID, ch.MatchDigits, true, denial); ok || err == nil {
			t.Fatalf("expected an approval carrying a denial signature to be rejected, got ok=%v err=%v", ok, err)
		}
	})

	t.Run("user with no signing device cannot be approved", func(t *testing.T) {
		other := &store.User{
			ID: uuid.New().String(), Username: "bob", Email: "bob@example.com",
			PasswordHash: "mock-hash", Role: "user", Status: "active",
		}
		if err := dbStore.CreateUser(other); err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}

		ch, _ := engine.CreatePushChallenge(other.ID)
		_, _, err := engine.RespondPushChallenge(ch.ID, ch.MatchDigits, true, device.sign(t, ch.ID, true, ch.MatchDigits))
		if !errors.Is(err, ErrUnsignedDevice) {
			t.Fatalf("expected ErrUnsignedDevice, got %v", err)
		}
	})
}

func TestPushChallengeApprovesExactlyOnce(t *testing.T) {
	engine, dbStore, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()

	device := pairSigningDevice(t, dbStore, user.ID, "phone-1")
	ch, err := engine.CreatePushChallenge(user.ID)
	if err != nil {
		t.Fatalf("CreatePushChallenge failed: %v", err)
	}
	sig := device.sign(t, ch.ID, true, ch.MatchDigits)

	const racers = 50
	var wg sync.WaitGroup
	results := make([]bool, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ok, _, _ := engine.RespondPushChallenge(ch.ID, ch.MatchDigits, true, sig)
			results[idx] = ok
		}(i)
	}
	wg.Wait()

	approvals := 0
	for _, ok := range results {
		if ok {
			approvals++
		}
	}
	if approvals != 1 {
		t.Fatalf("expected exactly one successful approval across %d concurrent responders, got %d", racers, approvals)
	}
}

func TestMFATokenIsSingleUseAndBound(t *testing.T) {
	engine, _, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()

	raw, err := engine.IssueMFAToken(user.ID, "challenge-abc", time.Now().UTC())
	if err != nil {
		t.Fatalf("IssueMFAToken failed: %v", err)
	}

	token, err := engine.ValidateMFAToken(raw)
	if err != nil {
		t.Fatalf("ValidateMFAToken failed: %v", err)
	}
	if token.UserID != user.ID || token.ChallengeID != "challenge-abc" {
		t.Fatalf("token bound to wrong user/challenge: %+v", token)
	}

	// A token forged in the old "<random>:<userID>" shape must resolve to nothing.
	if _, err := engine.ValidateMFAToken("deadbeef:" + user.ID); err == nil {
		t.Fatal("expected a forged mfa token to be rejected")
	}

	spent, err := engine.ConsumeMFAToken(token.ID)
	if err != nil || !spent {
		t.Fatalf("expected first consume to succeed, got spent=%v err=%v", spent, err)
	}
	spent, err = engine.ConsumeMFAToken(token.ID)
	if err != nil || spent {
		t.Fatalf("expected replayed consume to fail, got spent=%v err=%v", spent, err)
	}
	if _, err := engine.ValidateMFAToken(raw); err == nil {
		t.Fatal("expected a spent token to stop validating")
	}
}

func TestPushChallengeDigitsAreDistinctAndInRange(t *testing.T) {
	engine, _, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()

	for i := 0; i < 200; i++ {
		ch, err := engine.CreatePushChallenge(user.ID)
		if err != nil {
			t.Fatalf("CreatePushChallenge failed: %v", err)
		}

		var decoys []string
		if err := json.Unmarshal([]byte(ch.DecoyDigitsJSON), &decoys); err != nil {
			t.Fatalf("decoy digits are not valid JSON: %v", err)
		}
		if len(decoys) != 3 {
			t.Fatalf("expected 3 decoys, got %d", len(decoys))
		}

		seen := map[string]bool{ch.MatchDigits: true}
		for _, d := range append(decoys, ch.MatchDigits) {
			n, err := strconv.Atoi(d)
			if err != nil || n < 10 || n > 99 {
				t.Fatalf("digit %q outside [10,99]", d)
			}
		}
		for _, d := range decoys {
			if seen[d] {
				t.Fatalf("decoy %q collides with another displayed number", d)
			}
			seen[d] = true
		}
	}
}
