package mfa

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// covStoreChallenge writes a push challenge directly, so a test can choose its status and expiry.
func covStoreChallenge(t *testing.T, db *store.Store, userID, status string, expiresAt time.Time) *store.MFAChallenge {
	t.Helper()
	ch := &store.MFAChallenge{
		ID: uuid.New().String(), UserID: userID, MethodType: "push", MatchDigits: "42",
		DecoyDigitsJSON: `["11","22","33"]`, Status: status, Purpose: "step_up",
		ExpiresAt: expiresAt.UTC().Truncate(time.Second),
	}
	if err := db.CreateMFAChallenge(ch); err != nil {
		t.Fatalf("CreateMFAChallenge: %v", err)
	}
	return ch
}

func covChallengeStatus(t *testing.T, db *store.Store, id string) string {
	t.Helper()
	ch, err := db.GetMFAChallenge(id)
	if err != nil || ch == nil {
		t.Fatalf("GetMFAChallenge(%s) = %v, %v", id, ch, err)
	}
	return ch.Status
}

// A response for a challenge id the server never issued must fail, not approve.
func TestRespondPushChallengeUnknownChallenge(t *testing.T) {
	e, db, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	dev := pairSigningDevice(t, db, user.ID, "phone")

	ok, devID, err := e.RespondPushChallenge(uuid.New().String(), dev.id, "42", true, "sig")
	if ok || devID != "" || err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unknown challenge: ok=%v dev=%q err=%v", ok, devID, err)
	}
}

// A correctly signed approval that arrives after expiry must be refused, and the
// challenge recorded as expired so a later poll cannot complete the login.
func TestRespondPushChallengeExpiredIsRefusedAndMarkedExpired(t *testing.T) {
	e, db, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	dev := pairSigningDevice(t, db, user.ID, "phone")
	ch := covStoreChallenge(t, db, user.ID, "pending", time.Now().Add(-time.Minute))

	ok, _, err := e.RespondPushChallenge(ch.ID, dev.id, ch.MatchDigits, true, dev.sign(t, ch, true, ch.MatchDigits))
	if ok || err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired approval: ok=%v err=%v", ok, err)
	}
	if got := covChallengeStatus(t, db, ch.ID); got != "expired" {
		t.Fatalf("status = %q, want expired", got)
	}
}

// A replayed approval for a challenge already denied must not flip it to approved.
func TestRespondPushChallengeSettledChallengeIsNotReopened(t *testing.T) {
	e, db, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	dev := pairSigningDevice(t, db, user.ID, "phone")
	ch := covStoreChallenge(t, db, user.ID, "pending", time.Now().Add(time.Minute))

	ok, devID, err := e.RespondPushChallenge(ch.ID, dev.id, ch.MatchDigits, false, dev.sign(t, ch, false, ch.MatchDigits))
	if ok || err != nil || devID != dev.id {
		t.Fatalf("signed denial: ok=%v dev=%q err=%v", ok, devID, err)
	}
	if got := covChallengeStatus(t, db, ch.ID); got != "denied" {
		t.Fatalf("status after denial = %q", got)
	}

	ok, _, err = e.RespondPushChallenge(ch.ID, dev.id, ch.MatchDigits, true, dev.sign(t, ch, true, ch.MatchDigits))
	if ok || err == nil || !strings.Contains(err.Error(), "no longer pending") {
		t.Fatalf("approval after denial: ok=%v err=%v", ok, err)
	}
	if got := covChallengeStatus(t, db, ch.ID); got != "denied" {
		t.Fatalf("status after replay = %q, want denied", got)
	}
}

// An approval signed with the right digits but the wrong selection denies the challenge:
// picking a decoy is how a user signals the login is not theirs.
func TestRespondPushChallengeWrongDigitsDenies(t *testing.T) {
	e, db, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	dev := pairSigningDevice(t, db, user.ID, "phone")
	ch := covStoreChallenge(t, db, user.ID, "pending", time.Now().Add(time.Minute))

	ok, devID, err := e.RespondPushChallenge(ch.ID, dev.id, "11", true, dev.sign(t, ch, true, "11"))
	if ok || err != nil || devID != dev.id {
		t.Fatalf("decoy approval: ok=%v dev=%q err=%v", ok, devID, err)
	}
	if got := covChallengeStatus(t, db, ch.ID); got != "denied" {
		t.Fatalf("status = %q, want denied", got)
	}
}

// Another user's device, even one signing correctly with its own key, cannot answer this
// user's challenge; nor can a device id that does not exist.
func TestRespondPushChallengeRefusesForeignOrUnknownDevice(t *testing.T) {
	e, db, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	pairSigningDevice(t, db, user.ID, "own-phone")
	other := mfaUser(t, db)
	foreign := pairSigningDevice(t, db, other.ID, "other-phone")
	ch := covStoreChallenge(t, db, user.ID, "pending", time.Now().Add(time.Minute))

	for name, devID := range map[string]string{"foreign": foreign.id, "unknown": uuid.New().String()} {
		sig := (&testDevice{id: devID, priv: foreign.priv}).sign(t, ch, true, ch.MatchDigits)
		ok, gotDev, err := e.RespondPushChallenge(ch.ID, devID, ch.MatchDigits, true, sig)
		if ok || gotDev != "" || err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Errorf("%s device: ok=%v dev=%q err=%v", name, ok, gotDev, err)
		}
	}
	if got := covChallengeStatus(t, db, ch.ID); got != "pending" {
		t.Fatalf("refused responses moved the challenge to %q", got)
	}
}

// A store failure while loading the challenge surfaces as an error, never as an approval.
func TestRespondAndCheckPushChallengeStoreFailure(t *testing.T) {
	e, db, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	dev := pairSigningDevice(t, db, user.ID, "phone")
	ch := covStoreChallenge(t, db, user.ID, "pending", time.Now().Add(time.Minute))
	sig := dev.sign(t, ch, true, ch.MatchDigits)
	_ = db.Close()

	if ok, _, err := e.RespondPushChallenge(ch.ID, dev.id, ch.MatchDigits, true, sig); ok || err == nil {
		t.Fatalf("respond on closed store: ok=%v err=%v", ok, err)
	}
	if status, owner, err := e.CheckPushChallenge(ch.ID); err == nil || status != "" || owner != "" {
		t.Fatalf("check on closed store: %q %q %v", status, owner, err)
	}
}

// Polling a lapsed challenge reports expired and persists it, so the browser stops waiting;
// an unknown id is an error rather than an empty "pending".
func TestCheckPushChallengeExpiryAndUnknown(t *testing.T) {
	e, db, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	ch := covStoreChallenge(t, db, user.ID, "pending", time.Now().Add(-time.Second))

	status, owner, err := e.CheckPushChallenge(ch.ID)
	if err != nil || status != "expired" || owner != user.ID {
		t.Fatalf("lapsed challenge: %q %q %v", status, owner, err)
	}
	if got := covChallengeStatus(t, db, ch.ID); got != "expired" {
		t.Fatalf("stored status = %q", got)
	}
	// Already settled: an approved challenge past its deadline stays approved.
	approved := covStoreChallenge(t, db, user.ID, "approved", time.Now().Add(-time.Second))
	if status, _, err := e.CheckPushChallenge(approved.ID); err != nil || status != "approved" {
		t.Fatalf("settled challenge: %q %v", status, err)
	}
	if _, _, err := e.CheckPushChallenge(uuid.New().String()); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unknown challenge err = %v", err)
	}
}

// TOTP verification refuses a user who never enrolled, a secret sealed under another
// server key, and a wrong code, without spending anything.
func TestVerifyUserTOTPRefusals(t *testing.T) {
	e, db, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()

	if ok, err := e.VerifyUserTOTP(user.ID, "000000"); ok || err == nil || !strings.Contains(err.Error(), "not enrolled") {
		t.Fatalf("unenrolled: ok=%v err=%v", ok, err)
	}

	secret, _, err := e.GenerateTOTPSecret(user.Username, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SaveUserTOTP(user.ID, secret, nil); err != nil {
		t.Fatal(err)
	}
	code := currentTOTPCode(t, secret)
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	if ok, err := e.VerifyUserTOTP(user.ID, wrong); ok || err != nil {
		t.Fatalf("wrong code: ok=%v err=%v", ok, err)
	}

	otherKey, _ := crypto.GenerateRandomBytes(32)
	rotated := NewEngine(db, otherKey)
	if ok, err := rotated.VerifyUserTOTP(user.ID, code); ok || err == nil || !strings.Contains(err.Error(), "decrypt") {
		t.Fatalf("foreign server key: ok=%v err=%v", ok, err)
	}
	// The refusals above spent nothing: the real code still verifies once.
	if ok, err := e.VerifyUserTOTP(user.ID, code); !ok || err != nil {
		t.Fatalf("valid code after refusals: ok=%v err=%v", ok, err)
	}

	_ = db.Close()
	if ok, err := e.VerifyUserTOTP(user.ID, code); ok || err == nil {
		t.Fatalf("closed store: ok=%v err=%v", ok, err)
	}
}

// An empty issuer falls back to KyIdentity in the otpauth URL, and an undecodable secret
// never validates a code.
func TestTOTPSecretDefaultIssuerAndBadSecret(t *testing.T) {
	e, _, _, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	secret, uri, err := e.GenerateTOTPSecret("bob smith", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(uri, "otpauth://totp/KyIdentity:bob%20smith?secret="+secret) || !strings.Contains(uri, "&issuer=KyIdentity&") {
		t.Fatalf("uri = %q", uri)
	}
	if ValidateTOTP("not base32 !!", "123456") {
		t.Fatal("an undecodable secret validated a code")
	}
}

// Every write the engine makes reports a store failure instead of returning credentials
// that were never persisted.
func TestEngineWritesFailOnClosedStore(t *testing.T) {
	e, db, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	_ = db.Close()

	if codes, err := e.GenerateRecoveryCodes(user.ID, nil); err == nil || codes != nil {
		t.Errorf("recovery codes: %v %v", codes, err)
	}
	if tok, pin, _, err := e.GenerateDevicePairingToken(user.ID, false, nil); err == nil || tok != "" || pin != "" {
		t.Errorf("pairing token: %q %q %v", tok, pin, err)
	}
	if raw, err := e.IssueMFAToken(user.ID, "", time.Now()); err == nil || raw != "" {
		t.Errorf("mfa token: %q %v", raw, err)
	}
	if tok, err := e.ValidateMFAToken("abc"); err == nil || tok != nil {
		t.Errorf("validate mfa token: %v %v", tok, err)
	}
	for _, purpose := range []string{"login", "step_up"} {
		if ch, err := e.CreatePushChallenge(user.ID, purpose); err == nil || ch != nil {
			t.Errorf("%s challenge: %v %v", purpose, ch, err)
		}
	}
	_, pub := signingKey(t)
	for name, req := range map[string]*NativeDeviceRegisterRequest{
		"token": {PairingToken: "t", PublicKey: pub, PushToken: "fcm"},
		"pin":   {PINCode: "123456", UserID: user.ID, PublicKey: pub, PushToken: "fcm"},
	} {
		if dev, err := e.RegisterNativeDevice(req, nil); err == nil || dev != nil {
			t.Errorf("register by %s: %v %v", name, dev, err)
		}
	}
	if n, err := e.SweepAttestations(staticStatus{}, true, func(string, string, string) { t.Error("audited on a failed sweep") }); err == nil || n != 0 {
		t.Errorf("sweep: %d %v", n, err)
	}
}

// ValidateMFAToken rejects empty and oversized tokens before any lookup, and an unknown one.
func TestValidateMFATokenRejectsMalformed(t *testing.T) {
	e, _, _, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	for name, raw := range map[string]string{"empty": "", "oversized": strings.Repeat("a", 257), "unknown": "deadbeef"} {
		if tok, err := e.ValidateMFAToken(raw); err == nil || tok != nil {
			t.Errorf("%s: %v %v", name, tok, err)
		}
	}
}

// Once a token has spent MaxMFAAttempts, the engine reports ErrMFAAttemptsExhausted rather
// than a zero count a caller could mistake for success.
func TestReserveMFAAttemptReportsExhaustion(t *testing.T) {
	e, _, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	raw, err := e.IssueMFAToken(user.ID, "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	tok, err := e.ValidateMFAToken(raw)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= MaxMFAAttempts; i++ {
		if n, err := e.ReserveMFAAttempt(tok.ID); err != nil || n != i {
			t.Fatalf("attempt %d: n=%d err=%v", i, n, err)
		}
	}
	if n, err := e.ReserveMFAAttempt(tok.ID); !errors.Is(err, ErrMFAAttemptsExhausted) || n != 0 {
		t.Fatalf("attempt past the cap: n=%d err=%v", n, err)
	}
}

// Pairing needs a token, or a PIN together with the user it was issued to; and an
// unnamed device gets the default name.
func TestRegisterNativeDevicePairingInputs(t *testing.T) {
	e, db, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	_, pub := signingKey(t)

	for name, req := range map[string]*NativeDeviceRegisterRequest{
		"pin without user": {PINCode: "123456", PublicKey: pub, PushToken: "fcm"},
		"no credential":    {PublicKey: pub, PushToken: "fcm"},
		"unknown token":    {PairingToken: "never-issued", PublicKey: pub, PushToken: "fcm"},
	} {
		dev, err := e.RegisterNativeDevice(req, nil)
		var inputErr store.InputError
		if dev != nil || !errors.As(err, &inputErr) {
			t.Errorf("%s: dev=%v err=%v, want an input error", name, dev, err)
		}
	}
	if devs, _ := db.ListUserNativeDevices(user.ID); len(devs) != 0 {
		t.Fatalf("refused pairings stored %d devices", len(devs))
	}

	token, _, _, err := e.GenerateDevicePairingToken(user.ID, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	dev, err := e.RegisterNativeDevice(&NativeDeviceRegisterRequest{PairingToken: token, PublicKey: pub, PushToken: " fcm-token "}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if dev.DeviceName != "KyAuth Device" || dev.PushToken != "fcm-token" || dev.UserID != user.ID || dev.CanSignOn {
		t.Fatalf("device = %+v", dev)
	}
}

// A push target that smuggles a line break into its keys is refused at validation.
func TestValidatePushTargetRefusesLineBreakInKeys(t *testing.T) {
	rk := newReceiver(t)
	if _, err := ValidatePushTarget("ubuntupush", "tok", rk.p256dh+"\n", rk.a64); !errors.Is(err, errInvalidPushTarget) {
		t.Fatalf("p256dh with newline: %v", err)
	}
	if _, err := ValidatePushTarget("ubuntupush", "tok", rk.p256dh, rk.a64+"\r"); !errors.Is(err, errInvalidPushTarget) {
		t.Fatalf("auth with CR: %v", err)
	}
	if got, err := ValidatePushTarget("ubuntupush", "tok", rk.p256dh, rk.a64); err != nil || got != "ubuntupush" {
		t.Fatalf("clean keys: %q %v", got, err)
	}
}

// A send failure that is not a stale token leaves the device's push target in place:
// a transient outage must not unpair the authenticator.
func TestDispatchKeepsPushTargetOnTransientFailure(t *testing.T) {
	e, db, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	_, pub := signingKey(t)
	if err := db.UpsertNativeDevice(&store.NativeDevice{
		ID: uuid.New().String(), UserID: user.ID, DeviceName: "p", DeviceIdentifier: "p",
		PublicKey: pub, PushToken: "fcm-token", IsMFAApprover: true,
	}); err != nil {
		t.Fatal(err)
	}
	sender := &fakePushSender{err: errors.New("relay unavailable")}
	e.SetPushSender(sender)

	if _, err := e.CreatePushChallenge(user.ID, "step_up"); err != nil {
		t.Fatal(err)
	}
	if len(sender.sent) != 1 || sender.pushes[0].Username != user.Username {
		t.Fatalf("sent = %d pushes = %+v", len(sender.sent), sender.pushes)
	}
	devs, err := db.ListUserNativeDevices(user.ID)
	if err != nil || len(devs) != 1 || devs[0].PushToken != "fcm-token" {
		t.Fatalf("device after transient failure: %+v %v", devs, err)
	}
}
