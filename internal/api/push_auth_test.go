package api

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/auth"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/mfa"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

const testPassword = "valid-secret-password-123"

const testIssuerOrigin = "http://localhost:5867"

type pushFixture struct {
	server   *Server
	store    *store.Store
	user     *store.User
	deviceID string
	devKey   *ecdsa.PrivateKey
	csrf     string
	cookie   *http.Cookie
}

// newPushFixture builds a user enrolled in push MFA with one signing authenticator.
func newPushFixture(t *testing.T) (*pushFixture, func()) {
	t.Helper()

	server, dbStore, _, _, _, cleanup := setupTestServer(t)

	passHash, err := auth.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}
	user := &store.User{
		ID: uuid.New().String(), Username: "alice", DisplayName: "Alice",
		Email: "alice@example.com", PasswordHash: passHash, Role: "user", Status: "active",
	}
	if err := dbStore.CreateUser(user); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey failed: %v", err)
	}

	device := &store.NativeDevice{
		ID: uuid.New().String(), UserID: user.ID, DeviceName: "phone",
		DeviceIdentifier: "phone-1", PublicKey: base64.StdEncoding.EncodeToString(der),
		IsMFAApprover: true,
	}
	if err := dbStore.UpsertNativeDevice(device); err != nil {
		t.Fatalf("UpsertNativeDevice failed: %v", err)
	}
	if err := dbStore.SetMFAMethod(&store.MFAMethod{
		ID: uuid.New().String(), UserID: user.ID, MethodType: "push",
	}, nil); err != nil {
		t.Fatalf("SetMFAMethod failed: %v", err)
	}

	f := &pushFixture{server: server, store: dbStore, user: user, deviceID: device.ID, devKey: priv}

	rec := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(rec, httptest.NewRequest("GET", "/api/auth/csrf", nil))
	var csrfResp struct {
		CSRFToken string `json:"csrfToken"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&csrfResp); err != nil {
		t.Fatalf("decode csrf response: %v", err)
	}
	f.csrf = csrfResp.CSRFToken
	f.cookie = rec.Result().Cookies()[0]

	return f, cleanup
}

func (f *pushFixture) post(t *testing.T, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest("POST", path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", f.csrf)
	req.AddCookie(f.cookie)
	rec := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rec, req)
	return rec
}

// login performs the password step and returns the issued mfaToken and challengeId.
func (f *pushFixture) login(t *testing.T) (mfaToken, challengeID string) {
	t.Helper()
	rec := f.post(t, "/api/auth/login", map[string]string{"username": "alice", "password": testPassword})
	if rec.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", rec.Code, rec.Body.String())
	}
	var resp LoginResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if !resp.MFARequired || resp.MFAToken == "" || resp.ChallengeID == "" {
		t.Fatalf("expected an MFA challenge, got %+v", resp)
	}
	return resp.MFAToken, resp.ChallengeID
}

func (f *pushFixture) sign(t *testing.T, ch *store.MFAChallenge, approve bool, digits string) string {
	t.Helper()
	return signPush(t, f.devKey, f.deviceID, ch, testIssuerOrigin, approve, digits)
}

// signPush signs the v2 message for one device and challenge.
func signPush(t *testing.T, key *ecdsa.PrivateKey, deviceID string, ch *store.MFAChallenge, origin string, approve bool, digits string) string {
	t.Helper()
	msg, err := mfa.PushResponseMessage(mfa.PushBinding{Origin: origin, UserID: ch.UserID, DeviceID: deviceID, ChallengeID: ch.ID,
		Purpose: ch.Purpose, ExpiresAtMS: ch.ExpiresAt.UnixMilli()}, approve, digits)
	if err != nil {
		t.Fatalf("PushResponseMessage failed: %v", err)
	}
	digest := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("SignASN1 failed: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func sessionCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == "kyidentity_session" && c.Value != "" {
			return c
		}
	}
	return nil
}

// TestForgedMFATokenCannotFinishPushLogin is the regression test for the authentication
// bypass in which the server parsed a user ID out of an unvalidated client string, and
// never checked that the approved challenge belonged to that user.
func TestForgedMFATokenCannotFinishPushLogin(t *testing.T) {
	f, cleanup := newPushFixture(t)
	defer cleanup()

	// An attacker-controlled account with its own genuinely approved challenge.
	mallory := &store.User{
		ID: uuid.New().String(), Username: "mallory", Email: "mallory@example.com",
		PasswordHash: "mock-hash", Role: "user", Status: "active",
	}
	if err := f.store.CreateUser(mallory); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	mPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mDER, _ := x509.MarshalPKIXPublicKey(&mPriv.PublicKey)
	mDevID := uuid.New().String()
	if err := f.store.UpsertNativeDevice(&store.NativeDevice{
		ID: mDevID, UserID: mallory.ID, DeviceName: "mallory-phone",
		DeviceIdentifier: "mallory-phone", PublicKey: base64.StdEncoding.EncodeToString(mDER),
		IsMFAApprover: true,
	}); err != nil {
		t.Fatalf("UpsertNativeDevice failed: %v", err)
	}

	challenge, err := f.server.mfaEngine.CreatePushChallenge(mallory.ID, "login")
	if err != nil {
		t.Fatalf("CreatePushChallenge failed: %v", err)
	}
	approved, _, err := f.server.mfaEngine.RespondPushChallenge(
		challenge.ID, mDevID, challenge.MatchDigits, true, signPush(t, mPriv, mDevID, challenge, testIssuerOrigin, true, challenge.MatchDigits))
	if err != nil || !approved {
		t.Fatalf("setup: expected mallory's own challenge to be approved, got %v %v", approved, err)
	}

	// The old exploit: claim the victim's user ID in the token, present an approved challenge.
	for _, forged := range []string{
		"deadbeefdeadbeef:" + f.user.ID,
		f.user.ID,
		"",
	} {
		rec := f.post(t, "/api/auth/mfa/push/finish", map[string]string{
			"mfaToken":    forged,
			"challengeId": challenge.ID,
		})
		if rec.Code == http.StatusOK {
			t.Fatalf("forged mfaToken %q was accepted: %s", forged, rec.Body.String())
		}
		if sessionCookie(rec) != nil {
			t.Fatalf("forged mfaToken %q issued a session cookie", forged)
		}
	}
}

// approvedChallengeFor creates an approved push challenge owned by a freshly made user.
func (f *pushFixture) approvedChallengeFor(t *testing.T, username string) *store.MFAChallenge {
	t.Helper()

	other := &store.User{
		ID: uuid.New().String(), Username: username, Email: username + "@example.com",
		PasswordHash: "mock-hash", Role: "user", Status: "active",
	}
	if err := f.store.CreateUser(other); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	challenge, err := f.server.mfaEngine.CreatePushChallenge(other.ID, "login")
	if err != nil {
		t.Fatalf("CreatePushChallenge failed: %v", err)
	}
	moved, err := f.store.TransitionMFAChallengeStatus(challenge.ID, "pending", "approved")
	if err != nil || !moved {
		t.Fatalf("setup: could not approve challenge (moved=%v err=%v)", moved, err)
	}
	return challenge
}

// TestApprovedChallengeIsBoundToItsOwnToken covers both bindings that must hold before a
// session is issued: the token must name this challenge, and the challenge must belong to
// the token's user.
func TestApprovedChallengeIsBoundToItsOwnToken(t *testing.T) {
	f, cleanup := newPushFixture(t)
	defer cleanup()

	t.Run("token issued for a different challenge", func(t *testing.T) {
		victimToken, _ := f.login(t)
		foreign := f.approvedChallengeFor(t, "bob")

		rec := f.post(t, "/api/auth/mfa/push/finish", map[string]string{
			"mfaToken":    victimToken,
			"challengeId": foreign.ID,
		})
		if rec.Code == http.StatusOK || sessionCookie(rec) != nil {
			t.Fatalf("token accepted against an unrelated challenge: %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("token bound to a challenge owned by someone else", func(t *testing.T) {
		foreign := f.approvedChallengeFor(t, "carol")

		// Forge the strongest possible token: a real, unexpired record naming the victim,
		// bound to a challenge that is genuinely approved but belongs to another user.
		raw, err := crypto.GenerateRandomHex(32)
		if err != nil {
			t.Fatalf("GenerateRandomHex failed: %v", err)
		}
		if err := f.store.CreateMFAToken(&store.MFAToken{
			ID:          uuid.New().String(),
			UserID:      f.user.ID,
			TokenHash:   crypto.HashSHA256(raw),
			ChallengeID: foreign.ID,
			ExpiresAt:   time.Now().UTC().Add(time.Minute),
		}); err != nil {
			t.Fatalf("CreateMFAToken failed: %v", err)
		}

		rec := f.post(t, "/api/auth/mfa/push/finish", map[string]string{
			"mfaToken":    raw,
			"challengeId": foreign.ID,
		})
		if rec.Code == http.StatusOK || sessionCookie(rec) != nil {
			t.Fatalf("another user's approved challenge issued a session: %d %s", rec.Code, rec.Body.String())
		}
	})
}

func TestUnsignedPushResponseIsRejectedOverHTTP(t *testing.T) {
	f, cleanup := newPushFixture(t)
	defer cleanup()

	_, challengeID := f.login(t)
	challenge, err := f.store.GetMFAChallenge(challengeID)
	if err != nil || challenge == nil {
		t.Fatalf("GetMFAChallenge failed: %v", err)
	}

	// Knowing the match digits is no longer enough to approve anything.
	rec := f.post(t, "/api/mfa/push/respond", map[string]any{
		"challengeId":    challengeID,
		"selectedDigits": challenge.MatchDigits,
		"approve":        true,
	})
	if rec.Code == http.StatusOK {
		t.Fatalf("unsigned push approval was accepted: %s", rec.Body.String())
	}

	status, _, err := f.server.mfaEngine.CheckPushChallenge(challengeID)
	if err != nil {
		t.Fatalf("CheckPushChallenge failed: %v", err)
	}
	if status != "pending" {
		t.Fatalf("expected challenge to stay pending after a rejected response, got %s", status)
	}
}

func TestPushHappyPathStillWorks(t *testing.T) {
	f, cleanup := newPushFixture(t)
	defer cleanup()

	mfaToken, challengeID := f.login(t)
	challenge, err := f.store.GetMFAChallenge(challengeID)
	if err != nil || challenge == nil {
		t.Fatalf("GetMFAChallenge failed: %v", err)
	}

	rec := f.post(t, "/api/mfa/push/respond", map[string]any{
		"challengeId":    challengeID,
		"deviceId":       f.deviceID,
		"selectedDigits": challenge.MatchDigits,
		"approve":        true,
		"signature":      f.sign(t, challenge, true, challenge.MatchDigits),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("signed approval rejected: %d %s", rec.Code, rec.Body.String())
	}

	// Poll requires the token issued with the challenge.
	if rec := f.post(t, "/api/auth/mfa/push/poll", map[string]string{"challengeId": challengeID}); rec.Code == http.StatusOK {
		t.Fatalf("poll without an mfaToken was accepted: %s", rec.Body.String())
	}

	pollRec := f.post(t, "/api/auth/mfa/push/poll", map[string]string{
		"mfaToken": mfaToken, "challengeId": challengeID,
	})
	if pollRec.Code != http.StatusOK {
		t.Fatalf("poll failed: %d %s", pollRec.Code, pollRec.Body.String())
	}
	var poll struct {
		Status string `json:"status"`
	}
	_ = json.NewDecoder(pollRec.Body).Decode(&poll)
	if poll.Status != "approved" {
		t.Fatalf("expected approved status, got %q", poll.Status)
	}

	finishRec := f.post(t, "/api/auth/mfa/push/finish", map[string]string{
		"mfaToken": mfaToken, "challengeId": challengeID,
	})
	if finishRec.Code != http.StatusOK {
		t.Fatalf("finish failed: %d %s", finishRec.Code, finishRec.Body.String())
	}
	if sessionCookie(finishRec) == nil {
		t.Fatal("expected a session cookie after a fully signed push login")
	}

	sess := assertFactorEvidence(t, f.store, finishRec, "push")
	approved, err := f.store.GetMFAChallenge(challengeID)
	if err != nil || approved == nil || approved.VerifiedAt == nil || !sess.FactorAuthenticatedAt.Equal(*approved.VerifiedAt) {
		t.Fatalf("push finish did not preserve approval time: %v", err)
	}
	// The token is spent; a replay must not mint a second session.
	replayRec := f.post(t, "/api/auth/mfa/push/finish", map[string]string{
		"mfaToken": mfaToken, "challengeId": challengeID,
	})
	if replayRec.Code == http.StatusOK || sessionCookie(replayRec) != nil {
		t.Fatalf("replayed mfaToken issued a second session: %d %s", replayRec.Code, replayRec.Body.String())
	}
}

// TestLoginResponseCarriesNoKeyMaterial guards the boundary the split-key work will land on.
func TestLoginResponseCarriesNoKeyMaterial(t *testing.T) {
	f, cleanup := newPushFixture(t)
	defer cleanup()

	rec := f.post(t, "/api/auth/login", map[string]string{"username": "alice", "password": testPassword})
	if rec.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", rec.Code, rec.Body.String())
	}

	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	for _, forbidden := range []string{"serverShare", "clientShare", "wrappedClientShare", "kcv", "passwordHash"} {
		if _, present := body[forbidden]; present {
			t.Fatalf("login response leaked %q: %+v", forbidden, body)
		}
	}
}

// respondTo posts a push response and returns the recorder.
func (f *pushFixture) respondTo(t *testing.T, ch *store.MFAChallenge, deviceID, signature string) *httptest.ResponseRecorder {
	t.Helper()
	body := map[string]any{"challengeId": ch.ID, "selectedDigits": ch.MatchDigits, "approve": true, "signature": signature}
	if deviceID != "" {
		body["deviceId"] = deviceID
	}
	return f.post(t, "/api/mfa/push/respond", body)
}

func (f *pushFixture) requirePending(t *testing.T, challengeID string) {
	t.Helper()
	if status, _, err := f.server.mfaEngine.CheckPushChallenge(challengeID); err != nil || status != "pending" {
		t.Fatalf("challenge status = %q, %v; want pending", status, err)
	}
}

func TestPushRespondRejectsAnotherUsersDevice(t *testing.T) {
	f, cleanup := newPushFixture(t)
	defer cleanup()

	bob := &store.User{ID: uuid.New().String(), Username: "bob", Email: "bob@example.com", PasswordHash: "mock-hash", Role: "user", Status: "active"}
	if err := f.store.CreateUser(bob); err != nil {
		t.Fatal(err)
	}
	bKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bDER, _ := x509.MarshalPKIXPublicKey(&bKey.PublicKey)
	bDevID := uuid.New().String()
	if err := f.store.UpsertNativeDevice(&store.NativeDevice{ID: bDevID, UserID: bob.ID, DeviceName: "bob-phone", DeviceIdentifier: "bob-phone",
		PublicKey: base64.StdEncoding.EncodeToString(bDER), IsMFAApprover: true}); err != nil {
		t.Fatal(err)
	}

	_, challengeID := f.login(t)
	ch, err := f.store.GetMFAChallenge(challengeID)
	if err != nil || ch == nil {
		t.Fatal(err)
	}
	rec := f.respondTo(t, ch, bDevID, signPush(t, bKey, bDevID, ch, testIssuerOrigin, true, ch.MatchDigits))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "challenge_error") {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	f.requirePending(t, challengeID)
}

func TestPushRespondRejectsV1Signature(t *testing.T) {
	f, cleanup := newPushFixture(t)
	defer cleanup()

	_, challengeID := f.login(t)
	ch, err := f.store.GetMFAChallenge(challengeID)
	if err != nil || ch == nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("kysignon-push-v1|" + ch.ID + "|approve|" + ch.MatchDigits))
	sig, _ := ecdsa.SignASN1(rand.Reader, f.devKey, digest[:])
	rec := f.respondTo(t, ch, f.deviceID, base64.StdEncoding.EncodeToString(sig))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("v1 signature: %d %s", rec.Code, rec.Body.String())
	}
	f.requirePending(t, challengeID)
}

func TestPushRespondRequiresDeviceID(t *testing.T) {
	f, cleanup := newPushFixture(t)
	defer cleanup()

	_, challengeID := f.login(t)
	ch, err := f.store.GetMFAChallenge(challengeID)
	if err != nil || ch == nil {
		t.Fatal(err)
	}
	rec := f.respondTo(t, ch, "", f.sign(t, ch, true, ch.MatchDigits))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing deviceId: %d %s", rec.Code, rec.Body.String())
	}
	f.requirePending(t, challengeID)
}
