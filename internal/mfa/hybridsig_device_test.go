package mfa

import (
	"encoding/base64"
	"testing"

	"github.com/Busnes-app/ky-primitives/hybridsig"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
)

func TestHybridSigDeviceEnrollmentAndPushApprove(t *testing.T) {
	engine, _, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()

	token, _, _, err := engine.GenerateDevicePairingToken(user.ID, true, nil)
	if err != nil {
		t.Fatalf("GenerateDevicePairingToken: %v", err)
	}

	priv, err := hybridsig.Generate()
	if err != nil {
		t.Fatalf("hybridsig.Generate: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(priv.Public().Bytes())

	dev, err := engine.RegisterNativeDevice(&NativeDeviceRegisterRequest{
		PairingToken:     token,
		DeviceName:       "KyAuth Linux Hybrid",
		DeviceIdentifier: "kyauth-linux-hybrid-1",
		PublicKey:        pubB64,
		PushToken:        "fcm-token-1",
	}, nil)
	if err != nil {
		t.Fatalf("RegisterNativeDevice(hybridsig): %v", err)
	}

	ch, err := engine.CreatePushChallenge(user.ID, "login")
	if err != nil {
		t.Fatalf("CreatePushChallenge: %v", err)
	}

	msg, err := PushResponseMessage(PushBinding{
		Origin: testOrigin, UserID: user.ID, DeviceID: dev.ID, ChallengeID: ch.ID,
		Purpose: ch.Purpose, ExpiresAtMS: ch.ExpiresAt.UnixMilli(),
	}, true, ch.MatchDigits)
	if err != nil {
		t.Fatalf("PushResponseMessage: %v", err)
	}

	// Wrong label must be rejected without mutating the pending challenge.
	wrongLabelSig, err := priv.Sign(crypto.DevicePushTokenLabel, msg)
	if err != nil {
		t.Fatalf("Sign wrong label: %v", err)
	}
	if _, _, err := engine.RespondPushChallenge(ch.ID, dev.ID, ch.MatchDigits, true, base64.StdEncoding.EncodeToString(wrongLabelSig)); err == nil {
		t.Fatal("expected wrong-label hybridsig response to be rejected")
	}

	// Valid label verifies and approves the challenge.
	goodSig, err := priv.Sign(crypto.DevicePushResponseLabel, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	approved, responderID, err := engine.RespondPushChallenge(ch.ID, dev.ID, ch.MatchDigits, true, base64.StdEncoding.EncodeToString(goodSig))
	if err != nil {
		t.Fatalf("RespondPushChallenge(hybridsig): %v", err)
	}
	if !approved || responderID != dev.ID {
		t.Fatalf("approved=%v responder=%q want true/%q", approved, responderID, dev.ID)
	}
}
