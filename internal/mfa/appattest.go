package mfa

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"

	"github.com/Busnes-app/kyidentity-server/internal/appattest"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// AppAttestEvidence is KyAuth iOS's App Attest output for one pairing.
type AppAttestEvidence struct {
	KeyID       string `json:"keyId"`
	Attestation string `json:"attestation"` // standard base64 of the CBOR attestation object
}

// AppAttestor verifies an App Attest attestation object; a non-nil error is the reason it failed.
type AppAttestor interface {
	Verify(keyID string, attestation, clientDataHash []byte) error
}

// SetAppAttestor installs the App Attest verifier; nil grades every iOS registration none.
func (e *Engine) SetAppAttestor(a AppAttestor) { e.appAttestor = a }

// AppAttestClientData is the clientData KyAuth iOS hashes into its attestation: it binds the
// pairing credential and the exact publicKey string the request carries.
func AppAttestClientData(req *NativeDeviceRegisterRequest) []byte {
	cred := req.PairingToken
	if cred == "" {
		cred = req.UserID + "|" + req.PINCode
	}
	return []byte("kyidentity-appattest-v1|" + cred + "|" + req.PublicKey)
}

// gradeAppAttest grades an iOS registration. App Attest proves a genuine KyAuth build, not
// where its signing key lives or that a user was present, so the grade earns no second
// factor. Failures stay in the audit row and log.
func (e *Engine) gradeAppAttest(req *NativeDeviceRegisterRequest, device *store.NativeDevice) {
	if req.AppAttest == nil {
		return
	}
	device.AttestedLevel, device.BootState = "none", "unknown"
	if e.appAttestor == nil {
		device.AttestationReason = "app attest not configured"
		return
	}
	obj, err := base64.StdEncoding.DecodeString(req.AppAttest.Attestation)
	if err != nil {
		device.AttestationReason = string(appattest.ReasonDecode)
		e.logGradedNone(device.UserID, device.AttestationReason, err)
		return
	}
	sum := sha256.Sum256(AppAttestClientData(req))
	err = e.appAttestor.Verify(req.AppAttest.KeyID, obj, sum[:])
	if err == nil {
		device.AttestedLevel = "appattest"
		return
	}
	// The audit row keeps the fixed classification; the detail goes only to the log.
	var failure *appattest.Error
	if errors.As(err, &failure) {
		device.AttestationReason = string(failure.Reason)
	} else {
		device.AttestationReason = "app attest verification failed"
	}
	e.logGradedNone(device.UserID, device.AttestationReason, err)
}

// logGradedNone records a refused App Attest as one structured record: the actor, the fixed
// reason kept in the audit row, and the diagnostic detail, as separate fields.
func (e *Engine) logGradedNone(userID, reason string, detail error) {
	logger := e.logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.Warn("ios pairing graded none", "user", userID, "reason", reason, "detail", detail.Error())
}
