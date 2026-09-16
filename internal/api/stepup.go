package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// StepUpTTL is how long a step-up grant stays valid. Long enough to scan a QR code and read
// a rotating code off an authenticator, short enough that it is not a second session token.
const StepUpTTL = 5 * time.Minute

// StepUpHeader carries the grant on the operation it authorizes.
const StepUpHeader = "X-KyIdentity-StepUp"

var errStepUpRequired = errors.New("step-up authentication required")

// requireStepUp checks the grant carried on this request without spending it. Use for
// read-only steps that should fail early rather than after the operator has done work.
func requireStepUp(s *store.Store, r *http.Request) error {
	user := GetUserFromContext(r.Context())
	sess := GetSessionFromContext(r.Context())
	raw := r.Header.Get(StepUpHeader)
	if user == nil || sess == nil || raw == "" {
		return errStepUpRequired
	}
	valid, err := s.HasValidStepUpToken(crypto.HashSHA256(raw), user.ID, sess.ID, stepUpOperation(r.Method+" "+r.URL.Path))
	if err != nil {
		return err
	}
	if !valid {
		return errStepUpRequired
	}
	return nil
}

// consumeStepUp spends the grant carried on this request. Every mutating account-security
// operation calls this, so one re-authentication authorizes exactly one change.
func consumeStepUp(s *store.Store, r *http.Request) error {
	user := GetUserFromContext(r.Context())
	sess := GetSessionFromContext(r.Context())
	raw := r.Header.Get(StepUpHeader)
	if user == nil || sess == nil || raw == "" {
		return errStepUpRequired
	}
	spent, err := s.ConsumeStepUpToken(crypto.HashSHA256(raw), user.ID, sess.ID, stepUpOperation(r.Method+" "+r.URL.Path))
	if err != nil {
		return err
	}
	if !spent {
		return errStepUpRequired
	}
	return nil
}

// writeStepUpError distinguishes "you need to re-authenticate" from a server fault so the UI
// can prompt instead of showing a dead end.
func writeStepUpError(w http.ResponseWriter, err error) {
	if errors.Is(err, errStepUpRequired) {
		http.Error(w, `{"error":"step_up_required","error_description":"Re-enter your password to change account security settings"}`, http.StatusForbidden)
		return
	}
	http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
}
