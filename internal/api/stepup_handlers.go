package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/auth"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/Busnes-app/kyidentity-server/internal/webauthn"
	"github.com/google/uuid"
)

// Read-only enrollment preparation shares its grant with the final mutation.
func stepUpOperation(operation string) string {
	switch operation {
	case "POST /api/user/mfa/totp/setup":
		return "POST /api/user/mfa/totp/enable"
	case "POST /api/user/passkeys/register/begin":
		return "POST /api/user/passkeys/register/finish"
	}
	return operation
}

// The path is decoded URL.Path, so spaces and URL punctuation can be literal
// characters in an existing client ID. Only the exact consuming path can spend it.
func validStepUpOperation(operation string) bool {
	method, path, ok := strings.Cut(operation, " ")
	return ok && len(operation) <= 2048 && slices.Contains([]string{"GET", "POST", "PUT", "DELETE"}, method) && strings.HasPrefix(path, "/api/") && !strings.ContainsAny(path, "\x00\r\n")
}

func recoveryOperation(operation string) bool {
	return operation == "POST /api/user/mfa/totp/enable" || operation == "POST /api/user/passkeys/register/finish"
}

func (h *AuthHandler) stepUpMethods(userID, operation string) ([]string, error) {
	enrolled, err := h.store.ListUserMFAMethods(userID)
	if err != nil {
		return nil, err
	}
	methods := []string{}
	for _, m := range enrolled {
		if m.MethodType == "totp" || m.MethodType == "push" {
			methods = append(methods, m.MethodType)
		}
	}
	keys, err := h.store.ListUserWebAuthnCredentials(userID)
	if err != nil {
		return nil, err
	}
	if len(keys) > 0 {
		methods = append(methods, "webauthn")
	}
	if len(methods) > 0 && recoveryOperation(operation) {
		methods = append(methods, "recovery")
	}
	return methods, nil
}

func (h *AuthHandler) StepUpMethods(w http.ResponseWriter, r *http.Request) {
	methods, err := h.stepUpMethods(GetUserFromContext(r.Context()).ID, stepUpOperation(r.URL.Query().Get("operation")))
	if err != nil {
		stepUpInternalError(w)
		return
	}
	writeStepUpJSON(w, map[string]any{"methods": methods})
}

type stepUpRequest struct {
	Password  string `json:"password"`
	Code      string `json:"code"`
	Method    string `json:"method"`
	Operation string `json:"operation"`
}

func (h *AuthHandler) RequestStepUp(w http.ResponseWriter, r *http.Request, wh *WebAuthnHandler) {
	user, sess := GetUserFromContext(r.Context()), GetSessionFromContext(r.Context())
	var req stepUpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Password == "" || !validStepUpOperation(req.Operation) {
		auth.DummyVerify(req.Password)
		http.Error(w, `{"error":"invalid_request","error_description":"Password and target operation are required"}`, 400)
		return
	}
	enrollment, err := h.store.SessionEnrollmentStatus(user.ID, sess.ID)
	if err != nil {
		stepUpInternalError(w)
		return
	}
	if enrollment.Restricted && !enrollmentOperationAllowed(stepUpOperation(req.Operation)) {
		http.Error(w, `{"error":"enrollment_required"}`, 403)
		return
	}
	locked, err := h.store.IsAccountLocked(user.ID)
	if err != nil {
		stepUpInternalError(w)
		return
	}
	if locked {
		h.audit.Record("auth.step_up", user.ID, user.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "denied", map[string]any{"reason": "account_locked", "operation": stepUpOperation(req.Operation)})
		http.Error(w, `{"error":"account_locked"}`, 429)
		return
	}
	valid, err := auth.VerifyPassword(req.Password, user.PasswordHash)
	if err != nil || !valid {
		h.stepUpFailure(w, r, "bad_password")
		return
	}
	primaryAt := time.Now().UTC()
	req.Operation = stepUpOperation(req.Operation)
	methods, err := h.stepUpMethods(user.ID, req.Operation)
	if err != nil {
		stepUpInternalError(w)
		return
	}
	if len(methods) > 0 && !slices.Contains(methods, req.Method) {
		h.audit.Record("auth.step_up", user.ID, user.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "denied", map[string]any{"reason": "mfa_required", "method": req.Method, "operation": req.Operation})
		http.Error(w, `{"error":"mfa_required","error_description":"Choose an enrolled factor; recovery codes only authorize replacement factor enrollment"}`, 400)
		return
	}
	if len(methods) == 0 && req.Method != "" {
		http.Error(w, `{"error":"invalid_method"}`, 400)
		return
	}
	raw, err := crypto.GenerateRandomHex(32)
	if err != nil {
		stepUpInternalError(w)
		return
	}
	expires := primaryAt.Add(StepUpTTL)
	if sess.ExpiresAt.Before(expires) {
		expires = sess.ExpiresAt
	}
	grant := &store.StepUpToken{ID: uuid.NewString(), UserID: user.ID, SessionID: sess.ID, TokenHash: crypto.HashSHA256(raw), Operation: req.Operation, FactorMethod: req.Method, ExpiresAt: expires}
	switch req.Method {
	case "totp", "recovery":
		if req.Method == "totp" {
			valid, err = h.mfaEngine.VerifyUserTOTP(user.ID, req.Code)
		} else {
			valid, err = h.mfaEngine.VerifyAndConsumeRecoveryCode(user.ID, req.Code)
		}
		if err != nil {
			stepUpInternalError(w)
			return
		}
		if !valid {
			h.stepUpFailure(w, r, "bad_second_factor")
			return
		}
	case "push", "webauthn":
		c := &store.StepUpChallenge{TokenHash: grant.TokenHash, UserID: user.ID, SessionID: sess.ID, Operation: req.Operation, Method: req.Method, PrimaryAuthenticatedAt: primaryAt, ExpiresAt: expires}
		response := map[string]any{"kind": "challenge", "challengeToken": raw, "method": req.Method, "expiresAt": expires}
		if req.Method == "push" {
			challenge, err := h.mfaEngine.CreatePushChallenge(user.ID)
			if err != nil {
				stepUpInternalError(w)
				return
			}
			c.Proof = challenge.ID
			response["matchDigits"] = challenge.MatchDigits
		} else {
			c.Proof, err = crypto.GenerateRandomHex(32)
			if err != nil {
				stepUpInternalError(w)
				return
			}
			keys, err := h.store.ListUserWebAuthnCredentials(user.ID)
			if err != nil {
				stepUpInternalError(w)
				return
			}
			ids := make([]string, 0, len(keys))
			for _, key := range keys {
				ids = append(ids, key.CredentialID)
			}
			response["passkey"] = beginLoginResponse{Challenge: c.Proof, RPID: wh.rpID, AllowCredentials: ids}
		}
		issued := h.audit.Prepare("auth.step_up_challenge", user.ID, user.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"reason": "challenge_issued", "method": req.Method, "operation": req.Operation})
		if err := h.store.CreateStepUpChallenge(c, issued.Row); err != nil {
			stepUpInternalError(w)
			return
		}
		issued.Committed()
		writeStepUpJSON(w, response)
		return
	}
	event := h.audit.Prepare("auth.step_up", user.ID, user.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"method": req.Method, "operation": req.Operation, "recovery": req.Method == "recovery"})
	if err := h.store.CreateStepUpToken(grant, event.Row); err != nil {
		stepUpInternalError(w)
		return
	}
	event.Committed()
	_ = h.store.ClearFailedLogins(user.ID)
	writeStepUpJSON(w, map[string]any{"kind": "grant", "stepUpToken": raw, "expiresAt": expires})
}

type finishStepUpRequest struct {
	ChallengeToken string             `json:"challengeToken"`
	Assertion      finishLoginRequest `json:"assertion"`
}

func (h *AuthHandler) FinishStepUp(w http.ResponseWriter, r *http.Request, wh *WebAuthnHandler) {
	user, sess := GetUserFromContext(r.Context()), GetSessionFromContext(r.Context())
	var req finishStepUpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ChallengeToken == "" {
		http.Error(w, `{"error":"invalid_request"}`, 400)
		return
	}
	c, err := h.store.GetStepUpChallenge(crypto.HashSHA256(req.ChallengeToken), user.ID, sess.ID)
	if err != nil {
		stepUpInternalError(w)
		return
	}
	if c == nil {
		http.Error(w, `{"error":"invalid_challenge","error_description":"Restart re-authentication"}`, 400)
		return
	}
	locked, err := h.store.IsAccountLocked(user.ID)
	if err != nil {
		stepUpInternalError(w)
		return
	}
	if locked {
		h.audit.Record("auth.step_up", user.ID, user.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "denied", map[string]any{"reason": "account_locked", "method": c.Method, "operation": c.Operation})
		http.Error(w, `{"error":"account_locked"}`, 429)
		return
	}
	// Enrollment may have changed since the password step. A removed method cannot finish.
	methods, err := h.stepUpMethods(user.ID, c.Operation)
	if err != nil {
		stepUpInternalError(w)
		return
	}
	if !slices.Contains(methods, c.Method) {
		http.Error(w, `{"error":"invalid_method"}`, 400)
		return
	}
	switch c.Method {
	case "push":
		challenge, err := h.store.GetMFAChallenge(c.Proof)
		if err != nil {
			stepUpInternalError(w)
			return
		}
		if challenge != nil && challenge.UserID == user.ID && challenge.ExpiresAt.After(time.Now().UTC()) {
			if challenge.Status == "pending" {
				writeStepUpJSON(w, map[string]any{"kind": "pending"})
				return
			}
			if challenge.Status == "approved" && challenge.VerifiedAt != nil {
				break
			}
		}
		_ = h.store.CancelStepUp(c.TokenHash, user.ID, sess.ID)
		http.Error(w, `{"error":"push_denied","error_description":"Approval was denied or expired; restart re-authentication"}`, 400)
		return
	case "webauthn":
		if err := wh.verifyStepUpAssertion(user.ID, c.Proof, req.Assertion); err != nil {
			if err := h.store.FailStepUpChallenge(c.TokenHash); err != nil {
				stepUpInternalError(w)
				return
			}
			h.stepUpFailure(w, r, "bad_second_factor")
			return
		}
	default:
		http.Error(w, `{"error":"invalid_method"}`, 400)
		return
	}
	grant := &store.StepUpToken{ID: uuid.NewString(), UserID: user.ID, SessionID: sess.ID, TokenHash: c.TokenHash, Operation: c.Operation, FactorMethod: c.Method, ExpiresAt: c.ExpiresAt}
	event := h.audit.Prepare("auth.step_up", user.ID, user.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"method": c.Method, "operation": c.Operation})
	completed, err := h.store.CompleteStepUpChallenge(c, grant, event.Row)
	if err != nil {
		stepUpInternalError(w)
		return
	}
	if !completed {
		http.Error(w, `{"error":"invalid_challenge"}`, 400)
		return
	}
	event.Committed()
	_ = h.store.ClearFailedLogins(user.ID)
	writeStepUpJSON(w, map[string]any{"kind": "grant", "stepUpToken": req.ChallengeToken, "expiresAt": c.ExpiresAt})
}

func (h *WebAuthnHandler) verifyStepUpAssertion(userID, challenge string, req finishLoginRequest) error {
	cred, err := h.store.GetWebAuthnCredential(userID, req.CredentialID)
	if err != nil {
		return err
	}
	if cred == nil {
		return errors.New("unknown credential")
	}
	authData, e1 := base64.RawURLEncoding.DecodeString(req.AuthenticatorData)
	clientData, e2 := base64.RawURLEncoding.DecodeString(req.ClientDataJSON)
	signature, e3 := base64.RawURLEncoding.DecodeString(req.Signature)
	key, e4 := base64.RawURLEncoding.DecodeString(cred.PublicKeySPKI)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		return errors.New("invalid assertion encoding")
	}
	ad, err := webauthn.VerifyAssertion(webauthn.AssertionInput{AuthenticatorData: authData, ClientDataJSON: clientData, Signature: signature, PublicKeySPKI: key, Challenge: challenge, Origin: h.origin, RPID: h.rpID, StoredSignCount: cred.SignCount, BackupEligible: cred.BackupEligible})
	if err != nil {
		return err
	}
	return h.store.RecordWebAuthnUse(cred.ID, ad.SignCount, ad.BackupState(), time.Now().UTC())
}

func (h *AuthHandler) CancelStepUp(w http.ResponseWriter, r *http.Request) {
	var req finishStepUpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ChallengeToken == "" {
		http.Error(w, `{"error":"invalid_request"}`, 400)
		return
	}
	if err := h.store.CancelStepUp(crypto.HashSHA256(req.ChallengeToken), GetUserFromContext(r.Context()).ID, GetSessionFromContext(r.Context()).ID); err != nil {
		stepUpInternalError(w)
		return
	}
	writeStepUpJSON(w, map[string]bool{"success": true})
}

func (h *AuthHandler) stepUpFailure(w http.ResponseWriter, r *http.Request, reason string) {
	user := GetUserFromContext(r.Context())
	_, _ = h.store.RecordFailedLogin(user.ID)
	h.audit.Record("auth.step_up", user.ID, user.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "denied", map[string]any{"reason": reason})
	http.Error(w, `{"error":"invalid_credentials","error_description":"Re-authentication failed"}`, 401)
}

func stepUpInternalError(w http.ResponseWriter) { http.Error(w, `{"error":"internal_error"}`, 500) }
func writeStepUpJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}
