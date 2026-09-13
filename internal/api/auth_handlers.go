package api

import (
	"encoding/json"
	"errors"
	"github.com/Busness-app/kysignon-server/internal/oauth"
	"log"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/Busness-app/kysignon-server/internal/audit"
	"github.com/Busness-app/kysignon-server/internal/auth"
	"github.com/Busness-app/kysignon-server/internal/crypto"
	"github.com/Busness-app/kysignon-server/internal/mfa"
	"github.com/Busness-app/kysignon-server/internal/store"
	"github.com/google/uuid"
)

type AuthHandler struct {
	store         *store.Store
	mfaEngine     *mfa.Engine
	audit         *audit.Logger
	middleware    *MiddlewareManager
	secureCookies bool
	sessionTTL    time.Duration
}

func NewAuthHandler(s *store.Store, mfaEngine *mfa.Engine, audit *audit.Logger, mm *MiddlewareManager, secureCookies bool) *AuthHandler {
	return &AuthHandler{
		store:         s,
		mfaEngine:     mfaEngine,
		audit:         audit,
		middleware:    mm,
		secureCookies: secureCookies,
		sessionTTL:    24 * time.Hour,
	}
}

// GetCSRFToken issues a random CSRF token cookie and returns it.
func (h *AuthHandler) GetCSRFToken(w http.ResponseWriter, r *http.Request) {
	var sessionToken string
	if c, err := r.Cookie("kysignon_session"); err == nil {
		sessionToken = c.Value
	}
	csrfToken := h.middleware.IssueCSRFToken(sessionToken)
	if csrfToken == "" {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "kysignon_csrf",
		Value:    csrfToken,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		HttpOnly: false, // Accessible by frontend JavaScript for double-submit header
		Secure:   h.middleware.IsHTTPS(r) || h.secureCookies,
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"csrfToken": csrfToken})
}

type LoginRequest struct {
	Interaction string `json:"interaction"`
	Username    string `json:"username"`
	Password    string `json:"password"`
}

type LoginResponse struct {
	RestartAuthorization bool     `json:"restartAuthorization,omitempty"`
	Success              bool     `json:"success"`
	MFARequired          bool     `json:"mfaRequired,omitempty"`
	MFAToken             string   `json:"mfaToken,omitempty"`
	MFAMethods           []string `json:"mfaMethods,omitempty"`
	ChallengeID          string   `json:"challengeId,omitempty"`
	MatchDigits          string   `json:"matchDigits,omitempty"`
	DecoyDigits          []string `json:"decoyDigits,omitempty"`
	User                 any      `json:"user,omitempty"`
}

// Login handles primary username/password verification.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_request","error_description":"Malformed JSON body"}`, http.StatusBadRequest)
		return
	}

	ip := h.middleware.ClientIP(r)
	ua := r.UserAgent()

	user, err := h.store.GetUserByUsername(req.Username)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	// An unknown username must cost the same as a wrong password. Returning early here
	// would answer in ~1 ms against ~100 ms for a real account, which enumerates users.
	if user == nil {
		auth.DummyVerify(req.Password)
		h.audit.Record("auth.login", "", req.Username, "", "user", ip, ua, "failure", map[string]any{"reason": "user_not_found"})
		http.Error(w, `{"error":"invalid_credentials","error_description":"Invalid username or password"}`, http.StatusUnauthorized)
		return
	}

	if user.Status != "active" {
		auth.DummyVerify(req.Password)
		reason := "user_disabled"
		if user.Pending {
			reason = "user_pending"
		}
		h.audit.Record("auth.login", user.ID, user.Username, user.ID, "user", ip, ua, "denied", map[string]any{"reason": reason})
		http.Error(w, `{"error":"invalid_credentials","error_description":"Invalid username or password"}`, http.StatusUnauthorized)
		return
	}

	interactionHash := ""
	var interaction *store.AuthorizationInteraction
	if req.Interaction != "" {
		interactionHash = crypto.HashSHA256(req.Interaction)
		i, err := h.store.GetAuthorizationInteraction(interactionHash, h.middleware.authorizationBrowserHash(r))
		if err != nil || i.SessionID != "" || (i.UserID != "" && i.UserID != user.ID) {
			auth.DummyVerify(req.Password)
			http.Error(w, `{"error":"invalid_interaction","error_description":"Restart authorization with the original account and browser"}`, 400)
			return
		}
		interaction = i
	}

	// Per-account lockout. The per-IP limiter cannot see a spray distributed across hosts.
	locked, err := h.store.IsAccountLocked(user.ID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if locked {
		auth.DummyVerify(req.Password)
		h.audit.Record("auth.login", user.ID, user.Username, user.ID, "user", ip, ua, "denied", map[string]any{"reason": "account_locked"})
		http.Error(w, `{"error":"account_locked","error_description":"Too many failed attempts. Try again later."}`, http.StatusTooManyRequests)
		return
	}

	validPass, err := auth.VerifyPassword(req.Password, user.PasswordHash)
	if err != nil || !validPass {
		attempts, _ := h.store.RecordFailedLogin(user.ID)
		h.audit.Record("auth.login", user.ID, user.Username, user.ID, "user", ip, ua, "failure",
			map[string]any{"reason": "invalid_password", "consecutiveFailures": attempts})
		http.Error(w, `{"error":"invalid_credentials","error_description":"Invalid username or password"}`, http.StatusUnauthorized)
		return
	}

	primaryAt := time.Now().UTC()
	if err := h.store.ClearFailedLogins(user.ID); err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	// Check if user has enrolled MFA methods
	mfaMethods, err := h.store.ListUserMFAMethods(user.ID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	var methodTypes []string
	hasPush := false
	for _, m := range mfaMethods {
		methodTypes = append(methodTypes, m.MethodType)
		if m.MethodType == "push" {
			hasPush = true
		}
	}

	// Passkeys live in their own table because a user may hold several, so they are not
	// in mfa_methods and have to be counted separately.
	passkeys, err := h.store.ListUserWebAuthnCredentials(user.ID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if len(passkeys) > 0 {
		methodTypes = append(methodTypes, "webauthn")
	}

	enrollment, err := h.store.SessionEnrollmentStatus(user.ID, "")
	if err != nil {
		stepUpInternalError(w)
		return
	}
	if enrollment.Required && enrollment.Enrolled {
		filtered := []string{}
		for _, method := range methodTypes {
			if slices.Contains(enrollment.AllowedMethods, method) {
				filtered = append(filtered, method)
			}
		}
		if len(filtered) > 0 {
			methodTypes = filtered
			hasPush = slices.Contains(filtered, "push")
		}
	}
	if interaction != nil {
		q, err := url.ParseQuery(interaction.Request)
		if err != nil {
			stepUpInternalError(w)
			return
		}
		requirements, err := oauth.ParseAuthenticationRequest(q)
		if err != nil {
			stepUpInternalError(w)
			return
		}
		policy, err := h.store.ClientAuthenticationPolicy(q.Get("client_id"))
		if err != nil {
			stepUpInternalError(w)
			return
		}
		if policy.Factor == "passkey" {
			methodTypes = nil
			hasPush = false
			if len(passkeys) > 0 {
				methodTypes = []string{"webauthn"}
			}
		}
		if len(methodTypes) == 0 && (policy.Factor != "password" || requirements.ACR == oauth.MFAACR) {
			// A disallowed factor is still an enrolled credential; it must not be bypassed.
			if enrollment.Required && len(mfaMethods) == 0 && len(passkeys) == 0 && enrollment.Deadline <= time.Now().Unix() {
				h.createSessionAndRespond(w, r, user, store.AuthenticationEvidence{PrimaryAuthenticatedAt: &primaryAt}, interactionHash)
				return
			}
			http.Error(w, `{"error":"factor_enrollment_required","error_description":"This application requires an enrolled authenticator, or a passkey for passkey-only policy. Sign in to your dashboard to enroll, then restart from the application."}`, 403)
			return
		}
	}

	if len(methodTypes) > 0 {
		resp := LoginResponse{
			Success:     false,
			MFARequired: true,
			MFAMethods:  methodTypes,
		}

		var challengeID string
		if hasPush {
			challenge, err := h.mfaEngine.CreatePushChallenge(user.ID)
			if err == nil && challenge != nil {
				challengeID = challenge.ID
				resp.ChallengeID = challenge.ID
				resp.MatchDigits = challenge.MatchDigits
				var decoys []string
				_ = json.Unmarshal([]byte(challenge.DecoyDigitsJSON), &decoys)
				resp.DecoyDigits = decoys
			}
		}

		// The token is persisted and bound to this user and challenge. The user identity is
		// read back from that record on completion; it is never parsed from client input.
		mfaToken, err := h.mfaEngine.IssueMFATokenForInteraction(user.ID, challengeID, primaryAt, interactionHash)
		if err != nil {
			http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
			return
		}
		resp.MFAToken = mfaToken

		h.audit.Record("auth.mfa_challenge", user.ID, user.Username, user.ID, "user", ip, ua, "success", map[string]any{"methods": methodTypes})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	// No MFA enrolled, issue session directly
	h.createSessionAndRespond(w, r, user, store.AuthenticationEvidence{PrimaryAuthenticatedAt: &primaryAt}, interactionHash)
}

func (h *AuthHandler) createSessionAndRespond(w http.ResponseWriter, r *http.Request, user *store.User, evidence store.AuthenticationEvidence, interactionHash string) {
	rawToken, err := crypto.GenerateRandomHex(32)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	tokenHash := crypto.HashSHA256(rawToken)
	ip := h.middleware.ClientIP(r)
	ua := r.UserAgent()
	expiresAt := time.Now().UTC().Add(h.sessionTTL)

	sess := &store.Session{
		AuthenticationEvidence: evidence,
		ID:                     uuid.New().String(),
		UserID:                 user.ID,
		SessionTokenHash:       tokenHash,
		IPAddress:              ip,
		UserAgent:              ua,
		ExpiresAt:              expiresAt,
	}

	restartAuthorization := false
	err = h.store.CreateSessionForInteraction(sess, interactionHash, h.middleware.authorizationBrowserHash(r))
	if errors.Is(err, store.ErrAuthorizationInteraction) {
		// Proof has already succeeded and may have spent a recovery code. Preserve
		// that login without granting the cancelled/expired authorization request.
		err = h.store.CreateSession(sess)
		restartAuthorization = true
	}
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	enrollment, err := h.store.SessionEnrollmentStatus(user.ID, sess.ID)
	if err != nil {
		stepUpInternalError(w)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "kysignon_session",
		Value:    rawToken,
		Path:     "/",
		Expires:  expiresAt,
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
		Secure:   h.middleware.IsHTTPS(r) || h.secureCookies,
	})

	// Rebind the CSRF token to the new session; one issued before login belongs to nobody.
	http.SetCookie(w, &http.Cookie{
		Name:     "kysignon_csrf",
		Value:    h.middleware.IssueCSRFToken(rawToken),
		Path:     "/",
		Expires:  expiresAt,
		SameSite: http.SameSiteLaxMode,
		HttpOnly: false, // read by the frontend for the double-submit header
		Secure:   h.middleware.IsHTTPS(r) || h.secureCookies,
	})

	h.audit.Record("auth.login_success", user.ID, user.Username, user.ID, "user", ip, ua, "success", nil)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(LoginResponse{
		RestartAuthorization: restartAuthorization,
		Success:              true,
		User: map[string]any{
			"enrollment":  enrollment,
			"id":          user.ID,
			"username":    user.Username,
			"displayName": user.DisplayName,
			"email":       user.Email,
			"role":        user.Role,
			"status":      user.Status,
		},
	})
}

type MFAVerifyRequest struct {
	MFAToken string `json:"mfaToken"`
	Code     string `json:"code"`
}

// resolveMFAToken exchanges a raw second-factor token for the user it was issued to.
// The identity comes from the stored record, so a forged token resolves to nothing.
func (h *AuthHandler) resolveMFAToken(w http.ResponseWriter, rawToken string) (*store.MFAToken, *store.User, bool) {
	token, err := h.mfaEngine.ValidateMFAToken(rawToken)
	if err != nil {
		http.Error(w, `{"error":"invalid_mfa_token","error_description":"Second-factor token is invalid or expired"}`, http.StatusUnauthorized)
		return nil, nil, false
	}

	user, err := h.store.GetUserByID(token.UserID)
	if err != nil || user == nil || user.Status != "active" {
		http.Error(w, `{"error":"invalid_user"}`, http.StatusUnauthorized)
		return nil, nil, false
	}

	return token, user, true
}

// spendMFAToken consumes the token exactly once. A losing racer gets no session.
func (h *AuthHandler) spendMFAToken(w http.ResponseWriter, token *store.MFAToken) bool {
	spent, err := h.mfaEngine.ConsumeMFAToken(token.ID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return false
	}
	if !spent {
		http.Error(w, `{"error":"invalid_mfa_token","error_description":"Second-factor token already used"}`, http.StatusUnauthorized)
		return false
	}
	return true
}

// VerifyTOTP verifies a TOTP code and finishes login.
func (h *AuthHandler) VerifyTOTP(w http.ResponseWriter, r *http.Request) {
	var req MFAVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.MFAToken == "" || req.Code == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	token, user, ok := h.resolveMFAToken(w, req.MFAToken)
	if !ok {
		return
	}

	valid, err := h.mfaEngine.VerifyUserTOTP(user.ID, req.Code)
	if err != nil || !valid {
		// Count the miss against this login attempt. Without it, one token funds
		// unlimited guesses for its whole lifetime.
		attempts, _ := h.mfaEngine.RegisterMFAFailure(token.ID)
		h.audit.Record("auth.mfa_totp", user.ID, user.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "failure",
			map[string]any{"attempts": attempts})
		http.Error(w, `{"error":"invalid_totp_code","error_description":"Invalid 6-digit TOTP code"}`, http.StatusUnauthorized)
		return
	}

	factorAt := time.Now().UTC()
	if !h.spendMFAToken(w, token) {
		return
	}

	h.createSessionAndRespond(w, r, user, store.AuthenticationEvidence{PrimaryAuthenticatedAt: token.PrimaryAuthenticatedAt, FactorAuthenticatedAt: &factorAt, FactorMethod: "totp"}, token.InteractionHash)
}

// VerifyRecoveryCode verifies a one-time recovery code and finishes login.
func (h *AuthHandler) VerifyRecoveryCode(w http.ResponseWriter, r *http.Request) {
	var req MFAVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.MFAToken == "" || req.Code == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	token, user, ok := h.resolveMFAToken(w, req.MFAToken)
	if !ok {
		return
	}

	valid, err := h.mfaEngine.VerifyAndConsumeRecoveryCode(user.ID, req.Code)
	if err != nil || !valid {
		attempts, _ := h.mfaEngine.RegisterMFAFailure(token.ID)
		h.audit.Record("auth.mfa_recovery", user.ID, user.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "failure",
			map[string]any{"attempts": attempts})
		http.Error(w, `{"error":"invalid_recovery_code","error_description":"Invalid or already used recovery code"}`, http.StatusUnauthorized)
		return
	}

	factorAt := time.Now().UTC()
	if !h.spendMFAToken(w, token) {
		return
	}

	h.audit.Record("auth.mfa_recovery_consumed", user.ID, user.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	_ = h.store.ClearFailedLogins(user.ID)
	h.createSessionAndRespond(w, r, user, store.AuthenticationEvidence{PrimaryAuthenticatedAt: token.PrimaryAuthenticatedAt, FactorAuthenticatedAt: &factorAt, FactorMethod: "recovery"}, token.InteractionHash)
}

type PushPollRequest struct {
	MFAToken    string `json:"mfaToken"`
	ChallengeID string `json:"challengeId"`
}

// PollPushChallenge checks the status of a pending push challenge. It requires the token
// issued alongside that challenge, so a challenge ID alone reveals nothing.
func (h *AuthHandler) PollPushChallenge(w http.ResponseWriter, r *http.Request) {
	var req PushPollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ChallengeID == "" || req.MFAToken == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	token, _, ok := h.resolveMFAToken(w, req.MFAToken)
	if !ok {
		return
	}
	if token.ChallengeID == "" || token.ChallengeID != req.ChallengeID {
		http.Error(w, `{"error":"challenge_mismatch","error_description":"Token was not issued for this challenge"}`, http.StatusUnauthorized)
		return
	}

	status, _, err := h.mfaEngine.CheckPushChallenge(req.ChallengeID)
	if err != nil {
		http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": status})
}

type PushFinishRequest struct {
	MFAToken    string `json:"mfaToken"`
	ChallengeID string `json:"challengeId"`
}

// FinishPushLogin establishes a session after a push challenge is approved. The token, the
// challenge, and the user must all agree before anything is issued.
func (h *AuthHandler) FinishPushLogin(w http.ResponseWriter, r *http.Request) {
	var req PushFinishRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.MFAToken == "" || req.ChallengeID == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	token, user, ok := h.resolveMFAToken(w, req.MFAToken)
	if !ok {
		return
	}
	if token.ChallengeID == "" || token.ChallengeID != req.ChallengeID {
		http.Error(w, `{"error":"challenge_mismatch","error_description":"Token was not issued for this challenge"}`, http.StatusUnauthorized)
		return
	}

	challenge, err := h.store.GetMFAChallenge(req.ChallengeID)
	if err != nil || challenge == nil || challenge.Status != "approved" || challenge.VerifiedAt == nil || !challenge.ExpiresAt.After(time.Now().UTC()) {
		http.Error(w, `{"error":"mfa_not_approved","error_description":"Push challenge is not approved"}`, http.StatusUnauthorized)
		return
	}
	if challenge.UserID != user.ID {
		h.audit.Record("auth.mfa_push_mismatch", user.ID, user.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "denied",
			map[string]any{"reason": "challenge_owner_mismatch", "challengeId": req.ChallengeID})
		http.Error(w, `{"error":"mfa_not_approved","error_description":"Push challenge is not approved"}`, http.StatusUnauthorized)
		return
	}

	if !h.spendMFAToken(w, token) {
		return
	}

	h.audit.Record("auth.mfa_push_approved", user.ID, user.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	h.createSessionAndRespond(w, r, user, store.AuthenticationEvidence{PrimaryAuthenticatedAt: token.PrimaryAuthenticatedAt, FactorAuthenticatedAt: challenge.VerifiedAt, FactorMethod: "push"}, token.InteractionHash)
}

type PushRespondRequest struct {
	ChallengeID    string `json:"challengeId"`
	SelectedDigits string `json:"selectedDigits"`
	Approve        bool   `json:"approve"`
	Signature      string `json:"signature"`
}

// RespondPush handles a signed response from a paired mobile authenticator. This endpoint has
// no session; the device signature over the challenge is what authenticates it.
func (h *AuthHandler) RespondPush(w http.ResponseWriter, r *http.Request) {
	var req PushRespondRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ChallengeID == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	if req.Signature == "" {
		http.Error(w, `{"error":"signature_required","error_description":"Push responses must be signed by a paired device"}`, http.StatusUnauthorized)
		return
	}

	approved, deviceID, err := h.mfaEngine.RespondPushChallenge(req.ChallengeID, req.SelectedDigits, req.Approve, req.Signature)
	if err != nil {
		ip := h.middleware.ClientIP(r)
		if errors.Is(err, mfa.ErrUnsignedDevice) {
			h.audit.Record("auth.mfa_push_respond", "", "", req.ChallengeID, "mfa_challenge", ip, r.UserAgent(), "denied",
				map[string]any{"reason": "no_signing_device"})
			http.Error(w, `{"error":"device_not_enrolled_for_signing","error_description":"Re-pair your authenticator to approve sign-ins"}`, http.StatusUnauthorized)
			return
		}
		h.audit.Record("auth.mfa_push_respond", "", "", req.ChallengeID, "mfa_challenge", ip, r.UserAgent(), "failure",
			map[string]any{"reason": err.Error()})
		http.Error(w, `{"error":"challenge_error","error_description":"Challenge could not be answered"}`, http.StatusBadRequest)
		return
	}

	outcome := "denied"
	if approved {
		outcome = "success"
	}
	h.audit.Record("auth.mfa_push_respond", "", "", req.ChallengeID, "mfa_challenge", h.middleware.ClientIP(r), r.UserAgent(), outcome,
		map[string]any{"deviceId": deviceID})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": approved})
}

// Logout revokes active session.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	sess := GetSessionFromContext(r.Context())
	user := GetUserFromContext(r.Context())

	if sess != nil && user != nil {
		pending := h.audit.Prepare("auth.logout", user.ID, user.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
		if err := h.store.RevokeSession(user.ID, sess.ID, pending.Row); err != nil && !errors.Is(err, store.ErrNotFound) {
			log.Printf("logout for user %s failed: %v", user.ID, err)
			stepUpInternalError(w)
			return
		} else if err == nil {
			pending.Committed()
		}
	}

	clearSessionCookies(w)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// Me returns the current authenticated user profile.
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	enrollment, err := h.store.SessionEnrollmentStatus(user.ID, GetSessionFromContext(r.Context()).ID)
	if err != nil {
		stepUpInternalError(w)
		return
	}
	mfaMethods, _ := h.store.ListUserMFAMethods(user.ID)
	var methodTypes []string
	for _, m := range mfaMethods {
		methodTypes = append(methodTypes, m.MethodType)
	}
	access, err := accessFor(h.store, user)
	if err != nil {
		stepUpInternalError(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access":      access,
		"enrollment":  enrollment,
		"id":          user.ID,
		"username":    user.Username,
		"displayName": user.DisplayName,
		"email":       user.Email,
		"role":        user.Role,
		"status":      user.Status,
		"mfaMethods":  methodTypes,
		"createdAt":   user.CreatedAt,
	})
}
