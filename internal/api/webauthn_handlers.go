package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/Busness-app/kyidentity-server/internal/audit"
	"github.com/Busness-app/kyidentity-server/internal/crypto"
	"github.com/Busness-app/kyidentity-server/internal/mfa"
	"github.com/Busness-app/kyidentity-server/internal/store"
	"github.com/Busness-app/kyidentity-server/internal/webauthn"
	"github.com/google/uuid"
)

// challengeTTL bounds how long a ceremony may sit half-finished. Long enough for a user to
// find their phone, short enough that a captured challenge is worthless by the time it
// could be replayed — and it is single-use regardless.
const challengeTTL = 3 * time.Minute

// maxPasskeysPerUser caps enrolment. Unbounded credentials per account is a place for an
// attacker with one borrowed session to leave many durable factors behind.
const maxPasskeysPerUser = 10

type WebAuthnHandler struct {
	store      *store.Store
	audit      *audit.Logger
	mfaEngine  *mfa.Engine
	middleware *MiddlewareManager
	rpID       string
	origin     string
}

// NewWebAuthnHandler takes the relying party identity already derived and validated by
// config.Load, so a malformed issuer URL is a startup failure rather than a ceremony that
// fails for the first user who tries it.
func NewWebAuthnHandler(s *store.Store, auditLogger *audit.Logger, mfaEngine *mfa.Engine, mm *MiddlewareManager, rpID, origin string) *WebAuthnHandler {
	return &WebAuthnHandler{store: s, audit: auditLogger, mfaEngine: mfaEngine, middleware: mm, rpID: rpID, origin: origin}
}

type beginRegistrationResponse struct {
	Challenge  string   `json:"challenge"`
	RPID       string   `json:"rpId"`
	RPName     string   `json:"rpName"`
	UserHandle string   `json:"userHandle"`
	Username   string   `json:"username"`
	Exclude    []string `json:"excludeCredentials"`
}

// issueChallenge mints and stores a single-use nonce for one user and one ceremony.
func (h *WebAuthnHandler) issueChallenge(userID, purpose string) (string, error) {
	raw, err := crypto.GenerateRandomBytes(32)
	if err != nil {
		return "", err
	}
	challenge := base64.RawURLEncoding.EncodeToString(raw)
	return challenge, h.store.CreateWebAuthnChallenge(&store.WebAuthnChallenge{
		ID:        uuid.New().String(),
		UserID:    userID,
		Challenge: challenge,
		Purpose:   purpose,
		ExpiresAt: time.Now().UTC().Add(challengeTTL),
	})
}

// BeginRegistration returns the parameters for navigator.credentials.create. The step-up
// grant is checked but not spent: failing here rather than after the user has touched their
// authenticator is the better experience, and FinishRegistration spends it.
func (h *WebAuthnHandler) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	if err := requireStepUp(h.store, r); err != nil {
		writeStepUpError(w, err)
		return
	}

	existing, err := h.store.ListUserWebAuthnCredentials(user.ID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if len(existing) >= maxPasskeysPerUser {
		http.Error(w, `{"error":"too_many_passkeys","error_description":"Remove an existing passkey before enrolling another"}`, http.StatusConflict)
		return
	}

	challenge, err := h.issueChallenge(user.ID, "register")
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	// Existing credentials are excluded so an authenticator that already holds one for this
	// account says so instead of silently enrolling a duplicate.
	exclude := make([]string, 0, len(existing))
	for _, c := range existing {
		exclude = append(exclude, c.CredentialID)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(beginRegistrationResponse{
		Challenge:  challenge,
		RPID:       h.rpID,
		RPName:     "KyIdentity",
		UserHandle: base64.RawURLEncoding.EncodeToString([]byte(user.ID)),
		Username:   user.Username,
		Exclude:    exclude,
	})
}

type finishRegistrationRequest struct {
	CredentialID      string `json:"credentialId"`
	AuthenticatorData string `json:"authenticatorData"`
	ClientDataJSON    string `json:"clientDataJSON"`
	PublicKey         string `json:"publicKey"`
	Name              string `json:"name"`
}

func (h *WebAuthnHandler) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var req finishRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil ||
		req.CredentialID == "" || req.AuthenticatorData == "" || req.ClientDataJSON == "" || req.PublicKey == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	// A ceremony the caller conducted with their own authenticator proves nothing about
	// the account holder, so entitlement comes from the step-up grant, as it does for TOTP.
	if err := consumeStepUp(h.store, r); err != nil {
		writeStepUpError(w, err)
		return
	}

	authData, err1 := base64.RawURLEncoding.DecodeString(req.AuthenticatorData)
	clientData, err2 := base64.RawURLEncoding.DecodeString(req.ClientDataJSON)
	publicKey, err3 := base64.RawURLEncoding.DecodeString(req.PublicKey)
	credentialID, err4 := base64.RawURLEncoding.DecodeString(req.CredentialID)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		http.Error(w, `{"error":"invalid_request","error_description":"Ceremony fields must be base64url"}`, http.StatusBadRequest)
		return
	}
	// The WebAuthn spec caps credential IDs at 1023 bytes. The column is globally unique,
	// so an oversized or arbitrary value could break the caller's own login and squat a
	// string against every other account.
	if len(credentialID) > 1023 {
		http.Error(w, `{"error":"invalid_request","error_description":"Credential ID exceeds the maximum length"}`, http.StatusBadRequest)
		return
	}

	var cd struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(clientData, &cd); err != nil || cd.Challenge == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	// Redeem before verifying. A challenge that fails verification is burned either way,
	// so a caller cannot grind attempts against one issued nonce.
	spent, err := h.store.ConsumeWebAuthnChallenge(cd.Challenge, "register", user.ID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if !spent {
		http.Error(w, `{"error":"invalid_challenge","error_description":"Registration challenge is unknown, expired, or already used"}`, http.StatusBadRequest)
		return
	}

	ad, err := webauthn.VerifyRegistration(webauthn.RegistrationInput{
		AuthenticatorData: authData,
		ClientDataJSON:    clientData,
		PublicKeySPKI:     publicKey,
		Challenge:         cd.Challenge,
		Origin:            h.origin,
		RPID:              h.rpID,
	})
	if err != nil {
		h.audit.Record("mfa.passkey_enrol", user.ID, user.Username, user.ID, "user",
			h.middleware.ClientIP(r), r.UserAgent(), "failure", map[string]any{"reason": "verification_failed"})
		http.Error(w, `{"error":"invalid_credential","error_description":"Passkey registration could not be verified"}`, http.StatusBadRequest)
		return
	}

	name := req.Name
	if name == "" {
		name = "Passkey"
	}
	if len(name) > 64 {
		name = name[:64]
	}

	enrolled := h.audit.Prepare("mfa.passkey_enrol", user.ID, user.Username, user.ID, "user",
		h.middleware.ClientIP(r), r.UserAgent(), "success",
		map[string]any{"backupEligible": ad.BackupEligible(), "userVerified": ad.UserVerified()})
	if err := h.store.CreateWebAuthnCredential(&store.WebAuthnCredential{
		ID:             uuid.New().String(),
		UserID:         user.ID,
		CredentialID:   req.CredentialID,
		PublicKeySPKI:  req.PublicKey,
		SignCount:      ad.SignCount,
		Name:           name,
		BackupEligible: ad.BackupEligible(),
		BackupState:    ad.BackupState(),
	}, enrolled.Row); err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	enrolled.Committed()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}

type beginLoginRequest struct {
	MFAToken string `json:"mfaToken"`
}

type beginLoginResponse struct {
	Challenge        string   `json:"challenge"`
	RPID             string   `json:"rpId"`
	AllowCredentials []string `json:"allowCredentials"`
}

// BeginLogin returns the parameters for navigator.credentials.get. The user comes from the
// stored second-factor token, never from client input, so the allow-list cannot be steered
// onto another account's credentials.
//
// ponytail: passwordless passkey login needs discoverable credentials and a userHandle
// lookup — see companion plan 1b.
func (h *WebAuthnHandler) BeginLogin(w http.ResponseWriter, r *http.Request, auth *AuthHandler) {
	var req beginLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.MFAToken == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	token, _, ok := auth.resolveMFAToken(w, req.MFAToken)
	if !ok {
		return
	}

	creds, err := h.store.ListUserWebAuthnCredentials(token.UserID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if len(creds) == 0 {
		http.Error(w, `{"error":"no_passkey","error_description":"No passkey is enrolled for this account"}`, http.StatusBadRequest)
		return
	}

	challenge, err := h.issueChallenge(token.UserID, "authenticate")
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	allow := make([]string, 0, len(creds))
	for _, c := range creds {
		allow = append(allow, c.CredentialID)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(beginLoginResponse{Challenge: challenge, RPID: h.rpID, AllowCredentials: allow})
}

type finishLoginRequest struct {
	MFAToken          string `json:"mfaToken"`
	CredentialID      string `json:"credentialId"`
	AuthenticatorData string `json:"authenticatorData"`
	ClientDataJSON    string `json:"clientDataJSON"`
	Signature         string `json:"signature"`
}

// FinishLogin verifies an assertion and completes the login. It mirrors VerifyTOTP: the
// same token resolution, the same failure accounting, the same single-use spend.
func (h *WebAuthnHandler) FinishLogin(w http.ResponseWriter, r *http.Request, auth *AuthHandler) {
	var req finishLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil ||
		req.MFAToken == "" || req.CredentialID == "" || req.AuthenticatorData == "" ||
		req.ClientDataJSON == "" || req.Signature == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	token, user, ok := auth.resolveMFAToken(w, req.MFAToken)
	if !ok {
		return
	}

	// From here on, every rejection counts against token.ID: this is the one handler that
	// mints a session, so nothing past a resolved token gets free attempts. Status code and
	// body are chosen per call site; the counting and audit write always happen.
	failed := func(status int, body, reason string) {
		attempts, _ := h.mfaEngine.RegisterMFAFailure(token.ID)
		h.audit.Record("auth.mfa_passkey", user.ID, user.Username, user.ID, "user",
			h.middleware.ClientIP(r), r.UserAgent(), "failure",
			map[string]any{"reason": reason, "attempts": attempts})
		http.Error(w, body, status)
	}

	authData, err1 := base64.RawURLEncoding.DecodeString(req.AuthenticatorData)
	clientData, err2 := base64.RawURLEncoding.DecodeString(req.ClientDataJSON)
	signature, err3 := base64.RawURLEncoding.DecodeString(req.Signature)
	if err1 != nil || err2 != nil || err3 != nil {
		failed(http.StatusBadRequest, `{"error":"invalid_request","error_description":"Ceremony fields must be base64url"}`, "malformed_ceremony")
		return
	}

	var cd struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(clientData, &cd); err != nil || cd.Challenge == "" {
		failed(http.StatusBadRequest, `{"error":"invalid_request"}`, "malformed_ceremony")
		return
	}

	spent, err := h.store.ConsumeWebAuthnChallenge(cd.Challenge, "authenticate", user.ID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if !spent {
		failed(http.StatusUnauthorized, `{"error":"invalid_assertion","error_description":"Passkey verification failed"}`, "challenge_unusable")
		return
	}

	// The credential is looked up within this user, so an attacker's own passkey cannot
	// answer somebody else's challenge.
	cred, err := h.store.GetWebAuthnCredential(user.ID, req.CredentialID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if cred == nil {
		failed(http.StatusUnauthorized, `{"error":"invalid_assertion","error_description":"Passkey verification failed"}`, "unknown_credential")
		return
	}

	publicKey, err := base64.RawURLEncoding.DecodeString(cred.PublicKeySPKI)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	ad, err := webauthn.VerifyAssertion(webauthn.AssertionInput{
		AuthenticatorData: authData,
		ClientDataJSON:    clientData,
		Signature:         signature,
		PublicKeySPKI:     publicKey,
		Challenge:         cd.Challenge,
		Origin:            h.origin,
		RPID:              h.rpID,
		StoredSignCount:   cred.SignCount,
		BackupEligible:    cred.BackupEligible,
	})
	if err != nil {
		failed(http.StatusUnauthorized, `{"error":"invalid_assertion","error_description":"Passkey verification failed"}`, "assertion_invalid")
		return
	}

	factorAt := time.Now().UTC()
	if !auth.spendMFAToken(w, token) {
		return
	}

	if err := h.store.RecordWebAuthnUse(cred.ID, ad.SignCount, ad.BackupState(), time.Now().UTC()); err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	h.audit.Record("auth.mfa_passkey", user.ID, user.Username, user.ID, "user",
		h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"userVerified": ad.UserVerified()})
	_ = h.store.ClearFailedLogins(user.ID)
	auth.createSessionAndRespond(w, r, user, store.AuthenticationEvidence{PrimaryAuthenticatedAt: token.PrimaryAuthenticatedAt, FactorAuthenticatedAt: &factorAt, FactorMethod: "webauthn"}, token.InteractionHash)
}

// ListPasskeys returns the caller's enrolled passkeys. The public key and signature
// counter are omitted by the struct tags on store.WebAuthnCredential; nothing here needs
// to reach a browser.
func (h *WebAuthnHandler) ListPasskeys(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	creds, err := h.store.ListUserWebAuthnCredentials(user.ID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if creds == nil {
		creds = []store.WebAuthnCredential{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(creds)
}

// DeletePasskey removes one of the caller's passkeys. Removing a factor is destructive, so
// it costs a step-up grant: a borrowed session must not be able to strip the account back
// down to a single factor.
func (h *WebAuthnHandler) DeletePasskey(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	if err := consumeStepUp(h.store, r); err != nil {
		writeStepUpError(w, err)
		return
	}

	id := r.PathValue("id")
	removed := h.audit.Prepare("mfa.passkey_removed", user.ID, user.Username, user.ID, "user",
		h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"credentialRecordId": id})
	deleted, err := h.store.DeleteWebAuthnCredential(id, user.ID, removed.Row)
	if err != nil {
		if errors.Is(err, store.ErrLastCompliantFactor) {
			enrollmentError(w, err)
			return
		}
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if !deleted {
		http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
		return
	}
	removed.Committed()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}
