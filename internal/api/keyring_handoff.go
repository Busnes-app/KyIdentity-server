package api

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/oauth"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

type keyringHandoffContext struct {
	interaction *store.AuthorizationInteraction
	browserHash string
	query       url.Values
	client      *store.OAuthClient
	redirectURI string
	state       string
	keyringPK   string
	user        *store.User
	session     *store.Session
}

func validHandoffToken(raw string) bool {
	if len(raw) != 64 {
		return false
	}
	_, err := hex.DecodeString(raw)
	return err == nil
}

func (h *OAuthHandler) loadKeyringHandoff(r *http.Request) (*keyringHandoffContext, int, string) {
	user, sess := GetUserFromContext(r.Context()), GetSessionFromContext(r.Context())
	if user == nil || sess == nil {
		return nil, http.StatusUnauthorized, "Authentication required"
	}
	if user.Role != "user" {
		return nil, http.StatusForbidden, "Keyring is not available for this account"
	}
	raw := r.PathValue("id")
	if !validHandoffToken(raw) {
		return nil, http.StatusNotFound, "Keyring handoff expired or not found"
	}
	browserHash := h.middleware.authorizationBrowserHash(r)
	if browserHash == "" {
		return nil, http.StatusNotFound, "Keyring handoff expired or not found"
	}
	i, err := h.store.GetAuthorizationInteraction(crypto.HashSHA256(raw), browserHash)
	if err != nil || i.SessionID != sess.ID || i.UserID != user.ID {
		return nil, http.StatusNotFound, "Keyring handoff expired or not found"
	}
	q, err := url.ParseQuery(i.Request)
	if err != nil {
		return nil, http.StatusNotFound, "Keyring handoff expired or not found"
	}
	keyringPK := q.Get("keyring_pk")
	if len(q["keyring_pk"]) != 1 || !keyringPoint(keyringPK) {
		return nil, http.StatusNotFound, "Keyring handoff expired or not found"
	}
	clientID, redirectURI := q.Get("client_id"), q.Get("redirect_uri")
	client, err := h.store.GetOAuthClientByID(clientID)
	if err != nil || client == nil || !client.Enabled || !h.oauthEngine.ValidateRedirectURI(client, redirectURI) {
		return nil, http.StatusNotFound, "Keyring handoff expired or not found"
	}
	return &keyringHandoffContext{
		interaction: i,
		browserHash: browserHash,
		query:       q,
		client:      client,
		redirectURI: redirectURI,
		state:       q.Get("state"),
		keyringPK:   keyringPK,
		user:        user,
		session:     sess,
	}, 0, ""
}

func writeHandoffError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// KeyringHandoffDetails returns the binding context and keyring metadata needed by
// /keyring-handoff to unlock and seal an app subkey for the requesting OIDC client.
func (h *OAuthHandler) KeyringHandoffDetails(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	ctx, status, msg := h.loadKeyringHandoff(r)
	if status != 0 {
		writeHandoffError(w, status, msg)
		return
	}
	enrollment, err := h.store.SessionEnrollmentStatus(ctx.user.ID, ctx.session.ID)
	if err != nil {
		writeHandoffError(w, http.StatusInternalServerError, "Could not check enrollment")
		return
	}
	if enrollment.Restricted || ctx.user.PasswordChangeRequired {
		writeHandoffError(w, http.StatusForbidden, "Complete account setup before continuing")
		return
	}
	allowed, err := h.store.ClientAccessAllowed(ctx.user.ID, ctx.client.ID)
	if err != nil {
		writeHandoffError(w, http.StatusInternalServerError, "Could not check application access")
		return
	}
	if !allowed {
		writeHandoffError(w, http.StatusForbidden, "Access to this application is not permitted")
		return
	}
	org := orgStore(r)
	login := store.KeyringSession{UserID: ctx.user.ID, SessionID: ctx.session.ID}
	st, err := org.KeyringStatus(login)
	if err != nil {
		keyringError(w, err)
		return
	}
	type appKeyPayload struct {
		KeyVersion int    `json:"key_version"`
		Sealed     string `json:"sealed"`
	}
	var appKey *appKeyPayload
	if st.Version != "" {
		app, err := org.KeyringAppKey(login, ctx.client.ID)
		if err == nil {
			appKey = &appKeyPayload{KeyVersion: app.Version, Sealed: app.Sealed}
		} else if !errors.Is(err, sql.ErrNoRows) {
			keyringError(w, err)
			return
		}
	}
	wrappers := st.Wrappers
	if wrappers == nil {
		wrappers = []store.KeyringWrapperInfo{}
	}
	appName := ctx.client.LauncherName
	if appName == "" {
		appName = ctx.client.ClientName
	}
	if appName == "" {
		appName = ctx.client.ID
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":          h.oauthEngine.GetOIDCConfiguration().Issuer,
		"org_id":          org.ID().String(),
		"user_id":         ctx.user.ID,
		"client_id":       ctx.client.ID,
		"app_name":        appName,
		"redirect_uri":    ctx.redirectURI,
		"state":           ctx.state,
		"keyring_pk":      ctx.keyringPK,
		"keyring_version": st.Version,
		"wrappers":        wrappers,
		"app_key":         appKey,
	})
}

// KeyringHandoffComplete atomically consumes the handoff interaction and mints a fresh
// OIDC authorization code so the SPA can bind the sealed app subkey to that exact code.
func (h *OAuthHandler) KeyringHandoffComplete(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	ctx, status, msg := h.loadKeyringHandoff(r)
	if status != 0 {
		writeHandoffError(w, status, msg)
		return
	}
	q := ctx.query
	scope := q.Get("scope")
	nonce := q.Get("nonce")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")

	grantedScope, err := h.oauthEngine.GrantedScope(ctx.client.ID, scope)
	if err != nil {
		writeHandoffError(w, http.StatusBadRequest, "No requested scope is permitted for this client")
		return
	}
	requirements, err := oauth.ParseAuthenticationRequest(q)
	if err != nil {
		writeHandoffError(w, http.StatusBadRequest, "Invalid authorization request")
		return
	}
	policy, err := h.store.ClientAuthenticationPolicy(ctx.client.ID)
	if err != nil {
		writeHandoffError(w, http.StatusInternalServerError, "Could not check authentication policy")
		return
	}
	requirements = requirements.WithAppPolicy(policy)
	// Authentication freshness was established when Authorize created this interaction.
	requirements.Fresh = false

	enrollment, err := h.store.SessionEnrollmentStatus(ctx.user.ID, ctx.session.ID)
	if err != nil {
		writeHandoffError(w, http.StatusInternalServerError, "Could not check enrollment")
		return
	}
	if enrollment.Restricted || ctx.user.PasswordChangeRequired {
		writeHandoffError(w, http.StatusForbidden, "Complete account setup before continuing")
		return
	}
	allowed, err := h.store.ClientAccessAllowed(ctx.user.ID, ctx.client.ID)
	if err != nil {
		writeHandoffError(w, http.StatusInternalServerError, "Could not check application access")
		return
	}
	if !allowed {
		writeHandoffError(w, http.StatusForbidden, "Access to this application is not permitted")
		return
	}
	if !requirements.Satisfied(ctx.session.AuthenticationEvidence, time.Now().UTC()) {
		writeHandoffError(w, http.StatusConflict, "Authentication no longer meets application requirements; restart sign-in")
		return
	}

	code, err := h.oauthEngine.CreateAuthorizationCodeForInteraction(
		ctx.client.ID, ctx.session.ID, ctx.redirectURI, grantedScope, codeChallenge, codeChallengeMethod, nonce, requirements, ctx.interaction.Hash)
	if err != nil {
		if errors.Is(err, store.ErrAuthorizationInteraction) {
			writeHandoffError(w, http.StatusNotFound, "Keyring handoff expired or already completed")
			return
		}
		if errors.Is(err, store.ErrAppAuthentication) {
			writeHandoffError(w, http.StatusConflict, "Application requirements changed; restart sign-in")
			return
		}
		if errors.Is(err, store.ErrAppAccessDenied) {
			writeHandoffError(w, http.StatusForbidden, "Access to this application is not permitted")
			return
		}
		writeHandoffError(w, http.StatusInternalServerError, "Could not issue an authorization code")
		return
	}

	h.audit.Observe("oauth.authorize", ctx.user.ID, ctx.user.Username, ctx.client.ID, "client", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{
		"scope":          grantedScope,
		"requestedScope": scope,
		"keyringHandoff": true,
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"redirect_uri": ctx.redirectURI,
		"code":         code,
		"state":        ctx.state,
	})
}

// KeyringHandoffCancel drops the pending handoff interaction and returns the validated
// redirect_uri + state so the browser can return error=access_denied to the application.
func (h *OAuthHandler) KeyringHandoffCancel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	ctx, status, msg := h.loadKeyringHandoff(r)
	if status != 0 {
		writeHandoffError(w, status, msg)
		return
	}
	if err := h.store.CancelAuthorizationInteraction(ctx.interaction.Hash, ctx.browserHash); err != nil {
		writeHandoffError(w, http.StatusInternalServerError, "Could not cancel keyring handoff")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"redirect_uri": ctx.redirectURI,
		"state":        ctx.state,
	})
}
