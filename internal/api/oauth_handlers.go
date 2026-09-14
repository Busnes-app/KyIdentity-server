package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Busness-app/kysignon-server/internal/audit"
	"github.com/Busness-app/kysignon-server/internal/crypto"
	"github.com/Busness-app/kysignon-server/internal/oauth"
	"github.com/Busness-app/kysignon-server/internal/store"
)

type OAuthHandler struct {
	store       *store.Store
	oauthEngine *oauth.Engine
	audit       *audit.Logger
	middleware  *MiddlewareManager
}

func NewOAuthHandler(s *store.Store, oauthEngine *oauth.Engine, audit *audit.Logger, mm *MiddlewareManager) *OAuthHandler {
	return &OAuthHandler{
		store:       s,
		oauthEngine: oauthEngine,
		audit:       audit,
		middleware:  mm,
	}
}

// OIDCConfiguration returns OIDC discovery metadata.
func (h *OAuthHandler) OIDCConfiguration(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(h.oauthEngine.GetOIDCConfiguration())
}

// JWKS returns the public RSA keys for ID token verification.
func (h *OAuthHandler) JWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(h.oauthEngine.GetJWKS())
}

// redirectError returns an OAuth error to the client's registered redirect URI. It is only
// safe to call once redirectURI has been validated against the client's registration.
func redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, description string) {
	target, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, `{"error":"invalid_redirect_uri"}`, http.StatusBadRequest)
		return
	}
	q := target.Query()
	q.Set("error", code)
	if description != "" {
		q.Set("error_description", description)
	}
	if state != "" {
		q.Set("state", state)
	}
	target.RawQuery = q.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

// Authorize handles OIDC/OAuth2 authorization request.
func (h *OAuthHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if len(r.URL.RawQuery) > 8192 {
		http.Error(w, `{"error":"invalid_request"}`, 400)
		return
	}
	q, parseErr := url.ParseQuery(r.URL.RawQuery)
	if parseErr != nil {
		http.Error(w, `{"error":"invalid_request"}`, 400)
		return
	}
	interactionHash := ""
	if raw := q.Get("interaction"); raw != "" {
		if len(q) != 1 || len(q["interaction"]) != 1 || len(raw) != 64 {
			http.Error(w, `{"error":"invalid_request"}`, 400)
			return
		}
		interactionHash = crypto.HashSHA256(raw)
		i, err := h.store.GetAuthorizationInteraction(interactionHash, h.middleware.authorizationBrowserHash(r))
		sess := GetSessionFromContext(r.Context())
		if err != nil || sess == nil || i.SessionID != sess.ID {
			http.Error(w, `{"error":"invalid_interaction","error_description":"Sign-in expired or changed in another tab; restart authorization"}`, 400)
			return
		}
		q, parseErr = url.ParseQuery(i.Request)
		if parseErr != nil {
			stepUpInternalError(w)
			return
		}
	}
	// Reject duplicate routing parameters before trusting a redirect destination.
	for _, key := range []string{"client_id", "redirect_uri", "response_type"} {
		if len(q[key]) != 1 {
			http.Error(w, `{"error":"invalid_request"}`, 400)
			return
		}
	}
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	responseType := q.Get("response_type")
	scope := q.Get("scope")
	state := q.Get("state")
	nonce := q.Get("nonce")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")

	if clientID == "" || redirectURI == "" || responseType != "code" {
		http.Error(w, `{"error":"invalid_request","error_description":"Missing client_id, redirect_uri, or response_type=code"}`, http.StatusBadRequest)
		return
	}

	client, err := h.store.GetOAuthClientByID(clientID)
	if err != nil || client == nil || !client.Enabled {
		http.Error(w, `{"error":"unauthorized_client","error_description":"Client not found or disabled"}`, http.StatusUnauthorized)
		return
	}

	// Until this passes, the redirect URI is attacker-controlled and errors must not be
	// sent to it.
	if !h.oauthEngine.ValidateRedirectURI(client, redirectURI) {
		h.audit.Record("oauth.authorize", "", "", clientID, "client", h.middleware.ClientIP(r), r.UserAgent(), "denied",
			map[string]any{"reason": "redirect_uri_not_registered", "redirectUri": redirectURI})
		http.Error(w, `{"error":"invalid_redirect_uri","error_description":"Redirect URI does not match a registered URI for this client"}`, http.StatusBadRequest)
		return
	}

	// Validate the callback before rate-limit errors enter the OIDC error channel.
	// Keep shared limiter keys address-derived: rotating browser identities must
	// neither reset the source allowance nor allocate additional buckets.
	if !h.middleware.allowRateLimit("authorize:ip:"+h.middleware.ClientIP(r), 300, 5) {
		redirectError(w, r, redirectURI, state, "temporarily_unavailable", "Too many authorization requests; try again shortly")
		return
	}

	if codeChallenge == "" && client.ClientType == "public" {
		redirectError(w, r, redirectURI, state, "invalid_request", "PKCE (S256) is required for public clients")
		return
	}
	if codeChallenge != "" && codeChallengeMethod != "S256" {
		redirectError(w, r, redirectURI, state, "invalid_request", "Only the S256 code_challenge_method is supported")
		return
	}

	grantedScope, err := h.oauthEngine.GrantedScope(clientID, scope)
	if err != nil {
		redirectError(w, r, redirectURI, state, "invalid_scope", "No requested scope is permitted for this client")
		return
	}

	requirements, err := oauth.ParseAuthenticationRequest(q)
	if err != nil {
		redirectError(w, r, redirectURI, state, "invalid_request", err.Error())
		return
	}
	policy, err := h.store.ClientAuthenticationPolicy(clientID)
	if err != nil {
		redirectError(w, r, redirectURI, state, "server_error", "Could not check authentication policy")
		return
	}
	requirements = requirements.WithAppPolicy(policy)
	if interactionHash != "" {
		requirements.Fresh = false
	}
	user, session := GetUserFromContext(r.Context()), GetSessionFromContext(r.Context())
	if user == nil || session == nil {
		if requirements.Silent {
			redirectError(w, r, redirectURI, state, "login_required", "Sign-in is required")
			return
		}
		h.beginInteraction(w, r, q)
		return
	}

	enrollment, err := h.store.SessionEnrollmentStatus(user.ID, session.ID)
	if err != nil {
		redirectError(w, r, redirectURI, state, "server_error", "Could not check enrollment")
		return
	}
	if enrollment.Restricted {
		redirectError(w, r, redirectURI, state, "interaction_required", "Complete MFA enrollment at your account dashboard and sign in again")
		return
	}
	allowed, err := h.store.ClientAccessAllowed(user.ID, clientID)
	if err != nil {
		redirectError(w, r, redirectURI, state, "server_error", "Could not check application access")
		return
	}
	if !allowed {
		h.denyAccess(w, r, user, clientID, redirectURI, state)
		return
	}
	if !requirements.Satisfied(session.AuthenticationEvidence, time.Now().UTC()) {
		if requirements.Silent || interactionHash != "" {
			redirectError(w, r, redirectURI, state, "login_required", "Authentication does not meet the requested age or assurance")
			return
		}
		h.beginInteraction(w, r, q)
		return
	}
	code, err := h.oauthEngine.CreateAuthorizationCodeForInteraction(
		clientID, session.ID, redirectURI, grantedScope, codeChallenge, codeChallengeMethod, nonce, requirements, interactionHash)
	if err != nil {
		if errors.Is(err, store.ErrAppAuthentication) || errors.Is(err, store.ErrAuthorizationInteraction) {
			redirectError(w, r, redirectURI, state, "login_required", "Application requirements changed; restart sign-in")
			return
		}
		if errors.Is(err, store.ErrAppAccessDenied) {
			h.denyAccess(w, r, user, clientID, redirectURI, state)
			return
		}
		redirectError(w, r, redirectURI, state, "server_error", "Could not issue an authorization code")
		return
	}

	h.audit.Record("oauth.authorize", user.ID, user.Username, clientID, "client", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{
		"scope":          grantedScope,
		"requestedScope": scope,
	})

	targetURL, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, `{"error":"invalid_redirect_uri"}`, http.StatusBadRequest)
		return
	}
	params := targetURL.Query()
	params.Set("code", code)
	if state != "" {
		params.Set("state", state)
	}
	targetURL.RawQuery = params.Encode()

	http.Redirect(w, r, targetURL.String(), http.StatusFound)
}

// Token handles authorization code exchange for tokens.
func (h *OAuthHandler) Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"invalid_request","error_description":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}

	grantType := r.FormValue("grant_type")
	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	// Also check Basic Auth for confidential client credentials
	if u, p, ok := r.BasicAuth(); ok {
		clientID = u
		clientSecret = p
	}

	if grantType != "authorization_code" || code == "" || clientID == "" {
		http.Error(w, `{"error":"invalid_request","error_description":"grant_type=authorization_code, code, and client_id are required"}`, http.StatusBadRequest)
		return
	}

	tokenResp, err := h.oauthEngine.ExchangeAuthorizationCode(code, clientID, clientSecret, redirectURI, codeVerifier)
	if errors.Is(err, oauth.ErrClaimsTooLarge) {
		// A configuration problem, not a guess about credentials: name it so the app's
		// administrator can fix the mappings.
		h.audit.Record("oauth.token_exchange", "", "", clientID, "client", h.middleware.ClientIP(r), r.UserAgent(), "failure", map[string]any{"error": err.Error()})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request", "error_description": err.Error()})
		return
	}
	if err != nil {
		// The precise reason goes to the audit log, not to the caller: distinguishing
		// "client mismatch" from "invalid PKCE verifier" tells an attacker which half of
		// their guess was right.
		h.audit.Record("oauth.token_exchange", "", "", clientID, "client", h.middleware.ClientIP(r), r.UserAgent(), "failure", map[string]any{
			"error": err.Error(),
		})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": "The authorization code, client credentials, redirect URI, or PKCE verifier is invalid",
		})
		return
	}

	h.audit.Record("oauth.token_exchange", "", "", clientID, "client", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(tokenResp)
}

// Userinfo returns claims for an authenticated access token.
func (h *OAuthHandler) Userinfo(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, `{"error":"invalid_token","error_description":"Bearer token required"}`, http.StatusUnauthorized)
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	claims, err := h.oauthEngine.GetUserinfo(tokenString)
	if err != nil {
		// err may name the exact failed check; echoing it back into the response would
		// build an oracle out of the error string.
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, `{"error":"invalid_token","error_description":"The access token is invalid, expired, or revoked"}`, http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(claims)
}

// Revoke implements RFC 7009 token revocation. The caller must authenticate as the client
// the token was issued to.
func (h *OAuthHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"invalid_request","error_description":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}

	token := r.FormValue("token")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	if u, p, ok := r.BasicAuth(); ok {
		clientID = u
		clientSecret = p
	}

	if token == "" || clientID == "" {
		http.Error(w, `{"error":"invalid_request","error_description":"token and client_id are required"}`, http.StatusBadRequest)
		return
	}

	if err := h.oauthEngine.RevokeToken(token, clientID, clientSecret); err != nil {
		h.audit.Record("oauth.revoke", "", "", clientID, "client", h.middleware.ClientIP(r), r.UserAgent(), "failure",
			map[string]any{"error": err.Error()})
		http.Error(w, `{"error":"invalid_client","error_description":"Client authentication failed"}`, http.StatusUnauthorized)
		return
	}

	h.audit.Record("oauth.revoke", "", "", clientID, "client", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)

	// RFC 7009 §2.2: 200 regardless of whether the token was live, so the response is
	// not an oracle for token validity.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

// denyAccess audits an access denial with the reason and policy revisions of this
// moment, so an old denial is never explained with today's policy, and tells a user of
// a requestable app where to ask.
func (h *OAuthHandler) denyAccess(w http.ResponseWriter, r *http.Request, user *store.User, clientID, redirectURI, state string) {
	details := map[string]any{"reason": "app_access_denied"}
	description := "You do not have access to this application"
	if e, err := h.store.ExplainClientAccess(user.ID, clientID); err == nil {
		details = map[string]any{"reason": e.Reason, "revision": e.Revision, "authenticationRevision": e.AuthRevision, "roleRevision": e.RoleRevision}
		if e.Requestable {
			description += ". You can request it from your KySignOn dashboard"
		}
	}
	h.audit.Record("oauth.authorize", user.ID, user.Username, clientID, "client", h.middleware.ClientIP(r), r.UserAgent(), "denied", details)
	redirectError(w, r, redirectURI, state, "access_denied", description)
}
