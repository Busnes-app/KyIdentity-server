package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"github.com/Busnes-app/kyidentity-server/internal/oauth"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

const authorizationBrowserCookie = "kyidentity_authorization_browser"

func (m *MiddlewareManager) authorizationBrowserHash(r *http.Request) string {
	c, err := r.Cookie(authorizationBrowserCookie)
	if err != nil {
		return ""
	}
	raw, signature, ok := strings.Cut(c.Value, ".")
	if !ok || len(raw) != 64 {
		return ""
	}
	expected := crypto.SignHMACSHA256(m.csrfKey, []byte("authorization-browser:"+raw))
	if subtle.ConstantTimeCompare([]byte(signature), []byte(expected)) != 1 {
		return ""
	}
	return crypto.HashSHA256(raw)
}

func (h *OAuthHandler) ensureAuthorizationBrowserHash(w http.ResponseWriter, r *http.Request) (string, error) {
	browserHash := h.middleware.authorizationBrowserHash(r)
	if browserHash != "" {
		return browserHash, nil
	}
	raw, err := crypto.GenerateRandomHex(32)
	if err != nil {
		return "", err
	}
	browserHash = crypto.HashSHA256(raw)
	http.SetCookie(w, &http.Cookie{
		Name:     authorizationBrowserCookie,
		Value:    raw + "." + crypto.SignHMACSHA256(h.middleware.csrfKey, []byte("authorization-browser:"+raw)),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return browserHash, nil
}

func (h *OAuthHandler) beginInteraction(w http.ResponseWriter, r *http.Request, q url.Values) {
	browserHash, err := h.ensureAuthorizationBrowserHash(w, r)
	if err != nil {
		stepUpInternalError(w)
		return
	}
	raw, err := crypto.GenerateRandomHex(32)
	if err != nil {
		stepUpInternalError(w)
		return
	}
	now := time.Now().UTC()
	i := &store.AuthorizationInteraction{ClientID: q.Get("client_id"), Hash: crypto.HashSHA256(raw), BrowserHash: browserHash, Request: q.Encode(), CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	if sess := GetSessionFromContext(r.Context()); sess != nil {
		i.UserID = sess.UserID
		i.OriginalSessionID = sess.ID
	}
	if err := h.store.CreateAuthorizationInteraction(i); err != nil {
		if errors.Is(err, store.ErrAuthorizationInteraction) {
			redirectError(w, r, q.Get("redirect_uri"), q.Get("state"), "temporarily_unavailable", "Too many sign-in requests; wait a few minutes and restart")
		} else {
			redirectError(w, r, q.Get("redirect_uri"), q.Get("state"), "server_error", "Could not start sign-in")
		}
		return
	}
	h.audit.Observe("oauth.interaction", i.UserID, "", q.Get("client_id"), "client", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"reason": "interaction_started"})
	http.Redirect(w, r, "/login?interaction="+raw, http.StatusFound)
}

const keyringHandoffTTL = 10 * time.Minute

func (h *OAuthHandler) beginKeyringHandoff(w http.ResponseWriter, r *http.Request, q url.Values, user *store.User, sess *store.Session, existingRaw, existingHash string) {
	browserHash, err := h.ensureAuthorizationBrowserHash(w, r)
	if err != nil {
		redirectError(w, r, q.Get("redirect_uri"), q.Get("state"), "server_error", "Could not start keyring handoff")
		return
	}
	now := time.Now().UTC()
	raw := existingRaw
	if raw != "" && existingHash != "" {
		if err := h.store.ExtendAuthorizationInteraction(existingHash, browserHash, sess.ID, now.Add(keyringHandoffTTL)); err != nil {
			redirectError(w, r, q.Get("redirect_uri"), q.Get("state"), "login_required", "Sign-in expired; restart from the application")
			return
		}
	} else {
		raw, err = crypto.GenerateRandomHex(32)
		if err != nil {
			redirectError(w, r, q.Get("redirect_uri"), q.Get("state"), "server_error", "Could not start keyring handoff")
			return
		}
		i := &store.AuthorizationInteraction{
			ClientID:    q.Get("client_id"),
			Hash:        crypto.HashSHA256(raw),
			BrowserHash: browserHash,
			UserID:      user.ID,
			SessionID:   sess.ID,
			Request:     q.Encode(),
			CreatedAt:   now,
			ExpiresAt:   now.Add(keyringHandoffTTL),
		}
		if err := h.store.CreateAuthorizationInteraction(i); err != nil {
			if errors.Is(err, store.ErrAuthorizationInteraction) {
				redirectError(w, r, q.Get("redirect_uri"), q.Get("state"), "temporarily_unavailable", "Too many sign-in requests; wait a few minutes and restart")
			} else {
				redirectError(w, r, q.Get("redirect_uri"), q.Get("state"), "server_error", "Could not start keyring handoff")
			}
			return
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	http.Redirect(w, r, "/keyring-handoff?interaction="+raw, http.StatusFound)
}

func (h *OAuthHandler) CancelInteraction(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Interaction string `json:"interaction"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Interaction) != 64 {
		http.Error(w, `{"error":"invalid_request"}`, 400)
		return
	}
	if err := h.store.CancelAuthorizationInteraction(crypto.HashSHA256(req.Interaction), h.middleware.authorizationBrowserHash(r)); err != nil {
		stepUpInternalError(w)
		return
	}
	writeStepUpJSON(w, map[string]bool{"success": true})
}

func (h *OAuthHandler) InteractionDetails(w http.ResponseWriter, r *http.Request) {
	i, err := h.store.GetAuthorizationInteraction(crypto.HashSHA256(r.PathValue("id")), h.middleware.authorizationBrowserHash(r))
	if err != nil || i.SessionID != "" {
		http.Error(w, `{"error":"invalid_interaction","error_description":"Sign-in expired; restart from the application"}`, 400)
		return
	}
	q, err := url.ParseQuery(i.Request)
	if err != nil {
		stepUpInternalError(w)
		return
	}
	client, err := h.store.GetOAuthClientByID(q.Get("client_id"))
	if err != nil || client == nil || !client.Enabled {
		http.Error(w, `{"error":"invalid_interaction"}`, 400)
		return
	}
	username := ""
	if i.UserID != "" {
		u, err := h.store.PrincipalByID(i.UserID)
		if err != nil || u == nil || u.Status != "active" {
			http.Error(w, `{"error":"invalid_interaction"}`, 400)
			return
		}
		username = u.Username
	}
	requirements, err := oauth.ParseAuthenticationRequest(q)
	if err != nil {
		stepUpInternalError(w)
		return
	}
	policy, err := h.store.ClientAuthenticationPolicy(client.ID)
	if err != nil {
		stepUpInternalError(w)
		return
	}
	writeStepUpJSON(w, map[string]any{"appName": client.ClientName, "username": username, "requiresMFA": requirements.ACR == oauth.MFAACR || policy.Factor != "password", "requiresPasskey": policy.Factor == "passkey"})
}
