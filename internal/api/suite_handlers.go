package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Busnes-app/kyidentity-server/internal/audit"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/oauth"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// SuiteHandler serves the suite directory (docs/SUITE-DIRECTORY.md) to registered apps.
type SuiteHandler struct {
	store         *store.Store
	oauthEngine   *oauth.Engine
	audit         *audit.Logger
	middleware    *MiddlewareManager
	encryptionKey []byte
}

// suitePeers are the pairs KyIdentity introduces, each as {a, b} with a < b.
var suitePeers = map[[2]string]bool{{"kycalendar", "kypost"}: true}

func suiteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// Authenticate admits an enabled confidential client by HTTP Basic, then rate limits it.
func (h *SuiteHandler) Authenticate(next func(http.ResponseWriter, *http.Request, *store.OAuthClient)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		err := oauth.ErrInvalidClient
		var client *store.OAuthClient
		if id, secret, ok := r.BasicAuth(); ok {
			client, err = h.oauthEngine.AuthenticateConfidentialClient(id, secret)
		}
		if errors.Is(err, oauth.ErrInvalidClient) {
			w.Header().Set("WWW-Authenticate", `Basic realm="kyidentity"`)
			suiteJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
			return
		}
		if err != nil {
			suiteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
			return
		}
		if !h.middleware.allowRateLimit("suite_client:"+client.ID, 120, 2) {
			suiteJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limit_exceeded"})
			return
		}
		next(w, r, client)
	})
}

type suiteApp struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

// Apps lists launchable suite apps, for one user when sub is given.
func (h *SuiteHandler) Apps(w http.ResponseWriter, r *http.Request, caller *store.OAuthClient) {
	var keys, admin map[string]bool
	var err error
	if q := r.URL.Query(); q.Has("sub") {
		keys, err = h.store.LauncherAppAccess(q.Get("sub"))
		if err == nil {
			admin, err = h.store.LauncherAdminClients(q.Get("sub"))
		}
		if !keys["client:"+caller.ID] {
			keys = nil
		}
	} else {
		keys, err = h.store.EnabledAppKeys()
	}
	if err != nil {
		suiteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	apps, err := launcherApps(h.store, func(key string) bool { return keys[key] }, admin)
	if err != nil {
		suiteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	out := []suiteApp{}
	for _, app := range apps {
		if app.Source == "client" && validateExternalURL(app.URL) == nil {
			out = append(out, suiteApp{ID: app.ID, Name: app.Name, URL: app.URL})
		}
	}
	suiteJSON(w, http.StatusOK, map[string]any{"apps": out})
}

// suitePeerSecret is the shared secret of the pair a < b.
func suitePeerSecret(key []byte, a, b string) string {
	return base64.StdEncoding.EncodeToString(crypto.DeriveKey(key, "kyidentity:suite-peer:v1:"+a+"|"+b))
}

// Peer gives the caller its paired app's origin and their shared secret.
func (h *SuiteHandler) Peer(w http.ResponseWriter, r *http.Request, caller *store.OAuthClient) {
	// Exact IDs: registrations differing only in case are different clients.
	a, b := caller.ID, r.URL.Query().Get("client")
	if b < a {
		a, b = b, a
	}
	if !suitePeers[[2]string{a, b}] {
		suiteJSON(w, http.StatusNotFound, map[string]string{"error": "no_peer"})
		return
	}
	peer, err := h.store.GetOAuthClientByID(r.URL.Query().Get("client"))
	if err != nil {
		suiteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	origin := ""
	if peer != nil && peer.Enabled {
		origin, _ = clientRedirectOrigin(*peer)
	}
	if origin == "" || validateExternalURL(origin) != nil {
		suiteJSON(w, http.StatusNotFound, map[string]string{"error": "no_peer"})
		return
	}
	h.audit.Observe("suite.peer.issue", "", "", caller.ID, "client", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"client": caller.ID, "peer": peer.ID})
	suiteJSON(w, http.StatusOK, map[string]string{"client": peer.ID, "url": origin, "secret": suitePeerSecret(h.encryptionKey, a, b)})
}
