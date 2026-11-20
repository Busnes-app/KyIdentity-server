package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

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
	// multiTenant scopes groups by org_id and serves /api/suite/orgs (tenancy design).
	multiTenant bool
}

// suitePeers are the pairs KyIdentity introduces, each as {a, b} with a < b.
var suitePeers = map[[2]string]bool{
	{"kycalendar", "kypost"}:    true,
	{"kycalendar", "kymessage"}: true,
	{"kydrive", "kypost"}:       true,
	{"kymessage", "kypost"}:     true,
	{"kypost", "kypulse"}:       true,
}

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

type suitePerson struct {
	Sub   string `json:"sub"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// People searches (q) or resolves (email) the people the calling app may offer the user
// sub: active everyday users who may open the caller. Empty unless sub is such a user too.
func (h *SuiteHandler) People(w http.ResponseWriter, r *http.Request, caller *store.OAuthClient) {
	query := r.URL.Query()
	sub, text, emails, limit := query.Get("sub"), query.Get("q"), query["email"], 10
	ok := sub != "" && query.Has("q") != (emails != nil)
	if ok && emails == nil {
		n := utf8.RuneCountInString(text)
		ok = utf8.ValidString(text) && n >= 2 && n <= 64
		if query.Has("limit") {
			var err error
			limit, err = strconv.Atoi(query.Get("limit"))
			ok = ok && err == nil && limit >= 1 && limit <= 20
		}
	} else if ok {
		limit = len(emails)
		ok = limit <= 100 && !query.Has("limit")
		for _, e := range emails {
			ok = ok && e != "" && len(e) <= 254 && utf8.ValidString(e)
		}
	}
	if !ok {
		suiteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	out := []suitePerson{}
	user, err := h.store.PrincipalByID(sub)
	allowed := false
	if err == nil && user != nil && user.Role == "user" {
		allowed, err = h.store.ClientAccessAllowed(sub, caller.ID)
	}
	var people []store.SuitePerson
	if err == nil && allowed {
		// Only the sub's own org: the org comes from the user row, never the caller.
		people, err = h.store.Org(user.Org()).SuitePeople(caller.ID, text, emails, limit)
	}
	if err != nil {
		suiteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	for _, p := range people {
		out = append(out, suitePerson{Sub: p.ID, Name: p.Name, Email: p.Email})
	}
	suiteJSON(w, http.StatusOK, map[string]any{"people": out})
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

// Groups lists the suite groups for the calling app (docs/SUITE-DIRECTORY.md): the
// install's in single-tenant mode, else the org_id one's, which is required.
func (h *SuiteHandler) Groups(w http.ResponseWriter, r *http.Request, caller *store.OAuthClient) {
	org := h.store.DefaultOrg()
	if h.multiTenant {
		id := r.URL.Query().Get("org_id")
		if id == "" {
			suiteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
		o, ok, err := h.store.SuiteOrg(caller.ID, id)
		if err != nil {
			suiteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
			return
		}
		if !ok {
			suiteJSON(w, http.StatusNotFound, map[string]string{"error": "unknown_org"})
			return
		}
		org = h.store.Org(o)
	}
	groups, err := org.SuiteGroupsFor(caller.ID)
	if err != nil {
		suiteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	suiteJSON(w, http.StatusOK, map[string]any{"groups": groups})
}

// suiteOrgsLimit bounds one /api/suite/orgs page.
const suiteOrgsLimit = 500

// Orgs lists the orgs the calling app serves, with that app's enablement and quotas, in
// revision order (docs/SUITE-DIRECTORY.md). Multi-tenant only.
func (h *SuiteHandler) Orgs(w http.ResponseWriter, r *http.Request, caller *store.OAuthClient) {
	if !h.multiTenant {
		suiteJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}
	q := r.URL.Query()
	var after int64
	var afterID string
	limit, ok := 100, !(q.Has("since") && q.Has("cursor"))
	var err error
	if q.Has("since") {
		after, err = strconv.ParseInt(q.Get("since"), 10, 64)
		ok = ok && err == nil && after >= 0
	}
	if q.Has("cursor") {
		rev, id, found := strings.Cut(q.Get("cursor"), ".")
		after, err = strconv.ParseInt(rev, 10, 64)
		ok = ok && found && err == nil && after >= 0 && id != "" && len(id) <= 64
		afterID = id
	}
	if q.Has("limit") {
		limit, err = strconv.Atoi(q.Get("limit"))
		ok = ok && err == nil && limit >= 1 && limit <= suiteOrgsLimit
	}
	if !ok {
		suiteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	orgs, err := h.store.Platform().SuiteOrgs(caller.ID, after, afterID, limit)
	if err != nil {
		suiteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	body := map[string]any{"orgs": orgs}
	if len(orgs) == limit {
		last := orgs[len(orgs)-1]
		body["next"] = strconv.FormatInt(last.Revision, 10) + "." + last.ID
	}
	suiteJSON(w, http.StatusOK, body)
}
