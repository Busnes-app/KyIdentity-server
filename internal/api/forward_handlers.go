package api

import (
	"crypto/subtle"
	"errors"
	"html"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/audit"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// Forward-auth (docs/FORWARD-AUTH.md). The edge routes (check, begin, callback, logout)
// are reached only through nginx on the app's own host and authenticate the per-app edge
// secret; /forward/start runs on KyIdentity's own origin with the login session.
const (
	forwardCookie      = "__Host-ky_fwd"
	forwardNonceCookie = "__Host-ky_fwd_n"
	edgeSecretHeader   = "X-Ky-Edge-Secret"
	forwardCacheTTL    = 30 * time.Second
	forwardCacheMax    = 10000
)

type forwardDecision struct {
	status              int
	user, email, groups string
	header              string
	until               time.Time
}

type ForwardHandler struct {
	store      *store.Store
	audit      *audit.Logger
	middleware *MiddlewareManager
	issuer     string
	now        func() time.Time

	mu    sync.Mutex
	apps  map[string]forwardApp
	cache map[string]forwardDecision
}

type forwardApp struct {
	app   *store.ProxyApp
	until time.Time
}

func NewForwardHandler(s *store.Store, a *audit.Logger, m *MiddlewareManager, issuer string) *ForwardHandler {
	return &ForwardHandler{store: s, audit: a, middleware: m, issuer: strings.TrimRight(issuer, "/"), now: time.Now,
		apps: map[string]forwardApp{}, cache: map[string]forwardDecision{}}
}

// appByHost caches the proxy app row for at most forwardCacheTTL, so a secret rotation or
// edit reaches every replica within that time.
func (h *ForwardHandler) appByHost(host string) (*store.ProxyApp, error) {
	now := h.now()
	h.mu.Lock()
	if c, ok := h.apps[host]; ok && now.Before(c.until) {
		h.mu.Unlock()
		return c.app, nil
	}
	h.mu.Unlock()
	app, err := h.store.ProxyAppByHost(host)
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	if len(h.apps) >= forwardCacheMax {
		h.apps = map[string]forwardApp{}
	}
	h.apps[host] = forwardApp{app: app, until: now.Add(forwardCacheTTL)}
	h.mu.Unlock()
	return app, nil
}

// edge authenticates an edge route: the host must be a proxy app and the edge secret
// must be that app's. Failures spend a per-IP budget and are audited while it lasts.
func (h *ForwardHandler) edge(w http.ResponseWriter, r *http.Request) (*store.ProxyApp, bool) {
	w.Header().Set("Cache-Control", "no-store")
	host := r.Header.Get("X-Forwarded-Host")
	secret := r.Header.Get(edgeSecretHeader)
	var app *store.ProxyApp
	if host != "" && secret != "" && len(secret) <= 256 {
		var err error
		if app, err = h.appByHost(host); err != nil {
			log.Printf("forward: proxy app lookup failed: %v", err)
			http.Error(w, "", http.StatusInternalServerError)
			return nil, false
		}
	}
	if app == nil || subtle.ConstantTimeCompare([]byte(crypto.HashSHA256(secret)), []byte(app.SecretHash)) != 1 {
		if !h.middleware.allowRateLimit("forward_edge:"+h.middleware.rateLimitIP(r), 30, 1) {
			http.Error(w, "", http.StatusTooManyRequests)
			return nil, false
		}
		target := ""
		if app != nil {
			target = app.ID
		}
		h.audit.Observe("forward.edge_rejected", "", "", target, "application", h.middleware.ClientIP(r), r.UserAgent(), "denied", nil)
		http.Error(w, "", http.StatusUnauthorized)
		return nil, false
	}
	return app, true
}

// bypassed reports whether the raw request path falls under a bypass prefix. Anything
// that a backend might normalise differently (encodings, dot segments, doubled slashes,
// backslashes, path parameters) is never bypassed and gets the full check.
func bypassed(rawURI string, prefixes []string) bool {
	if len(prefixes) == 0 {
		return false
	}
	path, _, _ := strings.Cut(rawURI, "?")
	if !store.ForwardPath(path) || strings.ContainsAny(path, "%;") || strings.Contains(path, "..") {
		return false
	}
	for _, p := range prefixes {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// headerValue keeps a value only when it is printable ASCII, so nothing can split headers.
func headerValue(v string) string {
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] >= 0x7f {
			return ""
		}
	}
	return v
}

func (h *ForwardHandler) decide(app *store.ProxyApp, cookieHash string) (forwardDecision, error) {
	now := h.now()
	key := app.Host + "|" + cookieHash
	h.mu.Lock()
	d, ok := h.cache[key]
	h.mu.Unlock()
	if ok && now.Before(d.until) {
		return d, nil
	}
	fs, err := h.store.ForwardSessionFor(cookieHash, app.Host)
	if err != nil || fs == nil {
		return forwardDecision{status: http.StatusUnauthorized}, err
	}
	d = forwardDecision{status: http.StatusUnauthorized, until: now.Add(forwardCacheTTL)}
	if fs.ExpiresAt.Before(d.until) {
		d.until = fs.ExpiresAt
	}
	switch {
	case !fs.Access.Active:
	case !fs.Access.Allowed:
		d.status = http.StatusForbidden
	case !fs.Access.Permits(fs.Evidence, now):
	default:
		groups := make([]string, 0, len(fs.Groups))
		for _, g := range fs.Groups {
			if headerValue(g) != "" && !strings.Contains(g, ",") {
				groups = append(groups, g)
			}
		}
		d.status, d.user, d.email, d.groups, d.header = http.StatusOK, headerValue(fs.Username), headerValue(fs.Email), strings.Join(groups, ","), app.LoginHeader
		if d.user == "" {
			d.status = http.StatusUnauthorized
		}
	}
	if d.status != http.StatusOK {
		h.audit.Observe("forward.check_denied", fs.UserID, "", app.ID, "application", "", "", "denied", map[string]any{"status": d.status})
	}
	h.mu.Lock()
	if len(h.cache) >= forwardCacheMax {
		h.cache = map[string]forwardDecision{}
	}
	h.cache[key] = d
	h.mu.Unlock()
	return d, nil
}

// Check is nginx's auth_request: 200 with identity headers, 401 or 403.
func (h *ForwardHandler) Check(w http.ResponseWriter, r *http.Request) {
	app, ok := h.edge(w, r)
	if !ok {
		return
	}
	if bypassed(r.Header.Get("X-Original-URI"), app.Bypass) {
		w.WriteHeader(http.StatusOK)
		return
	}
	c, err := r.Cookie(forwardCookie)
	if err != nil || len(c.Value) != 64 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	d, err := h.decide(app, crypto.HashSHA256(c.Value))
	if err != nil {
		log.Printf("forward: check failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if d.status == http.StatusOK {
		w.Header().Set("X-Ky-User", d.user)
		w.Header().Set(d.header, d.user)
		w.Header().Set("X-Ky-Email", d.email)
		w.Header().Set("X-Ky-Groups", d.groups)
	}
	w.WriteHeader(d.status)
}

// Begin (/.ky/start on the app host) sets the browser nonce and sends the browser to
// KyIdentity's /forward/start. The path comes from rd, else from nginx's X-Original-URI.
func (h *ForwardHandler) Begin(w http.ResponseWriter, r *http.Request) {
	app, ok := h.edge(w, r)
	if !ok {
		return
	}
	path := r.URL.Query().Get("rd")
	if path == "" {
		path = r.Header.Get("X-Original-URI")
	}
	if !store.ForwardPath(path) || strings.HasPrefix(path, "/.ky/") {
		path = "/"
	}
	nonce, err := crypto.GenerateRandomHex(32)
	if err != nil {
		stepUpInternalError(w)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: forwardNonceCookie, Value: nonce, Path: "/", MaxAge: 600, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	q := url.Values{"rd": {"https://" + app.Host + path}, "n": {crypto.HashSHA256(nonce)}}
	http.Redirect(w, r, h.issuer+"/forward/start?"+q.Encode(), http.StatusFound)
}

// forwardTarget validates rd: an absolute https URL, no userinfo, port or fragment, whose
// host is exactly a registered proxy app. It returns the app and the path to return to.
func (h *ForwardHandler) forwardTarget(rd string) (*store.ProxyApp, string) {
	if rd == "" || len(rd) > store.MaxForwardPath+300 || strings.ContainsAny(rd, "\\") {
		return nil, ""
	}
	for i := 0; i < len(rd); i++ {
		if rd[i] <= 0x20 || rd[i] >= 0x7f {
			return nil, ""
		}
	}
	u, err := url.Parse(rd)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Port() != "" || u.Fragment != "" || strings.Contains(rd, "#") ||
		u.Host == "" || u.Host != strings.ToLower(u.Host) || !strings.HasPrefix(rd, "https://"+u.Host) {
		return nil, ""
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" || u.ForceQuery {
		path += "?" + u.RawQuery
	}
	if !store.ForwardPath(path) {
		return nil, ""
	}
	app, err := h.store.ProxyAppByHost(u.Host)
	if err != nil || app == nil {
		return nil, ""
	}
	return app, path
}

func forwardErrorPage(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>KyIdentity</title><link rel="stylesheet" href="/css/styles.css"></head><body><main class="auth-container"><h1>Cannot open this app</h1><p>` +
		html.EscapeString(message) + `</p><p><a href="/">Go to KyIdentity</a></p></main></body></html>`))
}

// Start runs on KyIdentity's origin: sign in if needed, check access and policy, then
// send the browser to the app host's callback with a one-time code.
func (h *ForwardHandler) Start(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	app, path := h.forwardTarget(q.Get("rd"))
	if app == nil || len(q["rd"]) != 1 || len(q["n"]) > 1 {
		forwardErrorPage(w, http.StatusBadRequest, "This link does not name an app protected by KyIdentity.")
		return
	}
	nonceHash := q.Get("n")
	if nonceHash == "" {
		// Started at KyIdentity: let the app host set the browser nonce first.
		http.Redirect(w, r, "https://"+app.Host+"/.ky/start?"+url.Values{"rd": {path}}.Encode(), http.StatusFound)
		return
	}
	if len(nonceHash) != 64 || strings.Trim(nonceHash, "0123456789abcdef") != "" {
		forwardErrorPage(w, http.StatusBadRequest, "This sign-in link is malformed. Open the app again.")
		return
	}
	user, sess := GetUserFromContext(r.Context()), GetSessionFromContext(r.Context())
	if user == nil || sess == nil {
		inner := "/forward/start?" + url.Values{"rd": {q.Get("rd")}, "n": {nonceHash}}.Encode()
		// LoginView decodes return_to once more after URLSearchParams has.
		http.Redirect(w, r, "/login?return_to="+url.QueryEscape(url.QueryEscape(inner)), http.StatusFound)
		return
	}
	ip := h.middleware.ClientIP(r)
	deny := func(reason, message string, status int) {
		h.audit.Observe("forward.start", user.ID, "", app.ID, "application", ip, r.UserAgent(), "denied", map[string]any{"reason": reason})
		forwardErrorPage(w, status, message)
	}
	enrollment, err := h.store.SessionEnrollmentStatus(user.ID, sess.ID)
	if err != nil {
		forwardErrorPage(w, http.StatusInternalServerError, "Something went wrong. Try again.")
		return
	}
	if enrollment.Restricted || user.PasswordChangeRequired {
		deny("account_action_required", "Finish the steps KyIdentity asks for on your account page, then open the app again.", http.StatusForbidden)
		return
	}
	access, err := h.store.ForwardAccessFor(app.ID, user.ID)
	if err != nil {
		forwardErrorPage(w, http.StatusInternalServerError, "Something went wrong. Try again.")
		return
	}
	if !access.Active || !access.Allowed {
		deny("not_assigned", "Your account has not been given access to this app. Ask an administrator.", http.StatusForbidden)
		return
	}
	if !access.Permits(sess.AuthenticationEvidence, time.Now().UTC()) {
		deny("policy", "This app needs a stronger or more recent sign-in. Sign out of KyIdentity, sign in again with your second factor, then open the app again.", http.StatusForbidden)
		return
	}
	code, err := crypto.GenerateRandomHex(32)
	if err != nil {
		stepUpInternalError(w)
		return
	}
	pending := h.audit.Prepare("forward.start", user.ID, "", app.ID, "application", ip, r.UserAgent(), "success", nil)
	if err := h.store.CreateForwardCode(&store.ForwardCode{Hash: crypto.HashSHA256(code), AppID: app.ID, Host: app.Host, SessionID: sess.ID, UserID: user.ID, NonceHash: nonceHash, Path: path}, pending.Row); err != nil {
		log.Printf("forward: code creation failed: %v", err)
		forwardErrorPage(w, http.StatusInternalServerError, "Something went wrong. Try again.")
		return
	}
	pending.Committed()
	http.Redirect(w, r, "https://"+app.Host+"/.ky/callback?code="+code, http.StatusFound)
}

// Callback (/.ky/callback on the app host) redeems the code and sets the host cookie.
func (h *ForwardHandler) Callback(w http.ResponseWriter, r *http.Request) {
	app, ok := h.edge(w, r)
	if !ok {
		return
	}
	ip := h.middleware.ClientIP(r)
	code := r.URL.Query().Get("code")
	nonce, err := r.Cookie(forwardNonceCookie)
	if len(code) != 64 || err != nil || len(nonce.Value) != 64 {
		h.audit.Observe("forward.code_rejected", "", "", app.ID, "application", ip, r.UserAgent(), "denied", map[string]any{"reason": "missing"})
		forwardErrorPage(w, http.StatusBadRequest, "This sign-in link has expired or was opened in another browser. Open the app again.")
		return
	}
	raw, err := crypto.GenerateRandomHex(32)
	if err != nil {
		stepUpInternalError(w)
		return
	}
	pending := h.audit.Prepare("forward.session_created", "", "", app.ID, "application", ip, r.UserAgent(), "success", nil)
	path, redeemed, err := h.store.RedeemForwardCode(crypto.HashSHA256(code), app.Host, crypto.HashSHA256(nonce.Value), crypto.HashSHA256(raw), pending.Row)
	if err != nil {
		reason := "invalid"
		if errors.Is(err, store.ErrForwardDenied) {
			reason = "access"
		} else if !errors.Is(err, store.ErrForwardCode) {
			log.Printf("forward: code redemption failed: %v", err)
			forwardErrorPage(w, http.StatusInternalServerError, "Something went wrong. Try again.")
			return
		}
		h.audit.Observe("forward.code_rejected", "", "", app.ID, "application", ip, r.UserAgent(), "denied", map[string]any{"reason": reason})
		forwardErrorPage(w, http.StatusBadRequest, "This sign-in link has expired or was opened in another browser. Open the app again.")
		return
	}
	pending.Committed()
	http.SetCookie(w, &http.Cookie{Name: forwardNonceCookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{Name: forwardCookie, Value: raw, Path: "/", MaxAge: int(redeemed.SessionSeconds), Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, path, http.StatusFound)
}

// Logout (/.ky/logout on the app host) ends this host's forward session.
func (h *ForwardHandler) Logout(w http.ResponseWriter, r *http.Request) {
	app, ok := h.edge(w, r)
	if !ok {
		return
	}
	if c, err := r.Cookie(forwardCookie); err == nil && len(c.Value) == 64 {
		hash := crypto.HashSHA256(c.Value)
		pending := h.audit.Prepare("forward.logout", "", "", app.ID, "application", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
		ended, err := h.store.EndForwardSession(hash, app.Host, pending.Row)
		if err != nil {
			log.Printf("forward: logout failed: %v", err)
			stepUpInternalError(w)
			return
		}
		if ended {
			pending.Committed()
		}
		h.mu.Lock()
		delete(h.cache, app.Host+"|"+hash)
		h.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: forwardCookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, h.issuer+"/", http.StatusFound)
}
