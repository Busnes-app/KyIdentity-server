package api

import (
	"errors"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/Busness-app/kysignon-server/internal/oauth"
	"github.com/Busness-app/kysignon-server/internal/store"
)

// EndSession implements OpenID Connect RP-Initiated Logout at /oauth/logout.
//
// A relying party may only steer the browser somewhere it registered, exactly, and may
// only end this browser's session silently when it proves, with an ID token this server
// issued to it for this user, that it is acting for the person signed in here. Anything
// weaker gets a confirmation page instead of a logout, and an unregistered redirect gets
// an error instead of a redirect.
func (h *OAuthHandler) EndSession(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil {
			logoutPage(w, http.StatusBadRequest, logoutView{Title: "Sign-out request rejected", Message: "The request was too large or malformed."})
			return
		}
	}
	q := r.Form
	if r.Method != http.MethodPost {
		q = r.URL.Query()
	}
	hintRaw, clientID := q.Get("id_token_hint"), q.Get("client_id")
	redirect, state := q.Get("post_logout_redirect_uri"), q.Get("state")
	if len(hintRaw) > 8192 || len(clientID) > 256 || len(redirect) > 2048 || len(state) > 512 {
		logoutPage(w, http.StatusBadRequest, logoutView{Title: "Sign-out request rejected", Message: "A request parameter exceeds its size limit."})
		return
	}

	var hint *oauth.IDTokenHint
	if hintRaw != "" {
		parsed, err := h.oauthEngine.ParseIDTokenHint(hintRaw)
		if err != nil || (clientID != "" && clientID != parsed.ClientID) {
			logoutPage(w, http.StatusBadRequest, logoutView{Title: "Sign-out request rejected", Message: "The ID token hint is not valid for this issuer and client."})
			return
		}
		hint, clientID = &parsed, parsed.ClientID
	}
	var client *store.OAuthClient
	if clientID != "" {
		c, err := h.store.GetOAuthClientByID(clientID)
		if err != nil {
			stepUpInternalError(w)
			return
		}
		if c == nil || !c.Enabled {
			logoutPage(w, http.StatusBadRequest, logoutView{Title: "Sign-out request rejected", Message: "Unknown or disabled application."})
			return
		}
		client = c
	}
	if redirect != "" && !h.oauthEngine.ValidatePostLogoutRedirectURI(client, redirect) {
		logoutPage(w, http.StatusBadRequest, logoutView{Title: "Sign-out request rejected", Message: "The application asked to send you to an address it has not registered for sign-out. Nothing was changed."})
		return
	}

	user, sess := GetUserFromContext(r.Context()), GetSessionFromContext(r.Context())
	if sess == nil {
		h.finishLogout(w, r, redirect, state)
		return
	}
	if hint == nil || hint.Subject != user.ID {
		cookie, _ := r.Cookie("kysignon_session")
		confirm := q.Get("confirm")
		if confirm == "" {
			name := "An application"
			if client != nil {
				name = client.ClientName
			}
			// Browsers apply form-action to the redirect that follows the form POST. The
			// origin is safe to allow because the full URI already matched the registration.
			if target, err := url.Parse(redirect); err == nil && redirect != "" {
				w.Header().Set("Content-Security-Policy", strings.Replace(w.Header().Get("Content-Security-Policy"), "form-action 'self';", "form-action 'self' "+target.Scheme+"://"+target.Host+";", 1))
			}
			logoutPage(w, http.StatusOK, logoutView{
				Title: "Sign out of KySignOn?", Message: name + " asked to sign you out of KySignOn in this browser.",
				Confirm: h.middleware.IssueCSRFToken(cookie.Value), Fields: map[string]string{"client_id": clientID, "post_logout_redirect_uri": redirect, "state": state},
			})
			return
		}
		if !h.middleware.csrfTokenMatchesSession(cookie.Value, confirm) {
			logoutPage(w, http.StatusForbidden, logoutView{Title: "Sign-out request rejected", Message: "The confirmation was not issued for this session. Nothing was changed."})
			return
		}
	}

	pending := h.audit.Prepare("auth.logout", user.ID, user.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"clientId": clientID, "initiator": "rp"})
	if err := h.store.RevokeSession(user.ID, sess.ID, pending.Row); err != nil && !errors.Is(err, store.ErrNotFound) {
		log.Printf("rp-initiated logout failed: %v", err)
		stepUpInternalError(w)
		return
	} else if err == nil {
		pending.Committed()
	}
	clearSessionCookies(w)
	h.finishLogout(w, r, redirect, state)
}

// finishLogout sends the browser to the validated post-logout URI, or shows a plain
// signed-out page when the relying party did not ask for one.
func (h *OAuthHandler) finishLogout(w http.ResponseWriter, r *http.Request, redirect, state string) {
	if redirect == "" {
		logoutPage(w, http.StatusOK, logoutView{Title: "Signed out", Message: "You are signed out of KySignOn in this browser."})
		return
	}
	target, err := url.Parse(redirect)
	if err != nil {
		stepUpInternalError(w)
		return
	}
	if state != "" {
		values := target.Query()
		values.Set("state", state)
		target.RawQuery = values.Encode()
	}
	http.Redirect(w, r, target.String(), http.StatusFound)
}

type logoutView struct {
	Title, Message, Confirm string
	Fields                  map[string]string
}

func logoutPage(w http.ResponseWriter, status int, v logoutView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = logoutTemplate.Execute(w, v)
}

// The page stands alone: no scripts, no external assets, so it renders the same whether
// or not the SPA bundle is present. Colours meet WCAG AA in both schemes; the accent is
// used for a border, never for text.
var logoutTemplate = template.Must(template.New("logout").Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} · KySignOn</title>
<style>
:root{color-scheme:light dark;--bg:#f6f7f9;--card:#ffffff;--ink:#1c2230;--muted:#4b5563;--line:#d5dae2;--accent:#0e7c86;--btn:#1c2230;--btn-ink:#ffffff}
@media(prefers-color-scheme:dark){:root{--bg:#12161c;--card:#1a2029;--ink:#e6e9ee;--muted:#aab2bf;--line:#2c3542;--accent:#5ad0da;--btn:#e6e9ee;--btn-ink:#12161c}}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,sans-serif}
main{max-width:26rem;margin:1rem;padding:1.5rem;background:var(--card);border:1px solid var(--line);border-top:3px solid var(--accent);border-radius:10px}
h1{font-size:1.25rem;margin:0 0 .5rem}p{margin:0 0 1rem;color:var(--muted)}
form{display:flex;gap:.75rem;align-items:center}button,a.btn{font:inherit;padding:.55rem 1rem;border-radius:6px;border:1px solid var(--line);background:var(--card);color:var(--ink);cursor:pointer;text-decoration:none}
button.primary{background:var(--btn);color:var(--btn-ink);border-color:var(--btn)}
</style></head><body><main>
<h1>{{.Title}}</h1><p>{{.Message}}</p>
{{if .Confirm}}<form method="post" action="/oauth/logout">
{{range $k, $v := .Fields}}{{if $v}}<input type="hidden" name="{{$k}}" value="{{$v}}">{{end}}{{end}}
<input type="hidden" name="confirm" value="{{.Confirm}}">
<button type="submit" class="primary">Sign out</button>
<a class="btn" href="/">Stay signed in</a>
</form>{{end}}
</main></body></html>`))
