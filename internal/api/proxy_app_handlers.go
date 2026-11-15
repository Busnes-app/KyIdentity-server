package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

type proxyAppRequest struct {
	Name           string   `json:"name"`
	Host           string   `json:"host"`
	LoginHeader    string   `json:"loginHeader"`
	Bypass         []string `json:"bypass"`
	SessionSeconds int64    `json:"sessionSeconds"`
}

// proxyAppInput reads a create (named) or edit (name ignored; rename the launcher card) body.
func (h *AdminHandler) proxyAppInput(w http.ResponseWriter, r *http.Request, create bool) (*proxyAppRequest, bool) {
	var req proxyAppRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "Malformed request")
		return nil, false
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Host = strings.TrimSpace(req.Host)
	if req.LoginHeader == "" {
		req.LoginHeader = "X-Ky-User"
	}
	if req.SessionSeconds == 0 {
		req.SessionSeconds = store.DefaultForwardSession
	}
	if req.Bypass == nil {
		req.Bypass = []string{}
	}
	issuer, _ := url.Parse(h.issuerURL)
	fail := func(msg string) (*proxyAppRequest, bool) {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", msg)
		return nil, false
	}
	switch {
	case create && (req.Name == "" || len(req.Name) > 100):
		return fail("Name is required (at most 100 characters)")
	case !store.ValidProxyHost(req.Host):
		return fail("Host must be an exact lowercase host name such as app.example.com, with no scheme, port, path or wildcard")
	case issuer != nil && strings.EqualFold(issuer.Hostname(), req.Host):
		return fail("Host must not be KyIdentity's own host")
	case !store.ValidLoginHeader(req.LoginHeader):
		return fail("Login header must be a plain header name (letters, digits, hyphens) that is not a transport, forwarding or Ky header")
	case req.SessionSeconds < store.MinForwardSession || req.SessionSeconds > store.MaxForwardSession:
		return fail("Session length must be between 5 minutes and 7 days")
	case len(req.Bypass) > 20:
		return fail("At most 20 bypass paths")
	}
	for _, p := range req.Bypass {
		if !store.ValidBypassPrefix(p) {
			return fail("Each bypass path must start with /, must not be /, end in / or contain .., //, %, ?, #, ; or spaces")
		}
	}
	return &req, true
}

func (h *AdminHandler) ListProxyApps(w http.ResponseWriter, r *http.Request) {
	apps, err := h.store.ListProxyApps()
	if err != nil {
		log.Printf("proxy app list failed: %v", err)
		stepUpInternalError(w)
		return
	}
	writeStepUpJSON(w, map[string]any{"proxyApps": apps})
}

func proxySecret() (string, string, error) {
	secret, err := crypto.GenerateRandomHex(32)
	return secret, crypto.HashSHA256(secret), err
}

func (h *AdminHandler) proxyWriteError(w http.ResponseWriter, err error) {
	var input store.InputError
	switch {
	case errors.As(err, &input):
		writeInputError(w, "invalid_request", err)
	case errors.Is(err, store.ErrAppRecordMissing):
		writeAPIError(w, http.StatusNotFound, "not_found", "Proxy app not found")
	default:
		log.Printf("proxy app change failed: %v", err)
		stepUpInternalError(w)
	}
}

// CreateProxyApp returns the edge secret once; only its hash is stored.
func (h *AdminHandler) CreateProxyApp(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	req, ok := h.proxyAppInput(w, r, true)
	if !ok {
		return
	}
	secret, hash, err := proxySecret()
	if err != nil {
		stepUpInternalError(w)
		return
	}
	card := &store.Application{ID: uuid.NewString(), Name: req.Name, URL: "https://" + req.Host + "/", IconName: "favicon", Enabled: true}
	p := &store.ProxyApp{ID: card.ID, Name: req.Name, Host: req.Host, LoginHeader: req.LoginHeader, Bypass: req.Bypass, SessionSeconds: req.SessionSeconds, SecretHash: hash}
	pending := h.audit.Prepare("admin.proxy_app_created", admin.ID, admin.Username, card.ID, "application", h.middleware.ClientIP(r), r.UserAgent(), "success",
		map[string]any{"host": p.Host, "loginHeader": p.LoginHeader, "bypass": p.Bypass, "sessionSeconds": p.SessionSeconds})
	if err := h.store.CreateProxyApp(card, p, pending.Row); err != nil {
		h.proxyWriteError(w, err)
		return
	}
	pending.Committed()
	writeJSON(w, http.StatusCreated, map[string]any{"proxyApp": p, "edgeSecret": secret})
}

func (h *AdminHandler) UpdateProxyApp(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	req, ok := h.proxyAppInput(w, r, false)
	if !ok {
		return
	}
	p := &store.ProxyApp{ID: r.PathValue("id"), Host: req.Host, LoginHeader: req.LoginHeader, Bypass: req.Bypass, SessionSeconds: req.SessionSeconds}
	pending := h.audit.Prepare("admin.proxy_app_updated", admin.ID, admin.Username, p.ID, "application", h.middleware.ClientIP(r), r.UserAgent(), "success",
		map[string]any{"host": p.Host, "loginHeader": p.LoginHeader, "bypass": p.Bypass, "sessionSeconds": p.SessionSeconds})
	if err := h.store.UpdateProxyApp(p, pending.Row); err != nil {
		h.proxyWriteError(w, err)
		return
	}
	pending.Committed()
	writeStepUpJSON(w, map[string]any{"success": true})
}

func (h *AdminHandler) RotateProxySecret(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	id := r.PathValue("id")
	secret, hash, err := proxySecret()
	if err != nil {
		stepUpInternalError(w)
		return
	}
	pending := h.audit.Prepare("admin.proxy_app_secret_rotated", admin.ID, admin.Username, id, "application", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	if err := h.store.RotateProxySecret(id, hash, pending.Row); err != nil {
		h.proxyWriteError(w, err)
		return
	}
	pending.Committed()
	writeStepUpJSON(w, map[string]any{"edgeSecret": secret})
}
