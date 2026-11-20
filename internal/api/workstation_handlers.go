package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/Busnes-app/kyidentity-server/internal/oauth"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// Workstation login: RFC 8628 device grant and workstation apps
// (docs/WORKSTATION-LOGIN.md, docs/superpowers/specs/2026-11-19-workstation-login-design.md).

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	body := map[string]string{"error": code}
	if description != "" {
		body["error_description"] = description
	}
	_ = json.NewEncoder(w).Encode(body)
}

// DeviceAuthorization is RFC 8628 §3.1. The workstation app is a public client: client_id
// in the body, no secret.
func (h *OAuthHandler) DeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	clientID := r.FormValue("client_id")
	if clientID == "" || len(r.Form["client_id"]) != 1 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "client_id is required")
		return
	}
	if !h.middleware.allowPerIP(r, "device_authorization", 10, 0.2) {
		writeOAuthError(w, http.StatusTooManyRequests, "slow_down", "")
		return
	}
	ip := h.middleware.ClientIP(r)
	resp, id, err := h.oauthEngine.IssueDeviceCode(clientID, r.FormValue("scope"), ip, r.UserAgent())
	switch {
	case errors.Is(err, oauth.ErrDeviceGrantNotAvailable):
		h.audit.Observe("device_grant.issued", "", "", clientID, "client", ip, r.UserAgent(), "denied", map[string]any{"reason": "grant_unavailable"})
		writeOAuthError(w, http.StatusBadRequest, "unauthorized_client", "The device grant is not enabled for this client")
		return
	case errors.Is(err, oauth.ErrInvalidScope):
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "")
		return
	case errors.Is(err, store.ErrDeviceCodeCapacity):
		h.audit.Observe("device_grant.issued", "", "", clientID, "client", ip, r.UserAgent(), "denied", map[string]any{"reason": "too_many_pending"})
		writeOAuthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "Too many pending sign-ins for this app")
		return
	case err != nil:
		log.Printf("device authorization failed: %v", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	h.audit.Observe("device_grant.issued", "", "", clientID, "client", ip, r.UserAgent(), "success", map[string]any{"deviceCodeId": id})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(resp)
}

// deviceCodeGrant answers a device-code poll at the token endpoint (RFC 8628 §3.4-3.5).
func (h *OAuthHandler) deviceCodeGrant(w http.ResponseWriter, r *http.Request, deviceCode, clientID string) {
	if deviceCode == "" || clientID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "device_code and client_id are required")
		return
	}
	ip := h.middleware.ClientIP(r)
	resp, d, err := h.oauthEngine.PollDeviceCode(deviceCode, clientID, ip, r.UserAgent())
	details := map[string]any{}
	userID := ""
	if d != nil {
		details["deviceCodeId"] = d.ID
		userID = d.UserID
	}
	switch {
	case err == nil:
		details["sessionId"] = d.SessionID
		h.audit.Observe("device_grant.redeemed", userID, "", clientID, "client", ip, r.UserAgent(), "success", details)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		_ = json.NewEncoder(w).Encode(resp)
	case errors.Is(err, oauth.ErrAuthorizationPending):
		writeOAuthError(w, http.StatusBadRequest, "authorization_pending", "")
	case errors.Is(err, oauth.ErrSlowDown):
		writeOAuthError(w, http.StatusBadRequest, "slow_down", "")
	case errors.Is(err, oauth.ErrAccessDenied):
		writeOAuthError(w, http.StatusBadRequest, "access_denied", "The sign-in was denied")
	case errors.Is(err, oauth.ErrExpiredToken):
		writeOAuthError(w, http.StatusBadRequest, "expired_token", "")
	case errors.Is(err, oauth.ErrDeviceGrantNotAvailable):
		writeOAuthError(w, http.StatusBadRequest, "unauthorized_client", "The device grant is not enabled for this client")
	case errors.Is(err, oauth.ErrDeviceCodeReplayed):
		// A second redemption means the code leaked: end what the first one created.
		ended := h.audit.Prepare("device_grant.replayed", userID, "", clientID, "client", ip, r.UserAgent(), "denied", details)
		if err := h.store.EndReplayedDeviceCode(d, ended.Row); err != nil {
			log.Printf("ending replayed device code session failed: %v", err)
		} else {
			ended.Committed()
		}
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "The device code is invalid")
	case errors.Is(err, oauth.ErrDeviceGrantInvalid):
		h.audit.Observe("device_grant.redeemed", userID, "", clientID, "client", ip, r.UserAgent(), "failure", details)
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "The device code is invalid")
	default:
		log.Printf("device code poll failed: %v", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
	}
}

type deviceCodeView struct {
	ClientID   string `json:"clientId"`
	ClientName string `json:"clientName"`
	IPAddress  string `json:"ipAddress"`
	CreatedAt  string `json:"createdAt"`
}

// lookupDeviceCode resolves a user code for the signed-in user, rate limited per account
// and address. Every miss is audited without the code.
func (h *OAuthHandler) lookupDeviceCode(w http.ResponseWriter, r *http.Request, raw string) (*store.DeviceCode, bool) {
	user := GetUserFromContext(r.Context())
	if !h.middleware.allowPerIP(r, "device_verify", 10, 0.1) || !h.middleware.allowRateLimit("device_verify_user:"+user.ID, 10, 0.1) {
		writeAPIError(w, http.StatusTooManyRequests, "rate_limited", "Too many codes entered; wait a minute and try again")
		return nil, false
	}
	var d *store.DeviceCode
	if hash, ok := h.oauthEngine.UserCodeHash(raw); ok {
		var err error
		if d, err = h.store.PendingDeviceCode(hash); err != nil {
			writeAPIError(w, http.StatusInternalServerError, "internal_error", "")
			return nil, false
		}
	}
	if d == nil {
		h.audit.Observe("device_grant.code_rejected", user.ID, user.Username, "", "client", h.middleware.ClientIP(r), r.UserAgent(), "failure", nil)
		writeAPIError(w, http.StatusNotFound, "code_not_found", "That code is not valid or has expired. Check it on the computer and try again.")
		return nil, false
	}
	return d, true
}

func decodeDeviceRequest(r *http.Request, v any) bool {
	return json.NewDecoder(r.Body).Decode(v) == nil
}

// DeviceLookup shows what a user code would sign in to, before the user decides.
func (h *OAuthHandler) DeviceLookup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var req struct {
		UserCode string `json:"userCode"`
	}
	if !decodeDeviceRequest(r, &req) {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "")
		return
	}
	d, ok := h.lookupDeviceCode(w, r, req.UserCode)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(deviceCodeView{ClientID: d.ClientID, ClientName: d.ClientName, IPAddress: d.IPAddress, CreatedAt: d.CreatedAt.UTC().Format("2006-01-02T15:04:05Z")})
}

// DeviceDecision approves or denies a user code for the signed-in user.
func (h *OAuthHandler) DeviceDecision(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var req struct {
		UserCode string `json:"userCode"`
		Approve  *bool  `json:"approve"`
	}
	if !decodeDeviceRequest(r, &req) || req.Approve == nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "")
		return
	}
	d, ok := h.lookupDeviceCode(w, r, req.UserCode)
	if !ok {
		return
	}
	user, sess := GetUserFromContext(r.Context()), GetSessionFromContext(r.Context())
	action := "device_grant.denied"
	if *req.Approve {
		action = "device_grant.approved"
	}
	event := h.audit.Prepare(action, user.ID, user.Username, d.ClientID, "client", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"deviceCodeId": d.ID})
	err := h.oauthEngine.DecideDeviceCode(d, user, sess, *req.Approve, event.Row)
	if err == nil {
		event.Committed()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"approved": *req.Approve})
		return
	}
	reason := map[error]string{
		oauth.ErrDeviceApprovalAccess:    "no_access",
		oauth.ErrDeviceApprovalSignIn:    "sign_in_again",
		oauth.ErrDeviceApprovalSetup:     "account_setup",
		oauth.ErrDeviceApprovalNotLive:   "code_not_found",
		oauth.ErrDeviceGrantNotAvailable: "grant_unavailable",
		store.ErrNotFound:                "code_not_found",
	}
	for e, code := range reason {
		if errors.Is(err, e) {
			h.audit.Observe("device_grant.approved", user.ID, user.Username, d.ClientID, "client", h.middleware.ClientIP(r), r.UserAgent(), "denied", map[string]any{"deviceCodeId": d.ID, "reason": code})
			writeAPIError(w, http.StatusForbidden, code, err.Error())
			return
		}
	}
	log.Printf("device decision failed: %v", err)
	writeAPIError(w, http.StatusInternalServerError, "internal_error", "")
}

// Admin: workstation apps.

func (h *AdminHandler) ListWorkstationApps(w http.ResponseWriter, r *http.Request) {
	apps, err := h.store.ListWorkstationApps()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"apps": apps, "issuer": h.issuerURL})
}

func (h *AdminHandler) CreateWorkstationApp(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	var req struct {
		ClientName string `json:"clientName"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.ClientName) == "" || len(req.ClientName) > 128 {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "A name of at most 128 characters is required")
		return
	}
	c := &store.OAuthClient{ID: uuid.NewString(), ClientName: strings.TrimSpace(req.ClientName)}
	created := h.audit.Prepare("admin.workstation_app_created", admin.ID, admin.Username, c.ID, "client", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	if err := h.store.CreateWorkstationApp(c, created.Row); err != nil {
		log.Printf("workstation app creation failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}
	created.Committed()
	app, err := h.store.GetWorkstationApp(c.ID)
	if err != nil || app == nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(app)
}

func (h *AdminHandler) UpdateWorkstationApp(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	var req struct {
		DeviceGrantEnabled *bool `json:"deviceGrantEnabled"`
		DeviceCodeTTL      *int  `json:"deviceCodeTtl"`
		OfflineWindow      *int  `json:"offlineWindow"`
		RequireTypedSignIn *bool `json:"requirePassword"`
		MacSignIn          *bool `json:"macSignIn"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.DeviceGrantEnabled == nil || req.DeviceCodeTTL == nil || req.OfflineWindow == nil || req.RequireTypedSignIn == nil || req.MacSignIn == nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "deviceGrantEnabled, deviceCodeTtl, offlineWindow, requirePassword and macSignIn are required")
		return
	}
	id := r.PathValue("id")
	set := store.WorkstationSettings{DeviceGrant: *req.DeviceGrantEnabled, DeviceCodeTTL: *req.DeviceCodeTTL, OfflineWindow: *req.OfflineWindow, RequireTypedSignIn: *req.RequireTypedSignIn, MacSignIn: *req.MacSignIn}
	event := h.audit.Prepare("admin.workstation_app_updated", admin.ID, admin.Username, id, "client", h.middleware.ClientIP(r), r.UserAgent(), "success",
		map[string]any{"deviceGrantEnabled": set.DeviceGrant, "deviceCodeTtl": set.DeviceCodeTTL, "offlineWindow": set.OfflineWindow, "requirePassword": set.RequireTypedSignIn, "macSignIn": set.MacSignIn})
	err := h.store.UpdateWorkstationApp(id, set, event.Row)
	var input store.InputError
	switch {
	case errors.As(err, &input):
		writeInputError(w, "invalid_request", err)
		return
	case errors.Is(err, store.ErrNotFound):
		writeAPIError(w, http.StatusNotFound, "not_found", "")
		return
	case err != nil:
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}
	event.Committed()
	app, err := h.store.GetWorkstationApp(id)
	if err != nil || app == nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(app)
}
