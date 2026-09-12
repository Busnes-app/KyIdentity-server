package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Busness-app/kysignon-server/internal/audit"
	"github.com/Busness-app/kysignon-server/internal/auth"
	"github.com/Busness-app/kysignon-server/internal/crypto"
	"github.com/Busness-app/kysignon-server/internal/store"
	"github.com/Busness-app/kysignon-server/internal/sync"
	"github.com/google/uuid"
)

type AdminHandler struct {
	store      *store.Store
	syncEngine *sync.Engine
	audit      *audit.Logger
	middleware *MiddlewareManager
	issuerURL  string
}

func NewAdminHandler(s *store.Store, syncEngine *sync.Engine, audit *audit.Logger, mm *MiddlewareManager, issuerURL string) *AdminHandler {
	return &AdminHandler{
		store:      s,
		syncEngine: syncEngine,
		audit:      audit,
		middleware: mm,
		issuerURL:  issuerURL,
	}
}

// ListUsers lists all user accounts.
func (h *AdminHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.store.ListUsers()
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if users == nil {
		users = []store.User{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"users": users})
}

type CreateUserRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	Role        string `json:"role"`   // "user", "admin"
	Status      string `json:"status"` // "active", "disabled"
}

// CreateUser creates a new user account and dispatches replication event.
func (h *AdminHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.TrimSpace(req.Email)
	req.DisplayName = strings.TrimSpace(req.DisplayName)

	if req.Username == "" || req.Email == "" || req.Password == "" {
		http.Error(w, `{"error":"missing_fields","error_description":"Username, email, and password are required"}`, http.StatusBadRequest)
		return
	}

	if req.Role != "admin" {
		req.Role = "user"
	}
	if req.Status != "disabled" {
		req.Status = "active"
	}

	passHash, err := auth.HashPassword(req.Password)
	if err != nil {
		http.Error(w, `{"error":"password_policy","error_description":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	user := &store.User{
		ID:           uuid.New().String(),
		Username:     req.Username,
		DisplayName:  req.DisplayName,
		Email:        req.Email,
		PasswordHash: passHash,
		Role:         req.Role,
		Status:       req.Status,
	}

	created := h.audit.Prepare("admin.user_created", admin.ID, admin.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{
		"username": user.Username,
		"role":     user.Role,
	})
	if err := h.syncEngine.CreateUserAndQueueSyncEvents(user, created.Row); err != nil {
		http.Error(w, `{"error":"user_exists","error_description":"Username or email already exists"}`, http.StatusConflict)
		return
	}
	created.Committed()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"user":    user,
	})
}

// UpdateUser updates user profile and dispatches replication event.
func (h *AdminHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	userID := r.PathValue("id")

	var req struct {
		DisplayName string `json:"displayName"`
		Email       string `json:"email"`
		Role        string `json:"role"`
		Status      string `json:"status"`
		Password    string `json:"password,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	user, err := h.store.GetUserByID(userID)
	if err != nil || user == nil {
		http.Error(w, `{"error":"user_not_found"}`, http.StatusNotFound)
		return
	}

	if req.DisplayName = strings.TrimSpace(req.DisplayName); req.DisplayName != "" {
		user.DisplayName = req.DisplayName
	}
	if req.Email = strings.TrimSpace(req.Email); req.Email != "" {
		user.Email = req.Email
	}
	wasAdmin := user.Role == "admin"
	if req.Role == "user" || req.Role == "admin" {
		user.Role = req.Role
	}
	wasActive := user.Status == "active"
	if req.Status == "active" || req.Status == "disabled" {
		user.Status = req.Status
	}

	passwordChanged := req.Password != ""
	if req.Password != "" {
		passHash, err := auth.HashPassword(req.Password)
		if err != nil {
			http.Error(w, `{"error":"password_policy","error_description":"`+err.Error()+`"}`, http.StatusBadRequest)
			return
		}
		user.PasswordHash = passHash
	}

	// Demotion is a revocation. An issued ID token carries "role":"admin" as a signed claim,
	// so a relying party keeps granting administrator access for the life of that token
	// unless the tokens behind it are revoked along with the row.
	demoted := wasAdmin && user.Role != "admin"
	revokeAccess := passwordChanged || (wasActive && user.Status == "disabled") || demoted

	updated := h.audit.Prepare("admin.user_updated", admin.ID, admin.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{
		"username":      user.Username,
		"role":          user.Role,
		"status":        user.Status,
		"demoted":       demoted,
		"accessRevoked": revokeAccess,
	})
	if err := h.syncEngine.UpdateUserAndQueueSyncEvents(user, revokeAccess, updated.Row); err != nil {
		if errors.Is(err, store.ErrEnrollmentPolicy) {
			enrollmentError(w, err)
		} else if errors.Is(err, store.ErrLastActiveAdmin) {
			http.Error(w, `{"error":"cannot_remove_last_admin"}`, http.StatusBadRequest)
		} else {
			http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		}
		return
	}
	if passwordChanged {
		if err := h.store.ClearFailedLogins(user.ID); err != nil {
			http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
			return
		}
	}

	updated.Committed()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"user":    user,
	})
}

// ResetUserMFA clears MFA methods/devices, revokes active sessions, and dispatches sync event.
func (h *AdminHandler) ResetUserMFA(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	userID := r.PathValue("id")

	user, err := h.store.GetUserByID(userID)
	if err != nil || user == nil {
		http.Error(w, `{"error":"user_not_found"}`, http.StatusNotFound)
		return
	}

	// Factor removal, session deletion, token revocation, pairing-token expiry and the sync
	// event all commit together or not at all. Discarding these errors and reporting success
	// anyway told the admin — and the audit trail — that an account was locked down while the
	// attacker was still holding a live session.
	reset := h.audit.Prepare("admin.user_mfa_reset", admin.ID, admin.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{
		"username": user.Username,
	})
	if err := h.syncEngine.ResetUserMFAAndRevoke(user.ID, reset.Row); err != nil {
		log.Printf("MFA reset for user %s failed: %v", user.ID, err)
		h.audit.Record("admin.user_mfa_reset", admin.ID, admin.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "failure", map[string]any{
			"username": user.Username,
			"error":    err.Error(),
		})
		http.Error(w, `{"error":"internal_error","error_description":"MFA reset failed; nothing was changed"}`, http.StatusInternalServerError)
		return
	}

	reset.Committed()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// RevokeUserSessions revokes all sessions for a user.
func (h *AdminHandler) RevokeUserSessions(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	userID := r.PathValue("id")

	// Revocation is the one place where reporting an unearned success is worse than
	// reporting failure: the admin stops looking.
	if err := h.store.RevokeUserAccess(userID); err != nil {
		log.Printf("session revocation for user %s failed: %v", userID, err)
		h.audit.Record("admin.sessions_revoked", admin.ID, admin.Username, userID, "user", h.middleware.ClientIP(r), r.UserAgent(), "failure", map[string]any{
			"error": err.Error(),
		})
		http.Error(w, `{"error":"internal_error","error_description":"Revocation failed; sessions may still be active"}`, http.StatusInternalServerError)
		return
	}
	h.audit.Record("admin.sessions_revoked", admin.ID, admin.Username, userID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// DeleteUser deletes a user.
func (h *AdminHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	userID := r.PathValue("id")

	user, err := h.store.GetUserByID(userID)
	if err != nil || user == nil {
		http.Error(w, `{"error":"user_not_found"}`, http.StatusNotFound)
		return
	}

	deleted := h.audit.Prepare("admin.user_deleted", admin.ID, admin.Username, userID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{
		"username": user.Username,
	})
	if err := h.syncEngine.DeleteUserAndQueueSyncEvents(userID, deleted.Row); err != nil {
		if errors.Is(err, store.ErrLastActiveAdmin) {
			http.Error(w, `{"error":"cannot_delete_last_admin","error_description":"Cannot delete the only active administrator"}`, http.StatusBadRequest)
		} else {
			http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		}
		return
	}

	deleted.Committed()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// CreatePairedSystem directly connects a downstream SCIM target service.
func (h *AdminHandler) CreatePairedSystem(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())

	var req sync.CreateSystemRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	ps, token, err := h.syncEngine.CreateSystem(&req)
	if err != nil {
		http.Error(w, `{"error":"invalid_request","error_description":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	h.audit.Record("admin.system_created", admin.ID, admin.Username, ps.ID, "system", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{
		"systemName": ps.Name,
		"systemType": ps.SystemType,
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"system":      ps,
		"bearerToken": token,
	})
}

// ListPairedSystems lists connected KySecurity products and SCIM targets.
func (h *AdminHandler) ListPairedSystems(w http.ResponseWriter, r *http.Request) {
	systems, err := h.store.ListAllPairedSystems()
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if systems == nil {
		systems = []store.PairedSystem{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"systems": systems})
}

// ResyncSystem triggers manual full directory replication.
func (h *AdminHandler) ResyncSystem(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	systemID := r.PathValue("id")

	if err := h.syncEngine.ResyncAllAccounts(systemID); err != nil {
		http.Error(w, `{"error":"resync_failed","error_description":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	h.audit.Record("admin.system_resynced", admin.ID, admin.Username, systemID, "system", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// DeletePairedSystem removes a connected KySecurity product.
func (h *AdminHandler) DeletePairedSystem(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	systemID := r.PathValue("id")

	deleted := h.audit.Prepare("admin.system_deleted", admin.ID, admin.Username, systemID, "system", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	removed, err := h.store.DeletePairedSystem(systemID, deleted.Row)
	if err != nil {
		log.Printf("paired system %s deletion failed: %v", systemID, err)
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if !removed {
		http.Error(w, `{"error":"system_not_found"}`, http.StatusNotFound)
		return
	}
	deleted.Committed()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// OAuth Client Management
func (h *AdminHandler) ListOAuthClients(w http.ResponseWriter, r *http.Request) {
	clients, err := h.store.ListOAuthClients()
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if clients == nil {
		clients = []store.OAuthClient{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"clients": clients})
}

type CreateClientRequest struct {
	ClientID      string   `json:"clientId"`
	ClientName    string   `json:"clientName"`
	ClientType    string   `json:"clientType"` // "public", "confidential"
	RedirectURIs  []string `json:"redirectUris"`
	AllowedScopes []string `json:"allowedScopes"`
	LaunchURL     string   `json:"launchUrl"`
}

// suiteClientIDs are the KySecurity services, every one of which is a server-side backend
// that can hold a secret. They may not be registered as public clients.
//
// This list lives in the registration path on purpose. It is admin-time configuration
// policy, evaluated once when a client is created or edited. It must never migrate into
// internal/oauth: client-specific branching in the authorization or token path is what
// turned redirect URI validation into a suggestion, and this package is the boundary that
// keeps that from happening again.
var suiteClientIDs = map[string]bool{
	"kypost":      true,
	"kydns":       true,
	"kypasswords": true,
	"kynotes":     true,
	"kybookmarks": true,
}

// requireConfidential reports whether a client ID names a suite service.
func requireConfidential(clientID string) bool {
	return suiteClientIDs[strings.ToLower(strings.TrimSpace(clientID))]
}

const suitePublicRejection = `{"error":"invalid_client_type","error_description":"This is a KySecurity suite service and must be registered as a confidential client. It runs server-side and can hold a client secret; a public client would drop that factor."}`

// generateClientSecret mints a client secret and its stored hash. The secret is 32 random
// bytes, so a plain SHA-256 is an appropriate one-way store: there is no low-entropy
// guess space for an attacker with the database to search.
func generateClientSecret() (raw, hash string, err error) {
	raw, err = crypto.GenerateRandomHex(32)
	if err != nil {
		return "", "", err
	}
	return raw, crypto.HashSHA256(raw), nil
}

func (h *AdminHandler) CreateOAuthClient(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	var req CreateClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ClientName == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	// Confidential is the default. For a public client PKCE is the only thing binding a
	// code to its requester; "public" stays available for SPAs and native apps, which
	// genuinely cannot keep a secret, but it has to be asked for.
	if req.ClientType != "public" {
		req.ClientType = "confidential"
	}
	if req.ClientType == "public" && requireConfidential(req.ClientID) {
		h.audit.Record("admin.oauth_client_created", admin.ID, admin.Username, req.ClientID, "client",
			h.middleware.ClientIP(r), r.UserAgent(), "denied",
			map[string]any{"reason": "suite_client_must_be_confidential"})
		http.Error(w, suitePublicRejection, http.StatusBadRequest)
		return
	}
	if len(req.AllowedScopes) == 0 {
		req.AllowedScopes = []string{"openid", "profile", "email"}
	}
	if len(req.RedirectURIs) == 0 {
		http.Error(w, `{"error":"invalid_request","error_description":"At least one redirect URI is required"}`, http.StatusBadRequest)
		return
	}

	var rawSecret, secretHash string
	if req.ClientType == "confidential" {
		var err error
		rawSecret, secretHash, err = generateClientSecret()
		if err != nil {
			http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
			return
		}
	}

	if err := validateRegisteredURLs(req.RedirectURIs, req.LaunchURL); err != nil {
		http.Error(w, `{"error":"invalid_request","error_description":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}
	redirectURIsJSON, _ := json.Marshal(req.RedirectURIs)
	scopesJSON, _ := json.Marshal(req.AllowedScopes)

	clientID := strings.TrimSpace(req.ClientID)
	if clientID == "" {
		clientID = uuid.New().String()
	}

	client := &store.OAuthClient{
		ID:                clientID,
		ClientName:        req.ClientName,
		ClientType:        req.ClientType,
		ClientSecretHash:  secretHash,
		RedirectURIsJSON:  string(redirectURIsJSON),
		AllowedScopesJSON: string(scopesJSON),
		LaunchURL:         strings.TrimSpace(req.LaunchURL),
		Enabled:           true,
	}

	if err := h.store.CreateOAuthClient(client); err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	h.audit.Record("admin.oauth_client_created", admin.ID, admin.Username, client.ID, "client", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{
		"clientName": client.ClientName,
		"clientType": client.ClientType,
	})

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success":      true,
		"client":       client,
		"clientSecret": rawSecret, // shown once; only the hash is kept
	})
}

type UpdateClientRequest struct {
	ClientName    *string   `json:"clientName,omitempty"`
	ClientType    *string   `json:"clientType,omitempty"`
	RedirectURIs  *[]string `json:"redirectUris,omitempty"`
	AllowedScopes *[]string `json:"allowedScopes,omitempty"`
	LaunchURL     *string   `json:"launchUrl,omitempty"`
	Enabled       *bool     `json:"enabled,omitempty"`
	RotateSecret  bool      `json:"rotateSecret,omitempty"`
}

// UpdateOAuthClient edits a registered client in place.
//
// This exists so a client registered without a secret can be promoted to confidential, and
// so a secret can be rotated, without deleting the client. Delete-and-recreate is not a
// migration path: it breaks the integration it is meant to secure, which is a good way to
// ensure nobody ever does it.
func (h *AdminHandler) UpdateOAuthClient(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	clientID := r.PathValue("id")

	var req UpdateClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	client, err := h.store.GetOAuthClientByID(clientID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if client == nil {
		http.Error(w, `{"error":"client_not_found"}`, http.StatusNotFound)
		return
	}
	wasEnabled, wasConfidential := client.Enabled, client.ClientType == "confidential"

	if req.ClientName != nil && strings.TrimSpace(*req.ClientName) != "" {
		client.ClientName = strings.TrimSpace(*req.ClientName)
	}
	if req.LaunchURL != nil {
		if err := validateExternalURL(*req.LaunchURL); err != nil {
			http.Error(w, `{"error":"invalid_request","error_description":"`+err.Error()+`"}`, http.StatusBadRequest)
			return
		}
		client.LaunchURL = strings.TrimSpace(*req.LaunchURL)
	}
	if req.Enabled != nil {
		client.Enabled = *req.Enabled
	}
	if req.RedirectURIs != nil {
		if len(*req.RedirectURIs) == 0 {
			http.Error(w, `{"error":"invalid_request","error_description":"At least one redirect URI is required"}`, http.StatusBadRequest)
			return
		}
		if err := validateRegisteredURLs(*req.RedirectURIs, ""); err != nil {
			http.Error(w, `{"error":"invalid_request","error_description":"`+err.Error()+`"}`, http.StatusBadRequest)
			return
		}
		encoded, err := json.Marshal(*req.RedirectURIs)
		if err != nil {
			http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
			return
		}
		client.RedirectURIsJSON = string(encoded)
	}
	if req.AllowedScopes != nil {
		encoded, err := json.Marshal(*req.AllowedScopes)
		if err != nil {
			http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
			return
		}
		client.AllowedScopesJSON = string(encoded)
	}

	// A promotion to confidential must come with a secret in the same response, or the
	// client is left declared confidential with nothing to authenticate with, and every
	// token exchange it attempts fails.
	rotate := req.RotateSecret
	if req.ClientType != nil {
		switch *req.ClientType {
		case "confidential":
			if client.ClientType != "confidential" || client.ClientSecretHash == "" {
				rotate = true
			}
			client.ClientType = "confidential"
		case "public":
			// The rule has to hold on the edit path too, or it is only a speed bump on
			// the create form.
			if requireConfidential(client.ID) {
				h.audit.Record("admin.oauth_client_updated", admin.ID, admin.Username, client.ID, "client",
					h.middleware.ClientIP(r), r.UserAgent(), "denied",
					map[string]any{"reason": "suite_client_must_be_confidential"})
				http.Error(w, suitePublicRejection, http.StatusBadRequest)
				return
			}
			client.ClientType = "public"
			client.ClientSecretHash = ""
			rotate = false
		default:
			http.Error(w, `{"error":"invalid_request","error_description":"clientType must be confidential or public"}`, http.StatusBadRequest)
			return
		}
	}

	var rawSecret string
	if rotate {
		if client.ClientType != "confidential" {
			http.Error(w, `{"error":"invalid_request","error_description":"Only a confidential client has a secret to rotate"}`, http.StatusBadRequest)
			return
		}
		var err error
		rawSecret, client.ClientSecretHash, err = generateClientSecret()
		if err != nil {
			http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
			return
		}
	}

	// Disabling a client, downgrading it to public, or rotating its secret each withdraw the
	// authority its outstanding tokens were issued under. Leaving those tokens valid turns
	// every one of these into a rename.
	revokeTokens := rotate ||
		(wasEnabled && !client.Enabled) ||
		(wasConfidential && client.ClientType != "confidential")

	updated := h.audit.Prepare("admin.oauth_client_updated", admin.ID, admin.Username, client.ID, "client", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{
		"clientType":     client.ClientType,
		"secretRotated":  rotate,
		"redirectsSet":   req.RedirectURIs != nil,
		"scopesSet":      req.AllowedScopes != nil,
		"enabledChanged": req.Enabled != nil,
		"tokensRevoked":  revokeTokens,
	})
	if err := h.store.UpdateOAuthClientWithAudit(client, revokeTokens, updated.Row); err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	updated.Committed()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success":      true,
		"client":       client,
		"clientSecret": rawSecret, // empty unless a new secret was just issued
	})
}

func (h *AdminHandler) DeleteOAuthClient(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	clientID := r.PathValue("id")

	// The delete, the revocation of every token this client issued, and the record of who
	// did it are one commit. Reporting "deleted" for a client that is still registered and
	// still serving is the failure mode that matters here: the admin stops looking.
	client, _ := h.store.GetOAuthClientByID(clientID)
	deleted := h.audit.Prepare("admin.oauth_client_deleted", admin.ID, admin.Username, clientID, "client", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	removed, err := h.store.DeleteOAuthClient(clientID, deleted.Row)
	if err != nil {
		log.Printf("oauth client %s deletion failed: %v", clientID, err)
		http.Error(w, `{"error":"internal_error","error_description":"Deletion failed; the client is still registered"}`, http.StatusInternalServerError)
		return
	}
	if !removed {
		http.Error(w, `{"error":"client_not_found"}`, http.StatusNotFound)
		return
	}
	deleted.Committed()
	if client != nil {
		h.dropIcon(client.IconName)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// launcherIcons is the closed set of icons a launcher card may use. The launcher renders
// whatever it is given, so an open field here is a rendering primitive an admin session can
// aim at every user's dashboard.
// The names are lucide icons; web/src/launcherIcons.ts holds the same list and a test
// keeps the two in step.
var launcherIcons = map[string]bool{
	"favicon": true,
	"globe":   true, "link": true, "mail": true, "message-square": true, "calendar": true,
	"sticky-note": true, "file-text": true, "book": true, "bookmark": true, "folder": true,
	"image": true, "camera": true, "video": true, "film": true, "music": true, "tv": true,
	"radio": true, "gamepad-2": true, "house": true, "users": true,
	"lock": true, "key": true, "shield": true, "server": true, "database": true,
	"hard-drive": true, "cloud": true, "container": true, "network": true, "wifi": true,
	"cpu": true, "monitor": true, "terminal": true, "code": true, "git-branch": true,
	"chart-line": true, "activity": true, "printer": true, "download": true, "rss": true,
	"wrench": true, "bug": true, "clock": true, "map": true,
}

// maxLauncherDescription bounds the blurb under a card. Long enough for a sentence, short
// enough that no card can push the rest of the launcher off the page.
const maxLauncherDescription = 200

// Applications Management
func (h *AdminHandler) ListApplications(w http.ResponseWriter, r *http.Request) {
	apps, err := h.store.ListApplications()
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if apps == nil {
		apps = []store.Application{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"applications": apps})
}

func (h *AdminHandler) CreateApplication(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	var req struct {
		Name        string `json:"name"`
		URL         string `json:"url"`
		IconName    string `json:"iconName"`
		Description string `json:"description"`
		SortOrder   int    `json:"sortOrder"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.URL == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	if err := validateExternalURL(req.URL); err != nil {
		http.Error(w, `{"error":"invalid_request","error_description":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}
	if req.IconName == "" {
		req.IconName = "favicon"
	}
	if !h.iconAllowed(req.IconName) {
		http.Error(w, `{"error":"invalid_request","error_description":"Unknown application icon"}`, http.StatusBadRequest)
		return
	}

	app := &store.Application{
		ID:          uuid.New().String(),
		Name:        req.Name,
		URL:         req.URL,
		IconName:    req.IconName,
		Description: req.Description,
		SortOrder:   req.SortOrder,
		Enabled:     true,
	}

	if err := h.store.CreateApplication(app); err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	h.audit.Record("admin.application_created", admin.ID, admin.Username, app.ID, "application", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "application": app})
}

func validateRegisteredURLs(redirectURIs []string, launchURL string) error {
	for _, raw := range redirectURIs {
		if err := validateExternalURL(raw); err != nil {
			return fmt.Errorf("invalid redirect URI: %w", err)
		}
	}
	if launchURL != "" {
		return validateExternalURL(launchURL)
	}
	return nil
}

func validateExternalURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return errors.New("URL must be an absolute URL without credentials or a fragment")
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" {
		host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
		ip := net.ParseIP(host)
		if host == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
	}
	return errors.New("URL must use https (http is allowed only on loopback)")
}

// UpdateApplication edits a launcher card that lives in the applications table. Without it
// a mistyped name or a stale URL can only be fixed by deleting the card and adding it back.
func (h *AdminHandler) UpdateApplication(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	appID := r.PathValue("id")

	var req struct {
		Name        string `json:"name"`
		URL         string `json:"url"`
		IconName    string `json:"iconName"`
		Description string `json:"description"`
		SortOrder   int    `json:"sortOrder"`
		Enabled     *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" || req.URL == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	if err := validateExternalURL(req.URL); err != nil {
		http.Error(w, `{"error":"invalid_request","error_description":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}
	if req.IconName == "" {
		req.IconName = "favicon"
	}
	if !h.iconAllowed(req.IconName) {
		http.Error(w, `{"error":"invalid_request","error_description":"Unknown application icon"}`, http.StatusBadRequest)
		return
	}
	description := strings.TrimSpace(req.Description)
	if len(description) > maxLauncherDescription {
		http.Error(w, `{"error":"invalid_request","error_description":"Description is too long"}`, http.StatusBadRequest)
		return
	}

	app, err := h.store.GetApplicationByID(appID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if app == nil {
		http.Error(w, `{"error":"application_not_found"}`, http.StatusNotFound)
		return
	}

	previousIcon := app.IconName
	app.Name = strings.TrimSpace(req.Name)
	app.URL = strings.TrimSpace(req.URL)
	app.IconName = req.IconName
	app.Description = description
	app.SortOrder = req.SortOrder
	if req.Enabled != nil {
		app.Enabled = *req.Enabled
	}

	if err := h.store.UpdateApplication(app); err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	h.audit.Record("admin.application_updated", admin.ID, admin.Username, app.ID, "application", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	h.dropIcon(previousIcon)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "application": app})
}

// UpdateClientLauncher edits only how a registered client is presented on the launcher: its
// blurb and its icon.
//
// It is deliberately a separate route from UpdateOAuthClient, which is step-up gated. Step-up
// grants are single-use, so describing seven cards through that handler costs seven MFA
// prompts, and an admin who is prompted seven times to fix cosmetic text learns to leave the
// text wrong. This handler cannot reach redirect URIs, scopes, the secret, the client type,
// or enablement, so nothing it can write is worth a grant.
func (h *AdminHandler) UpdateClientLauncher(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	clientID := r.PathValue("id")

	var req struct {
		Description string `json:"description"`
		IconName    string `json:"iconName"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	description := strings.TrimSpace(req.Description)
	if len(description) > maxLauncherDescription {
		http.Error(w, `{"error":"invalid_request","error_description":"Description is too long"}`, http.StatusBadRequest)
		return
	}
	iconName := strings.TrimSpace(req.IconName)
	if iconName == "" {
		iconName = "favicon"
	}
	if !h.iconAllowed(iconName) {
		http.Error(w, `{"error":"invalid_request","error_description":"Unknown application icon"}`, http.StatusBadRequest)
		return
	}

	client, err := h.store.GetOAuthClientByID(clientID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if client == nil {
		http.Error(w, `{"error":"client_not_found"}`, http.StatusNotFound)
		return
	}

	previousIcon := client.IconName
	client.Description = description
	client.IconName = iconName

	updated := h.audit.Prepare("admin.client_launcher_updated", admin.ID, admin.Username, clientID, "client", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	if err := h.store.UpdateOAuthClientWithAudit(client, false, updated.Row); err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	updated.Committed()
	h.dropIcon(previousIcon)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "client": client})
}

func (h *AdminHandler) DeleteApplication(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	appID := r.PathValue("id")

	app, _ := h.store.GetApplicationByID(appID)
	deleted := h.audit.Prepare("admin.application_deleted", admin.ID, admin.Username, appID, "application", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	removed, err := h.store.DeleteApplication(appID, deleted.Row)
	if err != nil {
		log.Printf("application %s deletion failed: %v", appID, err)
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if !removed {
		http.Error(w, `{"error":"application_not_found"}`, http.StatusNotFound)
		return
	}
	deleted.Committed()
	if app != nil {
		h.dropIcon(app.IconName)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// ListAuditEvents returns audit trail for admin inspection.
func (h *AdminHandler) ListAuditEvents(w http.ResponseWriter, r *http.Request) {
	page := 1
	if p, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && p > 0 {
		page = p
	}

	limit := 25
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 500 {
		limit = l
	}

	offset := (page - 1) * limit
	if o, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && o >= 0 {
		offset = o
		page = (offset / limit) + 1
	}

	events, total, err := h.store.ListAuditEvents(limit, offset)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if events == nil {
		events = []store.AuditEvent{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"auditEvents": events,
		"total":       total,
		"page":        page,
		"limit":       limit,
	})
}

// ConfigureSystem reviews a legacy connector or replaces a generic SCIM token.
func (h *AdminHandler) ConfigureSystem(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SystemType  string `json:"systemType"`
		BearerToken string `json:"bearerToken"`
		Groups      *bool  `json:"groups"`
		// ReconcileHours schedules repair reconciliation; omitted keeps the current value.
		ReconcileHours *int `json:"reconcileHours"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, `{"error":"invalid_request"}`, 400)
		return
	}
	sys, err := h.store.GetPairedSystemByID(r.PathValue("id"))
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, 500)
		return
	}
	if sys == nil {
		http.NotFound(w, r)
		return
	}
	// An omitted flag keeps the current setting; only an explicit value changes it.
	groups := sys.GroupsEnabled
	if req.Groups != nil {
		groups = *req.Groups
	}
	hours := sys.ReconcileHours
	if req.ReconcileHours != nil {
		hours = *req.ReconcileHours
	}
	admin := GetUserFromContext(r.Context())
	event := h.audit.Prepare("admin.system_configured", admin.ID, admin.Username, sys.ID, "system", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"systemName": sys.Name, "systemType": req.SystemType, "groups": groups, "reconcileHours": hours})
	if err = h.syncEngine.ReviewSystem(sys, req.SystemType, req.BearerToken, groups, hours, event.Row); err != nil {
		protocol := req.SystemType
		if protocol != "scim" && protocol != "suite_webhook" {
			protocol = "invalid"
		}
		h.audit.Record("admin.system_configured", admin.ID, admin.Username, sys.ID, "system", h.middleware.ClientIP(r), r.UserAgent(), "failure", map[string]any{"systemName": sys.Name, "systemType": protocol})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_connection", "error_description": err.Error()})
		return
	}
	event.Committed()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (h *AdminHandler) TestSystem(w http.ResponseWriter, r *http.Request) {
	sys, err := h.store.GetPairedSystemByID(r.PathValue("id"))
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, 500)
		return
	}
	if sys == nil {
		http.NotFound(w, r)
		return
	}
	err = h.syncEngine.TestSystem(r.Context(), sys)
	admin := GetUserFromContext(r.Context())
	result := "success"
	if err != nil {
		result = "failure"
	}
	h.audit.Record("admin.system_tested", admin.ID, admin.Username, sys.ID, "system", h.middleware.ClientIP(r), r.UserAgent(), result, nil)
	if err != nil {
		http.Error(w, `{"error":"connection_test_failed","error_description":"Check the SCIM base URL, bearer token, network access and externalId filtering."}`, 400)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}
