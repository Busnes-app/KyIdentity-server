package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/Busness-app/kysignon-server/internal/store"
)

// Administration of inbound SCIM connectors: create, rename or disable, issue and revoke
// tokens (shown once), and disconnect with an explicit choice for the accounts it owned.

type connectorView struct {
	store.SCIMConnector
	Tokens []store.SCIMConnectorToken `json:"tokens"`
	Users  int                        `json:"users"`
}

func (h *SCIMHandler) view(c *store.SCIMConnector) (*connectorView, error) {
	tokens, err := h.store.ListSCIMConnectorTokens(c.ID)
	if err != nil {
		return nil, err
	}
	users, err := h.store.CountSCIMConnectorUsers(c.ID)
	if err != nil {
		return nil, err
	}
	return &connectorView{SCIMConnector: *c, Tokens: tokens, Users: users}, nil
}

func (h *SCIMHandler) AdminList(w http.ResponseWriter, r *http.Request) {
	list, err := h.store.ListSCIMConnectors()
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	views := make([]connectorView, 0, len(list))
	for i := range list {
		v, err := h.view(&list[i])
		if err != nil {
			http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
			return
		}
		views = append(views, *v)
	}
	writeGroupJSON(w, map[string]any{"connectors": views, "endpoint": h.issuerURL + "/scim/v2"})
}

func (h *SCIMHandler) AdminCreate(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	pending := h.audit.Prepare("admin.scim_connector_created", admin.ID, admin.Username, "", "scim_connector", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"name": req.Name})
	c, err := h.store.CreateSCIMConnector(req.Name, pending.Row)
	if err != nil {
		http.Error(w, `{"error":"invalid_request","error_description":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}
	pending.Committed()
	v, err := h.view(c)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	writeGroupJSON(w, v)
}

func (h *SCIMHandler) AdminUpdate(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	id := r.PathValue("id")
	var req struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	pending := h.audit.Prepare("admin.scim_connector_updated", admin.ID, admin.Username, id, "scim_connector", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"name": req.Name, "status": req.Status})
	err := h.store.UpdateSCIMConnector(id, req.Name, req.Status, pending.Row)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, `{"error":"connector_not_found"}`, http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, `{"error":"invalid_request","error_description":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}
	pending.Committed()
	c, _ := h.store.GetSCIMConnector(id)
	v, err := h.view(c)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	writeGroupJSON(w, v)
}

// AdminIssueToken mints a connector token and returns it exactly once.
func (h *SCIMHandler) AdminIssueToken(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	id := r.PathValue("id")
	var req struct {
		Scope string `json:"scope"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Scope == "" {
		req.Scope = "write"
	}
	pending := h.audit.Prepare("admin.scim_token_issued", admin.ID, admin.Username, id, "scim_connector", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"scope": req.Scope})
	raw, tok, err := h.store.IssueSCIMToken(id, req.Scope, pending.Row)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, `{"error":"connector_not_found"}`, http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, `{"error":"invalid_request","error_description":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}
	pending.Committed()
	writeGroupJSON(w, map[string]any{"token": raw, "id": tok.ID, "scope": tok.Scope, "createdAt": tok.CreatedAt})
}

func (h *SCIMHandler) AdminRevokeToken(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	id, tokenID := r.PathValue("id"), r.PathValue("tokenId")
	pending := h.audit.Prepare("admin.scim_token_revoked", admin.ID, admin.Username, id, "scim_connector", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"tokenId": tokenID})
	err := h.store.RevokeSCIMToken(id, tokenID, pending.Row)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, `{"error":"token_not_found"}`, http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	pending.Committed()
	writeSuccess(w)
}

// AdminDelete disconnects an upstream. The body says what happens to the accounts it
// owned: "keep" makes them ordinary local accounts, "disable" offboards them first.
func (h *SCIMHandler) AdminDelete(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	id := r.PathValue("id")
	var req struct {
		Users string `json:"users"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Users != "keep" && req.Users != "disable" {
		http.Error(w, `{"error":"invalid_request","error_description":"users must be keep or disable"}`, http.StatusBadRequest)
		return
	}
	pending := h.audit.Prepare("admin.scim_connector_deleted", admin.ID, admin.Username, id, "scim_connector", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"users": req.Users})
	n, err := h.store.DeleteSCIMConnector(id, req.Users == "disable", pending.Row)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, `{"error":"connector_not_found"}`, http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("delete scim connector: %v", err)
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	pending.Committed()
	writeGroupJSON(w, map[string]any{"success": true, "affectedUsers": n})
}
