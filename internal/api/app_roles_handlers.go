package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Busness-app/kysignon-server/internal/store"
)

func writeAppRoleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrAppRoleExists):
		http.Error(w, `{"error":"role_exists","error_description":"A role with that name already exists for this app"}`, http.StatusConflict)
	case errors.Is(err, store.ErrAppRoleInvalid):
		http.Error(w, `{"error":"invalid_request","error_description":"`+store.ErrAppRoleInvalid.Error()+`"}`, http.StatusBadRequest)
	default:
		writeAppRegistryError(w, err)
	}
}

func (h *AdminHandler) ListAppRoles(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	roles, err := h.store.ListAppRoles(id)
	if err != nil {
		writeAppRegistryError(w, err)
		return
	}
	app, err := h.store.GetAppRecord(id)
	if err != nil {
		writeAppRegistryError(w, err)
		return
	}
	writeGroupJSON(w, map[string]any{"app": app, "roles": roles})
}

func (h *AdminHandler) CreateAppRole(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	actor := GetUserFromContext(r.Context())
	event := h.audit.Prepare("admin.app_role_created", actor.ID, actor.Username, r.PathValue("id"), "application", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	role, err := h.store.CreateAppRole(r.PathValue("id"), req.Name, req.Description, event.Row)
	if err != nil {
		writeAppRoleError(w, err)
		return
	}
	event.Committed()
	writeGroupJSON(w, map[string]any{"role": role})
}

func (h *AdminHandler) DeleteAppRole(w http.ResponseWriter, r *http.Request) {
	actor := GetUserFromContext(r.Context())
	event := h.audit.Prepare("admin.app_role_deleted", actor.ID, actor.Username, r.PathValue("id"), "application", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	if err := h.store.DeleteAppRole(r.PathValue("id"), r.PathValue("roleId"), event.Row); err != nil {
		writeAppRoleError(w, err)
		return
	}
	event.Committed()
	writeGroupJSON(w, map[string]bool{"success": true})
}

func (h *AdminHandler) SetAppRoleAssignment(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	if kind != "users" && kind != "groups" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	assigned := r.Method == http.MethodPut
	action := "admin.app_role_unmapped"
	if assigned {
		action = "admin.app_role_mapped"
	}
	actor := GetUserFromContext(r.Context())
	event := h.audit.Prepare(action, actor.ID, actor.Username, r.PathValue("id"), "application", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	if err := h.store.SetAppRoleAssignment(r.PathValue("id"), r.PathValue("roleId"), kind, r.PathValue("principal"), assigned, event.Row); err != nil {
		writeAppRoleError(w, err)
		return
	}
	event.Committed()
	writeGroupJSON(w, map[string]bool{"success": true})
}

func (h *AdminHandler) SetAppClaimSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LegacyRoleClaim *bool `json:"legacyRoleClaim"`
		GroupsClaim     *bool `json:"groupsClaim"`
		Revision        int   `json:"revision"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.LegacyRoleClaim == nil || req.GroupsClaim == nil || req.Revision < 1 {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	actor := GetUserFromContext(r.Context())
	event := h.audit.Prepare("admin.app_claims_changed", actor.ID, actor.Username, r.PathValue("id"), "application", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	if err := h.store.SetAppClaimSettings(r.PathValue("id"), *req.LegacyRoleClaim, *req.GroupsClaim, req.Revision, event.Row); err != nil {
		writeAppRegistryError(w, err)
		return
	}
	event.Committed()
	writeGroupJSON(w, map[string]bool{"success": true})
}
