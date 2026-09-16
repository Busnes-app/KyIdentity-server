package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
)

func (h *AdminHandler) ListAppAccessUsers(w http.ResponseWriter, r *http.Request) {
	p, err := parseGroupPage(r)
	if err != nil {
		http.Error(w, `{"error":"invalid_request"}`, 400)
		return
	}
	mode := r.URL.Query().Get("mode")
	if mode != "" && mode != "all_active_users" && mode != "assigned_only" {
		http.Error(w, `{"error":"invalid_request"}`, 400)
		return
	}
	var enabled *bool
	if raw := r.URL.Query().Get("enabled"); raw != "" {
		if raw != "true" && raw != "false" {
			http.Error(w, `{"error":"invalid_request"}`, 400)
			return
		}
		b := raw == "true"
		enabled = &b
	}
	result, err := h.store.ListAppAccessUsers(r.PathValue("id"), p.Query, mode, enabled, p.Limit, p.Offset)
	if err != nil {
		writeAppRegistryError(w, err)
		return
	}
	writeGroupJSON(w, result)
}
func (h *AdminHandler) ListAppAccessGroups(w http.ResponseWriter, r *http.Request) {
	p, err := parseGroupPage(r)
	if err != nil {
		http.Error(w, `{"error":"invalid_request"}`, 400)
		return
	}
	groups, total, err := h.store.ListAppAccessGroups(r.PathValue("id"), p.Query, p.Limit, p.Offset)
	if err != nil {
		writeAppRegistryError(w, err)
		return
	}
	writeGroupJSON(w, map[string]any{"groups": groups, "total": total, "limit": p.Limit, "offset": p.Offset})
}
func (h *AdminHandler) SetAppPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode     string `json:"mode"`
		Enabled  *bool  `json:"enabled"`
		Revision int    `json:"revision"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Enabled == nil || req.Revision < 1 || (req.Mode != "assigned_only" && req.Mode != "all_active_users") {
		http.Error(w, `{"error":"invalid_request"}`, 400)
		return
	}
	actor := GetUserFromContext(r.Context())
	event := h.audit.Prepare("admin.app_access_changed", actor.ID, actor.Username, r.PathValue("id"), "application", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	if err := h.store.SetAppPolicy(r.PathValue("id"), req.Mode, *req.Enabled, req.Revision, event.Row); err != nil {
		writeAppRegistryError(w, err)
		return
	}
	event.Committed()
	writeGroupJSON(w, map[string]bool{"success": true})
}
func (h *AdminHandler) SetAppAssignment(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	if kind != "users" && kind != "groups" {
		http.Error(w, `{"error":"invalid_request"}`, 400)
		return
	}
	assigned := r.Method == http.MethodPut
	action := "admin.app_assignment_removed"
	if assigned {
		action = "admin.app_assignment_added"
	}
	expiresAt, err := readExpiry(w, r)
	if err != nil {
		return
	}
	if expiresAt != nil && kind != "users" {
		http.Error(w, `{"error":"invalid_request","error_description":"Only direct user assignments expire"}`, http.StatusBadRequest)
		return
	}
	actor := GetUserFromContext(r.Context())
	details := map[string]any{"kind": kind, "principal": r.PathValue("principal")}
	if expiresAt != nil {
		details["expiresAt"] = expiresAt
	}
	event := h.audit.Prepare(action, actor.ID, actor.Username, r.PathValue("id"), "application", h.middleware.ClientIP(r), r.UserAgent(), "success", details)
	if assigned {
		err = h.store.SetAppAssignmentUntil(r.PathValue("id"), kind, r.PathValue("principal"), expiresAt, event.Row)
	} else {
		err = h.store.SetAppAssignment(r.PathValue("id"), kind, r.PathValue("principal"), false, event.Row)
	}
	if err != nil {
		writeAppRegistryError(w, err)
		return
	}
	event.Committed()
	writeGroupJSON(w, map[string]bool{"success": true})
}

// readExpiry reads an optional {"expiresAt": RFC3339} body. An instant in the past is
// refused: an operator who wanted "now" removes the grant instead.
func readExpiry(w http.ResponseWriter, r *http.Request) (*time.Time, error) {
	var req struct {
		ExpiresAt string `json:"expiresAt"`
	}
	if r.ContentLength != 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
			return nil, err
		}
	}
	at, err := parseInstant(req.ExpiresAt)
	if err != nil {
		http.Error(w, `{"error":"expiry_in_past","error_description":"The expiry must be a future RFC 3339 instant"}`, http.StatusBadRequest)
	}
	return at, err
}

func parseInstant(raw string) (*time.Time, error) {
	if raw == "" {
		return nil, nil
	}
	at, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, store.ErrExpiryInPast
	}
	at = at.UTC().Truncate(time.Second)
	if !at.After(time.Now()) {
		return nil, store.ErrExpiryInPast
	}
	return &at, nil
}
