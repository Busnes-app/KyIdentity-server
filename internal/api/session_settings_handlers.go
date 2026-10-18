package api

import (
	"encoding/json"
	"net/http"

	"github.com/Busnes-app/kyidentity-server/internal/audit"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// SessionSettingsHandler serves the global browser session limits.
type SessionSettingsHandler struct {
	store      *store.Store
	audit      *audit.Logger
	middleware *MiddlewareManager
}

func (h *SessionSettingsHandler) Get(w http.ResponseWriter, r *http.Request) {
	writeGroupJSON(w, h.store.SessionLimits())
}

func (h *SessionSettingsHandler) Put(w http.ResponseWriter, r *http.Request) {
	var req store.SessionLimits
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || !req.Valid() {
		http.Error(w, `{"error":"invalid_request","error_description":"Session lifetime must be 1 hour to 7 days and idle limit 5 minutes to 24 hours, no longer than the lifetime"}`, http.StatusBadRequest)
		return
	}
	old := h.store.SessionLimits()
	actor := GetUserFromContext(r.Context())
	event := h.audit.Prepare("admin.session_limits_configured", actor.ID, actor.Username, "session_limits", "settings", h.middleware.ClientIP(r), r.UserAgent(), "success",
		map[string]any{"old": old, "new": req})
	if err := h.store.SetSessionLimits(req, event.Row); err != nil {
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}
	event.Committed()
	writeGroupJSON(w, req)
}
