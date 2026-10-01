package api

import (
	"encoding/json"
	"net/http"

	"github.com/Busnes-app/kyidentity-server/internal/audit"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// AttestationHandler serves the device-attestation policy.
type AttestationHandler struct {
	store      *store.Store
	audit      *audit.Logger
	middleware *MiddlewareManager
}

func NewAttestationHandler(s *store.Store, a *audit.Logger, m *MiddlewareManager) *AttestationHandler {
	return &AttestationHandler{store: s, audit: a, middleware: m}
}

func (h *AttestationHandler) GetSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := h.store.AttestationSettings()
	if err != nil {
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}
	writeGroupJSON(w, settings)
}

func (h *AttestationHandler) PutSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RequireLockedBootloader *bool `json:"requireLockedBootloader"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.RequireLockedBootloader == nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	old, err := h.store.AttestationSettings()
	if err != nil {
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}
	settings := store.AttestationSettings{RequireLockedBootloader: *req.RequireLockedBootloader}
	actor := GetUserFromContext(r.Context())
	event := h.audit.Prepare("admin.attestation_configured", actor.ID, actor.Username, "attestation", "settings", h.middleware.ClientIP(r), r.UserAgent(), "success",
		map[string]any{"old": old.RequireLockedBootloader, "new": settings.RequireLockedBootloader})
	if err := h.store.SetAttestationSettings(settings, event.Row); err != nil {
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}
	event.Committed()
	writeGroupJSON(w, settings)
}
