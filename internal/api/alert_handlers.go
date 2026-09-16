package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/Busnes-app/kyidentity-server/internal/audit"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// AlertHandler serves the alert inbox and its settings. Reading is administrators and
// auditors; acknowledging and configuring is administrators, and recipients are named
// by username on the wire but checked by the store for the right to read alerts.
type AlertHandler struct {
	store      *store.Store
	audit      *audit.Logger
	middleware *MiddlewareManager
}

func NewAlertHandler(s *store.Store, a *audit.Logger, m *MiddlewareManager) *AlertHandler {
	return &AlertHandler{store: s, audit: a, middleware: m}
}

func (h *AlertHandler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	status := q.Get("status")
	if status == "" {
		status = "open"
	}
	if status != "open" && status != "acknowledged" && status != "resolved" && status != "all" {
		http.Error(w, `{"error":"invalid_request","error_description":"status must be open, acknowledged, resolved or all"}`, http.StatusBadRequest)
		return
	}
	limit, offset := 50, 0
	if l, err := strconv.Atoi(q.Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	if o, err := strconv.Atoi(q.Get("offset")); err == nil && o >= 0 {
		offset = o
	}
	alerts, total, err := h.store.ListAlerts(status, limit, offset)
	if err != nil {
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}
	writeGroupJSON(w, map[string]any{"alerts": alerts, "total": total, "limit": limit, "offset": offset})
}

func (h *AlertHandler) Acknowledge(w http.ResponseWriter, r *http.Request) {
	actor := GetUserFromContext(r.Context())
	id := r.PathValue("id")
	event := h.audit.Prepare("admin.alert_acknowledged", actor.ID, actor.Username, id, "alert", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	switch err := h.store.AcknowledgeAlert(id, actor.ID, event.Row); {
	case errors.Is(err, store.ErrAlertMissing):
		http.Error(w, `{"error":"alert_not_found"}`, http.StatusNotFound)
		return
	case errors.Is(err, store.ErrAlertNotOpen):
		http.Error(w, `{"error":"alert_not_open","error_description":"This alert was already acknowledged or has resolved"}`, http.StatusConflict)
		return
	case err != nil:
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}
	event.Committed()
	writeGroupJSON(w, map[string]bool{"success": true})
}

type alertRecipient struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

func (h *AlertHandler) GetSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := h.store.AlertSettings()
	if err != nil {
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}
	recipients := []alertRecipient{}
	for _, id := range settings.Recipients {
		if u, err := h.store.GetUserByID(id); err == nil && u != nil {
			recipients = append(recipients, alertRecipient{u.ID, u.Username})
		}
	}
	writeGroupJSON(w, map[string]any{"loginFailureThreshold": settings.LoginFailureThreshold, "loginFailureWindowSeconds": settings.LoginFailureWindowSeconds, "recipients": recipients})
}

func (h *AlertHandler) PutSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LoginFailureThreshold     int      `json:"loginFailureThreshold"`
		LoginFailureWindowSeconds int      `json:"loginFailureWindowSeconds"`
		Recipients                []string `json:"recipients"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Recipients) > 50 {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	settings := store.AlertSettings{LoginFailureThreshold: req.LoginFailureThreshold, LoginFailureWindowSeconds: req.LoginFailureWindowSeconds, Recipients: []string{}}
	names := []string{}
	for _, name := range req.Recipients {
		u, err := h.store.GetUserByUsername(name)
		if err != nil {
			http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
			return
		}
		if u == nil {
			http.Error(w, `{"error":"alert_recipient","error_description":"Recipients must be administrators or auditors"}`, http.StatusBadRequest)
			return
		}
		settings.Recipients = append(settings.Recipients, u.ID)
		names = append(names, u.Username)
	}
	actor := GetUserFromContext(r.Context())
	event := h.audit.Prepare("admin.alerts_configured", actor.ID, actor.Username, "alerts", "settings", h.middleware.ClientIP(r), r.UserAgent(), "success",
		map[string]any{"loginFailureThreshold": settings.LoginFailureThreshold, "loginFailureWindowSeconds": settings.LoginFailureWindowSeconds, "recipients": names})
	switch err := h.store.SetAlertSettings(settings, event.Row); {
	case errors.Is(err, store.ErrAlertRecipient):
		http.Error(w, `{"error":"alert_recipient","error_description":"Recipients must be administrators or auditors"}`, http.StatusBadRequest)
		return
	case errors.Is(err, store.ErrAlertSettings):
		http.Error(w, `{"error":"invalid_settings","error_description":"Threshold must be 1 to 1000 failures within 1 minute to 1 day"}`, http.StatusBadRequest)
		return
	case err != nil:
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}
	event.Committed()
	writeGroupJSON(w, map[string]bool{"success": true})
}
