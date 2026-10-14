package api

import (
	"encoding/json"
	"net/http"
)

func (h *AdminHandler) ListSyncDeliveries(w http.ResponseWriter, r *http.Request) {
	attempts, err := h.store.ListSyncDeliveryAttempts(r.PathValue("id"))
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(attempts)
}

func (h *AdminHandler) ReadBackSyncDelivery(w http.ResponseWriter, r *http.Request) {
	sys, err := h.store.GetPairedSystemByID(r.PathValue("id"))
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, 500)
		return
	}
	if sys == nil {
		http.NotFound(w, r)
		return
	}
	attempts, err := h.store.ListSyncDeliveryAttempts(sys.ID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, 500)
		return
	}
	for _, a := range attempts {
		if a.Token != r.PathValue("token") {
			continue
		}
		result, err := h.syncEngine.ReadBackSyncResource(r.Context(), sys, a.EventType, a.UserID)
		admin := GetUserFromContext(r.Context())
		outcome := "success"
		if err != nil {
			outcome = "failure"
		}
		if auditErr := h.audit.Record("admin.sync_delivery_read_back", admin.ID, admin.Username, sys.ID, "system", h.middleware.ClientIP(r), r.UserAgent(), outcome, map[string]any{"systemName": sys.Name, "attemptToken": a.Token, "userId": a.UserID}); auditErr != nil {
			http.Error(w, `{"error":"internal_error"}`, 500)
			return
		}
		if err != nil {
			http.Error(w, `{"error":"read_back_failed"}`, 502)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
		return
	}
	http.NotFound(w, r)
}

func (h *AdminHandler) ResumeSyncDelivery(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	details := map[string]any{"attemptToken": r.PathValue("token")}
	// Step-up has already been consumed. Every rejected handler path needs its
	// own audit entry, using fixed reasons rather than store/remote error text.
	reject := func(reason string, status int) {
		details["reason"] = reason
		h.audit.Observe("admin.sync_delivery_resumed", admin.ID, admin.Username, r.PathValue("id"), "system", h.middleware.ClientIP(r), r.UserAgent(), "failure", details)
		writeAPIError(w, status, reason, "")
	}
	sys, err := h.store.GetPairedSystemByID(r.PathValue("id"))
	if err != nil {
		reject("internal_error", 500)
		return
	}
	if sys == nil {
		reject("system_not_found", 404)
		return
	}
	details["systemName"] = sys.Name
	var req struct {
		ConfirmedQuiescent bool `json:"confirmedQuiescent"`
		AllowCreateRetry   bool `json:"allowCreateRetry"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || !req.ConfirmedQuiescent {
		reject("confirm_remote_quiescence", 400)
		return
	}
	if req.AllowCreateRetry {
		attempts, err := h.store.ListSyncDeliveryAttempts(sys.ID)
		if err != nil {
			reject("internal_error", 500)
			return
		}
		absent := false
		for _, a := range attempts {
			if a.Token != r.PathValue("token") {
				continue
			}
			result, err := h.syncEngine.ReadBackSyncResource(r.Context(), sys, a.EventType, a.UserID)
			absent = err == nil && result["state"] == "absent"
		}
		if !absent {
			reject("create_retry_requires_absent_remote_user", 409)
			return
		}
	}
	event := h.audit.Prepare("admin.sync_delivery_resumed", admin.ID, admin.Username, sys.ID, "system", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"systemName": sys.Name, "attemptToken": r.PathValue("token"), "confirmedQuiescent": true, "allowCreateRetry": req.AllowCreateRetry})
	if err = h.store.ResumeSyncDelivery(sys.ID, r.PathValue("token"), req.AllowCreateRetry, event.Row); err != nil {
		reject("attempt_changed_or_still_running", 409)
		return
	}
	event.Committed()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// ResumeSyncDeliveries releases every expired attempt of one connector after the same
// quiescence confirmation, with one step-up and one audit. Clearing an uncertain-create
// guard needs its own read-back, so it stays per attempt.
func (h *AdminHandler) ResumeSyncDeliveries(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	details := map[string]any{}
	reject := func(reason string, status int) {
		details["reason"] = reason
		h.audit.Observe("admin.sync_deliveries_resumed", admin.ID, admin.Username, r.PathValue("id"), "system", h.middleware.ClientIP(r), r.UserAgent(), "failure", details)
		writeAPIError(w, status, reason, "")
	}
	sys, err := h.store.GetPairedSystemByID(r.PathValue("id"))
	if err != nil {
		reject("internal_error", 500)
		return
	}
	if sys == nil {
		reject("system_not_found", 404)
		return
	}
	details["systemName"] = sys.Name
	var req struct {
		ConfirmedQuiescent bool `json:"confirmedQuiescent"`
		AllowCreateRetry   bool `json:"allowCreateRetry"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || !req.ConfirmedQuiescent {
		reject("confirm_remote_quiescence", 400)
		return
	}
	if req.AllowCreateRetry {
		reject("create_retry_requires_single_attempt", 400)
		return
	}
	event := h.audit.Prepare("admin.sync_deliveries_resumed", admin.ID, admin.Username, sys.ID, "system", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"systemName": sys.Name, "confirmedQuiescent": true})
	n, err := h.store.ResumeSyncDeliveries(sys.ID, event.Row)
	if err != nil {
		reject("no_expired_attempts", 409)
		return
	}
	event.Committed()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int{"resumed": n})
}
