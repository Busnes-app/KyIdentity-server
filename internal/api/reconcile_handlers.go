package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Busness-app/kysignon-server/internal/store"
)

func (h *AdminHandler) ListProvisioningState(w http.ResponseWriter, r *http.Request) {
	p, err := parseGroupPage(r)
	if err != nil {
		http.Error(w, `{"error":"invalid_request"}`, 400)
		return
	}
	rows, total, err := h.store.ListProvisioningState(r.PathValue("id"), p.Query, p.Limit, p.Offset)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, 500)
		return
	}
	writeGroupJSON(w, map[string]any{"users": rows, "total": total, "limit": p.Limit, "offset": p.Offset})
}

func (h *AdminHandler) RetryProvisioning(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	event := h.audit.Prepare("admin.provisioning_retried", admin.ID, admin.Username, r.PathValue("id"), "system", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"userId": r.PathValue("userId")})
	err := h.store.RetryProvisioning(r.PathValue("id"), r.PathValue("userId"), event.Row)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, 500)
		return
	}
	event.Committed()
	writeGroupJSON(w, map[string]bool{"success": true})
}

func (h *AdminHandler) ListReconcileJobs(w http.ResponseWriter, r *http.Request) {
	sys, err := h.store.GetPairedSystemByID(r.PathValue("id"))
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, 500)
		return
	}
	if sys == nil {
		http.NotFound(w, r)
		return
	}
	jobs, err := h.store.ListReconcileJobs(sys.ID, 20)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, 500)
		return
	}
	writeGroupJSON(w, map[string]any{"jobs": jobs})
}

// Preview is read-only at the target and needs no step-up; repair queues account
// changes and is registered behind operation-bound step-up.
func (h *AdminHandler) startReconcile(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		admin := GetUserFromContext(r.Context())
		event := h.audit.Prepare("admin.reconcile_requested", admin.ID, admin.Username, r.PathValue("id"), "system", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"kind": kind})
		job, err := h.store.CreateReconcileJob(r.PathValue("id"), kind, admin.Username, event.Row)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			http.NotFound(w, r)
			return
		case errors.Is(err, store.ErrReconcileBusy):
			http.Error(w, `{"error":"reconcile_busy"}`, http.StatusConflict)
			return
		case err != nil:
			http.Error(w, `{"error":"internal_error"}`, 500)
			return
		}
		event.Committed()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"job": job})
	}
}
