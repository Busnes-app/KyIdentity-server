package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Busness-app/kysignon-server/internal/store"
)

// GetDelegations reads one user's delegated permissions. Global administrators only.
func (h *AdminHandler) GetDelegations(w http.ResponseWriter, r *http.Request) {
	user, err := h.store.GetUserByID(r.PathValue("id"))
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if user == nil {
		http.Error(w, `{"error":"user_not_found"}`, http.StatusNotFound)
		return
	}
	d, err := h.store.Delegations(user.ID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	writeGroupJSON(w, map[string]any{"delegations": d})
}

// SetDelegations replaces one user's delegated permissions. Global administrators only;
// the change and its audit row commit together.
func (h *AdminHandler) SetDelegations(w http.ResponseWriter, r *http.Request) {
	var d store.Delegations
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&d); err != nil || len(d.AppOwner) > 200 {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	for _, id := range d.AppOwner {
		if id == "" || len(id) > 200 {
			http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
			return
		}
	}
	admin := GetUserFromContext(r.Context())
	userID := r.PathValue("id")
	pending := h.audit.Prepare("admin.delegations_updated", admin.ID, admin.Username, userID, "user",
		h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	err := h.store.SetDelegations(userID, d, pending.Row)
	switch {
	case errors.Is(err, store.ErrUserMissing):
		http.Error(w, `{"error":"user_not_found"}`, http.StatusNotFound)
		return
	case errors.Is(err, store.ErrAppRecordMissing):
		http.Error(w, `{"error":"unknown_app","error_description":"One of the apps does not exist"}`, http.StatusBadRequest)
		return
	case err != nil:
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	pending.Committed()
	saved, err := h.store.Delegations(userID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	writeGroupJSON(w, map[string]any{"delegations": saved})
}
