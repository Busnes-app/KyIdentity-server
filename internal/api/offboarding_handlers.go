package api

import (
	"database/sql"
	"errors"
	"net/http"

	"github.com/Busness-app/kyidentity-server/internal/store"
)

// UserOffboarding shows how far a user's removal has propagated. It answers for deleted
// users too, because that is when an operator most needs to see what is still pending.
func (h *AdminHandler) UserOffboarding(w http.ResponseWriter, r *http.Request) {
	off, err := h.store.UserOffboarding(r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, `{"error":"user_not_found"}`, http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	writeGroupJSON(w, struct {
		*store.Offboarding
		Logouts []logoutDeliveryView `json:"logouts"`
	}{off, logoutViews(off.Logouts, true)})
}
