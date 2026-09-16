package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/Busnes-app/kyidentity-server/internal/store"
)

func (h *AdminHandler) SetAppAuthenticationPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Policy   *store.AppAuthenticationPolicy `json:"policy"`
		Revision int                            `json:"revision"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || decoder.Decode(new(any)) != io.EOF || req.Policy == nil || !req.Policy.Valid() || req.Revision < 1 {
		http.Error(w, `{"error":"invalid_request","error_description":"Choose a valid authentication mode, factor and age in seconds"}`, 400)
		return
	}
	actor := GetUserFromContext(r.Context())
	event := h.audit.Prepare("admin.app_authentication_changed", actor.ID, actor.Username, r.PathValue("id"), "application", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	if err := h.store.SetAppAuthenticationPolicy(r.PathValue("id"), *req.Policy, req.Revision, event.Row); err != nil {
		if errors.Is(err, store.ErrAppAuthentication) {
			http.Error(w, `{"error":"invalid_request","error_description":"Authentication policy requires an OAuth client"}`, 400)
			return
		}
		writeAppRegistryError(w, err)
		return
	}
	event.Committed()
	writeGroupJSON(w, map[string]bool{"success": true})
}
