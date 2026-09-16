package api

import (
	"errors"
	"net/http"

	"github.com/Busness-app/kyidentity-server/internal/store"
)

// ExplainAppAccess explains one user's access to one app for an administrator, auditor
// or owner of that app. The route's permission scopes it to the app; the answer names
// only groups assigned to that app, which the same viewers already see.
func (h *AdminHandler) ExplainAppAccess(w http.ResponseWriter, r *http.Request) {
	e, err := h.store.ExplainAccess(r.PathValue("userId"), r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrAppRecordMissing), errors.Is(err, store.ErrUserMissing):
		http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
		return
	case err != nil:
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	writeGroupJSON(w, map[string]any{"explanation": e})
}

// OwnAccessExplanation tells the signed-in user whether they can open an app and what
// to do about it. A denial reads the same whatever its cause, an unknown client reads
// like a denial, and the app is named only when they have access or may request it, so
// the answer discloses nothing an authorize attempt would not.
func (h *AccessRequestHandler) OwnAccessExplanation(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("clientId")
	if clientID == "" || len(clientID) > 200 {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	user := GetUserFromContext(r.Context())
	denied := map[string]any{"allowed": false, "reason": "no_access", "requestable": false}
	e, err := h.store.ExplainClientAccess(user.ID, clientID)
	switch {
	case errors.Is(err, store.ErrAppRecordMissing):
		writeGroupJSON(w, denied)
		return
	case err != nil:
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if !e.Allowed {
		if e.Requestable && e.AppEnabled && e.ClientEnabled && e.AccessMode == "assigned_only" {
			denied["requestable"], denied["appName"] = true, e.AppName
		}
		writeGroupJSON(w, denied)
		return
	}
	out := map[string]any{"allowed": true, "reason": e.Reason, "requestable": false, "appName": e.AppName}
	if e.AccessEndsAt != nil {
		out["accessEndsAt"] = e.AccessEndsAt
	}
	writeGroupJSON(w, out)
}
