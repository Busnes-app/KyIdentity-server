package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Busness-app/kysignon-server/internal/store"
)

func writeAppRegistryError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrAppLinkConflict):
		http.Error(w, `{"error":"link_conflict","error_description":"Connections overlap, access settings differ, assignments exist, or the selection is stale. Remove assignments and match access settings before linking; refresh before trying again."}`, http.StatusConflict)
	case errors.Is(err, store.ErrAppRecordMissing):
		http.Error(w, `{"error":"not_found","error_description":"Application record no longer exists"}`, http.StatusNotFound)
	default:
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
	}
}
func (h *AdminHandler) ListAppRecords(w http.ResponseWriter, r *http.Request) {
	p, err := parseGroupPage(r)
	if err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	// An app owner sees the apps they own and nothing about the rest.
	var records []store.AppRecord
	var total int
	if a := accessFromContext(r.Context()); a.Admin || a.Auditor {
		records, total, err = h.store.ListAppRecords(p.Query, p.Limit, p.Offset)
	} else {
		records, total, err = h.store.ListAppRecordsOwnedBy(GetUserFromContext(r.Context()).ID, p.Query, p.Limit, p.Offset)
	}
	if err != nil {
		writeAppRegistryError(w, err)
		return
	}
	writeGroupJSON(w, map[string]any{"records": records, "total": total, "limit": p.Limit, "offset": p.Offset})
}
func (h *AdminHandler) LinkAppRecords(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SourceID       string `json:"sourceId"`
		TargetRevision int    `json:"targetRevision"`
		SourceRevision int    `json:"sourceRevision"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SourceID == "" || len(req.SourceID) > 200 || req.TargetRevision < 1 || req.SourceRevision < 1 {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	actor := GetUserFromContext(r.Context())
	event := h.audit.Prepare("admin.app_linked", actor.ID, actor.Username, r.PathValue("id"), "application", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	if err := h.store.LinkAppRecords(r.PathValue("id"), req.SourceID, req.TargetRevision, req.SourceRevision, event.Row); err != nil {
		writeAppRegistryError(w, err)
		return
	}
	event.Committed()
	writeGroupJSON(w, map[string]bool{"success": true})
}
func (h *AdminHandler) UnlinkAppRecord(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Kind     string `json:"kind"`
		Revision int    `json:"revision"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Revision < 1 || (req.Kind != "client" && req.Kind != "launcher" && req.Kind != "system") {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	actor := GetUserFromContext(r.Context())
	event := h.audit.Prepare("admin.app_unlinked", actor.ID, actor.Username, r.PathValue("id"), "application", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	id, err := h.store.UnlinkAppRecord(r.PathValue("id"), req.Kind, req.Revision, event.Row)
	if err != nil {
		writeAppRegistryError(w, err)
		return
	}
	event.Committed()
	writeGroupJSON(w, map[string]string{"id": id})
}
