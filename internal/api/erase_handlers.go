package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/audit"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// EraseHandler is Delete everything (tenancy design, amendment 2026-11-21). Multi-tenant
// only: a single-tenant install answers 404 on both routes.
type EraseHandler struct {
	store       *store.Store
	audit       *audit.Logger
	middleware  *MiddlewareManager
	multiTenant bool
}

// eraseOperation is the step-up operation the grant must name.
const eraseOperation = "POST /api/user/erase"

// eraseAddress is what the clicker types: the mailbox address, else the sign-in email.
func eraseAddress(u *store.User) string {
	if u.MailboxAddress != "" {
		return u.MailboxAddress
	}
	return u.Email
}

// Options answers whether the button applies, and what it deletes. GET /api/user/erase.
func (h *EraseHandler) Options(w http.ResponseWriter, r *http.Request) {
	if !h.multiTenant {
		writeAPIError(w, http.StatusNotFound, "not_found", "")
		return
	}
	user := GetUserFromContext(r.Context())
	scope, err := orgStore(r).ErasureScope(user.ID)
	if errors.Is(err, store.ErrErasureRefused) {
		writeAPIError(w, http.StatusNotFound, "not_found", "")
		return
	}
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, scope)
}

// Erase is the button. POST /api/user/erase {"address"} with a step-up grant that proved a
// second factor, spent by the store in the erasure's transaction.
func (h *EraseHandler) Erase(w http.ResponseWriter, r *http.Request) {
	if !h.multiTenant {
		writeAPIError(w, http.StatusNotFound, "not_found", "")
		return
	}
	user, sess := GetUserFromContext(r.Context()), GetSessionFromContext(r.Context())
	ip, ua := h.middleware.ClientIP(r), r.UserAgent()
	var req struct {
		Address string `json:"address"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "")
		return
	}
	if want := eraseAddress(user); want == "" || !strings.EqualFold(strings.TrimSpace(req.Address), want) {
		h.audit.Observe("account.erased", user.ID, "", user.ID, "user", ip, ua, "denied", map[string]any{"reason": "address_mismatch"})
		writeAPIError(w, http.StatusBadRequest, "address_mismatch", "Type your address exactly as shown")
		return
	}
	raw := r.Header.Get(StepUpHeader)
	if raw == "" {
		writeAPIError(w, http.StatusForbidden, "step_up_required", "Confirm with your password and a second factor")
		return
	}
	pending := h.audit.Prepare("account.erased", user.ID, "", user.ID, "user", ip, ua, "success", nil)
	out, err := orgStore(r).Erase(user.ID, sess.ID, crypto.HashSHA256(raw), eraseOperation, pending.Row)
	if err != nil {
		// Every refusal commits nothing, so each is observed.
		outcome, code, status, msg := "denied", "internal_error", http.StatusInternalServerError, ""
		switch {
		case errors.Is(err, store.ErrErasureStepUp):
			code, status, msg = "step_up_required", http.StatusForbidden, "Confirm with your password and a second factor"
		case errors.Is(err, store.ErrErasureRefused):
			code, status = "not_found", http.StatusNotFound
		case errors.Is(err, store.ErrOrgErased):
			code, status = "org_erased", http.StatusConflict
		case errors.Is(err, store.ErrAccountHolder):
			code, status = "account_holder", http.StatusConflict
		default:
			outcome = "failure"
			log.Printf("erase: %v", err)
		}
		h.audit.Observe("account.erased", user.ID, "", user.ID, "user", ip, ua, outcome, map[string]any{"reason": code})
		writeAPIError(w, status, code, msg)
		return
	}
	pending.Committed()
	clearSessionCookies(w)
	w.Header().Set("Cache-Control", "no-store")
	body := map[string]any{"deleted": out.Deleted}
	if !out.DeleteAfter.IsZero() {
		body["deleteAfter"] = out.DeleteAfter.Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, body)
}

// OrgExportStatus and ExportOrg are the holder's read-only directory export during
// billing-scheduled deletion. Other members retain only their own app export links.
func (h *EraseHandler) OrgExportStatus(w http.ResponseWriter, r *http.Request) {
	if !h.multiTenant {
		http.NotFound(w, r)
		return
	}
	status, err := orgStore(r).OrgExportStatus(GetUserFromContext(r.Context()).ID)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		stepUpInternalError(w)
		return
	}
	writeJSON(w, 200, status)
}
func (h *EraseHandler) ExportOrg(w http.ResponseWriter, r *http.Request) {
	if !h.multiTenant {
		http.NotFound(w, r)
		return
	}
	u := GetUserFromContext(r.Context())
	event := h.audit.Prepare("account.org_exported", u.ID, u.Username, u.Org().String(), "org", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	data, err := orgStore(r).ExportOrg(r.Context(), u.ID, event.Row)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		writeInputError(w, "export_failed", err)
		return
	}
	event.Committed()
	w.Header().Set("Content-Disposition", `attachment; filename="organisation.json"`)
	writeJSON(w, 200, data)
}
