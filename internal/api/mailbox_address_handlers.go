package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// PutMailboxAddress is staff setting or changing a hosted member's mailbox address
// (tenancy design, "Mailbox address"). Multi-tenant only: a single-tenant install answers
// 404, as for a route it does not have.
func (h *AdminHandler) PutMailboxAddress(w http.ResponseWriter, r *http.Request) {
	if !h.multiTenant {
		writeAPIError(w, http.StatusNotFound, "not_found", "")
		return
	}
	var req struct {
		MailboxAddress string `json:"mailboxAddress"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "")
		return
	}
	admin := GetUserFromContext(r.Context())
	id := r.PathValue("id")
	event := h.audit.Prepare("admin.user_mailbox_address_changed", admin.ID, admin.Username, id, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	user, changed, err := orgStore(r).SetMailboxAddress(id, req.MailboxAddress, true, event.Row)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeAPIError(w, http.StatusNotFound, "user_not_found", "")
	case errors.Is(err, store.ErrMailboxDomain):
		writeAPIError(w, http.StatusBadRequest, "mailbox_domain", "The mailbox address must be on one of the suite mail domains")
	case errors.Is(err, store.ErrMailboxAddressTaken):
		writeAPIError(w, http.StatusConflict, "mailbox_address_taken", "Another account already uses this address")
	case errors.Is(err, store.ErrMailboxCustomerOnly):
		writeAPIError(w, http.StatusBadRequest, "mailbox_customer_only", "Only accounts of a person or household org have a mailbox address")
	case err != nil:
		writeInputError(w, "invalid_request", err)
	default:
		if changed {
			event.Committed()
		}
		writeJSON(w, http.StatusOK, map[string]any{"user": user})
	}
}
