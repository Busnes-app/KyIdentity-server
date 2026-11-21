package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/audit"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/mail"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// EraseHandler is Delete everything (tenancy design, amendment 2026-11-21). Multi-tenant
// only: a single-tenant install answers 404 on both routes.
type EraseHandler struct {
	store         *store.Store
	audit         *audit.Logger
	middleware    *MiddlewareManager
	issuerURL     string
	encryptionKey []byte
	multiTenant   bool
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
	switch {
	case errors.Is(err, store.ErrErasureStepUp):
		h.audit.Observe("account.erased", user.ID, "", user.ID, "user", ip, ua, "denied", map[string]any{"reason": "step_up"})
		writeAPIError(w, http.StatusForbidden, "step_up_required", "Confirm with your password and a second factor")
		return
	case errors.Is(err, store.ErrErasureRefused):
		writeAPIError(w, http.StatusNotFound, "not_found", "")
		return
	case errors.Is(err, store.ErrOrgErased):
		writeAPIError(w, http.StatusConflict, "org_erased", "")
		return
	case errors.Is(err, store.ErrAccountHolder):
		writeAPIError(w, http.StatusConflict, "account_holder", "")
		return
	case err != nil:
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "")
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
	if len(out.Notify) > 0 {
		go h.notify(user.ID, ip, ua, out)
	}
}

// notify mails each other member that the org will be deleted. A failure is audited with
// no address.
func (h *EraseHandler) notify(holderID, ip, ua string, out *store.Erasure) {
	settings, err := mail.Load(h.store, h.encryptionKey)
	if err != nil || settings == nil {
		h.audit.Observe("account.erase_notice", holderID, "", holderID, "user", ip, ua, "failure", map[string]any{"reason": "mail_not_configured", "members": len(out.Notify)})
		return
	}
	failed := 0
	for _, n := range out.Notify {
		if settings.Send(n.Email, "Your household is being deleted", eraseNoticeBody(n.Name, h.issuerURL, out.DeleteAfter)) != nil {
			failed++
		}
	}
	if failed > 0 {
		h.audit.Observe("account.erase_notice", holderID, "", holderID, "user", ip, ua, "failure", map[string]any{"members": len(out.Notify), "failed": failed})
	}
}

func eraseNoticeBody(name, issuer string, at time.Time) string {
	return "Hello " + name + ",\r\n\r\nThe account holder of your household asked for everything in it to be deleted. " +
		"Your account and everything in it will be deleted on " + at.UTC().Format("2 January 2006") + ". This cannot be undone.\r\n\r\n" +
		"Until then you can sign in at " + issuer + " and export your data from each app. Mail sent to you is no longer delivered.\r\n"
}
