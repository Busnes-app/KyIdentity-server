package api

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// FindOrgs is the staff org finder (GET /api/admin/orgs?q=): the staff org for an empty q,
// else the org with that ID or billing_ref, or holding an account with that exact email.
// A cross-org read, audited as one platform row naming every org returned. 404 in a
// single-tenant install.
func (h *AdminHandler) FindOrgs(w http.ResponseWriter, r *http.Request) {
	if !h.multiTenant {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query().Get("q")
	if len(q) > 254 {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "The search is too long.")
		return
	}
	orgs, err := h.store.Platform().FindOrgs(q)
	if err != nil {
		log.Printf("admin: find orgs: %v", err)
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	ids := make([]string, len(orgs))
	for i, o := range orgs {
		ids[i] = o.ID
	}
	u := GetUserFromContext(r.Context())
	b, _ := json.Marshal(map[string]any{"orgs": ids})
	if err := h.store.Platform().RecordPlatformAudit("", &store.AuditEvent{ID: uuid.NewString(), ActorID: u.ID, ActorUsername: u.Username, Action: "staff.orgs_read",
		TargetType: "org", IPAddress: h.middleware.ClientIP(r), UserAgent: r.UserAgent(), Outcome: "success", DetailsJSON: string(b), CreatedAt: time.Now().UTC()}); err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	writeGroupJSON(w, map[string]any{"orgs": orgs})
}

// pinnedPolicy refuses a change to the administrators policy in a multi-tenant install,
// where it is pinned to passkeys (store.StaffPasskeyPolicy).
func (h *AdminHandler) pinnedPolicy(w http.ResponseWriter, r *http.Request, action string, p store.EnrollmentPolicy) bool {
	if !h.multiTenant || p.Scope != store.StaffPasskeyPolicy.Scope {
		return false
	}
	u := GetUserFromContext(r.Context())
	if err := h.audit.Record(action, u.ID, u.Username, p.Scope, "enrollment_policy", h.middleware.ClientIP(r), r.UserAgent(), "denied", map[string]any{"reason": "pinned_policy"}); err != nil {
		stepUpInternalError(w)
		return true
	}
	writeAPIError(w, http.StatusConflict, "pinned_policy", "Staff sign in with a passkey in a multi-tenant install; this policy cannot change.")
	return true
}
