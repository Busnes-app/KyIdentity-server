package api

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
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

// AuditByActor is staff-administrator-only and has no tenant-selected OrgStore.
func (h *AdminHandler) AuditByActor(w http.ResponseWriter, r *http.Request) {
	if !h.multiTenant {
		http.NotFound(w, r)
		return
	}
	f, err := auditFilterFrom(r)
	if err != nil {
		invalidFilter(w, err)
		return
	}
	f.Limit = 100
	f.Offset, err = strconv.Atoi(r.URL.Query().Get("offset"))
	if r.URL.Query().Get("offset") == "" {
		f.Offset = 0
		err = nil
	}
	if err != nil || f.Actor == "" || f.Offset < 0 || f.Offset > 1000000 {
		writeAPIError(w, 400, "invalid_request", "Supply an actor and an offset from 0 to 1000000.")
		return
	}
	events, total, err := h.store.Platform().AuditByActor(r.Context(), f)
	if err != nil {
		stepUpInternalError(w)
		return
	}
	u := GetUserFromContext(r.Context())
	details, _ := json.Marshal(map[string]any{"actor": f.Actor, "offset": f.Offset, "returned": len(events)})
	if err := h.store.Platform().RecordPlatformAudit("", &store.AuditEvent{ID: uuid.NewString(), ActorID: u.ID, ActorUsername: u.Username, Action: "staff.audit_read", TargetType: "audit", Outcome: "success", IPAddress: h.middleware.ClientIP(r), UserAgent: r.UserAgent(), DetailsJSON: string(details), CreatedAt: time.Now().UTC()}); err != nil {
		stepUpInternalError(w)
		return
	}
	writeGroupJSON(w, map[string]any{"auditEvents": events, "total": total, "offset": f.Offset, "limit": f.Limit})
}

func (h *AdminHandler) OrgLimits(w http.ResponseWriter, r *http.Request) {
	if !h.multiTenant {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodGet {
		org, err := h.store.Platform().PlatformOrg(orgStore(r).ID().String())
		if err != nil {
			staffPlatformError(w, err)
			return
		}
		writeGroupJSON(w, org)
		return
	}
	var req struct {
		MaxSeats            int64 `json:"max_seats"`
		StorageBytes        int64 `json:"storage_bytes"`
		StoragePerSeatBytes int64 `json:"storage_per_seat_bytes"`
		Ack                 bool  `json:"storage_over_pool_ack"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	d.DisallowUnknownFields()
	if d.Decode(&req) != nil || d.Decode(new(any)) != io.EOF {
		writeAPIError(w, 400, "invalid_request", "")
		return
	}
	u := GetUserFromContext(r.Context())
	event := h.audit.Prepare("org.limits_changed", u.ID, u.Username, orgStore(r).ID().String(), "org", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	if err := h.store.Platform().SetOrgLimits(orgStore(r).ID(), store.OrgLimits{MaxSeats: req.MaxSeats, StorageBytes: req.StorageBytes, StoragePerSeatBytes: req.StoragePerSeatBytes}, req.Ack, event.Row); err != nil {
		staffPlatformError(w, err)
		return
	}
	event.Committed()
	writeGroupJSON(w, map[string]bool{"success": true})
}

func staffPlatformError(w http.ResponseWriter, err error) {
	status, code, extra := platformErrorFor(err)
	platformError(w, status, code, extra)
}

// ResumeRestoredOrg is an explicit staff confirmation for an org suspended after a
// restore. It uses the org's own revision as its concurrency token and never alters
// billing_revision or lifts a billing-owned suspension or deletion schedule.
func (h *AdminHandler) ResumeRestoredOrg(w http.ResponseWriter, r *http.Request) {
	if !h.multiTenant {
		http.NotFound(w, r)
		return
	}
	var req struct {
		OrgRevision       int64  `json:"org_revision"`
		RestoreGeneration string `json:"restore_generation,omitempty"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	d.DisallowUnknownFields()
	if d.Decode(&req) != nil || d.Decode(new(any)) != io.EOF {
		writeAPIError(w, 400, "invalid_request", "")
		return
	}
	u := GetUserFromContext(r.Context())
	tx, err := h.store.Platform().ResumeOrgForStaff(orgStore(r).ID(), req.OrgRevision, &store.AuditEvent{ID: uuid.NewString(), ActorID: u.ID, ActorUsername: u.Username, IPAddress: h.middleware.ClientIP(r), UserAgent: r.UserAgent()}, req.RestoreGeneration)
	if err != nil {
		staffPlatformError(w, err)
		return
	}
	writeGroupJSON(w, tx)
}

func (h *AdminHandler) ExportOrg(w http.ResponseWriter, r *http.Request) {
	if !h.multiTenant {
		http.NotFound(w, r)
		return
	}
	auditOffset, err := parseOrgExportOffset(r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	u := GetUserFromContext(r.Context())
	event := h.audit.Prepare("staff.org_exported", u.ID, u.Username, orgStore(r).ID().String(), "org", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	data, err := orgStore(r).ExportOrgForStaff(r.Context(), event.Row, store.OrgExportOptions{AuditOffset: auditOffset})
	if err != nil {
		writeInputError(w, "export_failed", err)
		return
	}
	event.Committed()
	w.Header().Set("Content-Disposition", `attachment; filename="organisation.json"`)
	writeGroupJSON(w, data)
}
