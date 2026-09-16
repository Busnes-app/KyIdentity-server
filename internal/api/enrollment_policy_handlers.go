package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/Busnes-app/kyidentity-server/internal/store"
)

func enrollmentError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrEmergencyAdministrator):
		http.Error(w, `{"error":"compliant_admin_required","error_description":"Sign out and sign in with a permitted administrator factor, then apply within five minutes. This proves a local administrator can still sign in."}`, 409)
	case errors.Is(err, store.ErrEnrollmentPolicy):
		http.Error(w, `{"error":"invalid_policy","error_description":"Choose permitted factors and a grace period from 0 to 90 days. All applicable policies must share a permitted factor."}`, 400)
	case errors.Is(err, store.ErrLastCompliantFactor):
		http.Error(w, `{"error":"required_factor","error_description":"Enroll another permitted factor before removing your last compliant factor."}`, 409)
	case errors.Is(err, store.ErrGroupTargetMissing):
		http.Error(w, `{"error":"not_found","error_description":"Group or user no longer exists"}`, 404)
	default:
		writeAppRegistryError(w, err)
	}
}
func (h *AdminHandler) ListEnrollmentPolicies(w http.ResponseWriter, r *http.Request) {
	p, err := h.store.ListEnrollmentPolicies()
	if groupID := r.URL.Query().Get("groupId"); groupID != "" {
		var policy store.EnrollmentPolicy
		policy, err = h.store.GroupEnrollmentPolicy(groupID)
		p = []store.EnrollmentPolicy{policy}
	}
	if err != nil {
		enrollmentError(w, err)
		return
	}
	writeGroupJSON(w, map[string]any{"policies": p})
}
func readEnrollmentPolicy(r *http.Request) (store.EnrollmentPolicy, error) {
	var req struct {
		Scope          string   `json:"scope"`
		Required       *bool    `json:"required"`
		AllowedMethods []string `json:"allowedMethods"`
		GraceSeconds   *int64   `json:"graceSeconds"`
		Revision       int      `json:"revision"`
	}
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&req); err != nil || d.Decode(new(any)) != io.EOF || req.Required == nil || req.GraceSeconds == nil {
		return store.EnrollmentPolicy{}, store.ErrEnrollmentPolicy
	}
	p := store.EnrollmentPolicy{Scope: req.Scope, Required: *req.Required, AllowedMethods: req.AllowedMethods, GraceSeconds: *req.GraceSeconds, Revision: req.Revision}
	if !p.Valid() {
		return p, store.ErrEnrollmentPolicy
	}
	return p, nil
}

// Rejected writes have rolled back their success audit, so record the denial separately.
func (h *AdminHandler) enrollmentDenied(w http.ResponseWriter, r *http.Request, action, scope string, err error) {
	if scope != "organization" && scope != "administrators" {
		valid := false
		if strings.HasPrefix(scope, "group:") && len(scope) <= 512 {
			_, lookupErr := h.store.GroupEnrollmentPolicy(strings.TrimPrefix(scope, "group:"))
			valid = lookupErr == nil
		}
		if !valid {
			scope = ""
		}
	}
	reason := "storage_error"
	switch {
	case errors.Is(err, store.ErrEnrollmentPolicy):
		reason = "invalid_policy"
	case errors.Is(err, store.ErrEmergencyAdministrator):
		reason = "compliant_admin_required"
	case errors.Is(err, store.ErrAppLinkConflict):
		reason = "revision_conflict"
	}
	u := GetUserFromContext(r.Context())
	if auditErr := h.audit.Record(action, u.ID, u.Username, scope, "enrollment_policy", h.middleware.ClientIP(r), r.UserAgent(), "denied", map[string]any{"reason": reason}); auditErr != nil {
		stepUpInternalError(w)
		return
	}
	enrollmentError(w, err)
}

func (h *AdminHandler) PreviewEnrollmentPolicy(w http.ResponseWriter, r *http.Request) {
	p, err := readEnrollmentPolicy(r)
	if err != nil {
		h.enrollmentDenied(w, r, "admin.mfa_enrollment_policy_previewed", p.Scope, err)
		return
	}
	preview, err := h.store.PreviewEnrollmentPolicy(p, GetSessionFromContext(r.Context()).ID)
	if err != nil {
		h.enrollmentDenied(w, r, "admin.mfa_enrollment_policy_previewed", p.Scope, err)
		return
	}
	u := GetUserFromContext(r.Context())
	if err := h.audit.Record("admin.mfa_enrollment_policy_previewed", u.ID, u.Username, p.Scope, "enrollment_policy", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"policy": p, "impact": preview}); err != nil {
		stepUpInternalError(w)
		return
	}
	writeGroupJSON(w, preview)
}
func (h *AdminHandler) SetEnrollmentPolicy(w http.ResponseWriter, r *http.Request) {
	p, err := readEnrollmentPolicy(r)
	if err != nil {
		h.enrollmentDenied(w, r, "admin.mfa_enrollment_policy_changed", p.Scope, err)
		return
	}
	u := GetUserFromContext(r.Context())
	event := h.audit.Prepare("admin.mfa_enrollment_policy_changed", u.ID, u.Username, p.Scope, "enrollment_policy", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	if err = h.store.SetEnrollmentPolicy(p, GetSessionFromContext(r.Context()).ID, event.Row); err != nil {
		h.enrollmentDenied(w, r, "admin.mfa_enrollment_policy_changed", p.Scope, err)
		return
	}
	event.Committed()
	writeGroupJSON(w, map[string]bool{"success": true})
}

// Restricted sessions may only inspect their identity, enroll a replacement factor,
// obtain an operation-bound enrollment grant, or leave. Authorization is gated separately.
func enrollmentRouteAllowed(method, path string) bool {
	switch method + " " + path {
	case "GET /api/auth/me", "POST /api/auth/logout", "GET /api/user/devices", "GET /api/user/passkeys",
		"GET /api/auth/step-up/methods", "POST /api/auth/step-up", "POST /api/auth/step-up/finish", "POST /api/auth/step-up/cancel",
		"POST /api/user/devices/pairing-token", "POST /api/user/mfa/totp/setup", "POST /api/user/mfa/totp/enable",
		"POST /api/user/passkeys/register/begin", "POST /api/user/passkeys/register/finish":
		return true
	}
	return false
}
func enrollmentOperationAllowed(operation string) bool {
	switch operation {
	case "POST /api/user/mfa/totp/enable", "POST /api/user/passkeys/register/finish", "POST /api/user/devices/pairing-token":
		return true
	}
	return false
}
