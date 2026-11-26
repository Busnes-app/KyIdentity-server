package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"

	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// Delegated administration. Every admin route names one fixed permission; the acting
// user's access is computed on each request from the users row and the delegation
// rows, never cached in the session, so a demotion or a removed delegation takes
// effect on the next call. Global administrators hold every permission. Nobody else
// can change delegations, global policy, connector secrets, recovery material or
// OAuth credentials, whatever they own.
type permission struct {
	name string
	// auditor: read-only routes an auditor may call.
	auditor bool
	// helpdesk: account recovery on ordinary users.
	helpdesk bool
	// appOwner: routes whose {id} is an app record the owner holds.
	appOwner bool
	// anyOwner: directory reads an owner needs to pick principals.
	anyOwner bool
	// protectAdmins: {id} names a user; only a global admin may act on an administrator
	// or on anyone holding a delegation, since recovering such an account inherits it.
	protectAdmins bool
}

var (
	permAdmin     = permission{name: "admin"}
	permRead      = permission{name: "read", auditor: true}
	permDirectory = permission{name: "directory", auditor: true, helpdesk: true, anyOwner: true}
	permUserRead  = permission{name: "user_read", auditor: true, helpdesk: true, protectAdmins: true}
	permRecovery  = permission{name: "recovery", helpdesk: true, protectAdmins: true}
	permAppRead   = permission{name: "app_read", auditor: true, appOwner: true}
	permAppGrants = permission{name: "app_grants", appOwner: true}
	// requests: the inbox and decisions; the store narrows an owner to their apps.
	permRequests = permission{name: "requests", anyOwner: true}
)

// Access is what the acting user may do right now.
type Access struct {
	Admin    bool     `json:"admin"`
	Helpdesk bool     `json:"helpdesk"`
	Auditor  bool     `json:"auditor"`
	AppOwner []string `json:"appOwner"`
}

func (a Access) allows(p permission, r *http.Request) bool {
	switch {
	case a.Admin:
		return true
	case p.auditor && a.Auditor, p.helpdesk && a.Helpdesk:
		return true
	case p.appOwner && slices.Contains(a.AppOwner, r.PathValue("id")):
		return true
	case p.anyOwner && len(a.AppOwner) > 0:
		return true
	}
	return false
}

func accessFor(s *store.Store, user *store.User) (Access, error) {
	if user.Role == "admin" {
		return Access{Admin: true, AppOwner: []string{}}, nil
	}
	d, err := s.Org(user.Org()).Delegations(user.ID)
	if err != nil {
		return Access{}, err
	}
	return Access{Helpdesk: d.Helpdesk, Auditor: d.Auditor, AppOwner: d.AppOwner}, nil
}

const accessContextKey contextKey = "access"

func accessFromContext(ctx context.Context) Access {
	a, _ := ctx.Value(accessContextKey).(Access)
	return a
}

func writeForbidden(w http.ResponseWriter) {
	http.Error(w, `{"error":"forbidden","error_description":"Administrator access required"}`, http.StatusForbidden)
}

// require gates an admin route on a permission, then optionally on a step-up grant.
// Authorization runs before the grant is spent: a forbidden call must not consume one.
func (s *Server) require(p permission, scope routeScope, stepUp bool, h http.Handler) http.Handler {
	return s.middleware.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromContext(r.Context())
		a, err := accessFor(s.store, user)
		if err != nil {
			http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
			return
		}
		if !a.allows(p, r) || scope == platformRoute && s.cfg.Tenancy == "multi" && !a.Admin {
			writeForbidden(w)
			return
		}
		if s.cfg.Tenancy == "multi" {
			var ok bool
			if r, ok = s.staffOrgRequest(w, r, user, scope); !ok {
				return
			}
		}
		if p.protectAdmins && !a.Admin {
			target, err := orgStore(r).GetUserByID(r.PathValue("id"))
			if err != nil {
				http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
				return
			}
			if target != nil && target.Role == "admin" {
				writeForbidden(w)
				return
			}
			if target != nil {
				d, err := orgStore(r).Delegations(target.ID)
				if err != nil {
					http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
					return
				}
				if d.Helpdesk || d.Auditor || len(d.AppOwner) > 0 {
					writeForbidden(w)
					return
				}
			}
		}
		r = r.WithContext(context.WithValue(r.Context(), accessContextKey, a))
		if stepUp {
			s.requireStepUp(h).ServeHTTP(w, r)
			return
		}
		h.ServeHTTP(w, r)
	}))
}

// routeScope says which store an admin route works on (tenancy design, "Route classes").
// Every route names one: the zero value is refused when the routes are registered.
type routeScope int

const (
	// orgRoute works on one org's directory: in a multi-tenant install the org staff
	// selected (X-Ky-Org), else the caller's own.
	orgRoute routeScope = iota + 1
	// staffOrgRoute is org-scoped. In multi-tenant mode it requires selecting the staff org.
	staffOrgRoute
	// platformRoute changes what every org shares: apps, policies, settings. In a
	// multi-tenant install only global administrators may call it. Single-tenant: no change.
	platformRoute
	// crossOrgRoute reads across orgs for staff (the org finder) with no OrgStore of its
	// own; multi-tenant only, every route of the class answers 404 in a single-tenant install.
	crossOrgRoute
)

// OrgHeader names the org a staff member works in on an org route (multi-tenant).
const OrgHeader = "X-Ky-Org"

const staffCustomerOrgKey contextKey = "staffCustomerOrg"

// staffCustomerOrg reports a customer org selected by an authorised staff request.
func staffCustomerOrg(r *http.Request) bool {
	customer, _ := r.Context().Value(staffCustomerOrgKey).(bool)
	return customer
}

func staffReadDetails(r *http.Request) string {
	details, _ := json.Marshal(map[string]string{"route": r.Method + " " + r.Pattern, "path": r.URL.Path})
	return string(details)
}

// staffOrgRequest runs once require has found an admin principal in a multi-tenant
// install. The caller must be in the staff org. An org route then needs X-Ky-Org naming a
// live customer org or the staff org (400 org_required, 404 unknown_org), and the request's
// OrgStore is bound to it. A read on it is audited staff.read in that org's log.
func (s *Server) staffOrgRequest(w http.ResponseWriter, r *http.Request, user *store.User, scope routeScope) (*http.Request, bool) {
	staff, err := s.store.IsStaffOrg(user.Org())
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return r, false
	}
	if !staff {
		writeForbidden(w)
		return r, false
	}
	if scope != orgRoute && scope != staffOrgRoute {
		return r, true
	}
	raw := r.Header.Get(OrgHeader)
	if raw == "" {
		writeAPIError(w, http.StatusBadRequest, "org_required", "Select an organisation.")
		return r, false
	}
	org, customer, err := s.store.StaffOrg(raw)
	if errors.Is(err, store.ErrNotFound) {
		writeAPIError(w, http.StatusNotFound, "unknown_org", "No such organisation.")
		return r, false
	}
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return r, false
	}
	if scope == staffOrgRoute && customer {
		writeAPIError(w, http.StatusForbidden, "customer_credentials_protected", "Staff cannot configure inbound provisioning or issue connector tokens for a customer organisation.")
		return r, false
	}
	o := s.store.Org(org)
	if r.Method == http.MethodGet {
		if err := o.RecordStaffRead(&store.AuditEvent{ActorID: user.ID, ActorUsername: user.Username, Action: "staff.read", TargetID: org.String(), TargetType: "org",
			IPAddress: s.middleware.ClientIP(r), UserAgent: r.UserAgent(), Outcome: "success", DetailsJSON: staffReadDetails(r)}); err != nil {
			http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
			return r, false
		}
	}
	ctx := context.WithValue(r.Context(), orgContextKey, o)
	return r.WithContext(context.WithValue(ctx, staffCustomerOrgKey, customer)), true
}

type adminRoute struct {
	method, path string
	perm         permission
	scope        routeScope
	stepUp       bool
	h            http.Handler
}
