package api

import (
	"context"
	"net/http"
	"slices"

	"github.com/Busness-app/kysignon-server/internal/store"
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
)

// Access is what the acting user may do right now.
type Access struct {
	Admin    bool     `json:"admin"`
	Helpdesk bool     `json:"helpdesk"`
	Auditor  bool     `json:"auditor"`
	AppOwner []string `json:"appOwner"`
}

// Any reports whether the user can open the administration area at all.
func (a Access) Any() bool {
	return a.Admin || a.Helpdesk || a.Auditor || len(a.AppOwner) > 0
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
	d, err := s.Delegations(user.ID)
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
func (s *Server) require(p permission, stepUp bool, h http.Handler) http.Handler {
	return s.middleware.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromContext(r.Context())
		a, err := accessFor(s.store, user)
		if err != nil {
			http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
			return
		}
		if !a.allows(p, r) {
			writeForbidden(w)
			return
		}
		if p.protectAdmins && !a.Admin {
			target, err := s.store.GetUserByID(r.PathValue("id"))
			if err != nil {
				http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
				return
			}
			if target != nil && target.Role == "admin" {
				writeForbidden(w)
				return
			}
			if target != nil {
				d, err := s.store.Delegations(target.ID)
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

type adminRoute struct {
	method, path string
	perm         permission
	stepUp       bool
	h            http.Handler
}
