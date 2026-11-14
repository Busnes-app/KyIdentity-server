package api

import (
	"encoding/json"
	"log"
	"net/http"
	"net/netip"
	"strings"

	"github.com/Busnes-app/ky-primitives/netallow"
	"github.com/Busnes-app/kyidentity-server/internal/audit"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// exemptNetworks is the live allowlist and the stored (admin) half it was built from.
type exemptNetworks struct {
	list   *netallow.List
	stored string
}

func (m *MiddlewareManager) combineExemptNetworks(stored string) (*netallow.List, error) {
	return netallow.Parse(m.exemptEnv + "," + stored)
}

// reloadExemptNetworks rebuilds the allowlist from the stored setting. At startup a stored
// list that cannot be read or parsed is dropped for the environment's: fewer exemptions,
// never more. Later a failed read keeps the current list; an unchanged one keeps its count.
func (m *MiddlewareManager) reloadExemptNetworks(startup bool) {
	m.exemptMu.Lock()
	defer m.exemptMu.Unlock()
	stored, err := m.store.RateLimitExemptNetworks()
	if err != nil && !startup {
		log.Printf("rate limit: exempt networks not re-read, keeping the current list: %v", err)
		return
	}
	if cur := m.exempt.Load(); err == nil && cur != nil && cur.stored == stored {
		return
	}
	var list *netallow.List
	if err == nil {
		list, err = m.combineExemptNetworks(stored)
	}
	if err != nil {
		log.Printf("[SECURITY] stored rate-limit exempt networks ignored, using RATE_LIMIT_EXEMPT_CIDRS only: %v", err)
		list, _ = m.combineExemptNetworks("") // validated at config load
		stored = ""
	}
	m.exempt.Store(&exemptNetworks{list: list, stored: stored})
}

// perIPExempt reports whether the request comes from an allowlisted office network and so
// skips per-IP limits. Only those: per-account lockouts, MFA and instance-wide budgets still
// apply. It matches ClientIP, so a forged forwarding header from an untrusted peer, or one
// prepended to a trusted proxy's chain, claims nothing.
func (m *MiddlewareManager) perIPExempt(r *http.Request) bool {
	cur := m.exempt.Load()
	if cur == nil {
		return false
	}
	addr, err := netip.ParseAddr(m.ClientIP(r))
	return err == nil && cur.list.Exempt(addr)
}

// RateLimitExemptible is RateLimit that office networks skip. Use it only for a per-IP
// limit on a sign-in route that another per-account bound still guards.
func (m *MiddlewareManager) RateLimitExemptible(bucket string, maxTokens, refillRate float64) func(http.Handler) http.Handler {
	limited := m.RateLimit(bucket, maxTokens, refillRate)
	return func(next http.Handler) http.Handler {
		guarded := limited(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if m.perIPExempt(r) {
				next.ServeHTTP(w, r)
				return
			}
			guarded.ServeHTTP(w, r)
		})
	}
}

// RateLimitNetworksHandler serves the office-network allowlist setting.
type RateLimitNetworksHandler struct {
	store      *store.Store
	audit      *audit.Logger
	middleware *MiddlewareManager
}

func (h *RateLimitNetworksHandler) status() map[string]any {
	out := map[string]any{"networks": "", "environment": h.middleware.exemptEnv, "exempted": uint64(0)}
	if cur := h.middleware.exempt.Load(); cur != nil {
		out["networks"], out["exempted"] = cur.stored, cur.list.Exempted()
	}
	return out
}

func (h *RateLimitNetworksHandler) Get(w http.ResponseWriter, r *http.Request) {
	writeGroupJSON(w, h.status())
}

// Put replaces the administrator's half of the list; the environment's is not editable
// here. It takes effect at once and the exempted count restarts.
func (h *RateLimitNetworksHandler) Put(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Networks *string `json:"networks"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.Networks == nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", `Send {"networks":"..."}`)
		return
	}
	own, err := netallow.Parse(*req.Networks)
	var combined *netallow.List
	if err == nil {
		combined, err = h.middleware.combineExemptNetworks(own.String())
	}
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", strings.TrimPrefix(err.Error(), "netallow: "))
		return
	}
	m := h.middleware
	m.exemptMu.Lock()
	defer m.exemptMu.Unlock()
	old, err := h.store.RateLimitExemptNetworks()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	actor := GetUserFromContext(r.Context())
	event := h.audit.Prepare("admin.rate_limit_networks_configured", actor.ID, actor.Username, "rate_limit_networks", "settings", m.ClientIP(r), r.UserAgent(), "success",
		map[string]any{"old": old, "new": own.String()})
	if err := h.store.SetRateLimitExemptNetworks(own.String(), event.Row); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	event.Committed()
	m.exempt.Store(&exemptNetworks{list: combined, stored: own.String()})
	writeGroupJSON(w, h.status())
}
