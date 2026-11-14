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

// officeBudget is what all listed office networks together may spend each minute, as a
// burst of the same size, on one per-IP limit before their requests meet that limit again.
// It keeps one host inside an office from making unbounded attempts. Sized against what
// the exempted routes can create: 300 a minute for the 15-minute lockout window is 4,500
// of the 100,000 limiter buckets (sign-ins by unknown names create none, and lockout rows
// exist only for real accounts and are never evicted), and 300 a minute for the 5-minute
// life of a pending authorization is 1,500 of the 10,000 the instance holds, below the
// 9,999 at which unowned ones start being reclaimed.
const officeBudget = 300

// officeIP reports whether the request comes from a listed office network. It matches
// ClientIP, so a forged forwarding header from an untrusted peer, or one prepended to a
// trusted proxy's chain, claims nothing.
func (m *MiddlewareManager) officeIP(r *http.Request) (netip.Addr, *netallow.List, bool) {
	cur := m.exempt.Load()
	if cur == nil {
		return netip.Addr{}, nil, false
	}
	addr, err := netip.ParseAddr(m.ClientIP(r))
	return addr, cur.list, err == nil && cur.list.Contains(addr)
}

// allowPerIP is allowRateLimit for a limit keyed only on the client address. A request from
// a listed office network draws on the shared office budget for bucket instead, and on its
// own per-IP bucket once that is spent. The office bucket goes through allowRateLimit, so
// with replicas it is one database bucket all of them spend from. Only per-IP limits come
// here: per-account lockouts, MFA and instance-wide budgets still apply.
func (m *MiddlewareManager) allowPerIP(r *http.Request, bucket string, maxTokens, refillRate float64) bool {
	if addr, list, ok := m.officeIP(r); ok && m.allowRateLimit(bucket+":office", officeBudget, officeBudget/60.0) {
		list.Exempt(addr) // counted only when the per-IP limit was actually skipped
		return true
	}
	return m.allowRateLimit(bucket+":"+m.rateLimitIP(r), maxTokens, refillRate)
}

// RateLimitExemptible is RateLimit through allowPerIP. Use it only for a per-IP limit on
// a sign-in route that a per-account or per-token bound, reserved before the proof is
// checked, still guards.
func (m *MiddlewareManager) RateLimitExemptible(bucket string, maxTokens, refillRate float64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !m.allowPerIP(r, bucket, maxTokens, refillRate) {
				http.Error(w, `{"error":"rate_limit_exceeded","error_description":"Too many requests"}`, http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
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
