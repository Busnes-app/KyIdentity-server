package api

import (
	"context"
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Busness-app/kyidentity-server/internal/crypto"
	"github.com/Busness-app/kyidentity-server/internal/store"
)

type contextKey string

const (
	userContextKey    contextKey = "user"
	sessionContextKey contextKey = "session"
)

// limiterIdleTTL is how long an unused rate limiter bucket is kept. Without eviction the
// limiter map is an unbounded, remotely-driven allocation.
const limiterIdleTTL = 10 * time.Minute

// defaultMaxLimiters caps the bucket map so a stream of distinct clients cannot exhaust
// memory. Reaching it forces a sweep; if the sweep frees nothing, new buckets are refused
// rather than existing ones evicted.
const defaultMaxLimiters = 100_000

type MiddlewareManager struct {
	store             *store.Store
	trustedCIDRs      []*net.IPNet
	forwardedHeader   string
	rateLimiters      map[string]*RateLimiter
	rateLimitersMutex sync.Mutex
	lastSweep         time.Time
	maxLimiters       int
	csrfKey           []byte
	sessionIdleTTL    time.Duration
	// now is injectable so eviction behaviour can be tested without waiting real minutes.
	now func() time.Time
}

type RateLimiter struct {
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastRefill time.Time
	mu         sync.Mutex
}

func NewMiddlewareManager(s *store.Store, trustedCIDRs []string, forwardedHeader string, csrfKey []byte) *MiddlewareManager {
	var parsedCIDRs []*net.IPNet
	for _, cidr := range trustedCIDRs {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			parsedCIDRs = append(parsedCIDRs, ipNet)
		}
	}

	return &MiddlewareManager{
		store:           s,
		trustedCIDRs:    parsedCIDRs,
		forwardedHeader: http.CanonicalHeaderKey(strings.TrimSpace(forwardedHeader)),
		rateLimiters:    make(map[string]*RateLimiter),
		lastSweep:       time.Now(),
		maxLimiters:     defaultMaxLimiters,
		csrfKey:         csrfKey,
		sessionIdleTTL:  30 * time.Minute,
		now:             time.Now,
	}
}

// isTrustedProxy reports whether the request's immediate peer is a proxy the operator has
// named. Only such a peer's forwarding headers are believed.
func (m *MiddlewareManager) isTrustedProxy(r *http.Request) bool {
	if len(m.trustedCIDRs) == 0 {
		return false
	}
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = r.RemoteAddr
	}
	return m.isTrustedIP(net.ParseIP(remoteHost))
}

// isTrustedIP reports whether an address belongs to a configured proxy.
func (m *MiddlewareManager) isTrustedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, cidr := range m.trustedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// ClientIP returns the address the request should be attributed to.
//
// Exactly one forwarding header is honoured, and only from a configured proxy. Trying
// several headers in turn is what turns an attacker-supplied string into an identity: the
// edge overwrites the one it owns, and the attacker supplies whichever of the others the
// server happens to prefer. The value must parse as an IP, so a rate-limit bucket and an
// audit entry are always a real address rather than whatever the caller typed.
func (m *MiddlewareManager) ClientIP(r *http.Request) string {
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = r.RemoteAddr
	}

	if !m.isTrustedProxy(r) || m.forwardedHeader == "" {
		return remoteHost
	}

	// Walk the forwarded chain from the right. Everything appended by a proxy we trust is
	// skipped; the first entry that is not one of ours is the closest hop we can attribute,
	// and anything further left was written by someone we have no reason to believe.
	// A single-value header (CF-Connecting-IP, X-Real-IP) is simply a chain of length one.
	parts := strings.Split(r.Header.Get(m.forwardedHeader), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(parts[i]))
		if ip == nil {
			// A malformed entry means the chain cannot be trusted past this point.
			return remoteHost
		}
		if !m.isTrustedIP(ip) {
			return ip.String()
		}
	}
	return remoteHost
}

// IsHTTPS reports whether the request reached the user over TLS. X-Forwarded-Proto is only
// believed from a configured proxy.
func (m *MiddlewareManager) IsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if m.isTrustedProxy(r) && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return true
	}
	return false
}

// TrackedLimiters reports how many rate limit buckets are currently held.
func (m *MiddlewareManager) TrackedLimiters() int {
	m.rateLimitersMutex.Lock()
	defer m.rateLimitersMutex.Unlock()
	return len(m.rateLimiters)
}

// sweepLimiters drops buckets that carry no state worth keeping. A bucket that has fully
// refilled is indistinguishable from one that never existed, so dropping it loses nothing.
// The caller must hold rateLimitersMutex.
func (m *MiddlewareManager) sweepLimiters(now time.Time) {
	atCapacity := len(m.rateLimiters) >= m.maxLimiters
	if now.Sub(m.lastSweep) < time.Minute && !atCapacity {
		return
	}
	m.lastSweep = now

	for key, limiter := range m.rateLimiters {
		limiter.mu.Lock()
		idle := now.Sub(limiter.lastRefill)
		refilled := limiter.tokens+idle.Seconds()*limiter.refillRate >= limiter.maxTokens
		limiter.mu.Unlock()
		if idle > limiterIdleTTL || (refilled && idle > time.Minute) {
			delete(m.rateLimiters, key)
		}
	}
}

// SecurityHeaders applies security and CSP headers.
func (m *MiddlewareManager) SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/oauth/") {
			w.Header().Set("Cache-Control", "no-store")
		}

		// Content Security Policy allowing local assets, Google/local fonts, and inline styles for UI
		// Custom launcher favicons load directly in the browser. Keeping this to HTTPS images
		// avoids making the server an SSRF proxy or permitting active external content.
		csp := "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';"
		w.Header().Set("Content-Security-Policy", csp)

		next.ServeHTTP(w, r)
	})
}

// RateLimit limits requests per IP and action bucket.
func (m *MiddlewareManager) RateLimit(bucket string, maxTokens, refillRate float64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !m.allowRateLimit(bucket+":"+m.ClientIP(r), maxTokens, refillRate) {
				http.Error(w, `{"error":"rate_limit_exceeded","error_description":"Too many requests"}`, http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Protocol endpoints can reuse the same bounded limiter and send their own error.
func (m *MiddlewareManager) allowRateLimit(key string, maxTokens, refillRate float64) bool {
	now := m.now()
	m.rateLimitersMutex.Lock()
	m.sweepLimiters(now)
	limiter, exists := m.rateLimiters[key]
	if !exists {
		// Keep live buckets at capacity: evicting them would reset an attacker's allowance.
		if len(m.rateLimiters) >= m.maxLimiters {
			m.rateLimitersMutex.Unlock()
			return false
		}
		limiter = &RateLimiter{tokens: maxTokens, maxTokens: maxTokens, refillRate: refillRate, lastRefill: now}
		m.rateLimiters[key] = limiter
	}
	m.rateLimitersMutex.Unlock()
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	limiter.tokens += now.Sub(limiter.lastRefill).Seconds() * limiter.refillRate
	if limiter.tokens > limiter.maxTokens {
		limiter.tokens = limiter.maxTokens
	}
	limiter.lastRefill = now
	if limiter.tokens < 1 {
		return false
	}
	limiter.tokens--
	return true
}

// authenticate resolves the session cookie to a live session and active user, or returns
// nil. This is the single definition of "logged in"; RequireAuth and OptionalAuth both
// use it so no endpoint can accidentally apply a weaker rule.
func (m *MiddlewareManager) authenticate(r *http.Request) (*store.User, *store.Session) {
	cookie, err := r.Cookie("kyidentity_session")
	if err != nil || cookie.Value == "" {
		return nil, nil
	}

	// GetSessionByTokenHash filters on expires_at, so an expired session is never returned.
	sess, err := m.store.GetSessionByTokenHash(crypto.HashSHA256(cookie.Value), m.sessionIdleTTL)
	if err != nil || sess == nil {
		return nil, nil
	}

	user, err := m.store.GetUserByID(sess.UserID)
	if err != nil || user == nil || user.Status != "active" {
		return nil, nil
	}

	_ = m.store.TouchSession(sess.ID)
	return user, sess
}

func withIdentity(r *http.Request, user *store.User, sess *store.Session) *http.Request {
	ctx := context.WithValue(r.Context(), userContextKey, user)
	ctx = context.WithValue(ctx, sessionContextKey, sess)
	return r.WithContext(ctx)
}

// RequireAuth rejects the request unless it carries a live session.
func (m *MiddlewareManager) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, sess := m.authenticate(r)
		if user == nil {
			http.Error(w, `{"error":"unauthorized","error_description":"Authentication required"}`, http.StatusUnauthorized)
			return
		}
		status, err := m.store.SessionEnrollmentStatus(user.ID, sess.ID)
		if err != nil {
			stepUpInternalError(w)
			return
		}
		if status.Restricted && !enrollmentRouteAllowed(r.Method, r.URL.Path) {
			http.Error(w, `{"error":"enrollment_required","error_description":"Complete MFA enrollment and sign in again to continue."}`, 403)
			return
		}
		next.ServeHTTP(w, withIdentity(r, user, sess))
	})
}

// OptionalAuth attaches the identity when one is present and proceeds either way. Used by
// /oauth/authorize, which redirects anonymous callers to the login UI.
func (m *MiddlewareManager) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user, sess := m.authenticate(r); user != nil {
			r = withIdentity(r, user, sess)
		}
		next.ServeHTTP(w, r)
	})
}

// CSRFValidate enforces double-submit CSRF protection for non-GET/HEAD/OPTIONS methods.
func (m *MiddlewareManager) CSRFValidate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		// Bypass CSRF for public native push response, system registration, and OAuth token endpoints
		path := r.URL.Path
		if strings.HasPrefix(path, "/scim/v2/") || // Bearer-only machine boundary; cookies are never read there.
			path == "/api/systems/register" ||
			path == "/api/notifications/native/register" ||
			(strings.HasPrefix(path, "/api/notifications/native/devices/") && strings.HasSuffix(path, "/push-token")) ||
			path == "/api/mfa/push/respond" ||
			path == "/oauth/token" ||
			path == "/oauth/revoke" ||
			path == "/oauth/logout" { // Its same-site confirmation form carries the session-bound token in a `confirm` field, checked by EndSession; a cross-site POST has no session cookie and is bounced to a GET.
			next.ServeHTTP(w, r)
			return
		}

		csrfCookie, err := r.Cookie("kyidentity_csrf")
		if err != nil || csrfCookie.Value == "" {
			http.Error(w, `{"error":"invalid_csrf","error_description":"CSRF cookie missing"}`, http.StatusForbidden)
			return
		}

		csrfHeader := r.Header.Get("X-CSRF-Token")
		if csrfHeader == "" {
			csrfHeader = r.FormValue("csrf_token")
		}

		if subtle.ConstantTimeCompare([]byte(csrfCookie.Value), []byte(csrfHeader)) != 1 {
			http.Error(w, `{"error":"invalid_csrf","error_description":"CSRF token mismatch"}`, http.StatusForbidden)
			return
		}

		// Matching cookie and header alone proves only that the caller could set both,
		// which any sibling subdomain or network attacker able to write a cookie for this
		// domain can do. For a request that carries a session, the token must also be one
		// this server issued to that session.
		if sessionCookie, err := r.Cookie("kyidentity_session"); err == nil && sessionCookie.Value != "" {
			if !m.csrfTokenMatchesSession(sessionCookie.Value, csrfCookie.Value) {
				http.Error(w, `{"error":"invalid_csrf","error_description":"CSRF token was not issued for this session"}`, http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// IssueCSRFToken mints a CSRF token bound to a session. The token is the session-scoped
// HMAC itself, so validation needs no server-side storage and cannot be satisfied by a
// value the caller invented.
func (m *MiddlewareManager) IssueCSRFToken(sessionToken string) string {
	if sessionToken == "" {
		// Pre-login (the sign-in POST itself) there is no session to bind to. The token
		// still blocks a blind cross-site POST, which is all it can do at this point.
		random, err := crypto.GenerateRandomHex(32)
		if err != nil {
			return ""
		}
		return "u." + random
	}
	return "s." + crypto.SignHMACSHA256(m.csrfKey, []byte(crypto.HashSHA256(sessionToken)))
}

// csrfTokenMatchesSession reports whether a token was issued for this session.
func (m *MiddlewareManager) csrfTokenMatchesSession(sessionToken, csrfToken string) bool {
	expected := m.IssueCSRFToken(sessionToken)
	return expected != "" && subtle.ConstantTimeCompare([]byte(expected), []byte(csrfToken)) == 1
}

// GetUserFromContext retrieves authenticated user from context.
func GetUserFromContext(ctx context.Context) *store.User {
	if u, ok := ctx.Value(userContextKey).(*store.User); ok {
		return u
	}
	return nil
}

// GetSessionFromContext retrieves active session from context.
func GetSessionFromContext(ctx context.Context) *store.Session {
	if s, ok := ctx.Value(sessionContextKey).(*store.Session); ok {
		return s
	}
	return nil
}
