package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/Busness-app/kysignon-server/internal/audit"
	"github.com/Busness-app/kysignon-server/internal/store"
)

// SessionHandler lists and revokes browser sessions and per-app token grants. Revocation
// deliberately needs no step-up: shrinking access is the incident-response action a
// possibly-compromised operator must still be able to take quickly.
type SessionHandler struct {
	store      *store.Store
	audit      *audit.Logger
	middleware *MiddlewareManager
}

func NewSessionHandler(s *store.Store, audit *audit.Logger, mm *MiddlewareManager) *SessionHandler {
	return &SessionHandler{store: s, audit: audit, middleware: mm}
}

type sessionView struct {
	ID           string    `json:"id"`
	Current      bool      `json:"current"`
	IPAddress    string    `json:"ipAddress"`
	UserAgent    string    `json:"userAgent"`
	FactorMethod string    `json:"factorMethod"`
	CreatedAt    time.Time `json:"createdAt"`
	LastActiveAt time.Time `json:"lastActiveAt"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

// writeInventory renders a user's live browser sessions and the apps holding live tokens.
// App entries come from the token registry, not from the apps themselves, so they are
// not a complete inventory of downstream app sessions.
func (h *SessionHandler) writeInventory(w http.ResponseWriter, userID, currentSessionID string) {
	sessions, err := h.store.ListUserSessions(userID, h.middleware.sessionIdleTTL)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	apps, err := h.store.ListUserAppGrants(userID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	deliveries, err := h.store.ListLogoutDeliveries(userID, 50)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	logouts := make([]logoutDeliveryView, 0, len(deliveries))
	for _, d := range deliveries {
		logouts = append(logouts, logoutDeliveryView{ID: d.ID, ClientID: d.ClientID, ClientName: d.ClientName, Status: d.Status, Attempts: d.Attempts, LastError: d.LastError, NextAttemptAt: d.NextAttemptAt, UpdatedAt: d.UpdatedAt})
	}
	views := make([]sessionView, 0, len(sessions))
	for _, s := range sessions {
		views = append(views, sessionView{
			ID: s.ID, Current: s.ID == currentSessionID, IPAddress: s.IPAddress, UserAgent: s.UserAgent,
			FactorMethod: s.FactorMethod, CreatedAt: s.CreatedAt, LastActiveAt: s.LastActiveAt, ExpiresAt: s.ExpiresAt,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"sessions": views, "apps": apps, "logouts": logouts})
}

// logoutDeliveryView is one back-channel logout owed to an app: what the app was told, or not.
type logoutDeliveryView struct {
	ID            string    `json:"id"`
	ClientID      string    `json:"clientId"`
	ClientName    string    `json:"clientName"`
	Status        string    `json:"status"`
	Attempts      int       `json:"attempts"`
	LastError     string    `json:"lastError"`
	NextAttemptAt time.Time `json:"nextAttemptAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

// AdminRetryLogout makes a stuck back-channel logout due again with a fresh attempt budget.
func (h *SessionHandler) AdminRetryLogout(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	userID, id := r.PathValue("id"), r.PathValue("deliveryId")
	pending := h.audit.Prepare("admin.logout_retry", admin.ID, admin.Username, userID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"deliveryId": id})
	found, err := h.store.RetryLogoutDeliveryNow(userID, id, pending.Row)
	if err != nil {
		log.Printf("logout retry failed: %v", err)
		stepUpInternalError(w)
		return
	}
	if !found {
		http.Error(w, `{"error":"delivery_not_found"}`, http.StatusNotFound)
		return
	}
	pending.Committed()
	writeSuccess(w)
}

func (h *SessionHandler) ListOwn(w http.ResponseWriter, r *http.Request) {
	h.writeInventory(w, GetUserFromContext(r.Context()).ID, GetSessionFromContext(r.Context()).ID)
}

// RevokeOwn signs out one of the caller's sessions. Revoking the current one also clears
// the browser's cookies so the client does not keep presenting a dead credential.
func (h *SessionHandler) RevokeOwn(w http.ResponseWriter, r *http.Request) {
	user, sess := GetUserFromContext(r.Context()), GetSessionFromContext(r.Context())
	target := r.PathValue("id")
	pending := h.audit.Prepare("user.session_revoked", user.ID, user.Username, target, "session", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"current": target == sess.ID})
	if !h.revoke(w, r, pending, func() error { return h.store.RevokeSession(user.ID, target, pending.Row) }) {
		return
	}
	if target == sess.ID {
		clearSessionCookies(w)
	}
	writeSuccess(w)
}

func (h *SessionHandler) RevokeOthers(w http.ResponseWriter, r *http.Request) {
	user, sess := GetUserFromContext(r.Context()), GetSessionFromContext(r.Context())
	pending := h.audit.Prepare("user.other_sessions_revoked", user.ID, user.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	if h.revoke(w, r, pending, func() error { return h.store.RevokeOtherSessions(user.ID, sess.ID, pending.Row) }) {
		writeSuccess(w)
	}
}

func (h *SessionHandler) AdminList(w http.ResponseWriter, r *http.Request) {
	if !h.userExists(w, r.PathValue("id")) {
		return
	}
	h.writeInventory(w, r.PathValue("id"), "")
}

func (h *SessionHandler) AdminRevokeSession(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	userID, target := r.PathValue("id"), r.PathValue("sid")
	pending := h.audit.Prepare("admin.session_revoked", admin.ID, admin.Username, target, "session", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"userId": userID})
	if h.revoke(w, r, pending, func() error { return h.store.RevokeSession(userID, target, pending.Row) }) {
		writeSuccess(w)
	}
}

func (h *SessionHandler) AdminRevokeApp(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	userID, clientID := r.PathValue("id"), r.PathValue("clientId")
	if !h.userExists(w, userID) {
		return
	}
	pending := h.audit.Prepare("admin.app_access_revoked", admin.ID, admin.Username, userID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"clientId": clientID})
	if h.revoke(w, r, pending, func() error { return h.store.RevokeUserClientAccess(userID, clientID, pending.Row) }) {
		writeSuccess(w)
	}
}

// revoke runs a transactional revocation and reports it honestly: a failure must never
// read as success, because the operator stops looking once it does.
func (h *SessionHandler) revoke(w http.ResponseWriter, r *http.Request, pending *audit.Pending, fn func() error) bool {
	err := fn()
	if err == nil {
		pending.Committed()
		return true
	}
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, `{"error":"session_not_found"}`, http.StatusNotFound)
		return false
	}
	log.Printf("%s failed: %v", pending.Row.Action, err)
	h.audit.Record(pending.Row.Action, pending.Row.ActorID, pending.Row.ActorUsername, pending.Row.TargetID, pending.Row.TargetType, pending.Row.IPAddress, pending.Row.UserAgent, "failure", map[string]any{"error": err.Error()})
	http.Error(w, `{"error":"internal_error","error_description":"Revocation failed; access may still be active"}`, http.StatusInternalServerError)
	return false
}

func (h *SessionHandler) userExists(w http.ResponseWriter, userID string) bool {
	u, err := h.store.GetUserByID(userID)
	if err != nil || u == nil {
		http.Error(w, `{"error":"user_not_found"}`, http.StatusNotFound)
		return false
	}
	return true
}

func writeSuccess(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// clearSessionCookies expires both the session cookie and its CSRF pair.
func clearSessionCookies(w http.ResponseWriter) {
	for _, name := range []string{"kysignon_session", "kysignon_csrf"} {
		http.SetCookie(w, &http.Cookie{
			Name: name, Value: "", Path: "/", Expires: time.Unix(0, 0), MaxAge: -1,
			SameSite: http.SameSiteLaxMode, HttpOnly: name == "kysignon_session",
		})
	}
}
