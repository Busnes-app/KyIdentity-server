package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/audit"
	"github.com/Busnes-app/kyidentity-server/internal/auth"
	"github.com/Busnes-app/kyidentity-server/internal/mail"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// Account links: activation for invited accounts, reset for forgotten passwords. A GET
// on the link only opens the SPA form; only the POST below spends the token, so a mail
// scanner that follows the link cannot consume it.
const (
	ActivationTTL = 24 * time.Hour
	ResetTTL      = 30 * time.Minute
)

// OnboardingHandler owns activation, password reset, password change and mail settings.
type OnboardingHandler struct {
	store         *store.Store
	audit         *audit.Logger
	middleware    *MiddlewareManager
	issuerURL     string
	encryptionKey []byte
}

func NewOnboardingHandler(s *store.Store, audit *audit.Logger, mm *MiddlewareManager, issuerURL string, encryptionKey []byte) *OnboardingHandler {
	return &OnboardingHandler{store: s, audit: audit, middleware: mm, issuerURL: issuerURL, encryptionKey: encryptionKey}
}

func (h *OnboardingHandler) link(kind, raw string) string {
	path := "/reset"
	if kind == "activation" {
		path = "/activate"
	}
	return h.issuerURL + path + "?token=" + raw
}

// issue mints a link for userID and delivers it: by mail when asked and configured,
// otherwise it is returned for the administrator to hand over. The raw link is never
// written to the audit log.
func (h *OnboardingHandler) issue(r *http.Request, actor *store.User, u *store.User, kind string, send bool) (map[string]any, error) {
	ttl := ResetTTL
	if kind == "activation" {
		ttl = ActivationTTL
	}
	var settings *mail.Settings
	if send {
		var err error
		if settings, err = mail.Load(h.store, h.encryptionKey); err != nil {
			return nil, err
		}
		if settings == nil {
			return nil, errMailNotConfigured
		}
	}
	delivery := "manual"
	if settings != nil {
		delivery = "email"
	}
	pending := h.audit.Prepare("admin.account_link_issued", actor.ID, actor.Username, u.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"kind": kind, "delivery": delivery})
	raw, err := h.store.IssueAccountToken(u.ID, kind, delivery, ttl, pending.Row)
	if err != nil {
		return nil, err
	}
	pending.Committed()
	out := map[string]any{"kind": kind, "delivery": delivery, "expiresAt": time.Now().UTC().Add(ttl)}
	if settings == nil {
		out["link"] = h.link(kind, raw)
		return out, nil
	}
	if err := settings.Send(u.Email, h.subject(kind), h.body(u, kind, raw)); err != nil {
		h.audit.Record("admin.account_link_delivery", actor.ID, actor.Username, u.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "failure", map[string]any{"kind": kind, "error": err.Error()})
		return nil, errMailFailed
	}
	return out, nil
}

var (
	errMailNotConfigured = errors.New("mail delivery is not configured")
	errMailFailed        = errors.New("mail delivery failed")
)

func (h *OnboardingHandler) subject(kind string) string {
	if kind == "activation" {
		return "Activate your account"
	}
	return "Reset your password"
}

func (h *OnboardingHandler) body(u *store.User, kind, raw string) string {
	if kind == "activation" {
		return "Hello " + u.DisplayName + ",\r\n\r\nAn account named " + u.Username + " was created for you. Open this link within 24 hours to choose a password:\r\n\r\n" + h.link(kind, raw) + "\r\n\r\nIf you did not expect this, ignore this message.\r\n"
	}
	return "Hello " + u.DisplayName + ",\r\n\r\nA password reset was requested for " + u.Username + ". Open this link within 30 minutes to choose a new password:\r\n\r\n" + h.link(kind, raw) + "\r\n\r\nIf you did not request this, ignore this message; your password is unchanged.\r\n"
}

// AdminIssueLink mints an activation link (pending accounts) or a reset link (active
// accounts) at POST /api/admin/users/{id}/activation-link or /reset-link.
func (h *OnboardingHandler) AdminIssueLink(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		admin := GetUserFromContext(r.Context())
		u, err := h.store.GetUserByID(r.PathValue("id"))
		if err != nil || u == nil {
			http.Error(w, `{"error":"user_not_found"}`, http.StatusNotFound)
			return
		}
		var req struct {
			Send bool `json:"send"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		out, err := h.issue(r, admin, u, kind, req.Send)
		switch {
		case errors.Is(err, store.ErrNotFound):
			http.Error(w, `{"error":"link_not_applicable","error_description":"Activation links are for pending accounts and reset links for active ones"}`, http.StatusConflict)
		case errors.Is(err, errMailNotConfigured):
			http.Error(w, `{"error":"mail_not_configured"}`, http.StatusBadRequest)
		case errors.Is(err, errMailFailed):
			http.Error(w, `{"error":"mail_failed","error_description":"The link was issued but could not be sent; check Mail delivery and issue it again"}`, http.StatusBadGateway)
		case err != nil:
			log.Printf("issue %s link: %v", kind, err)
			http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		default:
			writeGroupJSON(w, out)
		}
	}
}

// Redeem spends a link and sets the password: POST /api/auth/activate and
// POST /api/auth/password/reset. Every failure is the same generic answer.
func (h *OnboardingHandler) Redeem(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Token    string `json:"token"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" || req.Password == "" {
			http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
			return
		}
		hash, err := auth.HashPassword(req.Password)
		if err != nil {
			http.Error(w, `{"error":"password_policy","error_description":"`+err.Error()+`"}`, http.StatusBadRequest)
			return
		}
		action := "auth.password_reset"
		if kind == "activation" {
			action = "auth.account_activated"
		}
		pending := h.audit.Prepare(action, "", "", "", "user", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"kind": kind})
		u, err := h.store.RedeemAccountToken(req.Token, kind, hash, pending.Row)
		if errors.Is(err, store.ErrNotFound) {
			h.audit.Record(action, "", "", "", "user", h.middleware.ClientIP(r), r.UserAgent(), "failure", map[string]any{"kind": kind, "reason": "invalid_link"})
			http.Error(w, `{"error":"invalid_link","error_description":"This link is no longer valid. Ask for a new one."}`, http.StatusBadRequest)
			return
		}
		if err != nil {
			log.Printf("redeem %s link: %v", kind, err)
			http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
			return
		}
		pending.Row.ActorID, pending.Row.ActorUsername, pending.Row.TargetID = u.ID, u.Username, u.ID
		pending.Committed()
		writeGroupJSON(w, map[string]any{"success": true, "username": u.Username})
	}
}

// Forgot starts a reset: POST /api/auth/password/forgot. The answer never says whether
// the account exists or mail is configured; per-IP and per-account limits bound abuse.
func (h *OnboardingHandler) Forgot(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Identifier string `json:"identifier"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Identifier) == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	generic := func() { writeGroupJSON(w, map[string]any{"success": true}) }
	id := strings.TrimSpace(req.Identifier)
	u, err := h.store.GetUserByUsername(id)
	if err == nil && u == nil && strings.Contains(id, "@") {
		u, err = h.store.GetUserByEmail(id)
	}
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if u == nil || u.Status != "active" || u.Pending {
		generic()
		return
	}
	if !h.middleware.allowRateLimit("reset:"+u.ID, 3, 1.0/3600) {
		h.audit.Record("auth.password_reset_requested", u.ID, u.Username, u.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "denied", map[string]any{"reason": "rate_limited"})
		generic()
		return
	}
	settings, err := mail.Load(h.store, h.encryptionKey)
	if err != nil || settings == nil {
		h.audit.Record("auth.password_reset_requested", u.ID, u.Username, u.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "failure", map[string]any{"reason": "mail_not_configured"})
		generic()
		return
	}
	pending := h.audit.Prepare("auth.password_reset_requested", u.ID, u.Username, u.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"delivery": "email"})
	raw, err := h.store.IssueAccountToken(u.ID, "reset", "email", ResetTTL, pending.Row)
	if err != nil {
		log.Printf("password reset for %s: %v", u.ID, err)
		generic()
		return
	}
	pending.Committed()
	// The answer goes out before the relay is contacted, so response time is the same
	// for an account that exists and one that does not.
	generic()
	ip, ua := h.middleware.ClientIP(r), r.UserAgent()
	go func() {
		if err := settings.Send(u.Email, h.subject("reset"), h.body(u, "reset", raw)); err != nil {
			h.audit.Record("auth.password_reset_delivery", u.ID, u.Username, u.ID, "user", ip, ua, "failure", map[string]any{"error": err.Error()})
		}
	}()
}

// ChangePassword is the signed-in path: current password plus a step-up grant, then every
// other session and grant ends. POST /api/user/password.
func (h *OnboardingHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	user, sess := GetUserFromContext(r.Context()), GetSessionFromContext(r.Context())
	var req struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CurrentPassword == "" || req.NewPassword == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	ok, err := auth.VerifyPassword(req.CurrentPassword, user.PasswordHash)
	if err != nil || !ok {
		h.audit.Record("user.password_changed", user.ID, user.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "failure", map[string]any{"reason": "invalid_password"})
		http.Error(w, `{"error":"invalid_credentials","error_description":"Current password is incorrect"}`, http.StatusUnauthorized)
		return
	}
	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		http.Error(w, `{"error":"password_policy","error_description":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}
	pending := h.audit.Prepare("user.password_changed", user.ID, user.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	if err := h.store.ChangePassword(user.ID, sess.ID, hash, pending.Row); err != nil {
		log.Printf("password change for %s: %v", user.ID, err)
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	pending.Committed()
	writeSuccess(w)
}

// Mail settings: GET returns everything but the password; PUT stores (blank password
// keeps the stored one, blank host clears delivery); POST test sends to the caller.
func (h *OnboardingHandler) GetMail(w http.ResponseWriter, r *http.Request) {
	settings, err := mail.Load(h.store, h.encryptionKey)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	writeGroupJSON(w, settings.View())
}

func (h *OnboardingHandler) PutMail(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	var req mail.Settings
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Host) == "" {
		if err := mail.Clear(h.store); err != nil {
			http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
			return
		}
		h.audit.Record("admin.mail_configured", admin.ID, admin.Username, "mail", "settings", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"configured": false})
		writeGroupJSON(w, (*mail.Settings)(nil).View())
		return
	}
	if err := mail.Save(h.store, h.encryptionKey, &req); err != nil {
		http.Error(w, `{"error":"invalid_request","error_description":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}
	h.audit.Record("admin.mail_configured", admin.ID, admin.Username, "mail", "settings", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"configured": true, "host": req.Host, "port": req.Port, "security": req.Security})
	writeGroupJSON(w, req.View())
}

func (h *OnboardingHandler) TestMail(w http.ResponseWriter, r *http.Request) {
	admin := GetUserFromContext(r.Context())
	settings, err := mail.Load(h.store, h.encryptionKey)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if settings == nil {
		http.Error(w, `{"error":"mail_not_configured"}`, http.StatusBadRequest)
		return
	}
	err = settings.Send(admin.Email, "KySignOn mail test", "This message confirms that KySignOn can send mail.\r\n")
	outcome, details := "success", map[string]any{"to": admin.Email}
	if err != nil {
		outcome, details["error"] = "failure", err.Error()
	}
	h.audit.Record("admin.mail_tested", admin.ID, admin.Username, "mail", "settings", h.middleware.ClientIP(r), r.UserAgent(), outcome, details)
	if err != nil {
		http.Error(w, `{"error":"mail_failed","error_description":"`+strings.ReplaceAll(err.Error(), `"`, "'")+`"}`, http.StatusBadGateway)
		return
	}
	writeSuccess(w)
}
