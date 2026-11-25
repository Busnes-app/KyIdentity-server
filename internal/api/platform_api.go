package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/mail"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// The platform provisioning API (tenancy design, "Platform provisioning API", build plan
// PR 4): billing and the customer portal manage customer orgs over /platform/v1 on their
// own listener, KYIDENTITY_PLATFORM_LISTEN. Nothing here is served on the public listener,
// and no browser or SCIM credential is accepted here: only a kyp_ bearer token.

// PlatformHandler is the platform listener's handler.
type PlatformHandler struct {
	store      *store.Store
	middleware *MiddlewareManager
	issuerURL  string
	// mailer returns the platform mail sender, nil when mail is not configured.
	mailer func() (func(to, subject, body string) error, error)
}

type platformTokenKey struct{}

// Failed authentications per IP: 10 at once, then one every 6 seconds.
const (
	platformFailBurst = 10
	platformFailRate  = 1.0 / 6
)

func newPlatformHandler(s *Server) http.Handler { return newPlatformAPI(s).routes() }

func newPlatformAPI(s *Server) *PlatformHandler {
	h := &PlatformHandler{store: s.store, middleware: s.middleware, issuerURL: s.cfg.IssuerURL}
	key := s.cfg.EncryptionKey
	h.mailer = func() (func(to, subject, body string) error, error) {
		settings, err := mail.Load(s.store, key)
		if err != nil || settings == nil {
			return nil, err
		}
		return settings.Send, nil
	}
	return h
}

func (h *PlatformHandler) routes() http.Handler {
	mux := http.NewServeMux()
	route := func(pattern, scope string, fn http.HandlerFunc) { mux.Handle(pattern, h.authenticate(scope, fn)) }
	route("POST /platform/v1/orgs", store.ScopeOrgsWrite, h.createOrg)
	route("GET /platform/v1/orgs", store.ScopeOrgsRead, h.listOrgs)
	route("GET /platform/v1/orgs/{id}", store.ScopeOrgsRead, h.getOrg)
	route("PATCH /platform/v1/orgs/{id}", store.ScopeOrgsWrite, h.patchOrg)
	route("POST /platform/v1/orgs/{id}/suspend", store.ScopeOrgsWrite, h.suspendOrg)
	route("POST /platform/v1/orgs/{id}/resume", store.ScopeOrgsWrite, h.resumeOrg)
	route("POST /platform/v1/orgs/{id}/schedule-deletion", store.ScopeOrgsWrite, h.scheduleDeletion)
	route("DELETE /platform/v1/orgs/{id}", store.ScopeOrgsDelete, h.deleteOrg)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { platformError(w, http.StatusNotFound, "not_found", nil) })
	return withDeadline(limitRequestBody(mux), mux, requestDeadline)
}

func platformError(w http.ResponseWriter, status int, code string, extra map[string]any) {
	body := map[string]any{"error": code}
	for k, v := range extra {
		body[k] = v
	}
	writePlatformJSON(w, status, body)
}

func writePlatformJSON(w http.ResponseWriter, status int, body any) {
	b, err := json.Marshal(body)
	if err != nil {
		status, b = http.StatusInternalServerError, []byte(`{"error":"internal_error"}`)
	}
	writePlatformRaw(w, status, b)
}

func writePlatformRaw(w http.ResponseWriter, status int, b []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// authenticate admits a live kyp_ token holding scope. Every request spends from the
// caller's IP bucket and the token's; a failed authentication also from a small per-IP
// failure bucket, so guessing is slow and a guesser is refused before the lookup.
func (h *PlatformHandler) authenticate(scope string, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := h.middleware.rateLimitIP(r)
		if !h.middleware.allowRateLimit("platform:"+ip, 300, 5) || !h.middleware.peekLocal("platform_fail:"+ip, platformFailBurst, platformFailRate) {
			platformError(w, http.StatusTooManyRequests, "rate_limited", nil)
			return
		}
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		var tok *store.PlatformToken
		var err error
		if ok {
			tok, err = h.store.Platform().AuthenticatePlatformToken(raw)
		}
		if err != nil {
			log.Printf("platform api: token lookup: %v", err)
			platformError(w, http.StatusServiceUnavailable, "unavailable", nil)
			return
		}
		if tok == nil {
			h.middleware.allowLocal("platform_fail:"+ip, platformFailBurst, platformFailRate, h.middleware.now())
			platformError(w, http.StatusUnauthorized, "invalid_token", nil)
			return
		}
		if !h.middleware.allowRateLimit("platform_token:"+tok.ID, 120, 2) {
			platformError(w, http.StatusTooManyRequests, "rate_limited", nil)
			return
		}
		if !tok.Has(scope) {
			h.observe(r, tok, r.PathValue("id"), "platform.refused", "denied", map[string]any{"error": "insufficient_scope"})
			platformError(w, http.StatusForbidden, "insufficient_scope", nil)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), platformTokenKey{}, tok)))
	})
}

func platformTokenFrom(r *http.Request) *store.PlatformToken {
	t, _ := r.Context().Value(platformTokenKey{}).(*store.PlatformToken)
	return t
}

func (h *PlatformHandler) caller(r *http.Request) store.PlatformCaller {
	return store.PlatformCaller{TokenID: platformTokenFrom(r).ID, IP: h.middleware.ClientIP(r), UserAgent: r.UserAgent()}
}

// observe audits a call the store did not: a read, a replay or a refusal. A call on one
// org goes in that org's log; a lost row is logged, as Observe does.
func (h *PlatformHandler) observe(r *http.Request, tok *store.PlatformToken, org, action, outcome string, details map[string]any) {
	b, _ := json.Marshal(details)
	e := &store.AuditEvent{ID: uuid.NewString(), ActorID: tok.ID, ActorUsername: "platform-token", Action: action, TargetID: org,
		TargetType: "org", IPAddress: h.middleware.ClientIP(r), UserAgent: r.UserAgent(), Outcome: outcome, DetailsJSON: string(b), CreatedAt: time.Now().UTC()}
	if org == "" {
		e.TargetType = ""
	}
	if err := h.store.Platform().RecordPlatformAudit(org, e); err != nil {
		log.Printf("platform api: audit %s: %v", action, err)
	}
}

// write is every POST, PATCH and DELETE: the Idempotency-Key, a strict JSON body into
// req (nil for none), and fn in the store's idempotent transaction.
func (h *PlatformHandler) write(w http.ResponseWriter, r *http.Request, req any, fn func(tx *sql.Tx, now time.Time) (int, any, error)) {
	tok := platformTokenFrom(r)
	org := r.PathValue("id")
	key := r.Header.Get("Idempotency-Key")
	if key == "" || len(key) > 128 {
		platformError(w, http.StatusBadRequest, "idempotency_key_required", nil)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		platformError(w, http.StatusRequestEntityTooLarge, "invalid_request", nil)
		return
	}
	if req != nil {
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if dec.Decode(req) != nil || dec.Decode(&struct{}{}) != io.EOF {
			h.observe(r, tok, org, "platform.refused", "denied", map[string]any{"error": "invalid_request"})
			platformError(w, http.StatusBadRequest, "invalid_request", nil)
			return
		}
	} else if len(bytes.TrimSpace(body)) != 0 {
		platformError(w, http.StatusBadRequest, "invalid_request", nil)
		return
	}
	hash := crypto.HashSHA256(r.Method + " " + r.URL.Path + "\n" + string(body))
	ans, replayed, err := h.store.Platform().PlatformWrite(tok.ID, key, hash, fn)
	if err != nil {
		status, code, extra := platformErrorFor(err)
		if status == http.StatusInternalServerError {
			log.Printf("platform api: %s %s: %v", r.Method, r.URL.Path, err)
		}
		h.observe(r, tok, org, "platform.refused", "denied", map[string]any{"error": code, "method": r.Method, "path": r.URL.Path})
		platformError(w, status, code, extra)
		return
	}
	if replayed {
		if org == "" {
			var created struct{ ID string }
			_ = json.Unmarshal(ans.Body, &created)
			org = created.ID
		}
		h.observe(r, tok, org, "platform.replayed", "success", map[string]any{"method": r.Method, "path": r.URL.Path})
	}
	writePlatformRaw(w, ans.Status, ans.Body)
}

var errMailNotReady = errors.New("mail_not_configured")

// platformErrorFor maps a store refusal to its answer.
func platformErrorFor(err error) (int, string, map[string]any) {
	var stale *store.StaleRevisionError
	var seats *store.SeatsInUseError
	var pool *store.StorageOverPoolError
	var input store.InputError
	switch {
	case errors.As(err, &stale):
		return http.StatusConflict, "stale_revision", map[string]any{"revision": stale.Current}
	case errors.As(err, &seats):
		return http.StatusConflict, "seats_in_use", map[string]any{"seats_used": seats.SeatsUsed}
	case errors.As(err, &pool):
		return http.StatusConflict, "storage_over_pool", map[string]any{"pool_bytes": pool.PoolBytes, "used_bytes": pool.UsedBytes}
	case errors.Is(err, store.ErrIdempotencyConflict):
		return http.StatusUnprocessableEntity, "idempotency_conflict", nil
	case errors.Is(err, store.ErrBillingRefConflict):
		return http.StatusConflict, "billing_ref_conflict", nil
	case errors.Is(err, store.ErrOrgState):
		return http.StatusConflict, "org_state", nil
	case errors.Is(err, store.ErrOrgErased):
		return http.StatusConflict, "org_erased", nil
	case errors.Is(err, store.ErrAccountHolder):
		return http.StatusConflict, "account_holder", nil
	case errors.Is(err, store.ErrNotFound):
		return http.StatusNotFound, "not_found", nil
	case errors.Is(err, store.ErrEmailInUse):
		return http.StatusConflict, "email_in_use", nil
	case errors.Is(err, store.ErrSeatLimit):
		return http.StatusConflict, "seat_limit", nil
	case errors.Is(err, store.ErrMailboxDomain):
		return http.StatusBadRequest, "mailbox_domain", nil
	case errors.Is(err, store.ErrInvalidHomeRegion):
		return http.StatusBadRequest, "invalid_home_region", nil
	case errors.Is(err, store.ErrInvalidMaxSeats):
		return http.StatusBadRequest, "invalid_max_seats", nil
	case errors.Is(err, store.ErrInvalidStorage):
		return http.StatusBadRequest, "invalid_storage", nil
	case errors.Is(err, store.ErrHolderNotMember):
		return http.StatusBadRequest, "invalid_account_holder", nil
	case errors.Is(err, errMailNotReady):
		return http.StatusServiceUnavailable, "mail_not_configured", nil
	case errors.As(err, &input):
		return http.StatusBadRequest, "invalid_request", map[string]any{"error_description": string(input)}
	}
	return http.StatusInternalServerError, "internal_error", nil
}

func (h *PlatformHandler) createOrg(w http.ResponseWriter, r *http.Request) {
	var req store.NewOrg
	var invite *store.Invite
	var send func(to, subject, body string) error
	h.write(w, r, &req, func(tx *sql.Tx, now time.Time) (int, any, error) {
		var err error
		if send, err = h.mailer(); err != nil {
			return 0, nil, err
		}
		if send == nil {
			return 0, nil, errMailNotReady
		}
		hash := crypto.HashSHA256(canonicalJSON(req))
		status, org, inv, err := h.store.Platform().CreateOrg(tx, now, h.caller(r), req, hash)
		invite = inv
		return status, org, err
	})
	if invite != nil {
		h.mailInvite(r, send, invite)
	}
}

// canonicalJSON is the create request as decoded, so create_request_hash does not depend
// on key order or spacing.
func canonicalJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// mailInvite mails an activation link. A failure is audited; the invite can be sent again.
func (h *PlatformHandler) mailInvite(r *http.Request, send func(to, subject, body string) error, inv *store.Invite) {
	link := h.issuerURL + "/activate?token=" + inv.Raw
	body := "Hello " + inv.Name + ",\r\n\r\nAn account for " + inv.Email + " was created for you. Open this link within 7 days to choose a password:\r\n\r\n" +
		link + "\r\n\r\nIf you did not expect this, ignore this message.\r\n"
	if err := send(inv.Email, "Activate your account", body); err != nil {
		h.observe(r, platformTokenFrom(r), "", "platform.invite_delivery", "failure", map[string]any{"user_id": inv.UserID, "error": err.Error()})
	}
}

func (h *PlatformHandler) getOrg(w http.ResponseWriter, r *http.Request) {
	o, err := h.store.Platform().PlatformOrg(r.PathValue("id"))
	if err != nil {
		status, code, _ := platformErrorFor(err)
		platformError(w, status, code, nil)
		return
	}
	h.observe(r, platformTokenFrom(r), o.ID, "platform.org_read", "success", nil)
	writePlatformJSON(w, http.StatusOK, o)
}

func (h *PlatformHandler) listOrgs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	const limit = 100
	orgs, err := h.store.Platform().PlatformOrgs(q.Get("status"), q.Get("billing_ref"), q.Get("cursor"), limit)
	if err != nil {
		log.Printf("platform api: list orgs: %v", err)
		platformError(w, http.StatusInternalServerError, "internal_error", nil)
		return
	}
	out := map[string]any{"orgs": orgs}
	if len(orgs) == limit {
		out["next"] = orgs[len(orgs)-1].ID
	}
	h.observe(r, platformTokenFrom(r), "", "platform.orgs_listed", "success", map[string]any{"count": len(orgs)})
	writePlatformJSON(w, http.StatusOK, out)
}

func (h *PlatformHandler) patchOrg(w http.ResponseWriter, r *http.Request) {
	var req store.OrgPatch
	h.write(w, r, &req, func(tx *sql.Tx, now time.Time) (int, any, error) {
		o, err := h.store.Platform().PatchOrg(tx, now, h.caller(r), r.PathValue("id"), req)
		return http.StatusOK, o, err
	})
}

type revisionBody struct {
	Revision int64 `json:"revision"`
}

func (h *PlatformHandler) suspendOrg(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason   string `json:"reason"`
		Revision int64  `json:"revision"`
	}
	h.write(w, r, &req, func(tx *sql.Tx, now time.Time) (int, any, error) {
		o, err := h.store.Platform().SuspendOrg(tx, now, h.caller(r), r.PathValue("id"), req.Reason, req.Revision)
		return http.StatusOK, o, err
	})
}

func (h *PlatformHandler) resumeOrg(w http.ResponseWriter, r *http.Request) {
	var req revisionBody
	h.write(w, r, &req, func(tx *sql.Tx, now time.Time) (int, any, error) {
		o, err := h.store.Platform().ResumeOrg(tx, now, h.caller(r), r.PathValue("id"), req.Revision)
		return http.StatusOK, o, err
	})
}

func (h *PlatformHandler) scheduleDeletion(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GraceDays int   `json:"grace_days"`
		Revision  int64 `json:"revision"`
	}
	h.write(w, r, &req, func(tx *sql.Tx, now time.Time) (int, any, error) {
		o, err := h.store.Platform().ScheduleDeletion(tx, now, h.caller(r), r.PathValue("id"), req.GraceDays, req.Revision)
		return http.StatusOK, o, err
	})
}

func (h *PlatformHandler) deleteOrg(w http.ResponseWriter, r *http.Request) {
	h.write(w, r, nil, func(tx *sql.Tx, now time.Time) (int, any, error) {
		o, err := h.store.Platform().DeleteOrg(tx, now, h.caller(r), r.PathValue("id"))
		return http.StatusOK, o, err
	})
}
