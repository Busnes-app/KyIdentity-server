package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/audit"
	"github.com/Busnes-app/kyidentity-server/internal/mail"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// Access requests: users ask, administrators and app owners answer. The store re-reads
// authority and policy at decision time; these handlers shape input and answers.
type AccessRequestHandler struct {
	store         *store.Store
	audit         *audit.Logger
	middleware    *MiddlewareManager
	encryptionKey []byte
}

func NewAccessRequestHandler(s *store.Store, audit *audit.Logger, mm *MiddlewareManager, encryptionKey []byte) *AccessRequestHandler {
	return &AccessRequestHandler{store: s, audit: audit, middleware: mm, encryptionKey: encryptionKey}
}

func writeAccessRequestError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrAppNotRequestable):
		http.Error(w, `{"error":"app_not_requestable","error_description":"That app is not open to requests"}`, http.StatusNotFound)
	case errors.Is(err, store.ErrAlreadyHasAccess):
		http.Error(w, `{"error":"already_has_access"}`, http.StatusConflict)
	case errors.Is(err, store.ErrDuplicateRequest):
		http.Error(w, `{"error":"duplicate_request","error_description":"A request for this app is already pending"}`, http.StatusConflict)
	case errors.Is(err, store.ErrTooManyRequests):
		http.Error(w, `{"error":"too_many_requests","error_description":"Wait for your pending requests to be answered"}`, http.StatusTooManyRequests)
	case errors.Is(err, store.ErrRequestNotPending):
		http.Error(w, `{"error":"request_not_pending","error_description":"This request was already answered, withdrawn or has expired"}`, http.StatusConflict)
	case errors.Is(err, store.ErrSelfApproval):
		http.Error(w, `{"error":"self_approval","error_description":"You cannot decide your own request"}`, http.StatusForbidden)
	case errors.Is(err, store.ErrCannotDecide):
		writeForbidden(w)
	case errors.Is(err, store.ErrAppLinkConflict):
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
	default:
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
	}
}

// ListOwn returns what the user may request and the requests they have made.
func (h *AccessRequestHandler) ListOwn(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	apps, err := h.store.RequestableApps(user.ID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	requests, _, err := h.store.ListAccessRequests(store.AccessRequestFilter{UserID: user.ID, Limit: 50})
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	writeGroupJSON(w, map[string]any{"requestable": apps, "requests": requests})
}

func (h *AccessRequestHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AppID           string `json:"appId"`
		Reason          string `json:"reason"`
		DurationSeconds int    `json:"durationSeconds"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8*1024)).Decode(&req); err != nil || req.AppID == "" || len(req.AppID) > 200 || strings.TrimSpace(req.Reason) == "" {
		http.Error(w, `{"error":"invalid_request","error_description":"appId and a reason are required"}`, http.StatusBadRequest)
		return
	}
	user := GetUserFromContext(r.Context())
	pending := h.audit.Prepare("access.request_created", user.ID, user.Username, req.AppID, "application", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	created, err := h.store.CreateAccessRequest(user.ID, req.AppID, req.Reason, time.Duration(req.DurationSeconds)*time.Second, pending.Row)
	if err != nil {
		writeAccessRequestError(w, err)
		return
	}
	pending.Committed()
	writeGroupJSON(w, map[string]any{"request": created})
}

func (h *AccessRequestHandler) Cancel(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	pending := h.audit.Prepare("access.request_cancelled", user.ID, user.Username, r.PathValue("id"), "access_request", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	if err := h.store.CancelAccessRequest(r.PathValue("id"), user.ID, pending.Row); err != nil {
		writeAccessRequestError(w, err)
		return
	}
	pending.Committed()
	writeGroupJSON(w, map[string]bool{"success": true})
}

// Inbox lists the requests the actor may decide: every app for a global administrator,
// the owned apps for a delegate. The store scopes by the actor's current authority.
func (h *AccessRequestHandler) Inbox(w http.ResponseWriter, r *http.Request) {
	p, err := parseGroupPage(r)
	if err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	status := r.URL.Query().Get("status")
	switch status {
	case "", "pending":
		status = "pending"
	case "approved", "denied", "cancelled", "expired", "all":
	default:
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	if status == "all" {
		status = ""
	}
	actor := GetUserFromContext(r.Context())
	requests, total, err := h.store.ListAccessRequests(store.AccessRequestFilter{ActorID: actor.ID, Status: status, Limit: p.Limit, Offset: p.Offset})
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	writeGroupJSON(w, map[string]any{"requests": requests, "total": total, "limit": p.Limit, "offset": p.Offset})
}

// Decide approves or denies one request. Approval grants an ordinary bounded assignment;
// the requester is told by mail when delivery is configured, best effort.
func (h *AccessRequestHandler) Decide(approve bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Note string `json:"note"`
		}
		if r.ContentLength != 0 {
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8*1024)).Decode(&req); err != nil {
				http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
				return
			}
		}
		actor := GetUserFromContext(r.Context())
		action := "access.request_denied"
		if approve {
			action = "access.request_approved"
		}
		pending := h.audit.Prepare(action, actor.ID, actor.Username, r.PathValue("id"), "access_request", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
		decided, err := h.store.DecideAccessRequest(r.PathValue("id"), actor.ID, approve, req.Note, pending.Row)
		if err != nil {
			writeAccessRequestError(w, err)
			return
		}
		pending.Committed()
		h.notify(decided)
		writeGroupJSON(w, map[string]any{"request": decided})
	}
}

func (h *AccessRequestHandler) notify(req *store.AccessRequest) {
	settings, err := mail.Load(h.store, h.encryptionKey)
	if err != nil || settings == nil {
		return
	}
	u, err := h.store.GetUserByID(req.UserID)
	if err != nil || u == nil || u.Email == "" {
		return
	}
	verdict := "denied"
	if req.Status == "approved" {
		verdict = "approved"
	}
	body := "Your request for access to " + req.AppName + " was " + verdict + "."
	if req.DecisionNote != "" {
		body += "\r\n\r\nNote from the approver: " + req.DecisionNote
	}
	if err := settings.Send(u.Email, "KySignOn access request "+verdict, body+"\r\n"); err != nil {
		log.Printf("access request notice to %s failed: %v", u.ID, err)
	}
}

// SetAppRequestable opens or closes an app to requests. Global administrators only.
func (h *AdminHandler) SetAppRequestable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Requestable *bool `json:"requestable"`
		Revision    int   `json:"revision"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Requestable == nil || req.Revision < 1 {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	actor := GetUserFromContext(r.Context())
	event := h.audit.Prepare("admin.app_requestable_changed", actor.ID, actor.Username, r.PathValue("id"), "application", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	if err := h.store.SetAppRequestable(r.PathValue("id"), *req.Requestable, req.Revision, event.Row); err != nil {
		writeAppRegistryError(w, err)
		return
	}
	event.Committed()
	writeGroupJSON(w, map[string]bool{"success": true})
}
