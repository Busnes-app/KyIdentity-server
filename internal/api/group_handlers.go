package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

type groupPage struct {
	Limit, Offset int
	Query         string
}

func parseGroupPage(r *http.Request) (groupPage, error) {
	p := groupPage{Limit: 25, Query: strings.TrimSpace(r.URL.Query().Get("q"))}
	for name, target := range map[string]*int{"limit": &p.Limit, "offset": &p.Offset} {
		if raw := r.URL.Query().Get(name); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil {
				return p, err
			}
			*target = n
		}
	}
	if p.Limit < 1 || p.Limit > 100 || p.Offset < 0 || p.Offset > 1000000 || !utf8.ValidString(p.Query) || utf8.RuneCountInString(p.Query) > 200 {
		return p, errors.New("invalid pagination or search")
	}
	return p, nil
}

func writeGroupError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrEnrollmentPolicy), errors.Is(err, store.ErrEmergencyAdministrator):
		enrollmentError(w, err)
	case errors.Is(err, store.ErrGroupSourceOwned):
		http.Error(w, `{"error":"source_owned","error_description":"This group's name is managed by its SCIM connector"}`, 400)
	case errors.Is(err, store.ErrGroupNameExists):
		http.Error(w, `{"error":"group_name_exists","error_description":"A group with that name already exists"}`, 409)
	case errors.Is(err, store.ErrGroupTargetMissing):
		http.Error(w, `{"error":"not_found","error_description":"Group or user no longer exists"}`, 404)
	default:
		http.Error(w, `{"error":"internal_error"}`, 500)
	}
}
func writeGroupJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func (h *AdminHandler) ListGroups(w http.ResponseWriter, r *http.Request) {
	p, err := parseGroupPage(r)
	if err != nil {
		http.Error(w, `{"error":"invalid_request","error_description":"Use limit 1–100, a nonnegative offset, and search up to 200 characters"}`, 400)
		return
	}
	groups, total, err := h.store.ListGroups(p.Query, r.URL.Query().Get("userId"), p.Limit, p.Offset)
	if err != nil {
		writeGroupError(w, err)
		return
	}
	writeGroupJSON(w, map[string]any{"groups": groups, "total": total, "limit": p.Limit, "offset": p.Offset})
}

func (h *AdminHandler) ListGroupUsers(w http.ResponseWriter, r *http.Request) {
	p, err := parseGroupPage(r)
	include := r.URL.Query().Get("includeNonMembers")
	if err != nil || (include != "" && include != "true" && include != "false") {
		http.Error(w, `{"error":"invalid_request"}`, 400)
		return
	}
	users, total, err := h.store.ListGroupUsers(r.PathValue("id"), p.Query, include == "true", p.Limit, p.Offset)
	if err != nil {
		writeGroupError(w, err)
		return
	}
	writeGroupJSON(w, map[string]any{"users": users, "total": total, "limit": p.Limit, "offset": p.Offset})
}

func readGroup(r *http.Request) (*store.Group, error) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, err
	}
	req.Name = strings.Trim(req.Name, " ")
	req.Description = strings.TrimSpace(req.Description)
	if req.Name == "" || !utf8.ValidString(req.Name) || !utf8.ValidString(req.Description) || utf8.RuneCountInString(req.Name) > 128 || utf8.RuneCountInString(req.Description) > 2048 || strings.ContainsFunc(req.Name, func(r rune) bool {
		return unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Cs, unicode.Co) || (unicode.IsSpace(r) && r != ' ')
	}) || strings.ContainsFunc(req.Description, func(r rune) bool { return unicode.Is(unicode.Cf, r) }) {
		return nil, errors.New("invalid group")
	}
	return &store.Group{ID: r.PathValue("id"), Name: req.Name, Description: req.Description}, nil
}

func (h *AdminHandler) CreateGroup(w http.ResponseWriter, r *http.Request) { h.saveGroup(w, r, true) }
func (h *AdminHandler) UpdateGroup(w http.ResponseWriter, r *http.Request) { h.saveGroup(w, r, false) }
func (h *AdminHandler) saveGroup(w http.ResponseWriter, r *http.Request, create bool) {
	g, err := readGroup(r)
	if err != nil {
		http.Error(w, `{"error":"invalid_request","error_description":"Group name must be 1–128 characters using visible characters and ordinary spaces; description may contain up to 2048 characters without Unicode format marks"}`, 400)
		return
	}
	action := "admin.group_updated"
	if create {
		g.ID = uuid.NewString()
		action = "admin.group_created"
	}
	actor := GetUserFromContext(r.Context())
	event := h.audit.Prepare(action, actor.ID, actor.Username, g.ID, "group", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"name": g.Name, "description": g.Description})
	if create {
		err = h.store.CreateGroup(g, event.Row)
	} else {
		err = h.store.UpdateGroup(g, event.Row)
	}
	if err != nil {
		writeGroupError(w, err)
		return
	}
	event.Committed()
	if create {
		writeGroupJSON(w, map[string]any{"group": g})
	} else {
		writeGroupJSON(w, map[string]bool{"success": true})
	}
}

func (h *AdminHandler) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	actor := GetUserFromContext(r.Context())
	id := r.PathValue("id")
	event := h.audit.Prepare("admin.group_deleted", actor.ID, actor.Username, id, "group", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	if err := h.store.DeleteGroupForSession(id, GetSessionFromContext(r.Context()).ID, event.Row); err != nil {
		if errors.Is(err, store.ErrEmergencyAdministrator) {
			if auditErr := h.audit.Record("admin.group_deleted", actor.ID, actor.Username, id, "group", h.middleware.ClientIP(r), r.UserAgent(), "denied", map[string]any{"reason": "compliant_admin_required"}); auditErr != nil {
				stepUpInternalError(w)
				return
			}
		}
		writeGroupError(w, err)
		return
	}
	event.Committed()
	writeGroupJSON(w, map[string]bool{"success": true})
}

func (h *AdminHandler) SetGroupMembership(w http.ResponseWriter, r *http.Request) {
	actor := GetUserFromContext(r.Context())
	groupID, userID := r.PathValue("id"), r.PathValue("userId")
	member := r.Method == http.MethodPut
	action := "admin.group_member_removed"
	if member {
		action = "admin.group_member_added"
	}
	expiresAt, err := readExpiry(w, r)
	if err != nil {
		return
	}
	details := map[string]any{"userId": userID}
	if expiresAt != nil {
		details["expiresAt"] = expiresAt
	}
	event := h.audit.Prepare(action, actor.ID, actor.Username, groupID, "group", h.middleware.ClientIP(r), r.UserAgent(), "success", details)
	sessionID := GetSessionFromContext(r.Context()).ID
	if member {
		err = h.store.SetGroupMembershipUntil(groupID, userID, expiresAt, sessionID, event.Row)
	} else {
		err = h.store.SetGroupMembershipForSession(groupID, userID, false, sessionID, event.Row)
	}
	if err != nil {
		if errors.Is(err, store.ErrEnrollmentPolicy) || errors.Is(err, store.ErrEmergencyAdministrator) {
			reason := "conflicting_mfa_policies"
			if errors.Is(err, store.ErrEmergencyAdministrator) {
				reason = "compliant_admin_required"
			}
			if auditErr := h.audit.Record(action, actor.ID, actor.Username, groupID, "group", h.middleware.ClientIP(r), r.UserAgent(), "denied", map[string]any{"reason": reason, "userId": userID}); auditErr != nil {
				stepUpInternalError(w)
				return
			}
		}
		writeGroupError(w, err)
		return
	}
	event.Committed()
	writeGroupJSON(w, map[string]bool{"success": true})
}
