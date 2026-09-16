package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/Busness-app/ky-primitives/scim"
)

// Inbound SCIM Groups over the flat directory groups. The upstream owns displayName and
// the member set; every member must be an account this connector owns, nested groups
// are refused, and a PATCH is applied as one replace so it either lands whole or not
// at all. Deleting a group never deletes a user.

const scimGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"

type scimMember struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Ref     string `json:"$ref,omitempty"`
	Type    string `json:"type,omitempty"`
}

type scimGroup struct {
	Schemas     []string     `json:"schemas"`
	ID          string       `json:"id,omitempty"`
	ExternalID  string       `json:"externalId,omitempty"`
	DisplayName string       `json:"displayName"`
	Members     []scimMember `json:"members"`
	Meta        *scim.Meta   `json:"meta,omitempty"`
}

func (h *SCIMHandler) groupResource(g *store.UpstreamGroup) scimGroup {
	created, modified := g.CreatedAt, g.UpdatedAt
	members := make([]scimMember, 0, len(g.Members))
	for _, id := range g.Members {
		members = append(members, scimMember{Value: id, Type: "User", Ref: h.issuerURL + "/scim/v2/Users/" + id})
	}
	return scimGroup{
		Schemas: []string{scimGroupSchema}, ID: g.ID, ExternalID: g.ExternalID, DisplayName: g.Name, Members: members,
		Meta: &scim.Meta{ResourceType: "Group", Created: &created, LastModified: &modified, Location: h.issuerURL + "/scim/v2/Groups/" + g.ID, Version: groupVersion(&g.Group)},
	}
}

func groupVersion(g *store.Group) string {
	return `W/"` + strconv.FormatInt(g.UpdatedAt.UnixNano(), 10) + `"`
}

func groupIfMatch(r *http.Request, g *store.Group) bool {
	want := strings.TrimSpace(r.Header.Get("If-Match"))
	if want == "" || want == "*" {
		return true
	}
	for _, v := range strings.Split(want, ",") {
		if strings.TrimSpace(v) == groupVersion(g) {
			return true
		}
	}
	return false
}

func (h *SCIMHandler) writeGroup(w http.ResponseWriter, status int, g *store.UpstreamGroup) {
	res := h.groupResource(g)
	w.Header().Set("ETag", res.Meta.Version)
	w.Header().Set("Location", res.Meta.Location)
	scimJSON(w, status, res)
}

// scimMaxMembers bounds one group write; a larger directory group must arrive in pages.
const scimMaxMembers = 1000

// memberIDs validates a member list: only User members by id, no groups, no blanks.
func memberIDs(members []scimMember) ([]string, string) {
	if len(members) > scimMaxMembers {
		return nil, "too many members in one request (at most 1000)"
	}
	out := make([]string, 0, len(members))
	for _, m := range members {
		if strings.EqualFold(m.Type, "Group") {
			return nil, "nested groups are not supported"
		}
		v := strings.TrimSpace(m.Value)
		if v == "" {
			return nil, "each member needs a value"
		}
		out = append(out, v)
	}
	return out, ""
}

func (h *SCIMHandler) groupError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrGroupTargetMissing):
		scimError(w, http.StatusNotFound, "", "Resource not found")
	case errors.Is(err, store.ErrGroupVersionStale):
		scimError(w, http.StatusPreconditionFailed, "", "Resource version does not match If-Match")
	case errors.Is(err, store.ErrGroupMemberForeign):
		scimError(w, http.StatusBadRequest, "invalidValue", "a member is not an account of this connector, or is a group; provision the user first and reference only Users")
	case errors.Is(err, store.ErrGroupNameExists):
		scimError(w, http.StatusConflict, "uniqueness", "displayName is already in use")
	case errors.Is(err, store.ErrGroupExternalExists):
		scimError(w, http.StatusConflict, "uniqueness", "externalId is already in use")
	case errors.Is(err, store.ErrEnrollmentPolicy):
		scimError(w, http.StatusConflict, "", "a member cannot satisfy this group's MFA policy; the change was not applied")
	case errors.Is(err, store.ErrEmergencyAdministrator):
		scimError(w, http.StatusConflict, "", "this group carries a required MFA policy that only a local administrator may change; the change was not applied")
	case err != nil && strings.Contains(err.Error(), "immutable"):
		scimError(w, http.StatusBadRequest, "mutability", "externalId is immutable")
	default:
		log.Printf("scim group: %v", err)
		scimError(w, http.StatusInternalServerError, "", "Internal error")
	}
}

func (h *SCIMHandler) ListGroups(w http.ResponseWriter, r *http.Request) {
	c := scimConnector(r)
	attribute, value, err := parseFilter(r.URL.Query().Get("filter"))
	if err != nil {
		scimError(w, http.StatusBadRequest, "invalidFilter", err.Error())
		return
	}
	start, count := 1, scimMaxResults
	if v := r.URL.Query().Get("startIndex"); v != "" {
		if start, err = strconv.Atoi(v); err != nil || start < 1 {
			scimError(w, http.StatusBadRequest, "invalidValue", "startIndex must be a positive integer")
			return
		}
	}
	if v := r.URL.Query().Get("count"); v != "" {
		if count, err = strconv.Atoi(v); err != nil || count < 0 {
			scimError(w, http.StatusBadRequest, "invalidValue", "count must be a non-negative integer")
			return
		}
	}
	groups, total, err := h.store.ListUpstreamGroups(c.ID, attribute, value, start, count)
	if err != nil {
		if strings.Contains(err.Error(), "unsupported filter") {
			scimError(w, http.StatusBadRequest, "invalidFilter", "filter attribute not supported; use displayName, externalId or id")
			return
		}
		h.groupError(w, err)
		return
	}
	resources := make([]scimGroup, 0, len(groups))
	for i := range groups {
		resources = append(resources, h.groupResource(&groups[i]))
	}
	scimJSON(w, http.StatusOK, map[string]any{"schemas": []string{scimListSchema}, "totalResults": total, "startIndex": start, "itemsPerPage": len(resources), "Resources": resources})
}

func (h *SCIMHandler) GetGroup(w http.ResponseWriter, r *http.Request) {
	g, err := h.store.GetUpstreamGroup(scimConnector(r).ID, r.PathValue("id"))
	if err != nil {
		h.groupError(w, err)
		return
	}
	if g == nil {
		scimError(w, http.StatusNotFound, "", "Resource not found")
		return
	}
	h.writeGroup(w, http.StatusOK, g)
}

func decodeGroup(r *http.Request) (*scimGroup, string) {
	var in scimGroup
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		return nil, "Malformed JSON body"
	}
	in.DisplayName, in.ExternalID = strings.TrimSpace(in.DisplayName), strings.TrimSpace(in.ExternalID)
	if in.DisplayName == "" || len(in.DisplayName) > 128 {
		return nil, "displayName is required (at most 128 characters)"
	}
	return &in, ""
}

func (h *SCIMHandler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	c := scimConnector(r)
	in, problem := decodeGroup(r)
	if problem != "" {
		scimError(w, http.StatusBadRequest, "invalidValue", problem)
		return
	}
	members, problem := memberIDs(in.Members)
	if problem != "" {
		scimError(w, http.StatusBadRequest, "invalidValue", problem)
		return
	}
	g := &store.Group{Name: in.DisplayName, SourceConnectorID: c.ID, ExternalID: in.ExternalID}
	pending := h.audit.Prepare("scim.group_created", c.ID, "connector:"+c.Name, "", "group", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"name": g.Name, "externalId": g.ExternalID, "members": len(members)})
	if err := h.store.CreateUpstreamGroup(g, members, pending.Row); err != nil {
		h.groupError(w, err)
		return
	}
	pending.Committed()
	stored, err := h.store.GetUpstreamGroup(c.ID, g.ID)
	if err != nil || stored == nil {
		scimError(w, http.StatusInternalServerError, "", "Internal error")
		return
	}
	h.writeGroup(w, http.StatusCreated, stored)
}

func (h *SCIMHandler) loadGroup(w http.ResponseWriter, r *http.Request) *store.UpstreamGroup {
	g, err := h.store.GetUpstreamGroup(scimConnector(r).ID, r.PathValue("id"))
	if err != nil {
		h.groupError(w, err)
		return nil
	}
	if g == nil {
		scimError(w, http.StatusNotFound, "", "Resource not found")
		return nil
	}
	if !groupIfMatch(r, &g.Group) {
		scimError(w, http.StatusPreconditionFailed, "", "Resource version does not match If-Match")
		return nil
	}
	return g
}

// expectedVersion turns an If-Match header into the version the write must still see.
func expectedVersion(r *http.Request, g *store.Group) *time.Time {
	if want := strings.TrimSpace(r.Header.Get("If-Match")); want == "" || want == "*" {
		return nil
	}
	v := g.UpdatedAt
	return &v
}

func (h *SCIMHandler) saveGroup(w http.ResponseWriter, r *http.Request, g *store.UpstreamGroup, members []string) {
	c := scimConnector(r)
	pending := h.audit.Prepare("scim.group_updated", c.ID, "connector:"+c.Name, g.ID, "group", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"name": g.Name, "members": len(members)})
	if err := h.store.ReplaceUpstreamGroup(c.ID, &g.Group, members, expectedVersion(r, &g.Group), pending.Row); err != nil {
		h.groupError(w, err)
		return
	}
	pending.Committed()
	stored, err := h.store.GetUpstreamGroup(c.ID, g.ID)
	if err != nil || stored == nil {
		scimError(w, http.StatusInternalServerError, "", "Internal error")
		return
	}
	h.writeGroup(w, http.StatusOK, stored)
}

func (h *SCIMHandler) ReplaceGroup(w http.ResponseWriter, r *http.Request) {
	g := h.loadGroup(w, r)
	if g == nil {
		return
	}
	in, problem := decodeGroup(r)
	if problem != "" {
		scimError(w, http.StatusBadRequest, "invalidValue", problem)
		return
	}
	if in.ExternalID != "" && g.ExternalID != "" && in.ExternalID != g.ExternalID {
		scimError(w, http.StatusBadRequest, "mutability", "externalId is immutable")
		return
	}
	members, problem := memberIDs(in.Members)
	if problem != "" {
		scimError(w, http.StatusBadRequest, "invalidValue", problem)
		return
	}
	g.Name = in.DisplayName
	if in.ExternalID != "" {
		g.ExternalID = in.ExternalID
	}
	h.saveGroup(w, r, g, members)
}

var memberFilter = regexp.MustCompile(`^members\[value\s+eq\s+"((?:[^"\\]|\\.)*)"\]$`)

// PatchGroup validates every operation against the current group, computes the final
// name and member set, and applies them as one replace: an invalid operation anywhere
// means nothing changes.
func (h *SCIMHandler) PatchGroup(w http.ResponseWriter, r *http.Request) {
	g := h.loadGroup(w, r)
	if g == nil {
		return
	}
	var body struct {
		Operations []struct {
			Op    string          `json:"op"`
			Path  string          `json:"path"`
			Value json.RawMessage `json:"value"`
		} `json:"Operations"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Operations) == 0 || len(body.Operations) > 100 {
		scimError(w, http.StatusBadRequest, "invalidSyntax", "PatchOp body with 1 to 100 Operations required")
		return
	}
	name := g.Name
	members := map[string]bool{}
	for _, id := range g.Members {
		members[id] = true
	}
	for _, op := range body.Operations {
		kind, path := strings.ToLower(strings.TrimSpace(op.Op)), strings.TrimSpace(op.Path)
		switch {
		case kind == "remove" && memberFilter.MatchString(path):
			id, err := strconv.Unquote(`"` + memberFilter.FindStringSubmatch(path)[1] + `"`)
			if err != nil {
				scimError(w, http.StatusBadRequest, "invalidPath", "malformed member filter")
				return
			}
			delete(members, id)
		case kind == "remove" && path == "members":
			list, problem := decodeMembers(op.Value)
			if problem != "" {
				scimError(w, http.StatusBadRequest, "invalidValue", problem)
				return
			}
			if len(list) == 0 {
				members = map[string]bool{}
			}
			for _, id := range list {
				delete(members, id)
			}
		case (kind == "add" || kind == "replace") && path == "members":
			list, problem := decodeMembers(op.Value)
			if problem != "" {
				scimError(w, http.StatusBadRequest, "invalidValue", problem)
				return
			}
			if kind == "replace" {
				members = map[string]bool{}
			}
			for _, id := range list {
				members[id] = true
			}
		case (kind == "add" || kind == "replace") && path == "displayName":
			var v string
			if err := json.Unmarshal(op.Value, &v); err != nil || strings.TrimSpace(v) == "" {
				scimError(w, http.StatusBadRequest, "invalidValue", "displayName must be a non-empty string")
				return
			}
			name = strings.TrimSpace(v)
		case (kind == "add" || kind == "replace") && path == "":
			var v struct {
				DisplayName *string      `json:"displayName"`
				ExternalID  *string      `json:"externalId"`
				Members     []scimMember `json:"members"`
			}
			if err := json.Unmarshal(op.Value, &v); err != nil {
				scimError(w, http.StatusBadRequest, "invalidValue", "a path-less operation needs an object value")
				return
			}
			if v.ExternalID != nil && g.ExternalID != "" && *v.ExternalID != g.ExternalID {
				scimError(w, http.StatusBadRequest, "mutability", "externalId is immutable")
				return
			}
			if v.DisplayName != nil {
				if strings.TrimSpace(*v.DisplayName) == "" {
					scimError(w, http.StatusBadRequest, "invalidValue", "displayName must be a non-empty string")
					return
				}
				name = strings.TrimSpace(*v.DisplayName)
			}
			if v.Members != nil {
				list, problem := memberIDs(v.Members)
				if problem != "" {
					scimError(w, http.StatusBadRequest, "invalidValue", problem)
					return
				}
				if kind == "replace" {
					members = map[string]bool{}
				}
				for _, id := range list {
					members[id] = true
				}
			}
		case path == "externalId":
			scimError(w, http.StatusBadRequest, "mutability", "externalId is immutable")
			return
		default:
			scimError(w, http.StatusBadRequest, "invalidPath", "unsupported operation "+kind+" on "+strconv.Quote(path))
			return
		}
	}
	final := make([]string, 0, len(members))
	for id := range members {
		final = append(final, id)
	}
	g.Name = name
	h.saveGroup(w, r, g, final)
}

func decodeMembers(raw json.RawMessage) ([]string, string) {
	var list []scimMember
	if len(raw) == 0 {
		return nil, ""
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		var one scimMember
		if err := json.Unmarshal(raw, &one); err != nil {
			return nil, "members must be a list of {value}"
		}
		list = []scimMember{one}
	}
	return memberIDs(list)
}

func (h *SCIMHandler) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	c := scimConnector(r)
	g := h.loadGroup(w, r)
	if g == nil {
		return
	}
	pending := h.audit.Prepare("scim.group_deleted", c.ID, "connector:"+c.Name, g.ID, "group", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"name": g.Name})
	if err := h.store.DeleteUpstreamGroup(c.ID, g.ID, expectedVersion(r, &g.Group), pending.Row); err != nil {
		h.groupError(w, err)
		return
	}
	pending.Committed()
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
