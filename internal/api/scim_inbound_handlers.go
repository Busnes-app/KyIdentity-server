package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/Busnes-app/ky-primitives/scim"
	"github.com/Busnes-app/kyidentity-server/internal/audit"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// Inbound SCIM 2.0 Users. The supported profile is deliberately small and advertised
// exactly: create, get, list with one exact-match filter, replace, PATCH of a few
// attributes, and delete-to-deactivate. The upstream owns userName, displayName, name,
// the primary email and the active flag; it never sets a password or a role, and never
// touches an account another connector or a local administrator created.

const (
	scimContentType   = "application/scim+json"
	scimListSchema    = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimMaxResults    = 200
	scimRateBurst     = 60
	scimRateRefill    = 10.0
	scimConnectorKey  = contextKey("scim-connector")
	scimTokenScopeKey = contextKey("scim-scope")
)

type SCIMHandler struct {
	store      *store.Store
	audit      *audit.Logger
	middleware *MiddlewareManager
	issuerURL  string
}

func NewSCIMHandler(s *store.Store, audit *audit.Logger, mm *MiddlewareManager, issuerURL string) *SCIMHandler {
	return &SCIMHandler{store: s, audit: audit, middleware: mm, issuerURL: issuerURL}
}

func scimError(w http.ResponseWriter, status int, scimType, detail string) {
	w.Header().Set("Content-Type", scimContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	body := map[string]any{"schemas": []string{scim.ErrorSchema}, "status": strconv.Itoa(status), "detail": detail}
	if scimType != "" {
		body["scimType"] = scimType
	}
	_ = json.NewEncoder(w).Encode(body)
}

func scimJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", scimContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// Authenticate resolves the Bearer token to a connector. Cookies are ignored entirely:
// a browser session never authorizes SCIM, and a SCIM token never authorizes the admin
// API. Every request is rate limited per connector.
func (h *SCIMHandler) Authenticate(write bool, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			w.Header().Set("WWW-Authenticate", `Bearer realm="scim"`)
			scimError(w, http.StatusUnauthorized, "", "Bearer token required")
			return
		}
		c, scope, err := h.store.AuthenticateSCIMToken(strings.TrimSpace(strings.TrimPrefix(header, "Bearer ")))
		if errors.Is(err, store.ErrNotFound) {
			if !h.middleware.allowRateLimit("scim_auth:"+h.middleware.ClientIP(r), 10, 0.2) {
				scimError(w, http.StatusTooManyRequests, "", "Too many failed authentications")
				return
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="scim", error="invalid_token"`)
			scimError(w, http.StatusUnauthorized, "", "Invalid or revoked token")
			return
		}
		if err != nil {
			scimError(w, http.StatusInternalServerError, "", "Internal error")
			return
		}
		if !h.middleware.allowRateLimit("scim:"+c.ID, scimRateBurst, scimRateRefill) {
			w.Header().Set("Retry-After", "5")
			scimError(w, http.StatusTooManyRequests, "", "Rate limit exceeded")
			return
		}
		if write && scope != "write" {
			scimError(w, http.StatusForbidden, "", "This token is read-only")
			return
		}
		ctx := context.WithValue(r.Context(), scimConnectorKey, c)
		next(w, r.WithContext(context.WithValue(ctx, scimTokenScopeKey, scope)))
	})
}

func scimConnector(r *http.Request) *store.SCIMConnector {
	c, _ := r.Context().Value(scimConnectorKey).(*store.SCIMConnector)
	return c
}

// Discovery documents describe exactly what is implemented.
func (h *SCIMHandler) ServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	scimJSON(w, http.StatusOK, map[string]any{
		"schemas":               []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"documentationUri":      h.issuerURL + "/",
		"patch":                 map[string]any{"supported": true},
		"bulk":                  map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":                map[string]any{"supported": true, "maxResults": scimMaxResults},
		"changePassword":        map[string]any{"supported": false},
		"sort":                  map[string]any{"supported": false},
		"etag":                  map[string]any{"supported": true},
		"authenticationSchemes": []map[string]any{{"type": "oauthbearertoken", "name": "Bearer token", "description": "Connector token issued by a KySignOn administrator"}},
		"meta":                  map[string]any{"resourceType": "ServiceProviderConfig", "location": h.issuerURL + "/scim/v2/ServiceProviderConfig"},
	})
}

func (h *SCIMHandler) ResourceTypes(w http.ResponseWriter, r *http.Request) {
	user := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "User", "name": "User", "endpoint": "/Users",
		"schema": scim.UserSchema, "meta": map[string]any{"resourceType": "ResourceType", "location": h.issuerURL + "/scim/v2/ResourceTypes/User"},
	}
	group := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "Group", "name": "Group", "endpoint": "/Groups",
		"schema": scimGroupSchema, "meta": map[string]any{"resourceType": "ResourceType", "location": h.issuerURL + "/scim/v2/ResourceTypes/Group"},
	}
	switch {
	case strings.HasSuffix(r.URL.Path, "/User"):
		scimJSON(w, http.StatusOK, user)
	case strings.HasSuffix(r.URL.Path, "/Group"):
		scimJSON(w, http.StatusOK, group)
	case strings.Contains(r.URL.Path, "/ResourceTypes/"):
		scimError(w, http.StatusNotFound, "", "Unknown resource type")
	default:
		scimJSON(w, http.StatusOK, map[string]any{"schemas": []string{scimListSchema}, "totalResults": 2, "startIndex": 1, "itemsPerPage": 2, "Resources": []any{user, group}})
	}
}

func (h *SCIMHandler) Schemas(w http.ResponseWriter, r *http.Request) {
	attr := func(name, typ string, mutability string, required bool) map[string]any {
		return map[string]any{"name": name, "type": typ, "multiValued": false, "required": required, "caseExact": false, "mutability": mutability, "returned": "default", "uniqueness": "none"}
	}
	userName := attr("userName", "string", "readWrite", true)
	userName["uniqueness"] = "server"
	externalID := attr("externalId", "string", "immutable", true)
	externalID["uniqueness"] = "server"
	emails := attr("emails", "complex", "readWrite", false)
	emails["multiValued"] = true
	emails["subAttributes"] = []map[string]any{attr("value", "string", "readWrite", true), attr("primary", "boolean", "readWrite", false), attr("type", "string", "readWrite", false)}
	name := attr("name", "complex", "readWrite", false)
	name["subAttributes"] = []map[string]any{attr("formatted", "string", "readWrite", false), attr("givenName", "string", "readWrite", false), attr("familyName", "string", "readWrite", false)}
	schema := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"}, "id": scim.UserSchema, "name": "User",
		"description": "KySignOn user. Passwords and roles are never provisioned; a new account is invited and activates through a link.",
		"attributes":  []map[string]any{userName, externalID, attr("displayName", "string", "readWrite", false), name, emails, attr("active", "boolean", "readWrite", false)},
		"meta":        map[string]any{"resourceType": "Schema", "location": h.issuerURL + "/scim/v2/Schemas/" + scim.UserSchema},
	}
	members := attr("members", "complex", "readWrite", false)
	members["multiValued"] = true
	members["subAttributes"] = []map[string]any{attr("value", "string", "immutable", true), attr("type", "string", "immutable", false)}
	groupExternal := attr("externalId", "string", "immutable", false)
	groupExternal["uniqueness"] = "server"
	groupSchema := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"}, "id": scimGroupSchema, "name": "Group",
		"description": "KySignOn directory group. Members are Users of this connector only; nested groups are refused.",
		"attributes":  []map[string]any{attr("displayName", "string", "readWrite", true), groupExternal, members},
		"meta":        map[string]any{"resourceType": "Schema", "location": h.issuerURL + "/scim/v2/Schemas/" + scimGroupSchema},
	}
	if strings.Contains(r.URL.Path, "/Schemas/") {
		switch {
		case strings.HasSuffix(r.URL.Path, scim.UserSchema):
			scimJSON(w, http.StatusOK, schema)
		case strings.HasSuffix(r.URL.Path, scimGroupSchema):
			scimJSON(w, http.StatusOK, groupSchema)
		default:
			scimError(w, http.StatusNotFound, "", "Unknown schema")
		}
		return
	}
	scimJSON(w, http.StatusOK, map[string]any{"schemas": []string{scimListSchema}, "totalResults": 2, "startIndex": 1, "itemsPerPage": 2, "Resources": []any{schema, groupSchema}})
}

// resource renders an owned account as the upstream sees it: active means the upstream's
// flag survives the local override, which is what its own records should match.
func (h *SCIMHandler) resource(u *store.User) scim.User {
	created, modified := u.CreatedAt, u.UpdatedAt
	res := scim.User{
		Schemas: []string{scim.UserSchema}, ID: u.ID, ExternalID: u.ExternalID, UserName: u.Username, DisplayName: u.DisplayName,
		Active: u.SourceActive && !u.LocallyDisabled,
		Meta:   &scim.Meta{ResourceType: "User", Created: &created, LastModified: &modified, Location: h.issuerURL + "/scim/v2/Users/" + u.ID, Version: version(u)},
	}
	if u.DisplayName != "" {
		res.Name = &scim.Name{Formatted: u.DisplayName}
	}
	if u.Email != "" {
		res.Emails = []scim.MultiValue{{Value: u.Email, Type: "work", Primary: true}}
	}
	return res
}

func version(u *store.User) string {
	return `W/"` + strconv.FormatInt(u.UpdatedAt.UnixNano(), 10) + `"`
}

func (h *SCIMHandler) writeResource(w http.ResponseWriter, status int, u *store.User) {
	res := h.resource(u)
	w.Header().Set("ETag", res.Meta.Version)
	w.Header().Set("Location", res.Meta.Location)
	scimJSON(w, status, res)
}

// ifMatch enforces a conditional write: a stale version is refused with 412.
func ifMatch(r *http.Request, u *store.User) bool {
	want := strings.TrimSpace(r.Header.Get("If-Match"))
	if want == "" || want == "*" {
		return true
	}
	for _, v := range strings.Split(want, ",") {
		if strings.TrimSpace(v) == version(u) {
			return true
		}
	}
	return false
}

var filterExpr = regexp.MustCompile(`^\s*([A-Za-z][A-Za-z.]*)\s+eq\s+"((?:[^"\\]|\\.)*)"\s*$`)

// parseFilter accepts exactly `attribute eq "value"` and nothing else.
func parseFilter(raw string) (attribute, value string, err error) {
	if raw == "" {
		return "", "", nil
	}
	m := filterExpr.FindStringSubmatch(raw)
	if m == nil {
		return "", "", errors.New("only `attribute eq \"value\"` filters are supported")
	}
	unq, err := strconv.Unquote(`"` + m[2] + `"`)
	if err != nil {
		return "", "", errors.New("malformed filter value")
	}
	return m[1], unq, nil
}

func (h *SCIMHandler) List(w http.ResponseWriter, r *http.Request) {
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
	if count > scimMaxResults {
		count = scimMaxResults
	}
	users, total, err := h.store.ListUpstreamUsers(c.ID, attribute, value, start, count)
	if err != nil {
		if strings.Contains(err.Error(), "unsupported filter") {
			scimError(w, http.StatusBadRequest, "invalidFilter", "filter attribute not supported; use userName, externalId, emails.value or id")
			return
		}
		scimError(w, http.StatusInternalServerError, "", "Internal error")
		return
	}
	resources := make([]scim.User, 0, len(users))
	for i := range users {
		resources = append(resources, h.resource(&users[i]))
	}
	scimJSON(w, http.StatusOK, map[string]any{"schemas": []string{scimListSchema}, "totalResults": total, "startIndex": start, "itemsPerPage": len(resources), "Resources": resources})
}

func (h *SCIMHandler) Get(w http.ResponseWriter, r *http.Request) {
	u, err := h.store.GetUpstreamUser(scimConnector(r).ID, r.PathValue("id"))
	if err != nil {
		scimError(w, http.StatusInternalServerError, "", "Internal error")
		return
	}
	if u == nil {
		scimError(w, http.StatusNotFound, "", "Resource not found")
		return
	}
	h.writeResource(w, http.StatusOK, u)
}

// decodeUser reads a User payload. Unknown attributes are ignored; a password is refused
// outright rather than silently dropped. hasActive tells an omitted active flag (which
// SCIM defaults to true) from an explicit false.
func decodeUser(r *http.Request) (in *scim.User, hasActive bool, problem string) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, false, "Body too large"
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, false, "Malformed JSON body"
	}
	if _, ok := fields["password"]; ok {
		return nil, false, "Password provisioning is not supported; accounts activate through a link"
	}
	in = &scim.User{}
	if err := json.Unmarshal(raw, in); err != nil {
		return nil, false, "Malformed JSON body"
	}
	_, hasActive = fields["active"]
	in.UserName, in.ExternalID, in.DisplayName = strings.TrimSpace(in.UserName), strings.TrimSpace(in.ExternalID), strings.TrimSpace(in.DisplayName)
	return in, hasActive, ""
}

func primaryEmail(in *scim.User) string {
	for _, e := range in.Emails {
		if e.Primary && e.Value != "" {
			return strings.TrimSpace(e.Value)
		}
	}
	for _, e := range in.Emails {
		if e.Value != "" {
			return strings.TrimSpace(e.Value)
		}
	}
	return ""
}

func displayName(in *scim.User) string {
	if in.DisplayName != "" {
		return in.DisplayName
	}
	if in.Name != nil {
		if in.Name.Formatted != "" {
			return strings.TrimSpace(in.Name.Formatted)
		}
		return strings.TrimSpace(strings.TrimSpace(in.Name.GivenName) + " " + strings.TrimSpace(in.Name.FamilyName))
	}
	return in.UserName
}

func (h *SCIMHandler) Create(w http.ResponseWriter, r *http.Request) {
	c := scimConnector(r)
	in, hasActive, problem := decodeUser(r)
	if problem != "" {
		scimError(w, http.StatusBadRequest, "invalidValue", problem)
		return
	}
	if in.UserName == "" || in.ExternalID == "" {
		scimError(w, http.StatusBadRequest, "invalidValue", "userName and externalId are required")
		return
	}
	email := primaryEmail(in)
	if email == "" {
		scimError(w, http.StatusBadRequest, "invalidValue", "an email is required")
		return
	}
	u := &store.User{Username: in.UserName, DisplayName: displayName(in), Email: email, SourceConnectorID: c.ID, ExternalID: in.ExternalID, SourceActive: in.Active || !hasActive}
	pending := h.audit.Prepare("scim.user_created", c.ID, "connector:"+c.Name, "", "user", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"username": u.Username, "externalId": u.ExternalID})
	err := h.store.CreateUpstreamUser(u, pending.Row)
	if errors.Is(err, store.ErrUserConflict) {
		scimError(w, http.StatusConflict, "uniqueness", "userName, email or externalId is already in use")
		return
	}
	if err != nil {
		log.Printf("scim create: %v", err)
		scimError(w, http.StatusInternalServerError, "", "Internal error")
		return
	}
	pending.Committed()
	h.writeResource(w, http.StatusCreated, u)
}

func (h *SCIMHandler) Replace(w http.ResponseWriter, r *http.Request) {
	c := scimConnector(r)
	u, err := h.store.GetUpstreamUser(c.ID, r.PathValue("id"))
	if err != nil {
		scimError(w, http.StatusInternalServerError, "", "Internal error")
		return
	}
	if u == nil {
		scimError(w, http.StatusNotFound, "", "Resource not found")
		return
	}
	if !ifMatch(r, u) {
		scimError(w, http.StatusPreconditionFailed, "", "Resource version does not match If-Match")
		return
	}
	in, hasActive, problem := decodeUser(r)
	if problem != "" {
		scimError(w, http.StatusBadRequest, "invalidValue", problem)
		return
	}
	if in.ExternalID != "" && in.ExternalID != u.ExternalID {
		scimError(w, http.StatusBadRequest, "mutability", "externalId is immutable")
		return
	}
	if in.UserName == "" {
		scimError(w, http.StatusBadRequest, "invalidValue", "userName is required")
		return
	}
	u.Username, u.DisplayName = in.UserName, displayName(in)
	if email := primaryEmail(in); email != "" {
		u.Email = email
	}
	u.SourceActive = in.Active || !hasActive
	h.save(w, r, c, u)
}

func (h *SCIMHandler) save(w http.ResponseWriter, r *http.Request, c *store.SCIMConnector, u *store.User) {
	pending := h.audit.Prepare("scim.user_updated", c.ID, "connector:"+c.Name, u.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"username": u.Username, "sourceActive": u.SourceActive})
	err := h.store.UpdateUpstreamUser(u, pending.Row)
	switch {
	case errors.Is(err, store.ErrUserConflict):
		scimError(w, http.StatusConflict, "uniqueness", "userName or email is already in use")
		return
	case errors.Is(err, store.ErrNotFound):
		scimError(w, http.StatusNotFound, "", "Resource not found")
		return
	case err != nil:
		log.Printf("scim update: %v", err)
		scimError(w, http.StatusInternalServerError, "", "Internal error")
		return
	}
	pending.Committed()
	stored, err := h.store.GetUpstreamUser(c.ID, u.ID)
	if err != nil || stored == nil {
		scimError(w, http.StatusInternalServerError, "", "Internal error")
		return
	}
	h.writeResource(w, http.StatusOK, stored)
}

// Patch applies add/replace operations to the supported attributes and remove to
// nothing; every operation is validated before any is applied.
func (h *SCIMHandler) Patch(w http.ResponseWriter, r *http.Request) {
	c := scimConnector(r)
	u, err := h.store.GetUpstreamUser(c.ID, r.PathValue("id"))
	if err != nil {
		scimError(w, http.StatusInternalServerError, "", "Internal error")
		return
	}
	if u == nil {
		scimError(w, http.StatusNotFound, "", "Resource not found")
		return
	}
	if !ifMatch(r, u) {
		scimError(w, http.StatusPreconditionFailed, "", "Resource version does not match If-Match")
		return
	}
	var body struct {
		Schemas    []string              `json:"schemas"`
		Operations []scim.PatchOperation `json:"Operations"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Operations) == 0 || len(body.Operations) > 50 {
		scimError(w, http.StatusBadRequest, "invalidSyntax", "PatchOp body with 1 to 50 Operations required")
		return
	}
	next := *u
	for _, op := range body.Operations {
		if problem := applyPatch(&next, op); problem != "" {
			scimError(w, http.StatusBadRequest, "invalidPath", problem)
			return
		}
	}
	h.save(w, r, c, &next)
}

func applyPatch(u *store.User, op scim.PatchOperation) string {
	kind := strings.ToLower(op.Op)
	if kind != "add" && kind != "replace" {
		return "only add and replace operations are supported"
	}
	path := strings.TrimSpace(op.Path)
	if path == "" {
		values, ok := op.Value.(map[string]any)
		if !ok {
			return "a path-less operation needs an object value"
		}
		for k, v := range values {
			if problem := setAttribute(u, k, v); problem != "" {
				return problem
			}
		}
		return ""
	}
	return setAttribute(u, path, op.Value)
}

func setAttribute(u *store.User, path string, value any) string {
	str := func() (string, bool) {
		s, ok := value.(string)
		return strings.TrimSpace(s), ok
	}
	switch strings.TrimPrefix(path, scim.UserSchema+":") {
	case "active":
		switch v := value.(type) {
		case bool:
			u.SourceActive = v
		case string:
			u.SourceActive = strings.EqualFold(v, "true")
		default:
			return "active must be a boolean"
		}
	case "userName":
		s, ok := str()
		if !ok || s == "" {
			return "userName must be a non-empty string"
		}
		u.Username = s
	case "displayName", "name.formatted":
		s, ok := str()
		if !ok {
			return path + " must be a string"
		}
		u.DisplayName = s
	case "name":
		obj, ok := value.(map[string]any)
		if !ok {
			return "name must be an object"
		}
		if f, _ := obj["formatted"].(string); strings.TrimSpace(f) != "" {
			u.DisplayName = strings.TrimSpace(f)
		} else {
			g, _ := obj["givenName"].(string)
			fam, _ := obj["familyName"].(string)
			if full := strings.TrimSpace(strings.TrimSpace(g) + " " + strings.TrimSpace(fam)); full != "" {
				u.DisplayName = full
			}
		}
	case "emails":
		list, ok := value.([]any)
		if !ok {
			return "emails must be a list"
		}
		var chosen string
		for _, item := range list {
			m, _ := item.(map[string]any)
			v, _ := m["value"].(string)
			p, _ := m["primary"].(bool)
			if v != "" && (chosen == "" || p) {
				chosen = strings.TrimSpace(v)
			}
		}
		if chosen == "" {
			return "emails needs at least one value"
		}
		u.Email = chosen
	case `emails[type eq "work"].value`, `emails[primary eq true].value`, "emails.value":
		s, ok := str()
		if !ok || s == "" {
			return "email value must be a non-empty string"
		}
		u.Email = s
	case "externalId":
		return "externalId is immutable"
	default:
		return fmt.Sprintf("attribute %q is not supported", path)
	}
	return ""
}

// Delete deactivates: the account stays for audit, re-provisioning and offboarding, and
// the upstream can reactivate it later by creating nothing and PATCHing active.
func (h *SCIMHandler) Delete(w http.ResponseWriter, r *http.Request) {
	c := scimConnector(r)
	u, err := h.store.GetUpstreamUser(c.ID, r.PathValue("id"))
	if err != nil {
		scimError(w, http.StatusInternalServerError, "", "Internal error")
		return
	}
	if u == nil {
		scimError(w, http.StatusNotFound, "", "Resource not found")
		return
	}
	if !ifMatch(r, u) {
		scimError(w, http.StatusPreconditionFailed, "", "Resource version does not match If-Match")
		return
	}
	u.SourceActive = false
	pending := h.audit.Prepare("scim.user_deactivated", c.ID, "connector:"+c.Name, u.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"username": u.Username})
	if err := h.store.UpdateUpstreamUser(u, pending.Row); err != nil {
		log.Printf("scim delete: %v", err)
		scimError(w, http.StatusInternalServerError, "", "Internal error")
		return
	}
	pending.Committed()
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
