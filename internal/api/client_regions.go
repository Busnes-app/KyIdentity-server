package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// Per-region app URLs (tenancy design, "Home region"): a regioned client serves an org only
// through the origin for the org's home region, and that origin must be one of the client's
// redirect origins, checked on write and again on every read.

// canonicalOrigin is raw as scheme://host[:port] with a lowercase host, or "" when raw is not
// exactly an allowed external origin.
func canonicalOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || validateExternalURL(raw) != nil || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery {
		return ""
	}
	return u.Scheme + "://" + strings.ToLower(u.Host)
}

// isRedirectOrigin reports whether origin is the origin of one of the client's redirect URIs.
func isRedirectOrigin(client store.OAuthClient, origin string) bool {
	_, uris := clientRedirectOrigin(client)
	for _, raw := range uris {
		if u, err := url.Parse(raw); err == nil && u.Host != "" && u.Scheme+"://"+strings.ToLower(u.Host) == origin {
			return true
		}
	}
	return false
}

// regionLaunchURL moves launchURL to origin, keeping its path and query; "" when origin is
// not one of the client's redirect origins.
func regionLaunchURL(client store.OAuthClient, launchURL, origin string) string {
	u, err := url.Parse(launchURL)
	if err != nil || origin == "" || !isRedirectOrigin(client, origin) {
		return ""
	}
	o, _ := url.Parse(origin)
	u.Scheme, u.Host = o.Scheme, o.Host
	return u.String()
}

// orgRegionOrigins is launcherApps' regions for a user of org: nil in single-tenant mode.
func orgRegionOrigins(st *store.Store, multiTenant bool, org store.OrgID) (map[string]string, error) {
	if !multiTenant {
		return nil, nil
	}
	return st.OrgRegionOrigins(org)
}

// regionsBody is the admin route's body and answer.
type regionsBody struct {
	Regions map[string]string `json:"regions"`
}

// GetClientRegions answers the client's region map. Multi-tenant only.
func (h *AdminHandler) GetClientRegions(w http.ResponseWriter, r *http.Request) {
	if !h.multiTenant {
		writeAPIError(w, http.StatusNotFound, "not_found", "")
		return
	}
	client, err := h.store.GetOAuthClientByID(r.PathValue("id"))
	if err != nil {
		log.Printf("client regions read failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}
	if client == nil {
		writeAPIError(w, http.StatusNotFound, "client_not_found", "")
		return
	}
	regions, err := h.store.ClientRegionOrigins(client.ID)
	if err != nil {
		log.Printf("client regions read failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}
	writeJSON(w, http.StatusOK, regionsBody{regions})
}

// PutClientRegions replaces the client's region map; {} clears it. Multi-tenant only.
func (h *AdminHandler) PutClientRegions(w http.ResponseWriter, r *http.Request) {
	if !h.multiTenant {
		writeAPIError(w, http.StatusNotFound, "not_found", "")
		return
	}
	var req regionsBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.Regions == nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "")
		return
	}
	client, err := h.store.GetOAuthClientByID(r.PathValue("id"))
	if err != nil {
		log.Printf("client regions read failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}
	if client == nil {
		writeAPIError(w, http.StatusNotFound, "client_not_found", "")
		return
	}
	clean := make(map[string]string, len(req.Regions))
	for region, raw := range req.Regions {
		origin := canonicalOrigin(raw)
		if origin == "" || !isRedirectOrigin(*client, origin) {
			writeAPIError(w, http.StatusBadRequest, "invalid_regions", "Each origin must be exactly the origin of one of the client's redirect URIs")
			return
		}
		clean[region] = origin
	}
	actor := GetUserFromContext(r.Context())
	event := h.audit.Prepare("admin.client_regions_changed", actor.ID, actor.Username, "client", client.ID, h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	if err := h.store.SetClientRegionOrigins(client.ID, clean, event.Row); errors.Is(err, store.ErrNotFound) {
		writeAPIError(w, http.StatusNotFound, "client_not_found", "")
		return
	} else if err != nil {
		writeInputError(w, "invalid_regions", err)
		return
	}
	event.Committed()
	writeJSON(w, http.StatusOK, regionsBody{clean})
}
