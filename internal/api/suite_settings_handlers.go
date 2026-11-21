package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/Busnes-app/kyidentity-server/internal/audit"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// Suite settings (docs/SUITE-DIRECTORY.md): the suite's mail domains and its default theme,
// platform-wide, set by an administrator and read by every suite app.
type SuiteSettingsHandler struct {
	store      *store.Store
	audit      *audit.Logger
	middleware *MiddlewareManager
}

// Appearance is public: the sign-in page applies the default theme before anyone signs in,
// and app backends read it without credentials. It names a ky-ui catalog entry only.
func (h *SuiteSettingsHandler) Appearance(w http.ResponseWriter, r *http.Request) {
	theme, err := h.store.SuiteDefaultTheme()
	if err != nil {
		log.Printf("suite theme read failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	writeJSON(w, http.StatusOK, map[string]string{"defaultTheme": theme})
}

// EmailDomains is the suite directory route: any enabled confidential client may read them.
func (h *SuiteHandler) EmailDomains(w http.ResponseWriter, r *http.Request, _ *store.OAuthClient) {
	domains, err := h.store.SuiteEmailDomains()
	if err != nil {
		log.Printf("suite domains read failed: %v", err)
		suiteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	suiteJSON(w, http.StatusOK, map[string]any{"domains": domains})
}

type suiteSettingsBody struct {
	EmailDomains []string `json:"emailDomains"`
	DefaultTheme string   `json:"defaultTheme"`
}

func (h *SuiteSettingsHandler) read() (suiteSettingsBody, error) {
	domains, err := h.store.SuiteEmailDomains()
	if err != nil {
		return suiteSettingsBody{}, err
	}
	theme, err := h.store.SuiteDefaultTheme()
	return suiteSettingsBody{EmailDomains: domains, DefaultTheme: theme}, err
}

func (h *SuiteSettingsHandler) Get(w http.ResponseWriter, r *http.Request) {
	body, err := h.read()
	if err != nil {
		log.Printf("suite settings read failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}
	writeJSON(w, http.StatusOK, body)
}

// PutEmailDomains replaces the list; an empty list clears it. Informational for apps:
// KyIdentity does not refuse user addresses outside it.
func (h *SuiteSettingsHandler) PutEmailDomains(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domains []string `json:"domains"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.Domains == nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "")
		return
	}
	clean, err := store.NormalizeEmailDomains(req.Domains)
	if err != nil {
		writeInputError(w, "invalid_request", err)
		return
	}
	// The store reads the old value and skips an unchanged save under its writer lock.
	actor := GetUserFromContext(r.Context())
	event := h.audit.Prepare("admin.suite_email_domains_changed", actor.ID, actor.Username, "suite_settings", "email_domains", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	var inUse *store.DomainInUseError
	if _, changed, err := h.store.SetSuiteEmailDomains(clean, event.Row); errors.As(err, &inUse) {
		writeAPIError(w, http.StatusConflict, "domain_in_use", inUse.Error())
		return
	} else if err != nil {
		writeInputError(w, "invalid_request", err)
		return
	} else if changed {
		event.Committed()
	}
	h.Get(w, r)
}

// PutDefaultTheme sets the suite default theme; "system" clears it. Users' own choices win.
func (h *SuiteSettingsHandler) PutDefaultTheme(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Theme *string `json:"theme"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.Theme == nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "")
		return
	}
	if !store.ValidSuiteTheme(*req.Theme) {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "Unknown theme")
		return
	}
	actor := GetUserFromContext(r.Context())
	event := h.audit.Prepare("admin.suite_default_theme_changed", actor.ID, actor.Username, "suite_settings", "default_theme", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	if changed, err := h.store.SetSuiteDefaultTheme(*req.Theme, event.Row); err != nil {
		writeInputError(w, "invalid_request", err)
		return
	} else if changed {
		event.Committed()
	}
	h.Get(w, r)
}
