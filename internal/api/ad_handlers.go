package api

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/audit"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/Busnes-app/kyidentity-server/internal/sync"
)

// queueDirectoryPassword seals a just-set password for every Active Directory connector
// holding the user. Only ciphertext is stored; a failure leaves the user's directory
// password stale, which the admin view shows. Never logs the password.
func queueDirectoryPassword(keys store.ADKeys, s *store.Store, l *audit.Logger, m *MiddlewareManager, r *http.Request, actorID, actorName, userID, hash, plaintext string, temporary bool) {
	if temporary {
		plaintext = lockPassword()
	}
	var queued []*audit.Pending
	_, err := s.QueueDirectoryPassword(keys, userID, hash, []byte(plaintext), func(systemID string, seq int64, superseded bool) *store.AuditEvent {
		p := l.Prepare("directory.password_queued", actorID, actorName, userID, "user", m.ClientIP(r), r.UserAgent(), "success",
			map[string]any{"systemId": systemID, "seq": seq, "superseded": superseded})
		queued = append(queued, p)
		return p.Row
	})
	if err != nil {
		log.Printf("directory password queue for user %s failed: %v", userID, err)
		l.Observe("directory.password_queued", actorID, actorName, userID, "user", m.ClientIP(r), r.UserAgent(), "failure", nil)
		// A tampered connector key fails only that connector; the rest were committed.
		if !errors.Is(err, store.ErrAgentKeyTampered) {
			return
		}
	}
	for _, p := range queued {
		p.Committed()
	}
}

// lockPassword is what the directory gets instead of a temporary password its owner must
// replace: random and never stored or shown, so the previous directory password stops
// working and the temporary one never works there. The suffix meets AD's complexity rule.
func lockPassword() string {
	return rand.Text() + "a1!"
}

func (h *AdminHandler) adSystem(w http.ResponseWriter, r *http.Request) *store.PairedSystem {
	sys, err := h.store.GetPairedSystemByID(r.PathValue("id"))
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "")
		return nil
	}
	if sys == nil || sys.SystemType != "active_directory" {
		writeAPIError(w, http.StatusNotFound, "system_not_found", "")
		return nil
	}
	return sys
}

// GetActiveDirectory returns a directory connector's settings, never its bind password or
// agent token, and where each managed user's directory password stands.
func (h *AdminHandler) GetActiveDirectory(w http.ResponseWriter, r *http.Request) {
	sys := h.adSystem(w, r)
	if sys == nil {
		return
	}
	settings, err := h.store.ADConnector(sys.ID)
	if err == nil && settings == nil {
		err = errors.New("directory connector has no settings")
	}
	var passwords []store.ADPasswordStatus
	if err == nil {
		passwords, err = h.store.ADPasswordStatuses(sys.ID)
	}
	if err != nil {
		log.Printf("directory connector %s: %v", sys.ID, err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ldapsUrl": sys.CallbackURL, "settings": settings, "passwords": passwords,
		"entrySigningKey": h.syncEngine.DirectoryKeys().SigningPublicKeyForAgent(settings.AgentPublicKey)})
}

// PutActiveDirectory replaces a directory connector's settings. bindPassword, when given,
// replaces the sealed one.
func (h *AdminHandler) PutActiveDirectory(w http.ResponseWriter, r *http.Request) {
	sys := h.adSystem(w, r)
	if sys == nil {
		return
	}
	var req struct {
		LDAPSURL     string `json:"ldapsUrl"`
		BindPassword string `json:"bindPassword"`
		sync.ADSettings
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if dec.Decode(&req) != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "")
		return
	}
	old, err := h.store.ADConnector(sys.ID)
	if err != nil || old == nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}
	admin := GetUserFromContext(r.Context())
	details := map[string]any{"systemName": sys.Name, "systemType": sys.SystemType, "credentialRotated": req.BindPassword != "",
		"agentKeyChanged": strings.TrimSpace(req.AgentPublicKey) != old.AgentPublicKey, "urlChanged": req.LDAPSURL != sys.CallbackURL}
	event := h.audit.Prepare("admin.system_configured", admin.ID, admin.Username, sys.ID, "system", h.middleware.ClientIP(r), r.UserAgent(), "success", details)
	if err := h.syncEngine.ConfigureAD(sys, req.LDAPSURL, req.BindPassword, &req.ADSettings, event.Row); err != nil {
		h.audit.Observe("admin.system_configured", admin.ID, admin.Username, sys.ID, "system", h.middleware.ClientIP(r), r.UserAgent(), "failure", map[string]any{"systemName": sys.Name, "systemType": sys.SystemType})
		writeInputError(w, "invalid_connection", err)
		return
	}
	event.Committed()
	writeSuccess(w)
}

// IssueADAgentToken replaces the connector's agent token and shows it once.
func (h *AdminHandler) IssueADAgentToken(w http.ResponseWriter, r *http.Request) {
	sys := h.adSystem(w, r)
	if sys == nil {
		return
	}
	random, err := crypto.GenerateRandomHex(32)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}
	token := "kyad_" + random
	admin := GetUserFromContext(r.Context())
	event := h.audit.Prepare("admin.ad_agent_token_issued", admin.ID, admin.Username, sys.ID, "system", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"systemName": sys.Name})
	if err := h.store.SetADAgentToken(sys.ID, token, event.Row); err != nil {
		log.Printf("agent token for %s: %v", sys.ID, err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}
	event.Committed()
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"agentToken": token})
}

// ADAgentHandler serves the DC agent: Bearer agent token only, never cookies, and only the
// token's own connector's queue.
type ADAgentHandler struct{ store *store.Store }

func (h *ADAgentHandler) authenticate(next func(w http.ResponseWriter, r *http.Request, systemID string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		systemID, err := h.store.ADSystemForAgentToken(strings.TrimSpace(token))
		if !ok || errors.Is(err, store.ErrNotFound) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="kyidentity-dc-agent"`)
			writeAPIError(w, http.StatusUnauthorized, "invalid_token", "")
			return
		}
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "internal_error", "")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		next(w, r, systemID)
	}
}

// Passwords is GET /api/ad-agent/v1/passwords: the connector's live ciphertexts.
func (h *ADAgentHandler) Passwords(w http.ResponseWriter, r *http.Request, systemID string) {
	now := time.Now().UTC()
	if _, err := h.store.ExpireADPasswords(now); err != nil {
		log.Printf("directory password expiry: %v", err)
	}
	entries, err := h.store.PendingADPasswords(systemID, now, 50)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"connectorId": systemID, "entries": entries})
}

// Result is POST /api/ad-agent/v1/passwords/{userId}/{seq}: applied, rejected or retry.
// 404 means the entry is gone: a newer password replaced it, or it expired or finished.
func (h *ADAgentHandler) Result(w http.ResponseWriter, r *http.Request, systemID string) {
	seq, err := strconv.ParseInt(r.PathValue("seq"), 10, 64)
	var req struct {
		Outcome string `json:"outcome"`
		Reason  string `json:"reason"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err != nil || dec.Decode(&req) != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "")
		return
	}
	err = h.store.FinishADPassword(systemID, r.PathValue("userId"), seq, req.Outcome, req.Reason)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeAPIError(w, http.StatusNotFound, "not_found", "")
	case err != nil:
		writeInputError(w, "invalid_request", err)
	default:
		writeSuccess(w)
	}
}
