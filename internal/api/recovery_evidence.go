package api

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Busnes-app/ky-primitives/syncauth"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// ExportRecoveryEvidence supplies a signed snapshot, not a restore release grant.
func (h *AdminHandler) ExportRecoveryEvidence(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var req struct {
		Nonce    string   `json:"nonce"`
		Subjects []string `json:"subjects"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	d.DisallowUnknownFields()
	err := d.Decode(&req)
	if err == nil {
		var extra any
		if d.Decode(&extra) != io.EOF {
			err = errors.New("trailing JSON")
		}
	}
	nonce, nonceErr := hex.DecodeString(req.Nonce)
	valid := err == nil && nonceErr == nil && len(nonce) == 32 && hex.EncodeToString(nonce) == req.Nonce && len(req.Subjects) > 0 && len(req.Subjects) <= 256
	seen := make(map[string]bool, len(req.Subjects))
	for _, id := range req.Subjects {
		if len(id) < 1 || len(id) > 128 || seen[id] || strings.IndexFunc(id, func(c rune) bool {
			return !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_')
		}) != -1 {
			valid = false
		}
		seen[id] = true
	}
	if !valid {
		http.Error(w, `{"error":"invalid_request","error_description":"Use a 64-character lowercase hex challenge and 1–256 unique subject identifiers"}`, 400)
		return
	}
	admin := GetUserFromContext(r.Context())
	event := h.audit.Prepare("admin.recovery_evidence_exported", admin.ID, admin.Username, r.PathValue("id"), "system", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"subjectCount": len(req.Subjects)})
	var signed syncauth.Headers
	payload, err := h.store.ExportRecoveryEvidence(r.PathValue("id"), h.issuerURL, req.Nonce, req.Subjects, event.Row, func(sys *store.PairedSystem, body []byte, now time.Time) error {
		secret, err := h.syncEngine.SigningSecret(sys)
		if err != nil {
			return store.ErrRecoveryEvidenceUnavailable
		}
		signed, err = syncauth.Sign([]byte(secret), now, "recovery.evidence", req.Nonce, body)
		if err != nil {
			return store.ErrRecoveryEvidenceUnavailable
		}
		return nil
	})
	switch {
	case errors.Is(err, sql.ErrNoRows):
		http.NotFound(w, r)
		return
	case errors.Is(err, store.ErrRecoveryEvidenceUnavailable):
		http.Error(w, `{"error":"recovery_evidence_unavailable","error_description":"Review pairing, connection status and authority restore hold first"}`, 409)
		return
	case errors.Is(err, store.ErrRecoveryEvidenceTooLarge):
		http.Error(w, `{"error":"recovery_evidence_too_large","error_description":"Complete evidence exceeds 256 KiB; keep restore held"}`, 413)
		return
	case err != nil:
		http.Error(w, `{"error":"internal_error"}`, 500)
		return
	}
	event.Committed()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(syncauth.HeaderSignature, signed.Signature)
	w.Header().Set(syncauth.HeaderTimestamp, signed.Timestamp)
	w.Header().Set(syncauth.HeaderEventType, signed.EventType)
	w.Header().Set(syncauth.HeaderEventID, signed.EventID)
	_, _ = w.Write(payload)
}
