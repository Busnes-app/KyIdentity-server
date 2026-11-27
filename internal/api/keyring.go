package api

import (
	"crypto/ecdh"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"strings"

	"github.com/Busnes-app/ky-primitives/xwing"
	"github.com/Busnes-app/kyidentity-server/internal/audit"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

const keyringPath = "/api/user/keyring"

type keyringAccount struct {
	org   *store.OrgStore
	login store.KeyringSession
	grant store.KeyringGrant
}

type keyringHandler struct{ s *Server }

func (s *Server) registerKeyring(mux *http.ServeMux) {
	h := keyringHandler{s: s}
	read := s.middleware.RateLimit("keyring_read", 60, 2)
	write := s.middleware.RateLimit("keyring_write", 30, 0.5)
	for _, route := range []struct {
		pattern string
		handle  func(http.ResponseWriter, *http.Request, keyringAccount)
	}{
		{"GET " + keyringPath, h.status},
		{"POST " + keyringPath, h.initialize},
		{"POST " + keyringPath + "/wrappers", h.addWrapper},
		{"GET " + keyringPath + "/wrappers/{id}", h.getWrapper},
		{"DELETE " + keyringPath + "/wrappers/{id}", h.revokeWrapper},
		{"PUT " + keyringPath + "/recovery", h.rotateRecovery},
		{"GET " + keyringPath + "/apps/{client}", h.getApp},
		{"PUT " + keyringPath + "/apps/{client}", h.putApp},
		{"POST " + keyringPath + "/transfers", h.requestTransfer},
		{"GET " + keyringPath + "/transfers/{id}", h.getTransfer},
		{"PUT " + keyringPath + "/transfers/{id}/approve", h.approveTransfer},
		{"POST " + keyringPath + "/transfers/{id}/claim", h.claimTransfer},
		{"DELETE " + keyringPath + "/transfers/{id}", h.cancelTransfer},
	} {
		handler := s.middleware.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, sess := GetUserFromContext(r.Context()), GetSessionFromContext(r.Context())
			if user.Role != "user" {
				keyringError(w, store.ErrKeyringDenied)
				return
			}
			if id := r.PathValue("id"); id != "" && !keyringID(id) {
				keyringInvalid(w)
				return
			}
			bucket, burst, refill := "keyring_member_write:", 16.0, 0.25
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				bucket, burst, refill = "keyring_member_read:", 40, 1
			}
			if !s.middleware.allowRateLimit(bucket+user.ID, burst, refill) {
				writeAPIError(w, http.StatusTooManyRequests, "rate_limit_exceeded", "Try again shortly.")
				return
			}
			account := keyringAccount{org: orgStore(r), login: store.KeyringSession{UserID: user.ID, SessionID: sess.ID}}
			if raw := r.Header.Get(StepUpHeader); raw != "" {
				account.grant = store.KeyringGrant{Hash: crypto.HashSHA256(raw), Operation: r.Method + " " + r.URL.Path}
			}
			route.handle(w, r, account)
		}))
		if strings.HasPrefix(route.pattern, "GET ") {
			mux.Handle(route.pattern, read(handler))
		} else {
			mux.Handle(route.pattern, write(handler))
		}
	}
	mux.Handle("GET /api/keyring/app", read(http.HandlerFunc(h.appForToken)))
}

func keyringError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, sql.ErrNoRows):
		writeAPIError(w, http.StatusNotFound, "not_found", "This keyring item is unavailable.")
	case errors.Is(err, store.ErrKeyringDenied):
		writeAPIError(w, http.StatusForbidden, "keyring_access_denied", "This account or application cannot access the keyring.")
	case errors.Is(err, store.ErrKeyringConflict):
		writeAPIError(w, http.StatusConflict, "keyring_conflict", "The keyring changed or reached its limit. Refresh and try again.")
	case errors.Is(err, store.ErrKeyringStepUp):
		writeAPIError(w, http.StatusForbidden, "step_up_required", "Confirm your identity to change the keyring.")
	default:
		// Errors from SQL can contain request values. Keep them out of server logs.
		log.Print("keyring operation failed")
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "The keyring request could not be completed.")
	}
}

func keyringInvalid(w http.ResponseWriter) {
	writeAPIError(w, http.StatusBadRequest, "invalid_request", "The keyring request is invalid.")
}

func keyringJSON(w http.ResponseWriter, r *http.Request, dest any) bool {
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err == nil && contentType == "application/json" {
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		dec.DisallowUnknownFields()
		if err = dec.Decode(dest); err == nil && errors.Is(dec.Decode(new(any)), io.EOF) {
			return true
		}
	}
	keyringInvalid(w)
	return false
}

func keyringID(v string) bool {
	id, err := uuid.Parse(v)
	return err == nil && id.String() == v && id.Version() == 4 && id.Variant() == uuid.RFC4122
}

func keyringBase64(v string, minBytes, maxBytes int) []byte {
	if len(v) > base64.RawURLEncoding.EncodedLen(maxBytes) {
		return nil
	}
	b, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil || len(b) < minBytes || len(b) > maxBytes || base64.RawURLEncoding.EncodeToString(b) != v {
		return nil
	}
	return b
}

func keyringPoint(v string) bool {
	b := keyringBase64(v, 65, 65)
	_, err := ecdh.P256().NewPublicKey(b)
	return err == nil
}

// Length selects an explicit suite; a failed X-Wing parse never falls back.
func keyringXwingKey(v string) bool {
	b := keyringBase64(v, xwing.PublicKeyBytes, xwing.PublicKeyBytes)
	_, err := xwing.ParsePublicKey(b)
	return err == nil
}

func keyringHandoffKey(v string) bool {
	return keyringPoint(v) || keyringXwingKey(v)
}

const keyringXwingMarker = "xwing:1"

func keyringXwingPacket(v string) bool {
	b := keyringBase64(v, xwing.Overhead+32, xwing.Overhead+32)
	return b != nil && b[0] == xwing.Version
}

func keyringDeviceHash(r *http.Request) string {
	raw := r.Header.Get("X-Ky-Keyring-Device")
	if keyringBase64(raw, 32, 32) == nil {
		return ""
	}
	return crypto.HashSHA256(raw)
}

type keyringWrapperInput struct {
	store.KeyringWrapperInfo
	Sealed     string `json:"sealed"`
	DeviceHash string `json:"device_hash"`
}

func (v keyringWrapperInput) valid() bool {
	if !keyringID(v.ID) || keyringBase64(v.Sealed, 60, 60) == nil {
		return false
	}
	switch v.Kind {
	case "device":
		b, err := hex.DecodeString(v.DeviceHash)
		return err == nil && len(b) == 32 && hex.EncodeToString(b) == v.DeviceHash && v.CredentialID == ""
	case "recovery":
		return v.DeviceHash == "" && v.CredentialID == ""
	case "prf":
		return v.DeviceHash == "" && keyringBase64(v.CredentialID, 1, 768) != nil
	default:
		return false
	}
}

func (v keyringWrapperInput) value() store.KeyringWrapper {
	return store.KeyringWrapper{KeyringWrapperInfo: v.KeyringWrapperInfo, Sealed: v.Sealed, DeviceHash: v.DeviceHash}
}

func (h keyringHandler) audit(r *http.Request, action, target string) *audit.Pending {
	u := GetUserFromContext(r.Context())
	return h.s.audit.Prepare("keyring."+action, u.ID, "", target, "keyring", h.s.middleware.ClientIP(r), r.UserAgent(), "success", nil)
}

func keyringReply(w http.ResponseWriter, data any, err error) {
	if err != nil {
		keyringError(w, err)
	} else {
		writeJSON(w, http.StatusOK, data)
	}
}

func keyringWritten(w http.ResponseWriter, pending *audit.Pending, err error) {
	if err != nil {
		keyringError(w, err)
		return
	}
	pending.Committed()
	w.WriteHeader(http.StatusNoContent)
}

func (h keyringHandler) status(w http.ResponseWriter, r *http.Request, a keyringAccount) {
	out, err := a.org.KeyringStatus(a.login)
	keyringReply(w, struct {
		store.KeyringStatus
		Issuer string `json:"issuer"`
		Org    string `json:"org_id"`
		User   string `json:"user_id"`
	}{out, h.s.cfg.IssuerURL, a.org.ID().String(), a.login.UserID}, err)
}

func (h keyringHandler) initialize(w http.ResponseWriter, r *http.Request, a keyringAccount) {
	var body struct {
		Version  string              `json:"keyring_version"`
		Org      string              `json:"org_id"`
		User     string              `json:"user_id"`
		Device   keyringWrapperInput `json:"device"`
		Recovery keyringWrapperInput `json:"recovery"`
	}
	if !keyringJSON(w, r, &body) {
		return
	}
	if body.Org != a.org.ID().String() || body.User != a.login.UserID || !keyringID(body.Version) || body.Device.Kind != "device" || !body.Device.valid() || body.Recovery.Kind != "recovery" || !body.Recovery.valid() {
		keyringInvalid(w)
		return
	}
	p := h.audit(r, "initialized", a.login.UserID)
	keyringWritten(w, p, a.org.InitializeKeyring(a.login, body.Version, body.Device.value(), body.Recovery.value(), a.grant, p.Row))
}

func (h keyringHandler) addWrapper(w http.ResponseWriter, r *http.Request, a keyringAccount) {
	var body struct {
		Version string              `json:"keyring_version"`
		Wrapper keyringWrapperInput `json:"wrapper"`
	}
	if !keyringJSON(w, r, &body) {
		return
	}
	if !keyringID(body.Version) || body.Wrapper.Kind == "recovery" || !body.Wrapper.valid() {
		keyringInvalid(w)
		return
	}
	p := h.audit(r, "wrapper_added", body.Wrapper.ID)
	keyringWritten(w, p, a.org.AddKeyringWrapper(a.login, body.Version, body.Wrapper.value(), a.grant, p.Row))
}

func (h keyringHandler) getWrapper(w http.ResponseWriter, r *http.Request, a keyringAccount) {
	out, err := a.org.KeyringWrapper(a.login, r.PathValue("id"), keyringDeviceHash(r))
	keyringReply(w, out, err)
}

func (h keyringHandler) revokeWrapper(w http.ResponseWriter, r *http.Request, a keyringAccount) {
	id := r.PathValue("id")
	p := h.audit(r, "wrapper_revoked", id)
	keyringWritten(w, p, a.org.RevokeKeyringWrapper(a.login, id, a.grant, p.Row))
}

func (h keyringHandler) rotateRecovery(w http.ResponseWriter, r *http.Request, a keyringAccount) {
	var body struct {
		Version  string              `json:"keyring_version"`
		Previous string              `json:"previous_id"`
		Wrapper  keyringWrapperInput `json:"wrapper"`
	}
	if !keyringJSON(w, r, &body) {
		return
	}
	if !keyringID(body.Version) || !keyringID(body.Previous) || body.Previous == body.Wrapper.ID ||
		body.Wrapper.Kind != "recovery" || !body.Wrapper.valid() {
		keyringInvalid(w)
		return
	}
	p := h.audit(r, "recovery_rotated", body.Wrapper.ID)
	keyringWritten(w, p, a.org.RotateKeyringRecovery(a.login, body.Version, body.Previous, body.Wrapper.value(), a.grant, p.Row))
}

func (h keyringHandler) getApp(w http.ResponseWriter, r *http.Request, a keyringAccount) {
	out, err := a.org.KeyringAppKey(a.login, r.PathValue("client"))
	keyringReply(w, out, err)
}

func (h keyringHandler) putApp(w http.ResponseWriter, r *http.Request, a keyringAccount) {
	var body struct {
		Ring    string  `json:"keyring_version"`
		Version int     `json:"key_version"`
		Sealed  *string `json:"sealed"`
	}
	if !keyringJSON(w, r, &body) {
		return
	}
	if !keyringID(body.Ring) || body.Version < 1 || body.Version > 2147483647 || body.Sealed == nil ||
		(*body.Sealed != "" && keyringBase64(*body.Sealed, 60, 60) == nil) {
		keyringInvalid(w)
		return
	}
	client := r.PathValue("client")
	p := h.audit(r, "app_key_changed", client)
	keyringWritten(w, p, a.org.PutKeyringAppKey(a.login, body.Ring, client, store.KeyringAppKey{Version: body.Version, Sealed: *body.Sealed}, a.grant, p.Row))
}

func (h keyringHandler) appForToken(w http.ResponseWriter, r *http.Request) {
	auth := strings.Fields(r.Header.Get("Authorization"))
	if len(auth) != 2 || !strings.EqualFold(auth[0], "Bearer") || len(auth[1]) > 16384 {
		writeAPIError(w, http.StatusUnauthorized, "invalid_token", "A KyIdentity access token is required.")
		return
	}
	sub, client, jti, org, valid := h.s.oauthEngine.KeyringAccessToken(auth[1])
	if !valid {
		writeAPIError(w, http.StatusUnauthorized, "invalid_token", "A KyIdentity access token is required.")
		return
	}
	if !h.s.middleware.allowRateLimit("keyring_token:"+sub, 40, 1) {
		writeAPIError(w, http.StatusTooManyRequests, "rate_limit_exceeded", "Try again shortly.")
		return
	}
	user, err := h.s.store.PrincipalByID(sub)
	if err != nil {
		keyringError(w, err)
		return
	}
	if user == nil || (h.s.cfg.Tenancy == "multi" && user.Org().String() != org) {
		keyringError(w, store.ErrKeyringDenied)
		return
	}
	out, err := h.s.store.Org(user.Org()).KeyringAppKeyForToken(sub, client, jti)
	keyringReply(w, out, err)
}

func (h keyringHandler) requestTransfer(w http.ResponseWriter, r *http.Request, a keyringAccount) {
	var body struct {
		Version string `json:"keyring_version"`
		ID      string `json:"id"`
		store.KeyringTransferRequest
	}
	if !keyringJSON(w, r, &body) {
		return
	}
	if !keyringID(body.Version) || !keyringID(body.ID) || !keyringXwingKey(body.RecipientKey) || keyringBase64(body.RequestMAC, 32, 32) == nil {
		keyringInvalid(w)
		return
	}
	p := h.audit(r, "transfer_requested", body.ID)
	expires, err := a.org.RequestKeyringTransfer(a.login, body.Version, body.ID, body.KeyringTransferRequest, p.Row)
	if err == nil {
		p.Committed()
	}
	keyringReply(w, map[string]int64{"expires_at": expires}, err)
}

func (h keyringHandler) getTransfer(w http.ResponseWriter, r *http.Request, a keyringAccount) {
	out, err := a.org.KeyringTransfer(a.login, r.PathValue("id"))
	keyringReply(w, out, err)
}

func (h keyringHandler) approveTransfer(w http.ResponseWriter, r *http.Request, a keyringAccount) {
	var body struct {
		DeviceID string `json:"device_id"`
		store.KeyringTransferResponse
	}
	if !keyringJSON(w, r, &body) {
		return
	}
	if !keyringID(body.DeviceID) || body.SenderKey != keyringXwingMarker || !keyringXwingPacket(body.Sealed) {
		keyringInvalid(w)
		return
	}
	id := r.PathValue("id")
	p := h.audit(r, "transfer_approved", id)
	keyringWritten(w, p, a.org.ApproveKeyringTransfer(a.login, id, body.DeviceID, keyringDeviceHash(r), body.KeyringTransferResponse, a.grant, p.Row))
}

func (h keyringHandler) claimTransfer(w http.ResponseWriter, r *http.Request, a keyringAccount) {
	id := r.PathValue("id")
	p := h.audit(r, "transfer_claimed", id)
	out, err := a.org.ClaimKeyringTransfer(a.login, id, p.Row)
	if err == nil {
		p.Committed()
	}
	keyringReply(w, out, err)
}

func (h keyringHandler) cancelTransfer(w http.ResponseWriter, r *http.Request, a keyringAccount) {
	id := r.PathValue("id")
	p := h.audit(r, "transfer_cancelled", id)
	keyringWritten(w, p, a.org.CancelKeyringTransfer(a.login, id, p.Row))
}
