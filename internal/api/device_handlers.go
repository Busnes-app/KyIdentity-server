package api

import (
	"cmp"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/audit"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/mfa"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

type DeviceHandler struct {
	store      *store.Store
	mfaEngine  *mfa.Engine
	audit      *audit.Logger
	middleware *MiddlewareManager
	issuerURL  string
}

func NewDeviceHandler(s *store.Store, mfaEngine *mfa.Engine, audit *audit.Logger, mm *MiddlewareManager, issuerURL string) *DeviceHandler {
	return &DeviceHandler{
		store:      s,
		mfaEngine:  mfaEngine,
		audit:      audit,
		middleware: mm,
		issuerURL:  issuerURL,
	}
}

// GenerateDevicePairingToken creates an ephemeral 90s PIN/QR pairing token.
func (h *DeviceHandler) GenerateDevicePairingToken(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	// Optional body; absent or empty means the device may not sign on.
	var body struct {
		SignOn *bool `json:"signOn"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	signOn := body.SignOn != nil && *body.SignOn

	if err := consumeStepUp(h.store, r); err != nil {
		writeStepUpError(w, err)
		return
	}

	generated := h.audit.Prepare("device.pairing_token_generated", user.ID, user.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"signOn": signOn})
	token, pin, expiresAt, err := h.mfaEngine.GenerateDevicePairingToken(user.ID, signOn, generated.Row)
	if err != nil {
		log.Printf("device pairing token creation failed for user %s: %v", user.ID, err)
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	qrPayload := map[string]any{
		"type":      "kyidentity_device_pairing",
		"serverUrl": h.issuerURL,
		// The token is the credential. userId is carried so a device pairing by PIN can
		// scope its redemption to this account rather than matching any live PIN.
		"pairingToken": token,
		"pinCode":      pin,
		"userId":       user.ID,
		"username":     user.Username,
		"expiresAt":    expiresAt.Unix(),
	}
	qrBytes, _ := json.Marshal(qrPayload)

	generated.Committed()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"signOn":       signOn,
		"pairingToken": token,
		"pinCode":      pin,
		"expiresAt":    expiresAt,
		"qrPayload":    string(qrBytes),
	})
}

// RegisterNativeDevice allows native mobile client to exchange 90s pairing token or PIN for registration.
func (h *DeviceHandler) RegisterNativeDevice(w http.ResponseWriter, r *http.Request) {
	var req mfa.NativeDeviceRegisterRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_request","error_description":"Malformed JSON body"}`, http.StatusBadRequest)
		return
	}

	var registered *audit.Pending
	dev, err := h.mfaEngine.RegisterNativeDevice(&req, func(dev *store.NativeDevice) *store.AuditEvent {
		registered = h.audit.Prepare("device.registered", dev.UserID, "", dev.ID, "device", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{
			"deviceName":        dev.DeviceName,
			"attestedLevel":     dev.AttestedLevel,
			"bootState":         dev.BootState,
			"attestationReason": dev.AttestationReason,
			"pushTransport":     dev.PushTransport,
		})
		return registered.Row
	})
	if err != nil {
		writeInputError(w, "registration_failed", err)
		return
	}
	registered.Committed()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success":  true,
		"deviceId": dev.ID,
		"device":   dev,
	})
}

const pushTokenClockSkew = 5 * time.Minute

type pushTokenRefreshRequest struct {
	PushToken     string `json:"pushToken"`
	PushTransport string `json:"pushTransport"`
	PushP256dh    string `json:"pushP256dh"`
	PushAuth      string `json:"pushAuth"`
	IssuedAt      int64  `json:"issuedAt"`
	Signature     string `json:"signature"`
}

// RefreshNativeDevicePushToken lets an already-paired device replace its push target.
// Its enrolled P-256 key is the credential; a push token or endpoint is only a delivery address.
func (h *DeviceHandler) RefreshNativeDevicePushToken(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("id")
	var req pushTokenRefreshRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_request","error_description":"Malformed JSON body"}`, http.StatusBadRequest)
		return
	}
	req.PushToken = strings.TrimSpace(req.PushToken)
	transport, err := mfa.ValidatePushTarget(req.PushTransport, req.PushToken, req.PushP256dh, req.PushAuth)
	if err != nil || req.IssuedAt <= 0 {
		http.Error(w, `{"error":"invalid_request","error_description":"A valid push target and issuedAt are required"}`, http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()
	issuedAt := time.UnixMilli(req.IssuedAt)
	if issuedAt.Before(now.Add(-pushTokenClockSkew)) || issuedAt.After(now.Add(pushTokenClockSkew)) {
		http.Error(w, `{"error":"stale_request","error_description":"issuedAt is outside the allowed clock window"}`, http.StatusBadRequest)
		return
	}

	dev, err := h.store.GetNativeDevice(deviceID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	origin, err := mfa.IssuerOrigin(h.issuerURL)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	message, err := mfa.PushTokenRefreshMessage(origin, deviceID, req.IssuedAt, transport, req.PushToken, req.PushP256dh, req.PushAuth)
	if err != nil || dev == nil || dev.PublicKey == "" || !crypto.VerifyECDSAP256(dev.PublicKey, message, req.Signature) {
		http.Error(w, `{"error":"device_authentication_failed"}`, http.StatusUnauthorized)
		return
	}
	if !mfa.PlatformAllowsTransport(dev.Platform, transport) {
		http.Error(w, `{"error":"invalid_request","error_description":"pushTransport is not available on this device platform"}`, http.StatusBadRequest)
		return
	}

	pending := h.audit.Prepare("device.push_token_refreshed", dev.UserID, "", dev.ID, "device",
		h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"pushTransport": transport})
	updated, err := h.store.UpdateNativeDevicePushToken(dev.ID, transport, req.PushToken, req.PushP256dh, req.PushAuth, req.IssuedAt, now, pending.Row)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	if !updated {
		http.Error(w, `{"error":"replayed_request"}`, http.StatusConflict)
		return
	}
	pending.Committed()
	w.WriteHeader(http.StatusNoContent)
}

// ListUserDevices lists registered devices for current user.
func (h *DeviceHandler) ListUserDevices(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	devices, err := h.store.ListUserNativeDevices(user.ID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	if devices == nil {
		devices = []store.NativeDevice{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"devices": devices})
}

// DeleteUserDevice deletes a device. Removing a factor costs a step-up grant, as for passkeys.
func (h *DeviceHandler) DeleteUserDevice(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	if err := consumeStepUp(h.store, r); err != nil {
		writeStepUpError(w, err)
		return
	}

	deviceID := r.PathValue("id")
	deleted := h.audit.Prepare("device.deleted", user.ID, user.Username, deviceID, "device", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	if !deviceChangeFailed(w, h.store.DeleteNativeDevice(deviceID, user.ID, deleted.Row)) {
		deleted.Committed()
		writeDeviceSuccess(w)
	}
}

// SetDeviceMFAApprover enables/disables a device as an MFA approver. Either direction
// changes which phone can approve sign-ins, so it costs a step-up grant.
func (h *DeviceHandler) SetDeviceMFAApprover(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	deviceID := r.PathValue("id")
	var req struct {
		IsMFAApprover bool `json:"isMfaApprover"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	if err := consumeStepUp(h.store, r); err != nil {
		writeStepUpError(w, err)
		return
	}

	changed := h.audit.Prepare("device.mfa_approver_changed", user.ID, user.Username, deviceID, "device", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"isMfaApprover": req.IsMFAApprover})
	if !deviceChangeFailed(w, h.store.SetNativeDeviceMFAApprover(deviceID, user.ID, req.IsMFAApprover, changed.Row)) {
		changed.Committed()
		writeDeviceSuccess(w)
	}
}

// SetDeviceSignOn enables/disables a device as a sign-on device. Both directions cost a
// step-up grant: one rule is simpler to reason about than a per-direction one.
func (h *DeviceHandler) SetDeviceSignOn(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	deviceID := r.PathValue("id")
	var req struct {
		CanSignOn bool `json:"canSignOn"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	if err := consumeStepUp(h.store, r); err != nil {
		writeStepUpError(w, err)
		return
	}

	details := map[string]any{"canSignOn": req.CanSignOn}
	changed := h.audit.Prepare("device.sign_on_changed", user.ID, user.Username, deviceID, "device", h.middleware.ClientIP(r), r.UserAgent(), "success", details)
	err := h.store.SetNativeDeviceCanSignOn(deviceID, user.ID, req.CanSignOn, changed.Row)
	if deviceChangeFailed(w, err) {
		h.audit.Observe("device.sign_on_changed", user.ID, user.Username, deviceID, "device", h.middleware.ClientIP(r), r.UserAgent(), "failure", details)
		return
	}
	changed.Committed()
	writeDeviceSuccess(w)
}

// deviceChangeFailed writes the error response for a failed device mutation.
func deviceChangeFailed(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, sql.ErrNoRows):
		http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
	case errors.Is(err, store.ErrDeviceNotApprover):
		http.Error(w, `{"error":"device_not_approver"}`, http.StatusConflict)
	case errors.Is(err, store.ErrLastCompliantFactor):
		enrollmentError(w, err)
	default:
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
	}
	return true
}

func writeDeviceSuccess(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// SetupTOTP generates a new TOTP secret and QR/URI.
func (h *DeviceHandler) SetupTOTP(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	// Checked but not spent: this only mints a candidate secret, and failing here rather
	// than after the operator has scanned a QR code is the better experience.
	if err := requireStepUp(h.store, r); err != nil {
		writeStepUpError(w, err)
		return
	}

	secret, uri, err := h.mfaEngine.GenerateTOTPSecret(user.Username, "KyIdentity")
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"secret": secret,
		"uri":    uri,
	})
}

type EnableTOTPRequest struct {
	Secret string `json:"secret"`
	Code   string `json:"code"`
}

// EnableTOTP validates the code and persists the TOTP secret.
func (h *DeviceHandler) EnableTOTP(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var req EnableTOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Secret == "" || req.Code == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	// A code generated by this request's own secret proves nothing about the account holder,
	// so entitlement comes from the step-up grant, not from the code below.
	if err := consumeStepUp(h.store, r); err != nil {
		writeStepUpError(w, err)
		return
	}

	if !mfa.ValidateTOTP(req.Secret, req.Code) {
		http.Error(w, `{"error":"invalid_code","error_description":"TOTP code verification failed"}`, http.StatusBadRequest)
		return
	}

	// Enrolling a factor and the record of who enrolled it commit together. An account that
	// gained an authenticator with no durable trail of where it came from is exactly the
	// state an attacker who has borrowed a session wants to leave behind.
	enabled := h.audit.Prepare("mfa.totp_enabled", user.ID, user.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	if err := h.mfaEngine.SaveUserTOTP(user.ID, req.Secret, enabled.Row); err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	enabled.Committed()

	issued := h.audit.Prepare("mfa.recovery_codes_generated", user.ID, user.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"reason": "totp_enrollment"})
	recoveryCodes, err := h.mfaEngine.GenerateRecoveryCodes(user.ID, issued.Row)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	issued.Committed()

	// Replacing a factor logs out every other session. If this replacement was an attacker
	// with a stolen cookie, the legitimate user keeps nothing; if it was the legitimate
	// user, the stolen cookie is what gets cut.
	if sess := GetSessionFromContext(r.Context()); sess != nil {
		if err := h.store.RevokeOtherSessions(user.ID, sess.ID, nil); err != nil {
			log.Printf("failed to revoke sibling sessions after TOTP replacement for %s: %v", user.ID, err)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success":       true,
		"recoveryCodes": recoveryCodes,
	})
}

// GenerateRecoveryCodes generates 8 new recovery codes for user.
func (h *DeviceHandler) GenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	// Regenerating invalidates the codes the account holder is already storing offline, so
	// it is a factor change and gated the same way.
	if err := consumeStepUp(h.store, r); err != nil {
		writeStepUpError(w, err)
		return
	}

	regenerated := h.audit.Prepare("mfa.recovery_codes_generated", user.ID, user.Username, user.ID, "user", h.middleware.ClientIP(r), r.UserAgent(), "success", nil)
	codes, err := h.mfaEngine.GenerateRecoveryCodes(user.ID, regenerated.Row)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	regenerated.Committed()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"recoveryCodes": codes,
	})
}

// ssoLoginPaths maps a suite client to the endpoint that starts its SSO handshake, so the
// launcher lands the user signed in rather than on a login form. Anything not listed opens
// at its origin.
var ssoLoginPaths = map[string]string{
	"kydns":       "/auth/sso/login",
	"kypost":      "/api/auth/oidc/login",
	"kypasswords": "/api/auth/oidc/login",
	"kybookmarks": "/api/auth/oidc/login",
	"kynotes":     "/api/auth/oidc/login",
	"kycalendar":  "/api/sso/kysignon/login",
	"kydrive":     "/api/sso/kysignon/login",
	"kymessage":   "/api/sso/kyidentity/login",
}

// clientRedirectOrigin is the origin of the client's first redirect URI, preferring one
// off localhost, plus the parsed URIs.
func clientRedirectOrigin(client store.OAuthClient) (string, []string) {
	var uris []string
	_ = json.Unmarshal([]byte(client.RedirectURIsJSON), &uris)
	origin := ""
	for _, uStr := range uris {
		if parsed, err := url.Parse(uStr); err == nil && parsed.Scheme != "" && parsed.Host != "" {
			if origin == "" || (strings.Contains(origin, "localhost") && !strings.Contains(parsed.Host, "localhost")) {
				origin = fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
			}
		}
	}
	return origin, uris
}

// clientLaunchURL is where a client's card opens: its launch URL, else its redirect origin
// plus its SSO start path, else its first redirect URI. Empty means not launchable.
func clientLaunchURL(client store.OAuthClient) string {
	if launchURL := strings.TrimSpace(client.LaunchURL); launchURL != "" {
		return launchURL
	}
	origin, uris := clientRedirectOrigin(client)
	switch {
	case origin != "":
		return origin + ssoLoginPaths[strings.ToLower(client.ID)]
	case len(uris) > 0:
		return uris[0]
	}
	return ""
}

// launcherApps lists the enabled custom cards and OAuth clients whose key allow admits, in
// launcher order, under each client's launcher name. A card for admins only shows when
// admin holds its client ID (nil for no viewer). The launcher and the suite directory both
// read it; neither audience nor name changes access.
func launcherApps(st *store.Store, allow func(key string) bool, admin map[string]bool) ([]store.Application, error) {
	customApps, err := st.ListApplications()
	if err != nil {
		return nil, err
	}
	oauthClients, err := st.ListOAuthClients()
	if err != nil {
		oauthClients = []store.OAuthClient{}
	}

	result := make([]store.Application, 0, len(customApps)+len(oauthClients))
	for _, app := range customApps {
		if app.Enabled && allow("custom:"+app.ID) {
			app.Source = "custom"
			app.Key = "custom:" + app.ID
			result = append(result, app)
		}
	}

	// Registered OAuth clients are launchable too. What they look like on the launcher is
	// whatever an admin set on the client; an undescribed card carries no description rather
	// than a generated one, because "OAuth 2.0 / OIDC SSO App (confidential)" restates the
	// page title and tells the user nothing about the app.
	for _, client := range oauthClients {
		if !client.Enabled || !allow("client:"+client.ID) || client.LauncherAudience == store.LauncherAdmins && !admin[client.ID] {
			continue
		}
		launchURL := clientLaunchURL(client)
		if launchURL == "" {
			continue
		}
		iconName := client.IconName
		if iconName == "" {
			iconName = "favicon"
		}
		result = append(result, store.Application{
			Source:      "client",
			Key:         "client:" + client.ID,
			ID:          client.ID,
			Name:        cmp.Or(client.LauncherName, client.ClientName),
			URL:         launchURL,
			IconName:    iconName,
			Description: client.Description,
			Enabled:     true,
		})
	}

	// Without this the launcher reshuffles on every page load despite sort_order existing.
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].SortOrder != result[j].SortOrder {
			return result[i].SortOrder < result[j].SortOrder
		}
		return result[i].Name < result[j].Name
	})
	return result, nil
}

// ListApplications returns dashboard application links, aggregating custom applications and registered OAuth clients.
func (h *DeviceHandler) ListApplications(w http.ResponseWriter, r *http.Request) {
	userID := GetUserFromContext(r.Context()).ID
	allowed, err := h.store.LauncherAppAccess(userID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	admin, err := h.store.LauncherAdminClients(userID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	result, err := launcherApps(h.store, func(key string) bool { return allowed[key] }, admin)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	prefs, err := h.store.GetLauncherPrefs(userID)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"applications": result, "preferences": prefs})
}

// PutLauncherPrefs saves how the caller arranges their own launcher. It changes no access,
// so it needs no step-up and leaves no audit entry.
func (h *DeviceHandler) PutLauncherPrefs(w http.ResponseWriter, r *http.Request) {
	var prefs store.LauncherPrefs
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&prefs); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	err := h.store.SetLauncherPrefs(GetUserFromContext(r.Context()).ID, prefs)
	if errors.Is(err, store.ErrInvalidLauncherPrefs) {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *DeviceHandler) DeleteLauncherPrefs(w http.ResponseWriter, r *http.Request) {
	if err := h.store.DeleteLauncherPrefs(GetUserFromContext(r.Context()).ID); err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
