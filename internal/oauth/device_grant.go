package oauth

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// RFC 8628 device authorization grant, for workstation apps only.

const DeviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// userCodeAlphabet is RFC 8628 §6.1's consonant set: no vowels, no look-alikes.
const userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

const userCodeLength = 8

// Token-endpoint outcomes of a device-code poll, named as RFC 8628 §3.5 errors.
var (
	ErrAuthorizationPending = errors.New("authorization_pending")
	ErrSlowDown             = errors.New("slow_down")
	ErrAccessDenied         = errors.New("access_denied")
	ErrExpiredToken         = errors.New("expired_token")
	// ErrDeviceCodeReplayed: the code was already redeemed; the caller ends its session.
	ErrDeviceCodeReplayed = errors.New("device code already redeemed")
	ErrDeviceGrantInvalid = errors.New("invalid device code")
)

// Approval refusals the /device screen explains.
var (
	ErrDeviceApprovalAccess    = errors.New("no access to this app")
	ErrDeviceApprovalSignIn    = errors.New("this app needs a newer or stronger sign-in")
	ErrDeviceApprovalSetup     = errors.New("finish MFA enrollment or the password change first")
	ErrDeviceApprovalNotLive   = errors.New("code expired or already used")
	ErrDeviceGrantNotAvailable = store.ErrDeviceGrantUnavailable
)

type DeviceAuthorization struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// SetUserCodeKey derives the user-code HMAC key from the server secret. User codes are
// short, so a plain hash would fall to an offline search of a database copy.
func (e *Engine) SetUserCodeKey(secret []byte) {
	e.userCodeKey = crypto.DeriveKey(secret, "kyidentity:device-user-code")
}

// NormalizeUserCode upper-cases and drops separators; ok is false unless the result is
// exactly userCodeLength characters of the alphabet.
func NormalizeUserCode(in string) (string, bool) {
	var b strings.Builder
	for _, r := range strings.ToUpper(in) {
		switch {
		case r == '-' || r == ' ':
		case strings.ContainsRune(userCodeAlphabet, r):
			b.WriteRune(r)
		default:
			return "", false
		}
	}
	return b.String(), b.Len() == userCodeLength
}

// UserCodeHash is the stored form of a user code; ok is false for a malformed code.
func (e *Engine) UserCodeHash(code string) (string, bool) {
	norm, ok := NormalizeUserCode(code)
	if !ok || len(e.userCodeKey) == 0 {
		return "", false
	}
	return crypto.SignHMACSHA256(e.userCodeKey, []byte(norm)), true
}

func newUserCode() (string, error) {
	out := make([]byte, userCodeLength)
	for i := range out {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(userCodeAlphabet))))
		if err != nil {
			return "", err
		}
		out[i] = userCodeAlphabet[n.Int64()]
	}
	return string(out[:4]) + "-" + string(out[4:]), nil
}

// IssueDeviceCode starts a device grant for an enabled workstation app with the grant on.
func (e *Engine) IssueDeviceCode(clientID, scope, ip, userAgent string) (*DeviceAuthorization, string, error) {
	if len(e.userCodeKey) == 0 {
		return nil, "", errors.New("device grant has no user-code key")
	}
	ws, err := e.store.GetWorkstationApp(clientID)
	if err != nil {
		return nil, "", err
	}
	if ws == nil || !ws.Enabled || !ws.DeviceGrantEnabled {
		return nil, "", ErrDeviceGrantNotAvailable
	}
	if strings.TrimSpace(scope) == "" {
		scope = "openid"
	}
	granted, err := e.GrantedScope(clientID, scope)
	if err != nil {
		return nil, "", ErrInvalidScope
	}
	device, err := crypto.GenerateRandomHex(32)
	if err != nil {
		return nil, "", err
	}
	for attempt := 0; ; attempt++ {
		user, err := newUserCode()
		if err != nil {
			return nil, "", err
		}
		hash, _ := e.UserCodeHash(user)
		d := &store.DeviceCode{ID: uuid.NewString(), ClientID: clientID, DeviceCodeHash: crypto.HashSHA256(device), UserCodeHash: hash,
			Scope: granted, IPAddress: ip, UserAgent: userAgent, Interval: store.DeviceCodeInterval,
			ExpiresAt: time.Now().UTC().Add(time.Duration(ws.DeviceCodeTTL) * time.Second)}
		err = e.store.CreateDeviceCode(d)
		if err != nil && attempt < 3 && strings.Contains(strings.ToLower(err.Error()), "unique") {
			continue // a live user code collided; draw again
		}
		if err != nil {
			return nil, "", err
		}
		uri := e.issuerURL + "/device"
		return &DeviceAuthorization{DeviceCode: device, UserCode: user, VerificationURI: uri,
			VerificationURIComplete: uri + "?user_code=" + user, ExpiresIn: ws.DeviceCodeTTL, Interval: d.Interval}, d.ID, nil
	}
}

// ErrInvalidScope: none of the requested scopes is permitted for the client.
var ErrInvalidScope = errors.New("invalid_scope")

// DecideDeviceCode records the signed-in user's decision on a pending code. Approval
// re-checks the app, the user's access, enrollment, a required password change and the
// app's authentication policy against this browser session's evidence. The app's "fresh"
// policy is met by a sign-in made after the device asked for its code.
func (e *Engine) DecideDeviceCode(d *store.DeviceCode, user *store.User, sess *store.Session, approve bool, audit *store.AuditEvent) error {
	if !approve {
		return e.store.DecideDeviceCode(d.ID, false, sess, store.AppPolicyBinding{}, audit)
	}
	ws, err := e.store.GetWorkstationApp(d.ClientID)
	if err != nil {
		return err
	}
	if ws == nil || !ws.Enabled || !ws.DeviceGrantEnabled {
		return ErrDeviceGrantNotAvailable
	}
	// The /device screen carries no interaction to prove a password was typed for this code.
	if ws.RequirePassword {
		return ErrDeviceApprovalSignIn
	}
	if allowed, err := e.store.ClientAccessAllowed(user.ID, d.ClientID); err != nil {
		return err
	} else if !allowed {
		return ErrDeviceApprovalAccess
	}
	enrollment, err := e.store.SessionEnrollmentStatus(user.ID, sess.ID)
	if err != nil {
		return err
	}
	if enrollment.Restricted || user.PasswordChangeRequired {
		return ErrDeviceApprovalSetup
	}
	policy, binding, err := e.store.ClientAuthenticationPolicyBinding(d.ClientID)
	if err != nil {
		return err
	}
	ev := sess.AuthenticationEvidence
	if policy.EvidenceReason(ev, time.Now().UTC()) != "" ||
		(policy.Mode == "fresh" && (ev.PrimaryAuthenticatedAt == nil || ev.PrimaryAuthenticatedAt.Before(d.CreatedAt))) {
		return ErrDeviceApprovalSignIn
	}
	if err := e.store.DecideDeviceCode(d.ID, true, sess, binding, audit); errors.Is(err, store.ErrNotFound) {
		return ErrDeviceApprovalNotLive
	} else if err != nil {
		return err
	}
	return nil
}

// PollDeviceCode answers one token-endpoint poll. On success the code is spent and a
// workstation session created; when the app's offline window is above zero a refresh
// token comes with it. The returned code row (nil when unknown) is for the audit and,
// on ErrDeviceCodeReplayed, for ending the session it created.
func (e *Engine) PollDeviceCode(raw, clientID, ip, userAgent string) (*TokenResponse, *store.DeviceCode, error) {
	d, tooFast, err := e.store.PollDeviceCode(crypto.HashSHA256(raw))
	if err != nil {
		return nil, nil, err
	}
	if d == nil || subtle.ConstantTimeCompare([]byte(d.ClientID), []byte(clientID)) != 1 {
		return nil, nil, ErrDeviceGrantInvalid
	}
	if d.RedeemedAt != nil {
		return nil, d, ErrDeviceCodeReplayed
	}
	now := time.Now().UTC()
	if !now.Before(d.ExpiresAt) {
		return nil, d, ErrExpiredToken
	}
	ws, err := e.store.GetWorkstationApp(clientID)
	if err != nil {
		return nil, d, err
	}
	if ws == nil || !ws.Enabled || !ws.DeviceGrantEnabled {
		return nil, d, ErrDeviceGrantNotAvailable
	}
	switch d.Status {
	case "pending":
		if tooFast {
			return nil, d, ErrSlowDown
		}
		return nil, d, ErrAuthorizationPending
	case "denied":
		return nil, d, ErrAccessDenied
	}
	user, err := e.store.PrincipalByID(d.UserID)
	if err != nil {
		return nil, d, err
	}
	if user == nil || user.Status != "active" {
		return nil, d, ErrDeviceGrantInvalid
	}
	sessionEnd, err := e.workstationSessionEnd(ws, user.ID, d.AuthenticationEvidence, now)
	if errors.Is(err, store.ErrAppAuthentication) {
		return nil, d, ErrDeviceGrantInvalid
	} else if err != nil {
		return nil, d, err
	}
	exp := now.Add(AccessTokenTTL)
	if sessionEnd.Before(exp) {
		exp = sessionEnd
	}
	sessionSecret, err := crypto.GenerateRandomHex(32)
	if err != nil {
		return nil, d, err
	}
	// The session's token is never handed out: it cannot be a browser cookie.
	sess := &store.Session{ID: uuid.NewString(), SessionTokenHash: crypto.HashSHA256("workstation:" + sessionSecret), IPAddress: ip, UserAgent: userAgent, ExpiresAt: sessionEnd}
	access := &store.IssuedToken{JTI: uuid.NewString(), UserID: user.ID, ClientID: clientID, ExpiresAt: exp}
	var family *store.RefreshFamily
	var refresh string
	if ws.OfflineWindow > 0 {
		if refresh, err = crypto.GenerateRandomHex(32); err != nil {
			return nil, d, err
		}
		family = &store.RefreshFamily{JTI: uuid.NewString(), UserID: user.ID, ClientID: clientID, Scope: d.Scope,
			AuthenticationEvidence: d.AuthenticationEvidence, Policy: d.Policy, Idle: sessionEnd.Sub(now), ExpiresAt: sessionEnd}
		access.FamilyJTI = family.JTI
	}
	if err := e.store.RedeemDeviceCode(d, sess, access, family, crypto.HashSHA256(refresh)); err != nil {
		if errors.Is(err, store.ErrAppAccessDenied) {
			return nil, d, ErrDeviceGrantInvalid
		}
		return nil, d, err
	}
	d.SessionID = sess.ID
	resp, err := e.tokenResponse(user, clientID, sess.ID, d.Scope, d.AuthenticationEvidence, "", access.JTI, exp, now)
	if err != nil {
		return nil, d, fmt.Errorf("device grant tokens: %w", err)
	}
	resp.RefreshToken = refresh
	return resp, d, nil
}
