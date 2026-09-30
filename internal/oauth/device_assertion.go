package oauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// deviceAssertion is the RFC 7523 assertion a paired KyAuth device signs with its
// enrolled P-256 key to sign in to a suite app. Only the fields the grant checks.
type deviceAssertion struct {
	DeviceID  string
	Subject   string
	Audience  string
	ClientID  string
	JTI       string
	IssuedAt  int64
	ExpiresAt int64
}

const maxAssertionLen = 4096

// parseDeviceAssertion splits a compact JWS and pins the header to exactly what
// KyAuth emits. It verifies nothing about the signature; that needs the device row.
func parseDeviceAssertion(compact string) (*deviceAssertion, []byte, []byte, error) {
	if len(compact) > maxAssertionLen {
		return nil, nil, nil, errors.New("assertion too long")
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, nil, nil, errors.New("assertion is not a compact JWS")
	}
	headerJSON, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil {
		return nil, nil, nil, errors.New("bad header encoding")
	}
	var header map[string]json.RawMessage
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, nil, nil, errors.New("bad header")
	}
	var alg, typ, kid string
	_ = json.Unmarshal(header["alg"], &alg)
	_ = json.Unmarshal(header["typ"], &typ)
	_ = json.Unmarshal(header["kid"], &kid)
	if alg != "ES256" || typ != "JWT" || kid == "" || len(header) != 3 {
		return nil, nil, nil, errors.New("header must be exactly alg=ES256, typ=JWT, kid")
	}
	claimsJSON, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return nil, nil, nil, errors.New("bad claims encoding")
	}
	var c struct {
		Iss      string `json:"iss"`
		Sub      string `json:"sub"`
		Aud      string `json:"aud"`
		ClientID string `json:"client_id"`
		JTI      string `json:"jti"`
		Iat      int64  `json:"iat"`
		Exp      int64  `json:"exp"`
	}
	if err := json.Unmarshal(claimsJSON, &c); err != nil {
		return nil, nil, nil, errors.New("bad claims")
	}
	if c.Iss != "device:"+kid {
		return nil, nil, nil, errors.New("iss does not name the kid device")
	}
	if c.Sub == "" || c.Aud == "" || c.ClientID == "" || c.JTI == "" || c.Iat == 0 || c.Exp == 0 {
		return nil, nil, nil, errors.New("missing claim")
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil {
		return nil, nil, nil, errors.New("bad signature encoding")
	}
	a := &deviceAssertion{DeviceID: kid, Subject: c.Sub, Audience: c.Aud, ClientID: c.ClientID, JTI: c.JTI, IssuedAt: c.Iat, ExpiresAt: c.Exp}
	return a, []byte(parts[0] + "." + parts[1]), sig, nil
}

// verifyES256 checks a JWS raw r||s signature over signingInput. DER input is
// refused by length; r and s outside [1, n) are refused before the curve math.
func verifyES256(pub *ecdsa.PublicKey, signingInput, sig []byte) bool {
	if pub == nil || pub.Curve != elliptic.P256() || len(sig) != 64 {
		return false
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	n := elliptic.P256().Params().N
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(n) >= 0 || s.Cmp(n) >= 0 {
		return false
	}
	digest := sha256.Sum256(signingInput)
	return ecdsa.Verify(pub, digest[:], r, s)
}

const (
	deviceAssertionMaxWindow = 300 * time.Second
	deviceAssertionSkew      = 60 * time.Second
)

// DeviceSignOnActor names the authenticated device and its user, for audit.
type DeviceSignOnActor struct {
	DeviceID string
	UserID   string
	Username string
}

var ErrDeviceSignOnDisabled = errors.New("device sign-on is disabled")

// Refusal reasons. The handler maps all of them to invalid_grant; they exist for
// audit and tests.
var (
	errAssertionClient    = errors.New("client_id does not match the assertion")
	errAssertionAudience  = errors.New("assertion audience is not this token endpoint")
	errAssertionFuture    = errors.New("assertion issued in the future")
	errAssertionExpired   = errors.New("assertion expired")
	errAssertionWindow    = errors.New("assertion validity window invalid")
	errUnknownDevice      = errors.New("unknown device for subject")
	errAssertionSignature = errors.New("assertion signature invalid")
	errAssertionReplay    = errors.New("assertion replayed")
	errUnknownClient      = errors.New("unknown client")
	errUserInactive       = errors.New("user not found or inactive")
	errAppPolicy          = errors.New("app sign-in policy not satisfied")
	errNoOpenIDScope      = errors.New("client may not be granted the openid scope")
)

// beforeDeviceTokenRecord is a test seam between policy evaluation and token registration.
var beforeDeviceTokenRecord = func() {}

// ExchangeDeviceAssertion is the RFC 7523 jwt-bearer grant for a paired KyAuth device.
// The assertion is the client authentication: the device's enrolled key is the only
// thing that can produce it, so no client_secret is required for this grant. The
// returned identity is empty until the signature has verified, and Username is
// filled once the user row is loaded.
func (e *Engine) ExchangeDeviceAssertion(compact, clientID, ip, userAgent string) (*TokenResponse, DeviceSignOnActor, error) {
	a, input, sig, err := parseDeviceAssertion(compact)
	if err != nil {
		return nil, DeviceSignOnActor{}, err
	}
	now := time.Now().UTC()
	iat, assertionExp := time.Unix(a.IssuedAt, 0), time.Unix(a.ExpiresAt, 0)
	switch {
	case a.ClientID != clientID:
		return nil, DeviceSignOnActor{}, errAssertionClient
	case a.Audience != e.issuerURL+"/oauth/token":
		return nil, DeviceSignOnActor{}, errAssertionAudience
	case iat.After(now.Add(deviceAssertionSkew)):
		return nil, DeviceSignOnActor{}, errAssertionFuture
	case assertionExp.Before(now.Add(-deviceAssertionSkew)):
		return nil, DeviceSignOnActor{}, errAssertionExpired
	case !assertionExp.After(iat) || assertionExp.Sub(iat) > deviceAssertionMaxWindow:
		return nil, DeviceSignOnActor{}, errAssertionWindow
	}
	dev, err := e.store.GetNativeDevice(a.DeviceID)
	if err != nil {
		return nil, DeviceSignOnActor{}, err
	}
	if dev == nil || dev.UserID != a.Subject || dev.PublicKey == "" {
		return nil, DeviceSignOnActor{}, errUnknownDevice
	}
	pub, err := crypto.ParseP256PublicKey(dev.PublicKey)
	if err != nil || !verifyES256(pub, input, sig) {
		return nil, DeviceSignOnActor{}, errAssertionSignature
	}
	// Past this point the device is authenticated, so its identity is safe to audit.
	who := DeviceSignOnActor{DeviceID: dev.ID, UserID: dev.UserID}
	if !dev.CanSignOn || !dev.IsMFAApprover {
		return nil, who, ErrDeviceSignOnDisabled
	}
	client, err := e.store.GetOAuthClientByID(clientID)
	if err != nil {
		return nil, who, err
	}
	if client == nil || !client.Enabled {
		return nil, who, errUnknownClient
	}
	fresh, err := e.store.ConsumeDeviceSignOnJTI(a.JTI, assertionExp.Add(deviceAssertionSkew))
	if err != nil {
		return nil, who, err
	}
	if !fresh {
		return nil, who, errAssertionReplay
	}
	user, err := e.store.GetUserByID(a.Subject)
	if err != nil {
		return nil, who, err
	}
	if user == nil || user.Status != "active" {
		return nil, who, errUserInactive
	}
	who.Username = user.Username
	scope, err := e.GrantedScope(clientID, "openid profile email")
	if err != nil {
		return nil, who, err
	}
	if !hasScope(scope, "openid") {
		return nil, who, errNoOpenIDScope
	}
	// Single factor: nothing proves the device key is hardware-bound or user-verified,
	// so mfa_session_access and factor-requiring app policies refuse this session.
	evidence := store.AuthenticationEvidence{PrimaryAuthenticatedAt: &now}
	policy, binding, err := e.store.ClientAuthenticationPolicyBinding(clientID)
	if err != nil {
		return nil, who, err
	}
	if !policy.Valid() || policy.EvidenceReason(evidence, now) != "" {
		return nil, who, errAppPolicy
	}
	exp := now.Add(AccessTokenTTL)
	if end, err := e.store.AccessEndsAt(user.ID, clientID); err != nil {
		return nil, who, err
	} else if end != nil && end.Before(exp) {
		exp = *end
	}
	if at := policy.Deadline(evidence); at != nil && at.Before(exp) {
		exp = *at
	}
	if !exp.After(now) {
		return nil, who, errAppPolicy
	}

	// A device login session: no browser holds its token (the hash preimage is
	// discarded); it exists so sid, EnsureClientSession and back-channel logout
	// treat this sign-in like any other.
	sess := &store.Session{
		ID: uuid.NewString(), UserID: user.ID, SessionTokenHash: crypto.HashSHA256(uuid.NewString()),
		IPAddress: ip, UserAgent: userAgent, ExpiresAt: now.Add(AccessTokenTTL), CreatedAt: now, LastActiveAt: now,
		AuthenticationEvidence: evidence,
	}
	if err := e.store.CreateSession(sess); err != nil {
		return nil, who, err
	}
	issued := false
	defer func() {
		if !issued {
			_ = e.store.DeleteSession(sess.ID)
		}
	}()
	accessJTI := uuid.NewString()
	beforeDeviceTokenRecord()
	// Binding the evaluated revisions refuses the token if a policy or role edit landed since.
	if err := e.store.RecordIssuedToken(&store.IssuedToken{JTI: accessJTI, UserID: user.ID, ClientID: clientID, ExpiresAt: exp, SessionID: sess.ID, Policy: binding}); err != nil {
		return nil, who, fmt.Errorf("failed to record issued token: %w", err)
	}
	accessToken, err := e.keyManager.SignJWT(map[string]any{
		"iss": e.issuerURL, "sub": user.ID, "aud": clientID, "exp": exp.Unix(), "iat": now.Unix(),
		"jti": accessJTI, "scope": scope, "token_use": "access_token",
	})
	if err != nil {
		return nil, who, fmt.Errorf("failed to sign access token: %w", err)
	}
	sid, err := e.store.EnsureClientSession(clientID, sess.ID, user.ID)
	if err != nil {
		return nil, who, fmt.Errorf("failed to bind session to client: %w", err)
	}
	claims, err := e.identityClaims(user, clientID, scope)
	if err != nil {
		return nil, who, err
	}
	claims["sid"] = sid
	claims["iss"] = e.issuerURL
	claims["aud"] = clientID
	claims["exp"] = exp.Unix()
	claims["iat"] = now.Unix()
	claims["jti"] = uuid.NewString()
	claims["token_use"] = "id_token"
	claims["auth_time"] = now.Unix()
	claims["amr"] = []string{"hwk"}
	claims["acr"] = DeviceACR
	claims["signon_method"] = "device"
	claims["device_id"] = dev.ID
	idToken, err := e.keyManager.SignJWT(claims)
	if err != nil {
		return nil, who, fmt.Errorf("failed to sign ID token: %w", err)
	}
	issued = true
	_ = e.store.TouchNativeDeviceLastSeen(dev.ID, now)
	return &TokenResponse{AccessToken: accessToken, TokenType: "Bearer", ExpiresIn: int(exp.Sub(now).Seconds()), IDToken: idToken, Scope: scope}, who, nil
}
