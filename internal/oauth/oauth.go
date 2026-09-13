package oauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Busness-app/kysignon-server/internal/crypto"
	"github.com/Busness-app/kysignon-server/internal/store"
	"github.com/google/uuid"
)

// AccessTokenTTL bounds how long an access token is honoured. Downstream services that
// validate tokens offline against JWKS cannot observe a revocation until it elapses, so
// this is deliberately short. Services that need immediate revocation must call
// /oauth/userinfo, which consults the revocation list on every request.
const AccessTokenTTL = 15 * time.Minute

// AuthorizationCodeTTL bounds the window between the authorize redirect and the exchange.
const AuthorizationCodeTTL = 60 * time.Second

type Engine struct {
	store      *store.Store
	keyManager *crypto.JWTKeyManager
	issuerURL  string
}

func NewEngine(s *store.Store, km *crypto.JWTKeyManager, issuerURL string) *Engine {
	return &Engine{
		store:      s,
		keyManager: km,
		issuerURL:  issuerURL,
	}
}

// OIDCConfiguration returns RFC 8414 / OpenID Connect Discovery metadata.
type OIDCConfiguration struct {
	ACRValuesSupported               []string `json:"acr_values_supported"`
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
	JwksURI                          string   `json:"jwks_uri"`
	RevocationEndpoint               string   `json:"revocation_endpoint,omitempty"`
	EndSessionEndpoint               string   `json:"end_session_endpoint"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                  []string `json:"scopes_supported"`
	TokenEndpointAuthMethods         []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
}

// SupportsRevocation reports whether /oauth/revoke actually invalidates a token. Discovery
// only advertises the endpoint when this is true.
func (e *Engine) SupportsRevocation() bool { return true }

func (e *Engine) GetOIDCConfiguration() OIDCConfiguration {
	cfg := OIDCConfiguration{
		ACRValuesSupported:               []string{PasswordACR, MFAACR},
		Issuer:                           e.issuerURL,
		AuthorizationEndpoint:            e.issuerURL + "/oauth/authorize",
		TokenEndpoint:                    e.issuerURL + "/oauth/token",
		UserinfoEndpoint:                 e.issuerURL + "/oauth/userinfo",
		JwksURI:                          e.issuerURL + "/.well-known/jwks.json",
		ResponseTypesSupported:           []string{"code"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ScopesSupported:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethods:         []string{"client_secret_post", "client_secret_basic", "none"},
		CodeChallengeMethodsSupported:    []string{"S256"},
		EndSessionEndpoint:               e.issuerURL + "/oauth/logout",
		ClaimsSupported: []string{"sub", "iss", "aud", "exp", "iat", "jti", "nonce", "auth_time", "amr", "acr", "sid",
			"preferred_username", "name", "email", "role"},
	}
	if e.SupportsRevocation() {
		cfg.RevocationEndpoint = e.issuerURL + "/oauth/revoke"
	}
	return cfg
}

func (e *Engine) GetJWKS() crypto.JWKS {
	return e.keyManager.GetJWKS()
}

// ValidatePKCE checks a code_verifier against the recorded challenge. Only S256 is
// accepted: under "plain" the challenge is the verifier, so anyone who observes the
// authorize request can complete the exchange.
func ValidatePKCE(verifier, challenge, method string) bool {
	if method != "S256" || verifier == "" || challenge == "" {
		return false
	}
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

// ValidateRedirectURI reports whether uri is byte-for-byte one of the client's registered
// redirect URIs.
//
// There are deliberately no host aliases, no port families, no trailing-slash tolerance,
// and no per-client fallbacks. Every one of those turns registration into a suggestion,
// and a redirect URI is the only thing deciding who receives an authorization code. A
// deployment that needs three ports registers three URIs.
func (e *Engine) ValidateRedirectURI(client *store.OAuthClient, uri string) bool {
	if client == nil {
		return false
	}
	return registeredExactly(client.RedirectURIsJSON, uri)
}

// ValidatePostLogoutRedirectURI applies the same exact-match rule to the URIs a client
// registered for RP-initiated logout.
func (e *Engine) ValidatePostLogoutRedirectURI(client *store.OAuthClient, uri string) bool {
	if client == nil {
		return false
	}
	return registeredExactly(client.PostLogoutRedirectURIsJSON, uri)
}

func registeredExactly(registeredJSON, uri string) bool {
	if uri == "" {
		return false
	}
	var registered []string
	if err := json.Unmarshal([]byte(registeredJSON), &registered); err != nil {
		return false
	}
	for _, candidate := range registered {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(uri)) == 1 {
			return true
		}
	}
	return false
}

// GrantedScope intersects the requested scope with the client's registered allowlist and
// returns what may actually be granted. Requesting a scope a client is not entitled to
// never widens the grant.
func (e *Engine) GrantedScope(clientID, requested string) (string, error) {
	client, err := e.store.GetOAuthClientByID(clientID)
	if err != nil {
		return "", err
	}
	if client == nil {
		return "", errors.New("unknown client")
	}

	var allowed []string
	if err := json.Unmarshal([]byte(client.AllowedScopesJSON), &allowed); err != nil {
		return "", fmt.Errorf("client %s has a malformed scope allowlist: %w", clientID, err)
	}
	permitted := make(map[string]bool, len(allowed))
	for _, s := range allowed {
		permitted[strings.TrimSpace(s)] = true
	}

	var granted []string
	seen := map[string]bool{}
	for _, s := range strings.Fields(requested) {
		if permitted[s] && !seen[s] {
			seen[s] = true
			granted = append(granted, s)
		}
	}
	if len(granted) == 0 {
		return "", errors.New("none of the requested scopes are permitted for this client")
	}
	return strings.Join(granted, " "), nil
}

// CreateAuthorizationCode creates a short-lived, single-use authorization code.
func (e *Engine) CreateAuthorizationCode(clientID, sessionID, redirectURI, scope, challenge, method string) (string, error) {
	return e.CreateAuthorizationCodeWithNonce(clientID, sessionID, redirectURI, scope, challenge, method, "")
}

// CreateAuthorizationCodeWithNonce is CreateAuthorizationCode plus the OIDC nonce, which
// is echoed into the ID token so a client can detect replay.
func (e *Engine) CreateAuthorizationCodeWithNonce(clientID, sessionID, redirectURI, scope, challenge, method, nonce string) (string, error) {
	return e.CreateAuthorizationCodeForInteraction(clientID, sessionID, redirectURI, scope, challenge, method, nonce, AuthenticationRequest{}, "")
}

func (e *Engine) CreateAuthorizationCodeForInteraction(clientID, sessionID, redirectURI, scope, challenge, method, nonce string, requirements AuthenticationRequest, interactionHash string) (string, error) {
	client, err := e.store.GetOAuthClientByID(clientID)
	if err != nil {
		return "", err
	}
	if client == nil || !client.Enabled {
		return "", errors.New("invalid or disabled client")
	}

	// A public client presents no secret, so PKCE is the only thing binding this code to
	// the party that requested it. Refuse to mint a code that nothing can bind.
	if client.ClientType == "public" && challenge == "" {
		return "", errors.New("PKCE is required for public clients")
	}
	if challenge != "" && method != "S256" {
		return "", fmt.Errorf("unsupported code_challenge_method %q; only S256 is accepted", method)
	}

	session, err := e.store.GetSessionByID(sessionID)
	if err != nil {
		return "", err
	}
	if session == nil {
		return "", errors.New("active session required")
	}
	policy, err := e.store.ClientAuthenticationPolicy(clientID)
	if err != nil {
		return "", err
	}
	requirements = requirements.WithAppPolicy(policy)
	if interactionHash != "" {
		requirements.Fresh = false
	}
	if !requirements.Satisfied(session.AuthenticationEvidence, time.Now().UTC()) {
		return "", store.ErrAppAuthentication
	}
	rawCode, err := crypto.GenerateRandomHex(32)
	if err != nil {
		return "", err
	}

	item := &store.AuthorizationCode{
		InteractionHash:        interactionHash,
		SessionID:              session.ID,
		AuthenticationEvidence: session.AuthenticationEvidence,
		ID:                     uuid.New().String(),
		CodeHash:               crypto.HashSHA256(rawCode),
		ClientID:               clientID,
		UserID:                 session.UserID,
		RedirectURI:            redirectURI,
		Scope:                  scope,
		CodeChallenge:          challenge,
		CodeChallengeMethod:    method,
		Nonce:                  nonce,
		ExpiresAt:              time.Now().UTC().Add(AuthorizationCodeTTL),
	}
	if requirements.MaxAge != nil {
		until := session.PrimaryAuthenticatedAt.Add(time.Duration(*requirements.MaxAge) * time.Second)
		item.AuthenticationExpiresAt = &until
	}
	if err := e.store.CreateAuthorizationCode(item); err != nil {
		return "", err
	}
	return rawCode, nil
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token,omitempty"`
	Scope       string `json:"scope,omitempty"`
}

// authenticateClient verifies the caller is entitled to act as clientID.
func (e *Engine) authenticateClient(client *store.OAuthClient, clientSecret string) error {
	switch client.ClientType {
	case "confidential":
		if client.ClientSecretHash == "" {
			return errors.New("confidential client has no secret configured; re-register it")
		}
		presented := crypto.HashSHA256(clientSecret)
		if subtle.ConstantTimeCompare([]byte(presented), []byte(client.ClientSecretHash)) != 1 {
			return errors.New("invalid client secret")
		}
		return nil
	case "public":
		return nil
	default:
		return fmt.Errorf("unknown client type %q", client.ClientType)
	}
}

// ExchangeAuthorizationCode validates the code, the client, the redirect URI and the PKCE
// verifier, then issues an access token and, for the openid scope, an ID token.
func (e *Engine) ExchangeAuthorizationCode(codeStr, clientID, clientSecret, redirectURI, codeVerifier string) (*TokenResponse, error) {
	authCode, err := e.store.GetValidAuthorizationCode(crypto.HashSHA256(codeStr))
	if err != nil {
		return nil, err
	}
	if authCode == nil {
		return nil, errors.New("invalid or expired authorization code")
	}

	// Every binding is checked before the code is spent. Consuming first would let anyone
	// holding the code burn it with a junk verifier, denying the legitimate client its
	// login; single-use is preserved by the compare-and-swap below, not by ordering.
	if subtle.ConstantTimeCompare([]byte(authCode.ClientID), []byte(clientID)) != 1 {
		return nil, errors.New("client mismatch")
	}

	client, err := e.store.GetOAuthClientByID(clientID)
	if err != nil {
		return nil, err
	}
	if client == nil || !client.Enabled {
		return nil, errors.New("invalid or disabled client")
	}
	if err := e.authenticateClient(client, clientSecret); err != nil {
		return nil, err
	}

	if subtle.ConstantTimeCompare([]byte(authCode.RedirectURI), []byte(redirectURI)) != 1 {
		return nil, errors.New("redirect uri mismatch")
	}

	// Public clients must always prove possession of the verifier; a stored challenge is
	// always enforced regardless of client type.
	if client.ClientType == "public" || authCode.CodeChallenge != "" {
		if !ValidatePKCE(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
			return nil, errors.New("invalid PKCE code verifier")
		}
	}

	// Now that the caller has proven entitlement, spend the code. The compare-and-swap is
	// what makes this single-use; a read followed by an unconditional write is a race that
	// hands the same code to every concurrent caller.
	spent, err := e.store.ConsumeAuthorizationCode(authCode.ID)
	if err != nil {
		return nil, err
	}
	if !spent {
		return nil, errors.New("authorization code has already been redeemed")
	}

	user, err := e.store.GetUserByID(authCode.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil || user.Status != "active" {
		return nil, errors.New("user not found or inactive")
	}

	now := time.Now().UTC()
	exp := now.Add(AccessTokenTTL)
	accessJTI := uuid.New().String()

	// Register the token before handing it out, so revocation has something to revoke.
	if err := e.store.RecordIssuedToken(&store.IssuedToken{
		AuthorizationCodeID: authCode.ID, JTI: accessJTI, UserID: user.ID, ClientID: clientID, ExpiresAt: exp, SessionID: authCode.SessionID,
	}); err != nil {
		return nil, fmt.Errorf("failed to record issued token: %w", err)
	}

	accessToken, err := e.keyManager.SignJWT(map[string]any{
		"iss":       e.issuerURL,
		"sub":       user.ID,
		"aud":       clientID,
		"exp":       exp.Unix(),
		"iat":       now.Unix(),
		"jti":       accessJTI,
		"scope":     authCode.Scope,
		"token_use": "access_token",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	var idToken string
	if hasScope(authCode.Scope, "openid") {
		sid, err := e.store.EnsureClientSession(clientID, authCode.SessionID, user.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to bind session to client: %w", err)
		}
		claims := map[string]any{
			"sid":                sid,
			"iss":                e.issuerURL,
			"sub":                user.ID,
			"aud":                clientID,
			"exp":                exp.Unix(),
			"iat":                now.Unix(),
			"jti":                uuid.New().String(),
			"token_use":          "id_token",
			"username":           user.Username,
			"preferred_username": user.Username,
			"name":               user.DisplayName,
			"email":              user.Email,
			"role":               user.Role,
		}
		addAuthenticationClaims(claims, authCode.AuthenticationEvidence)
		if authCode.Nonce != "" {
			claims["nonce"] = authCode.Nonce
		}
		idToken, err = e.keyManager.SignJWT(claims)
		if err != nil {
			return nil, fmt.Errorf("failed to sign ID token: %w", err)
		}
	}

	return &TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(AccessTokenTTL.Seconds()),
		IDToken:     idToken,
		Scope:       authCode.Scope,
	}, nil
}

// hasScope reports whether scope contains the exact space-delimited value. A substring
// test would match "not-openid-really".
func hasScope(scope, want string) bool {
	for _, s := range strings.Fields(scope) {
		if s == want {
			return true
		}
	}
	return false
}

// verifyAccessToken validates a bearer token as an access token issued by this server and
// still present on the revocation list.
func (e *Engine) verifyAccessToken(tokenString string) (map[string]any, error) {
	claims, err := e.keyManager.VerifyJWT(tokenString)
	if err != nil {
		return nil, err
	}
	if claims["token_use"] != "access_token" {
		return nil, errors.New("token is not an access token")
	}
	if claims["iss"] != e.issuerURL {
		return nil, errors.New("token was issued by a different issuer")
	}

	jti, _ := claims["jti"].(string)
	if jti == "" {
		return nil, errors.New("token has no jti claim")
	}
	revoked, err := e.store.IsTokenRevoked(jti)
	if err != nil {
		return nil, err
	}
	if revoked {
		return nil, errors.New("token has been revoked")
	}
	return claims, nil
}

// GetUserinfo returns OIDC profile claims for a valid, unrevoked access token.
func (e *Engine) GetUserinfo(tokenString string) (map[string]any, error) {
	claims, err := e.verifyAccessToken(tokenString)
	if err != nil {
		return nil, err
	}

	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return nil, errors.New("missing sub claim in token")
	}

	user, err := e.store.GetUserByID(sub)
	if err != nil {
		return nil, err
	}
	if user == nil || user.Status != "active" {
		return nil, errors.New("user not found or inactive")
	}

	return map[string]any{
		"sub":                user.ID,
		"username":           user.Username,
		"preferred_username": user.Username,
		"name":               user.DisplayName,
		"email":              user.Email,
		"email_verified":     true,
		"role":               user.Role,
	}, nil
}

// RevokeToken implements RFC 7009. The caller must authenticate as the client the token
// was issued to; otherwise anyone could revoke anyone else's sessions.
func (e *Engine) RevokeToken(tokenString, clientID, clientSecret string) error {
	client, err := e.store.GetOAuthClientByID(clientID)
	if err != nil {
		return err
	}
	if client == nil || !client.Enabled {
		return errors.New("invalid or disabled client")
	}
	if err := e.authenticateClient(client, clientSecret); err != nil {
		return err
	}

	// RFC 7009 §2.2: an invalid token is not an error, to avoid an oracle. Only an
	// unauthenticated caller is rejected, and that already happened above.
	claims, err := e.keyManager.VerifyJWT(tokenString)
	if err != nil {
		return nil
	}
	if claims["aud"] != clientID {
		return nil
	}
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return nil
	}
	return e.store.RevokeToken(jti)
}
