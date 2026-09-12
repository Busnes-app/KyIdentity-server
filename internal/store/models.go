package store

import (
	"time"
)

type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	DisplayName  string    `json:"displayName"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"`   // "user", "admin"
	Status       string    `json:"status"` // "active", "disabled"
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

// AuthenticationEvidence records server-verified login facts. Nil timestamps mean
// unknown (legacy sessions), never the time a session or token happened to be issued.
type AuthenticationEvidence struct {
	PrimaryAuthenticatedAt *time.Time `json:"-"`
	FactorAuthenticatedAt  *time.Time `json:"-"`
	FactorMethod           string     `json:"-"` // "", "totp", "push", "webauthn", "recovery"
}

type Session struct {
	AuthenticationEvidence
	ID               string    `json:"id"`
	UserID           string    `json:"userId"`
	SessionTokenHash string    `json:"-"`
	IPAddress        string    `json:"ipAddress"`
	UserAgent        string    `json:"userAgent"`
	ExpiresAt        time.Time `json:"expiresAt"`
	CreatedAt        time.Time `json:"createdAt"`
	LastActiveAt     time.Time `json:"lastActiveAt"`
}

type PairedSystem struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	SystemType  string `json:"systemType"` // "kypost", "kypasswords", "kybookmarks", "kynotes", "scim", "custom"
	Description string `json:"description,omitempty"`
	IconURL     string `json:"iconUrl,omitempty"`
	CallbackURL string `json:"callbackUrl"`
	// HMACSecretEncrypted holds the Bearer API token/signing secret under the deployment encryption key.
	HMACSecretEncrypted string     `json:"-"`
	Status              string     `json:"status"` // "active", "failing", "disabled"
	LastSyncedAt        *time.Time `json:"lastSyncedAt,omitempty"`
	CreatedAt           time.Time  `json:"createdAt"`
	// GroupsEnabled delivers SCIM Groups; only generic SCIM connectors may opt in.
	GroupsEnabled bool `json:"groupsEnabled"`
	// ReconcileHours schedules a repair reconciliation at this interval; 0 disables it.
	ReconcileHours int `json:"reconcileHours"`
}

type AccountSyncEvent struct {
	ClaimToken  string `json:"-"`
	ID          string `json:"id"`
	UserID      string `json:"userId"`
	SystemID    string `json:"systemId"`
	EventType   string `json:"eventType"` // user.created|updated|deleted|mfa_reset, group.updated|deleted
	PayloadJSON string `json:"payloadJson"`
	// Revision is the resource's monotonic desired-state counter when this event was queued.
	Revision    int        `json:"revision"`
	Attempts    int        `json:"attempts"`
	Status      string     `json:"status"` // "pending", "delivered", "failed"
	LastError   string     `json:"lastError,omitempty"`
	NextAttempt *time.Time `json:"nextAttemptAt,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
}

type NativeDevice struct {
	ID                   string     `json:"id"`
	UserID               string     `json:"userId"`
	DeviceName           string     `json:"deviceName"`
	DeviceIdentifier     string     `json:"deviceIdentifier"`
	Platform             string     `json:"platform"`
	PublicKey            string     `json:"publicKey,omitempty"`
	PushToken            string     `json:"pushToken,omitempty"`
	PushTokenUpdatedAtMS int64      `json:"-"`
	IsMFAApprover        bool       `json:"isMfaApprover"`
	LastSeenAt           *time.Time `json:"lastSeenAt,omitempty"`
	CreatedAt            time.Time  `json:"createdAt"`
}

type DevicePairingToken struct {
	ID        string     `json:"id"`
	UserID    string     `json:"userId"`
	TokenHash string     `json:"-"`
	PINHash   string     `json:"-"`
	ExpiresAt time.Time  `json:"expiresAt"`
	UsedAt    *time.Time `json:"usedAt,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
}

type MFAMethod struct {
	ID              string    `json:"id"`
	UserID          string    `json:"userId"`
	MethodType      string    `json:"methodType"` // "totp", "push"
	EncryptedSecret string    `json:"-"`
	IsPrimary       bool      `json:"isPrimary"`
	CreatedAt       time.Time `json:"createdAt"`
}

type MFAChallenge struct {
	VerifiedAt      *time.Time `json:"-"`
	ID              string     `json:"id"`
	UserID          string     `json:"userId"`
	MethodType      string     `json:"methodType"`
	MatchDigits     string     `json:"matchDigits"`
	DecoyDigitsJSON string     `json:"decoyDigitsJson"`
	Status          string     `json:"status"` // "pending", "approved", "denied", "expired"
	ExpiresAt       time.Time  `json:"expiresAt"`
	CreatedAt       time.Time  `json:"createdAt"`
}

// MFAToken is a single-use, server-side bearer token issued after primary password
// verification and redeemed by exactly one second-factor completion.
type MFAToken struct {
	InteractionHash        string     `json:"-"`
	PrimaryAuthenticatedAt *time.Time `json:"-"`
	ID                     string     `json:"id"`
	UserID                 string     `json:"userId"`
	TokenHash              string     `json:"-"`
	ChallengeID            string     `json:"challengeId,omitempty"`
	Attempts               int        `json:"-"`
	ExpiresAt              time.Time  `json:"expiresAt"`
	UsedAt                 *time.Time `json:"usedAt,omitempty"`
	CreatedAt              time.Time  `json:"createdAt"`
}

type RecoveryCode struct {
	ID        string     `json:"id"`
	UserID    string     `json:"userId"`
	CodeHash  string     `json:"-"`
	UsedAt    *time.Time `json:"usedAt,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
}

type OAuthClient struct {
	ID                string    `json:"id"`
	ClientName        string    `json:"clientName"`
	ClientType        string    `json:"clientType"` // "public", "confidential"
	ClientSecretHash  string    `json:"-"`
	RedirectURIsJSON  string    `json:"redirectUrisJson"`
	AllowedScopesJSON string    `json:"allowedScopesJson"`
	LaunchURL         string    `json:"launchUrl,omitempty"`
	Description       string    `json:"description,omitempty"`
	IconName          string    `json:"iconName,omitempty"`
	Enabled           bool      `json:"enabled"`
	CreatedAt         time.Time `json:"createdAt"`
}

type AuthorizationCode struct {
	AuthenticationAppID          string     `json:"-"`
	AuthenticationPolicyRevision int        `json:"-"`
	InteractionHash              string     `json:"-"`
	AuthenticationExpiresAt      *time.Time `json:"-"`
	AuthenticationEvidence
	SessionID           string     `json:"-"`
	ID                  string     `json:"id"`
	CodeHash            string     `json:"-"`
	ClientID            string     `json:"clientId"`
	UserID              string     `json:"userId"`
	RedirectURI         string     `json:"redirectUri"`
	Scope               string     `json:"scope"`
	CodeChallenge       string     `json:"codeChallenge"`
	CodeChallengeMethod string     `json:"codeChallengeMethod"`
	Nonce               string     `json:"-"`
	ExpiresAt           time.Time  `json:"expiresAt"`
	UsedAt              *time.Time `json:"usedAt,omitempty"`
	CreatedAt           time.Time  `json:"createdAt"`
}

// IssuedToken records an access token so it can be revoked before it expires.
type IssuedToken struct {
	AuthorizationCodeID string     `json:"-"` // Checked at registration, not stored.
	SessionID           string     `json:"-"`
	JTI                 string     `json:"jti"`
	UserID              string     `json:"userId"`
	ClientID            string     `json:"clientId"`
	ExpiresAt           time.Time  `json:"expiresAt"`
	RevokedAt           *time.Time `json:"revokedAt,omitempty"`
	CreatedAt           time.Time  `json:"createdAt"`
}

type Application struct {
	// Source is derived when the launcher is assembled, not stored: "custom" for a row in
	// this table, "client" for a card synthesised from a registered OAuth client. The
	// dashboard needs it to know which endpoint edits the card.
	Source      string    `json:"source,omitempty"`
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	IconName    string    `json:"iconName"`
	Description string    `json:"description,omitempty"`
	SortOrder   int       `json:"sortOrder"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"createdAt"`
}

// LauncherIcon is an admin-uploaded image a launcher card names as "icon:<id>".
type LauncherIcon struct {
	ID          string
	ContentType string
	Data        []byte
	CreatedAt   time.Time
}

type AuditEvent struct {
	ID            string    `json:"id"`
	ActorID       string    `json:"actorId,omitempty"`
	ActorUsername string    `json:"actorUsername,omitempty"`
	Action        string    `json:"action"`
	TargetID      string    `json:"targetId,omitempty"`
	TargetType    string    `json:"targetType,omitempty"`
	IPAddress     string    `json:"ipAddress"`
	UserAgent     string    `json:"userAgent"`
	Outcome       string    `json:"outcome"` // "success", "failure", "denied"
	DetailsJSON   string    `json:"detailsJson,omitempty"`
	CreatedAt     time.Time `json:"createdAt"`
}

// StepUpToken is a short-lived, single-use grant proving the live session just re-proved the
// account's own credentials.
type StepUpToken struct {
	Operation    string     `json:"-"`
	FactorMethod string     `json:"-"`
	ID           string     `json:"id"`
	UserID       string     `json:"userId"`
	SessionID    string     `json:"sessionId"`
	TokenHash    string     `json:"-"`
	ExpiresAt    time.Time  `json:"expiresAt"`
	UsedAt       *time.Time `json:"usedAt,omitempty"`
	CreatedAt    time.Time  `json:"createdAt"`
}

// WebAuthnCredential is one enrolled passkey. The public key is stored SPKI DER,
// base64url-encoded; there is no secret here, so it is not encrypted at rest.
type WebAuthnCredential struct {
	ID            string `json:"id"`
	UserID        string `json:"userId"`
	CredentialID  string `json:"credentialId"`
	PublicKeySPKI string `json:"-"`
	SignCount     uint32 `json:"-"`
	Name          string `json:"name"`
	// BackupEligible reports whether the authenticator may sync this credential to a
	// provider cloud; BackupState whether it currently is. Recorded and surfaced, and also
	// gates signature-counter enforcement at login (internal/webauthn.VerifyAssertion):
	// backup-eligible credentials are exempt so a sibling device reporting a lower counter
	// after a cloud sync isn't locked out permanently.
	BackupEligible bool       `json:"backupEligible"`
	BackupState    bool       `json:"backupState"`
	LastUsedAt     *time.Time `json:"lastUsedAt,omitempty"`
	CreatedAt      time.Time  `json:"createdAt"`
}

// WebAuthnChallenge is a single-use nonce bound to one user and one ceremony.
type WebAuthnChallenge struct {
	ID        string     `json:"id"`
	UserID    string     `json:"userId"`
	Challenge string     `json:"-"`
	Purpose   string     `json:"purpose"` // "register", "authenticate"
	ExpiresAt time.Time  `json:"expiresAt"`
	UsedAt    *time.Time `json:"usedAt,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
}
