package sync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Busness-app/ky-primitives/scim"
	"github.com/Busness-app/ky-primitives/syncauth"
	"github.com/Busness-app/kysignon-server/internal/crypto"
	"github.com/Busness-app/kysignon-server/internal/netguard"
	"github.com/Busness-app/kysignon-server/internal/store"
	"github.com/google/uuid"
)

type Engine struct {
	store         *store.Store
	httpClient    *http.Client
	encryptionKey []byte
}

func NewEngine(s *store.Store, encryptionKey []byte) *Engine {
	return &Engine{
		store:         s,
		encryptionKey: encryptionKey,
		httpClient:    netguard.Client(5 * time.Second),
	}
}

// ValidateCallbackURL rejects anything the server should not be made to POST the user
// directory at.
func ValidateCallbackURL(raw string) error {
	return netguard.ValidateURL(raw, "callbackUrl")
}

// SigningSecret recovers the encrypted connector credential (signing secret or SCIM Bearer token).
func (e *Engine) SigningSecret(sys *store.PairedSystem) (string, error) {
	if sys.HMACSecretEncrypted == "" {
		return "", errors.New("paired system has no signing secret; re-pair it")
	}
	plain, err := crypto.DecryptAESGCM(e.encryptionKey, sys.HMACSecretEncrypted)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt signing secret for %s: %w", sys.Name, err)
	}
	return string(plain), nil
}

// The store computes each connector's desired state from effective access inside the
// mutation transaction; these wrappers exist so handlers keep one entry point.
func (e *Engine) CreateUserAndQueueSyncEvents(user *store.User, audit *store.AuditEvent) error {
	return e.store.CreateUserWithSyncEvents(user, audit)
}

func (e *Engine) UpdateUserAndQueueSyncEvents(user *store.User, revokeAccess bool, audit *store.AuditEvent) error {
	return e.store.UpdateUserWithSyncEvents(user, revokeAccess, audit)
}

// ResetUserMFAAndRevoke atomically strips every factor, revokes everything those factors
// were protecting, and notifies every connector holding the account.
func (e *Engine) ResetUserMFAAndRevoke(userID string, audit *store.AuditEvent) error {
	return e.store.ResetUserMFA(userID, audit)
}

// DeleteUserAndQueueSyncEvents removes a user and queues its deletion atomically, so a
// downstream product cannot retain an account when the source deletion succeeds.
func (e *Engine) DeleteUserAndQueueSyncEvents(userID string, audit *store.AuditEvent) error {
	return e.store.DeleteUserWithSyncEvents(userID, audit)
}

// SCIM Schema URIs and standard types (RFC 7643 / RFC 7644)
const (
	SCIMUserSchema = "urn:ietf:params:scim:schemas:core:2.0:User"
)

type SCIMName struct {
	Formatted  string `json:"formatted,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
}

type SCIMEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary"`
}

type SCIMRole struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary"`
}

type SCIMMeta struct {
	ResourceType string     `json:"resourceType"`
	Created      *time.Time `json:"created,omitempty"`
	LastModified *time.Time `json:"lastModified,omitempty"`
	Location     string     `json:"location,omitempty"`
	// Version carries the resource's monotonic revision to suite receivers as a weak
	// ETag, so a receiver can refuse a write older than one it already applied.
	Version string `json:"version,omitempty"`
}

type SCIMUserResource struct {
	Schemas     []string    `json:"schemas"`
	ID          string      `json:"id"`
	ExternalID  string      `json:"externalId,omitempty"`
	UserName    string      `json:"userName"`
	DisplayName string      `json:"displayName,omitempty"`
	Name        *SCIMName   `json:"name,omitempty"`
	Emails      []SCIMEmail `json:"emails,omitempty"`
	Roles       []SCIMRole  `json:"roles,omitempty"`
	Active      bool        `json:"active"`
	Meta        *SCIMMeta   `json:"meta,omitempty"`
}

// UserToSCIMResource converts an internal KySignOn user into a standard SCIM 2.0 User resource.
func UserToSCIMResource(u *store.User) *SCIMUserResource {
	if u == nil {
		return nil
	}
	res := &SCIMUserResource{
		Schemas:     []string{SCIMUserSchema},
		ID:          u.ID,
		ExternalID:  u.ID,
		UserName:    u.Username,
		DisplayName: u.DisplayName,
		Name: &SCIMName{
			Formatted: u.DisplayName,
		},
		Active: u.Status == "active",
		Meta: &SCIMMeta{
			ResourceType: "User",
			Created:      &u.CreatedAt,
			LastModified: &u.UpdatedAt,
		},
	}
	if u.Email != "" {
		res.Emails = []SCIMEmail{
			{
				Value:   u.Email,
				Type:    "work",
				Primary: true,
			},
		}
	}
	if u.Role != "" {
		res.Roles = []SCIMRole{
			{
				Value:   u.Role,
				Primary: true,
			},
		}
	}
	return res
}

// FormatUserAsSCIM parses arbitrary user payload data into a SCIM 2.0 User resource.
func FormatUserAsSCIM(userPayload any) (*SCIMUserResource, error) {
	if userPayload == nil {
		return nil, errors.New("nil user payload")
	}
	switch v := userPayload.(type) {
	case *SCIMUserResource:
		return v, nil
	case SCIMUserResource:
		return &v, nil
	case *store.User:
		return UserToSCIMResource(v), nil
	case store.User:
		return UserToSCIMResource(&v), nil
	default:
		data, err := json.Marshal(userPayload)
		if err != nil {
			return nil, err
		}
		var temp struct {
			Schemas     []string `json:"schemas"`
			ID          string   `json:"id"`
			UserName    string   `json:"userName"`
			DisplayName string   `json:"displayName"`
			Email       string   `json:"email"`
			Username    string   `json:"username"`
			Role        string   `json:"role"`
			Status      string   `json:"status"`
			Active      *bool    `json:"active"`
		}
		if err := json.Unmarshal(data, &temp); err != nil {
			return nil, err
		}
		if len(temp.Schemas) > 0 {
			var scimRes SCIMUserResource
			if err := json.Unmarshal(data, &scimRes); err == nil {
				return &scimRes, nil
			}
		}
		uname := temp.UserName
		if uname == "" {
			uname = temp.Username
		}
		active := true
		if temp.Active != nil {
			active = *temp.Active
		} else if temp.Status != "" {
			active = (temp.Status == "active")
		}

		res := &SCIMUserResource{
			Schemas:     []string{SCIMUserSchema},
			ID:          temp.ID,
			ExternalID:  temp.ID,
			UserName:    uname,
			DisplayName: temp.DisplayName,
			Name: &SCIMName{
				Formatted: temp.DisplayName,
			},
			Active: active,
			Meta: &SCIMMeta{
				ResourceType: "User",
			},
		}
		if temp.Email != "" {
			res.Emails = []SCIMEmail{
				{Value: temp.Email, Type: "work", Primary: true},
			}
		}
		if temp.Role != "" {
			res.Roles = []SCIMRole{
				{Value: temp.Role, Primary: true},
			}
		}
		return res, nil
	}
}

type SyncWebhookPayload struct {
	Schemas     []string        `json:"schemas,omitempty"`
	ID          string          `json:"id,omitempty"`
	EventID     string          `json:"eventId"`
	EventType   string          `json:"eventType"`
	Timestamp   string          `json:"timestamp"`
	User        json.RawMessage `json:"user"`
	UserName    string          `json:"userName,omitempty"`
	DisplayName string          `json:"displayName,omitempty"`
	Name        *SCIMName       `json:"name,omitempty"`
	Emails      []SCIMEmail     `json:"emails,omitempty"`
	Roles       []SCIMRole      `json:"roles,omitempty"`
	Active      bool            `json:"active"`
	Meta        *SCIMMeta       `json:"meta,omitempty"`
}

type CreateSystemRequest struct {
	Name        string `json:"name"`
	SystemType  string `json:"systemType"`
	Description string `json:"description,omitempty"`
	IconURL     string `json:"iconUrl,omitempty"`
	CallbackURL string `json:"callbackUrl"`
	BearerToken string `json:"bearerToken,omitempty"`
}

// CreateSystem stores a supplied SCIM token or generates a suite webhook signing secret.
func (e *Engine) CreateSystem(req *CreateSystemRequest) (*store.PairedSystem, string, error) {
	if req.Name == "" {
		req.Name = req.SystemType
	}
	if req.Name == "" {
		return nil, "", errors.New("name is required")
	}
	if req.SystemType == "" {
		req.SystemType = "scim"
	}
	if err := ValidateCallbackURL(req.CallbackURL); err != nil {
		return nil, "", err
	}

	if !supportedSystemType(req.SystemType) {
		return nil, "", errors.New("select scim or suite_webhook explicitly for a custom service")
	}
	token := req.BearerToken
	var err error
	if req.SystemType == "scim" {
		if err = validateSCIMConfig(req.CallbackURL, token); err != nil {
			return nil, "", err
		}
	} else {
		if token != "" {
			return nil, "", errors.New("suite webhooks use a generated signing secret")
		}
		token, err = crypto.GenerateRandomHex(32)
		if err != nil {
			return nil, "", err
		}
	}

	encrypted, err := crypto.EncryptAESGCM(e.encryptionKey, []byte(token))
	if err != nil {
		return nil, "", fmt.Errorf("failed to encrypt bearer token: %w", err)
	}

	ps := &store.PairedSystem{
		ID:                  uuid.New().String(),
		Name:                req.Name,
		SystemType:          req.SystemType,
		Description:         req.Description,
		IconURL:             req.IconURL,
		CallbackURL:         req.CallbackURL,
		HMACSecretEncrypted: encrypted,
		Status:              "active",
	}
	if err := e.store.CreatePairedSystem(ps); err != nil {
		return nil, "", err
	}
	if req.SystemType == "scim" {
		return ps, "", nil
	}
	return ps, token, nil
}

// retryDelay is exponential with a ceiling, so a system that is down is not hammered every
// tick until its attempt budget runs out.
func retryDelay(attempts int) time.Duration {
	delay := time.Duration(1<<attempts) * 30 * time.Second
	if delay > 30*time.Minute {
		delay = 30 * time.Minute
	}
	return delay
}

// deliveryLease bounds unsent claims. Once delivery begins, its durable resource
// fence survives this deadline until a known outcome or operator recovery.
const deliveryLease = 60 * time.Second

// DispatchPendingEvents delivers due events to the system each was queued for.
//
// Events are claimed before any network I/O. Reading without claiming let two dispatchers —
// overlapping ticks, or two instances during a rolling deploy — both deliver the same
// user.created and create duplicate downstream accounts.
func (e *Engine) DispatchPendingEvents(ctx context.Context) error {
	events, err := e.store.ClaimDueSyncEvents(50, deliveryLease)
	if err != nil || len(events) == 0 {
		return err
	}

	// Cache systems and their decrypted secrets for this pass.
	systems := map[string]*store.PairedSystem{}
	secrets := map[string]string{}

	for _, ev := range events {
		begun, err := e.store.BeginSyncDelivery(ev, deliveryLease)
		if err != nil {
			return err
		}
		if !begun {
			continue
		}

		sys, ok := systems[ev.SystemID]
		if !ok {
			sys, err = e.store.GetPairedSystemByID(ev.SystemID)
			if err != nil {
				_ = e.store.FinishSyncDelivery(ev, "pending", "", ev.Attempts, ev.NextAttempt)
				return err
			}
			systems[ev.SystemID] = sys
			if sys != nil {
				if secret, serr := e.SigningSecret(sys); serr == nil {
					secrets[ev.SystemID] = secret
				}
			}
		}

		// A system that has been deleted can never receive this event. Anything else stays
		// queued: "nobody is listening yet" is not the same as "delivered".
		if sys == nil {
			if err := e.store.FinishSyncDelivery(ev, "failed", "paired system no longer exists", ev.Attempts, nil); err != nil {
				return err
			}
			continue
		}
		if sys.Status == "disabled" || !supportedSystemType(sys.SystemType) {
			if err := e.store.FinishSyncDelivery(ev, "pending", "", ev.Attempts, ev.NextAttempt); err != nil {
				return err
			}
			continue
		}
		secret, ok := secrets[ev.SystemID]
		if !ok {
			next := time.Now().UTC().Add(retryDelay(ev.Attempts))
			if err := e.store.FinishSyncDelivery(ev, "pending", "signing secret unavailable", ev.Attempts+1, &next); err != nil {
				return err
			}
			continue
		}

		var scimUser *SCIMUserResource
		if !strings.HasPrefix(ev.EventType, "group.") {
			scimUser, _ = FormatUserAsSCIM(json.RawMessage(ev.PayloadJSON))
		}
		// Scoped to this event on purpose. Assigning to the function-scoped err let a
		// marshal failure on one event survive into the next iteration and fail an event
		// that was perfectly deliverable.
		var payloadBytes []byte
		var merr error
		if scimUser != nil {
			if scimUser.Meta == nil {
				scimUser.Meta = &SCIMMeta{ResourceType: "User"}
			}
			scimUser.Meta.Version = fmt.Sprintf(`W/"%d"`, ev.Revision)
			payloadBytes, merr = json.Marshal(scimUser)
		} else {
			payloadBytes = []byte(ev.PayloadJSON)
		}
		if merr != nil {
			if serr := e.store.FinishSyncDelivery(ev, "failed", merr.Error(), ev.Attempts+1, nil); serr != nil {
				return serr
			}
			continue
		}

		// Clone the client so simultaneous dispatchers never share outcome tracking.
		delivery := *e
		client := *e.httpClient
		transport := client.Transport
		if transport == nil {
			transport = http.DefaultTransport
		}
		outcome := &deliveryTransport{base: transport}
		client.Transport = outcome
		delivery.httpClient = &client
		if derr := delivery.deliver(ctx, sys, secret, ev.ID, ev.EventType, ev.UserID, payloadBytes); derr != nil {
			if outcome.uncertain.Load() {
				// Keep the fence even after the lease expires. The remote may still
				// commit this write after a newer write would otherwise be sent.
				if err := e.store.MarkSyncDeliveryUncertain(ev); err != nil {
					return err
				}
				continue
			}
			attempts := ev.Attempts + 1
			if attempts >= 5 {
				if serr := e.store.FinishSyncDelivery(ev, "failed", deliveryError(derr), attempts, nil); serr != nil {
					return serr
				}
			} else {
				delay := retryDelay(ev.Attempts)
				var remoteErr *scim.Error
				if errors.As(derr, &remoteErr) {
					delay = max(delay, remoteErr.RetryAfter)
				}
				next := time.Now().UTC().Add(delay)
				if serr := e.store.FinishSyncDelivery(ev, "pending", deliveryError(derr), attempts, &next); serr != nil {
					return serr
				}
			}
			continue
		}

		// Persist acknowledgment and release the resource in one transaction.
		if serr := e.store.FinishSyncDelivery(ev, "delivered", "", ev.Attempts+1, nil); serr != nil {
			return serr
		}
	}

	return nil
}

// resolveSCIMURL calculates the RESTful SCIM 2.0 route and HTTP method according to RFC 7644.
func resolveSCIMURL(sys *store.PairedSystem, eventType, userID string) (method string, targetURL string, isBodyRequired bool) {
	trimmed := strings.TrimRight(sys.CallbackURL, "/")
	if sys.SystemType == "kybookmarks" {
		// The historical UI preset named a conventional SCIM path even though
		// KyBookmarks implements the suite's signed webhook. Normalize stored
		// preset rows as well as new ones so upgrades do not require re-pairing.
		if u, err := url.Parse(trimmed); err == nil && strings.TrimRight(u.Path, "/") == "/scim/v2" {
			u.Path = "/api/sync/events"
			u.RawPath = ""
			trimmed = u.String()
		}
		return http.MethodPost, trimmed, true
	}

	// For legacy webhooks, default to POST callback URL directly
	return http.MethodPost, trimmed, true
}

func (e *Engine) deliver(ctx context.Context, sys *store.PairedSystem, secret, eventID, eventType, userID string, payload []byte) error {
	if strings.HasPrefix(eventType, "group.") {
		if sys.SystemType != "scim" || !sys.GroupsEnabled {
			return errors.New("group delivery is not enabled for this connector")
		}
		return e.deliverSCIMGroup(ctx, sys, secret, eventType, userID)
	}
	if sys.SystemType == "scim" {
		return e.deliverSCIM(ctx, sys, secret, eventType, userID, payload)
	}
	if !supportedSystemType(sys.SystemType) {
		return errors.New("connector protocol requires administrator review")
	}
	method, targetURL, isBodyRequired := resolveSCIMURL(sys, eventType, userID)

	var bodyReader *bytes.Reader
	var signPayload []byte
	if isBodyRequired && payload != nil {
		bodyReader = bytes.NewReader(payload)
		signPayload = payload
	} else {
		bodyReader = bytes.NewReader(nil)
		signPayload = []byte{}
	}

	headers, err := syncauth.Sign([]byte(secret), time.Now().UTC(), eventType, eventID, signPayload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, method, targetURL, bodyReader)
	if err != nil {
		return err
	}
	if isBodyRequired {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	req.Header.Set("Accept", "application/scim+json, application/json")
	headers.Apply(req)
	// A stable key per queued event. Retries reuse it, so a recipient that saw the request
	// but whose response was lost can recognise the replay instead of acting twice.
	req.Header.Set("Idempotency-Key", eventID)

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("system %s error: %w", sys.Name, err)
	}
	defer resp.Body.Close()

	// Preserve suite webhook acknowledgments: already-gone deletion or deactivation,
	// and a create the receiver already holds.
	var body struct{ Active *bool }
	_ = json.Unmarshal(payload, &body)
	inactive := body.Active != nil && !*body.Active
	if (resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusNoContent) ||
		((eventType == "user.deleted" || (eventType == "user.updated" && inactive)) && resp.StatusCode == http.StatusNotFound) ||
		(eventType == "user.created" && resp.StatusCode == http.StatusConflict) {
		return nil
	}

	return fmt.Errorf("system %s returned status %d", sys.Name, resp.StatusCode)
}

// ResyncAllAccounts re-sends every in-scope account and group to one paired system.
func (e *Engine) ResyncAllAccounts(systemID string) error {
	return e.store.ResyncSystem(systemID)
}

// StartWorker runs the background sync dispatcher. The slower reconcile tick catches
// effective-access changes that arrived through cascades rather than a mutation path.
func (e *Engine) StartWorker(ctx context.Context) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	reconcile := time.NewTicker(time.Minute)
	defer reconcile.Stop()
	go e.reconcileWorker(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-reconcile.C:
			if err := e.store.ReconcileProvisioning(); err != nil && ctx.Err() == nil {
				log.Printf("provisioning reconcile failed: %v", err)
			}
			if err := e.store.ScheduleReconcileJobs(time.Now().UTC()); err != nil && ctx.Err() == nil {
				log.Printf("reconciliation scheduling failed: %v", err)
			}
		case <-ticker.C:
			if err := e.DispatchPendingEvents(ctx); err != nil && ctx.Err() == nil {
				// Delivery failures are recorded per event; this is the local persistence
				// layer failing. An attempt already begun remains fenced for recovery;
				// only unsent claims become available when their leases expire.
				log.Printf(`{"level":"ERROR","component":"sync","error":%q}`, err.Error())
			}
		}
	}
}
