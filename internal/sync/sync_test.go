package sync

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/syncauth"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/netguard"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// queueForAll enqueues one event per active connector directly, bypassing scope, so
// wire-format tests can exercise delivery without configuring assignments.
func queueForAll(t *testing.T, e *Engine, userID, eventType string, payload any) {
	t.Helper()
	systems, err := e.store.ListAllPairedSystems()
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, sys := range systems {
		if sys.Status == "disabled" {
			continue
		}
		insertSyncEvent(t, e.store, store.AccountSyncEvent{ID: uuid.NewString(), UserID: userID, SystemID: sys.ID, EventType: eventType, PayloadJSON: string(body), Status: "pending", Revision: 1})
	}
}

// syncTestDBs maps a fixture's store to its file, so a test can write rows no production
// path writes on its own: a bare outbox event, a disabled connector.
var syncTestDBs = map[*store.Store]string{}

func execRaw(t *testing.T, s *store.Store, query string, args ...any) {
	t.Helper()
	path, ok := syncTestDBs[s]
	if !ok {
		t.Fatal("store was not built by a sync test fixture")
	}
	raw, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

func insertSyncEvent(t *testing.T, s *store.Store, ev store.AccountSyncEvent) {
	t.Helper()
	now := time.Now().UTC()
	execRaw(t, s, `INSERT INTO account_sync_events (id, user_id, system_id, event_type, payload_json, attempts, status, created_at, updated_at, revision) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.ID, ev.UserID, ev.SystemID, ev.EventType, ev.PayloadJSON, ev.Attempts, ev.Status, now, now, ev.Revision)
}

// grantAllUsers puts every active user in the connector's provisioning scope.
func grantAllUsers(t *testing.T, s *store.Store, systemID string) {
	t.Helper()
	apps, _, err := s.ListAppRecords("", 1000, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range apps {
		if a.SystemID == systemID {
			if err := s.SetAppPolicy(a.ID, "all_active_users", true, a.Revision, nil); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatalf("no app record for system %s", systemID)
}

func setupTestSyncEngine(t *testing.T) (*Engine, *store.Store, *store.User, func()) {
	tmpDir, err := os.MkdirTemp("", "kyidentity-sync-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	dbStore, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("store.New failed: %v", err)
	}
	syncTestDBs[dbStore] = dbPath

	adminUser := &store.User{
		ID:           uuid.New().String(),
		Username:     "admin",
		DisplayName:  "Administrator",
		Email:        "admin@example.com",
		PasswordHash: "mock-hash",
		Role:         "admin",
		Status:       "active",
	}
	if err := dbStore.CreateUser(adminUser); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	engine := NewEngine(dbStore, key)

	// Pairing callbacks in these tests point at httptest servers on loopback.
	netguard.AllowPrivate, netguard.AllowLoopback = true, true
	t.Cleanup(func() { netguard.AllowPrivate, netguard.AllowLoopback = false, false })

	cleanup := func() {
		_ = dbStore.Close()
		_ = os.RemoveAll(tmpDir)
	}

	return engine, dbStore, adminUser, cleanup
}

func TestDirectSCIMSystemCreationAndRecovery(t *testing.T) {
	engine, dbStore, _, cleanup := setupTestSyncEngine(t)
	defer cleanup()

	// 1. Create SCIM system directly
	req := &CreateSystemRequest{
		Name:        "Production KyPost",
		SystemType:  "kypost",
		CallbackURL: "https://kypost.local/scim/v2",
	}

	ps, token, err := engine.CreateSystem(req, nil)
	if err != nil {
		t.Fatalf("CreateSystem failed: %v", err)
	}

	if ps.ID == "" || ps.Status != "active" || len(token) < 32 {
		t.Fatalf("unexpected system created: %+v, token=%s", ps, token)
	}

	// 2. Recover secret
	secret, err := engine.SigningSecret(ps)
	if err != nil {
		t.Fatalf("SigningSecret failed: %v", err)
	}
	if secret != token {
		t.Fatalf("expected recovered secret '%s', got '%s'", token, secret)
	}

	// 3. Check system persisted in store
	loaded, err := dbStore.GetPairedSystemByID(ps.ID)
	if err != nil || loaded == nil {
		t.Fatalf("paired system not found in store: %v", err)
	}
	if loaded.Name != "Production KyPost" || loaded.Status != "active" {
		t.Fatalf("unexpected paired system in store: %+v", loaded)
	}
}

// A connector credential copied onto another connector's row must not open there, or a
// database write would redirect one target's token to another's endpoint.
func TestConnectorTokenSwappedBetweenSystemsDoesNotOpen(t *testing.T) {
	engine, dbStore, _, cleanup := setupTestSyncEngine(t)
	defer cleanup()
	a, _, err := engine.CreateSystem(&CreateSystemRequest{Name: "A", SystemType: "scim", CallbackURL: "https://a.example.test/scim/v2", BearerToken: "token-for-a-0123456789abcdef"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := engine.CreateSystem(&CreateSystemRequest{Name: "B", SystemType: "scim", CallbackURL: "https://b.example.test/scim/v2", BearerToken: "token-for-b-0123456789abcdef"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := dbStore.GetPairedSystemByID(b.ID)
	if err != nil {
		t.Fatal(err)
	}
	loaded.HMACSecretEncrypted = a.HMACSecretEncrypted
	if got, err := engine.SigningSecret(loaded); err == nil {
		t.Fatalf("A's token opened on B: %q", got)
	}
	if got, err := engine.SigningSecret(a); err != nil || got != "token-for-a-0123456789abcdef" {
		t.Fatalf("A's own token: %q %v", got, err)
	}
}

func TestKyBookmarksLegacyPresetUsesSignedWebhook(t *testing.T) {
	sys := &store.PairedSystem{SystemType: "kybookmarks", CallbackURL: "https://bookmarks.example.com/scim/v2"}
	for _, eventType := range []string{"user.created", "user.updated", "user.deleted"} {
		method, target, bodyRequired := resolveSCIMURL(sys, eventType, "user-1")
		if method != http.MethodPost || target != "https://bookmarks.example.com/api/sync/events" || !bodyRequired {
			t.Errorf("%s resolved to %s %s body=%v", eventType, method, target, bodyRequired)
		}
	}
}

func TestAccountSyncWebhookDispatch(t *testing.T) {
	engine, dbStore, adminUser, cleanup := setupTestSyncEngine(t)
	defer cleanup()

	var receivedCount int32
	var lastReceivedEventType string
	var lastReceivedSignature string

	sharedSecret := "mock-hmac-secret-32-chars-long!"

	// Mock downstream KyPost sync receiver server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&receivedCount, 1)
		lastReceivedSignature = r.Header.Get("X-KySignOn-Signature")
		lastReceivedEventType = r.Header.Get("X-KySignOn-Event-Type")

		var payload SyncWebhookPayload
		_ = json.NewDecoder(r.Body).Decode(&payload)

		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()

	// Register paired system pointing to mock server
	psID := uuid.New().String()
	ps := &store.PairedSystem{
		ID:                  psID,
		Name:                "Mock KyPost",
		SystemType:          "kypost",
		CallbackURL:         mockServer.URL,
		HMACSecretEncrypted: mustEncrypt(t, engine, psID, sharedSecret),
		Status:              "active",
	}
	if err := dbStore.CreatePairedSystem(ps, nil); err != nil {
		t.Fatalf("CreatePairedSystem failed: %v", err)
	}

	// Create user & queue sync event
	userPayload := map[string]any{
		"id":          adminUser.ID,
		"username":    adminUser.Username,
		"displayName": adminUser.DisplayName,
		"email":       adminUser.Email,
		"role":        adminUser.Role,
		"status":      adminUser.Status,
	}

	queueForAll(t, engine, adminUser.ID, "user.created", userPayload)

	// Dispatch pending events
	if err := engine.DispatchPendingEvents(context.Background()); err != nil {
		t.Fatalf("DispatchPendingEvents failed: %v", err)
	}

	if atomic.LoadInt32(&receivedCount) != 1 {
		t.Fatalf("expected 1 webhook delivery, got %d", receivedCount)
	}
	if lastReceivedEventType != "user.created" {
		t.Fatalf("unexpected event type: %s", lastReceivedEventType)
	}
	if lastReceivedSignature == "" {
		t.Fatal("missing HMAC signature on outbound sync webhook")
	}
}

func TestAccountSyncSCIMPayloadAndHeaders(t *testing.T) {
	engine, dbStore, adminUser, cleanup := setupTestSyncEngine(t)
	defer cleanup()

	var receivedCount int32
	var receivedContentType string
	var receivedAuthHeader string
	var receivedSCIMUser SCIMUserResource
	var verifyErr error

	sharedSecret := "mock-hmac-secret-32-chars-long!"

	mockSCIMServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&receivedCount, 1)
		receivedContentType = r.Header.Get("Content-Type")
		receivedAuthHeader = r.Header.Get("Authorization")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			verifyErr = err
		} else {
			_, verifyErr = syncauth.Verify([]byte(sharedSecret), syncauth.FromRequest(r), body, syncauth.Options{})
			_ = json.Unmarshal(body, &receivedSCIMUser)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer mockSCIMServer.Close()

	psID := uuid.New().String()
	ps := &store.PairedSystem{
		ID:                  psID,
		Name:                "SCIM Downstream",
		SystemType:          "suite_webhook",
		CallbackURL:         mockSCIMServer.URL,
		HMACSecretEncrypted: mustEncrypt(t, engine, psID, sharedSecret),
		Status:              "active",
	}
	if err := dbStore.CreatePairedSystem(ps, nil); err != nil {
		t.Fatalf("CreatePairedSystem failed: %v", err)
	}

	scimUser := UserToSCIMResource(adminUser)
	queueForAll(t, engine, adminUser.ID, "user.created", scimUser)

	if err := engine.DispatchPendingEvents(context.Background()); err != nil {
		t.Fatalf("DispatchPendingEvents failed: %v", err)
	}

	if atomic.LoadInt32(&receivedCount) != 1 {
		t.Fatalf("expected 1 SCIM delivery, got %d", receivedCount)
	}
	if receivedContentType != "application/scim+json" {
		t.Fatalf("expected application/scim+json content-type, got %s", receivedContentType)
	}
	if receivedAuthHeader != "" {
		t.Fatalf("sync secret leaked through Authorization: %q", receivedAuthHeader)
	}
	if verifyErr != nil {
		t.Fatalf("receiver could not verify canonical syncauth headers: %v", verifyErr)
	}
	if len(receivedSCIMUser.Schemas) == 0 || receivedSCIMUser.Schemas[0] != SCIMUserSchema {
		t.Fatalf("expected SCIM schema %s, got %+v", SCIMUserSchema, receivedSCIMUser.Schemas)
	}
	if receivedSCIMUser.UserName != adminUser.Username {
		t.Fatalf("expected SCIM userName %s, got %s", adminUser.Username, receivedSCIMUser.UserName)
	}
	if len(receivedSCIMUser.Emails) == 0 || receivedSCIMUser.Emails[0].Value != adminUser.Email {
		t.Fatalf("expected SCIM email %s, got %+v", adminUser.Email, receivedSCIMUser.Emails)
	}
	if !receivedSCIMUser.Active {
		t.Fatal("expected SCIM active to be true")
	}
}

// mustEncrypt seals a webhook signing secret the way pairing does, so a hand-built
// PairedSystem in a test carries a secret the engine can actually recover.
func mustEncrypt(t *testing.T, e *Engine, systemID, secret string) string {
	t.Helper()
	sealed, err := crypto.Seal(e.encryptionKey, store.SealConnector, systemID, []byte(secret))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return sealed
}

// Native signed delivery must not turn an empty app role set into a global admin
// grant, including after the app's final role definition is deleted.
func TestAppWebhookGlobalAdminRequiresExplicitRole(t *testing.T) {
	engine, s, admin, cleanup := setupTestSyncEngine(t)
	defer cleanup()
	var secret string
	received := make(chan []byte, 16)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err == nil {
			_, err = syncauth.Verify([]byte(secret), syncauth.FromRequest(r), body, syncauth.Options{})
		}
		if err != nil {
			t.Error(err)
			w.WriteHeader(401)
			return
		}
		received <- body
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	engine.httpClient = srv.Client()
	sys, token, err := engine.CreateSystem(&CreateSystemRequest{Name: "target", SystemType: "suite_webhook", CallbackURL: srv.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	secret = token
	app := appRecordFor(t, s, sys.ID)
	if err := s.SetAppAssignment(app.ID, "users", admin.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	check := func(want string, active bool) {
		t.Helper()
		drain(t, engine)
		select {
		case body := <-received:
			var profile struct{ Active bool }
			if err := json.Unmarshal(body, &profile); err != nil {
				t.Fatal(err)
			}
			if profile.Active != active {
				t.Fatalf("active = %v, want %v: %s", profile.Active, active, body)
			}
			if !strings.Contains(string(body), `"id":"`+admin.ID+`"`) || !strings.Contains(string(body), want) {
				t.Fatalf("unexpected webhook: %s, want %s", body, want)
			}
		default:
			t.Fatal("no signed webhook delivered")
		}
	}
	// Simulate a persisted pre-upgrade profile. The native dispatcher must send
	// current app roles, not this old global administrator grant.
	execRaw(t, s, `UPDATE account_sync_events SET payload_json=json_set(payload_json,'$.roles',json('[{"value":"admin","primary":true}]')) WHERE system_id=? AND user_id=? AND status='pending'`, sys.ID, admin.ID)
	check(`"roles":[]`, true)
	role, err := s.CreateAppRole(app.ID, "admin", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	check(`"roles":[]`, true)
	if err := s.SetAppRoleAssignment(app.ID, role.ID, "users", admin.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	check(`"roles":[{"value":"admin","primary":true}]`, true)
	if err := s.DeleteAppRole(app.ID, role.ID, nil); err != nil {
		t.Fatal(err)
	}
	check(`"roles":[]`, true)
	// All newly generated inactive paths must also stay app-scoped.
	if err := s.SetAppAssignment(app.ID, "users", admin.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	check(`"roles":[]`, false)
	if err := s.ResyncSystem(sys.ID, nil); err != nil {
		t.Fatal(err)
	}
	check(`"roles":[]`, false)
	if _, err := s.ReconcileDrift(sys.ID, store.RemoteListing{Supported: true, Complete: true,
		Users: []store.RemoteAccount{{ID: admin.ID, ExternalID: admin.ID, UserName: admin.Username, Active: true}}}, true); err != nil {
		t.Fatal(err)
	}
	check(`"roles":[]`, false)
	if err := s.SetAppAssignment(app.ID, "users", admin.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	check(`"roles":[]`, true)
	other := &store.User{ID: uuid.NewString(), Username: "remaining-admin", DisplayName: "Remaining", Role: "admin", Status: "active", PasswordHash: "fixture"}
	if err := s.CreateUser(other); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EditUser(admin.ID, nil, func(u *store.User) (bool, error) { u.Status = "disabled"; return true, nil }); err != nil {
		t.Fatal(err)
	}
	check(`"roles":[]`, false)
}

func TestLegacyQueuedWebhookRoles(t *testing.T) {
	for _, kind := range []string{"user.created", "user.mfa_reset"} {
		for _, assigned := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/assigned=%v", kind, assigned), func(t *testing.T) {
				e, s, admin, cleanup := setupTestSyncEngine(t)
				defer cleanup()
				var secret string
				type receipt struct {
					body []byte
					id   string
				}
				received := make(chan receipt, 4)
				srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, err := io.ReadAll(r.Body)
					if err == nil {
						_, err = syncauth.Verify([]byte(secret), syncauth.FromRequest(r), body, syncauth.Options{})
					}
					if err != nil {
						t.Error(err)
						w.WriteHeader(401)
						return
					}
					received <- receipt{body, r.Header.Get("Idempotency-Key")}
					w.WriteHeader(http.StatusCreated)
				}))
				defer srv.Close()
				e.httpClient = srv.Client()
				sys, token, err := e.CreateSystem(&CreateSystemRequest{Name: "legacy", SystemType: "suite_webhook", CallbackURL: srv.URL}, nil)
				if err != nil {
					t.Fatal(err)
				}
				secret = token
				app := appRecordFor(t, s, sys.ID)
				if assigned {
					role, err := s.CreateAppRole(app.ID, "operator", "", nil)
					if err != nil {
						t.Fatal(err)
					}
					if err := s.SetAppRoleAssignment(app.ID, role.ID, "users", admin.ID, true, nil); err != nil {
						t.Fatal(err)
					}
				}
				if err := s.SetAppAssignment(app.ID, "users", admin.ID, true, nil); err != nil {
					t.Fatal(err)
				}
				drain(t, e)
				select {
				case <-received:
				default:
					t.Fatal("initial profile was not delivered")
				}
				// The historical persisted form has no schemas and a singular global role.
				legacy, err := json.Marshal(map[string]any{"id": admin.ID, "username": admin.Username, "status": "active", "role": "admin"})
				if err != nil {
					t.Fatal(err)
				}
				eventID := uuid.NewString()
				insertSyncEvent(t, s, store.AccountSyncEvent{ID: eventID, UserID: admin.ID, SystemID: sys.ID, EventType: kind, PayloadJSON: string(legacy), Revision: 13, Status: "pending"})
				drain(t, e)
				select {
				case got := <-received:
					var profile SCIMUserResource
					if err := json.Unmarshal(got.body, &profile); err != nil {
						t.Fatal(err)
					}
					if got.id != eventID || profile.Meta == nil || profile.Meta.Version != `W/"13"` || !profile.Active || profile.ID != admin.ID || profile.UserName != admin.Username {
						t.Fatalf("event identity/revision/profile changed: %s %+v", got.body, got)
					}
					if assigned {
						if len(profile.Roles) != 1 || profile.Roles[0].Value != "operator" {
							t.Fatalf("explicit role lost in legacy conversion: %s", got.body)
						}
					} else if !strings.Contains(string(got.body), `"roles":[]`) {
						t.Fatalf("legacy global admin re-granted: %s", got.body)
					}
				default:
					t.Fatal("legacy event was not delivered")
				}
			})
		}
	}
}
