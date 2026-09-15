package sync

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/Busness-app/ky-primitives/syncauth"
	"github.com/Busness-app/kyidentity-server/internal/crypto"
	"github.com/Busness-app/kyidentity-server/internal/netguard"
	"github.com/Busness-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// queueForAll enqueues one event per active connector directly, bypassing scope, so
// wire-format tests can exercise delivery without configuring assignments.
func queueForAll(t *testing.T, e *Engine, userID, eventType string, payload any) {
	t.Helper()
	systems, err := e.store.ListActivePairedSystems()
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, sys := range systems {
		if err := e.store.CreateAccountSyncEvent(&store.AccountSyncEvent{ID: uuid.NewString(), UserID: userID, SystemID: sys.ID, EventType: eventType, PayloadJSON: string(body), Status: "pending", Revision: 1}); err != nil {
			t.Fatal(err)
		}
	}
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
	netguard.AllowPrivate = true
	t.Cleanup(func() { netguard.AllowPrivate = false })

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

	ps, token, err := engine.CreateSystem(req)
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
	ps := &store.PairedSystem{
		ID:                  uuid.New().String(),
		Name:                "Mock KyPost",
		SystemType:          "kypost",
		CallbackURL:         mockServer.URL,
		HMACSecretEncrypted: mustEncrypt(t, engine, sharedSecret),
		Status:              "active",
	}
	if err := dbStore.CreatePairedSystem(ps); err != nil {
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

	ps := &store.PairedSystem{
		ID:                  uuid.New().String(),
		Name:                "SCIM Downstream",
		SystemType:          "suite_webhook",
		CallbackURL:         mockSCIMServer.URL,
		HMACSecretEncrypted: mustEncrypt(t, engine, sharedSecret),
		Status:              "active",
	}
	if err := dbStore.CreatePairedSystem(ps); err != nil {
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
func mustEncrypt(t *testing.T, e *Engine, secret string) string {
	t.Helper()
	sealed, err := crypto.EncryptAESGCM(e.encryptionKey, []byte(secret))
	if err != nil {
		t.Fatalf("EncryptAESGCM: %v", err)
	}
	return sealed
}
