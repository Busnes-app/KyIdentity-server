package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func setupTestStore(t *testing.T) (*Store, func()) {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "webauthn.db"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	return s, func() { _ = s.Close() }
}

func createTestUser(t *testing.T, s *Store) *User {
	t.Helper()
	return createTestUserNamed(t, s, "user-"+uuid.New().String()[:8])
}

func createTestUserNamed(t *testing.T, s *Store, username string) *User {
	t.Helper()
	u := &User{
		ID: uuid.New().String(), Username: username,
		DisplayName: username, Email: username + "@test.invalid",
		PasswordHash: "x", Role: "user", Status: "active",
	}
	if err := s.CreateUser(u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return u
}

func TestDeleteUserWithSyncEventsMigratesLegacyForeignKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`
		PRAGMA foreign_keys = ON;
		CREATE TABLE users (
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			display_name TEXT NOT NULL,
			email TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL,
			status TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE account_sync_events (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			system_id TEXT NOT NULL,
			event_type TEXT NOT NULL,
			payload_json TEXT NOT NULL,
			attempts INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL,
			last_error TEXT,
			next_attempt_at DATETIME,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX idx_sync_events_status ON account_sync_events(status);
		INSERT INTO users (id, username, display_name, email, password_hash, role, status)
			VALUES ('deleted-user', 'deleted', 'Deleted User', 'deleted@example.test', 'hash', 'user', 'active');
		INSERT INTO account_sync_events (id, user_id, system_id, event_type, payload_json, status)
			VALUES ('stale-event', 'deleted-user', 'system', 'user.updated', '{}', 'pending');`)
	if err != nil {
		_ = legacy.Close()
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.CreatePairedSystem(&PairedSystem{ID: "system", Name: "system", SystemType: "scim", CallbackURL: "https://example.com/scim", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO sync_resource_state(system_id,resource_id,active,provisioned,revision) VALUES('system','deleted-user',1,1,1)`); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUserWithSyncEvents("deleted-user", nil); err != nil {
		t.Fatal(err)
	}

	var definition string
	if err := s.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'account_sync_events'`).Scan(&definition); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToUpper(definition), "REFERENCES USERS") {
		t.Fatal("legacy user foreign key was not removed")
	}
	pending, err := s.GetPendingSyncEvents(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].UserID != "deleted-user" || pending[0].EventType != "user.deleted" || pending[0].Revision != 2 {
		t.Fatalf("deletion event was not retained: %+v", pending)
	}
}

func TestUpdateUserWithSyncEventsPreservesLastAdmin(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	u := &User{ID: "admin", Username: "admin", DisplayName: "Admin", Email: "admin@example.test", PasswordHash: "hash", Role: "admin", Status: "active"}
	if err := s.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	u.Role = "user"
	if err := s.UpdateUserWithSyncEvents(u, false, nil); !errors.Is(err, ErrLastActiveAdmin) {
		t.Fatalf("demoting final admin error = %v", err)
	}
}

func TestIdleSessionIsRejectedBeforeAbsoluteExpiry(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	user := &User{ID: "user", Username: "user", DisplayName: "User", Email: "user@example.test", PasswordHash: "hash", Role: "user", Status: "active"}
	if err := s.CreateUser(user); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(&Session{ID: "session", UserID: user.ID, SessionTokenHash: "token", IPAddress: "127.0.0.1", UserAgent: "test", ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE sessions SET last_active_at = ? WHERE id = ?`, time.Now().UTC().Add(-31*time.Minute), "session"); err != nil {
		t.Fatal(err)
	}
	session, err := s.GetSessionByTokenHash("token", 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if session != nil {
		t.Fatal("idle session remained valid before its absolute expiry")
	}
}

func TestLegacyDevicePairingTokensAreRebuiltWithoutPlaintextPINs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`
		CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT NOT NULL, display_name TEXT NOT NULL, email TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL, status TEXT NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP);
		CREATE TABLE device_pairing_tokens (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), token_hash TEXT NOT NULL UNIQUE, pin_code TEXT NOT NULL, expires_at DATETIME NOT NULL, used_at DATETIME, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP);
		INSERT INTO users (id, username, display_name, email, password_hash, role, status) VALUES ('u1', 'user', 'User', 'user@example.test', 'hash', 'user', 'active');
		INSERT INTO device_pairing_tokens (id, user_id, token_hash, pin_code, expires_at) VALUES ('old', 'u1', 'hash', '123456', CURRENT_TIMESTAMP);`)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var definition string
	if err := s.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'device_pairing_tokens'`).Scan(&definition); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToUpper(definition), "PIN_CODE") {
		t.Fatal("legacy plaintext pairing PIN column survived migration")
	}
	if err := s.CreateDevicePairingToken(&DevicePairingToken{ID: "new", UserID: "u1", TokenHash: "new-hash", PINHash: "new-pin-hash", ExpiresAt: time.Now().UTC().Add(time.Minute)}); err != nil {
		t.Fatalf("new pairing token failed after migration: %v", err)
	}
}

func TestNativeDevicePushTokenReplayStateMigrates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-native-device.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`CREATE TABLE native_devices (
		id TEXT PRIMARY KEY, user_id TEXT NOT NULL, device_name TEXT NOT NULL,
		device_identifier TEXT NOT NULL, platform TEXT NOT NULL DEFAULT 'android',
		public_key TEXT, push_token TEXT, is_mfa_approver BOOLEAN NOT NULL DEFAULT 0,
		last_seen_at DATETIME, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(user_id, device_identifier));`)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM pragma_table_info('native_devices') WHERE name = 'push_token_updated_at_ms'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("push-token replay state column was not migrated")
	}
}

func TestListAuditEventsPagination(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "audit_test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	for i := 1; i <= 15; i++ {
		err := s.RecordAuditEvent(&AuditEvent{
			ID:            strings.Repeat("a", 10) + string(rune('0'+i)),
			ActorUsername: "admin",
			Action:        "test.action",
			Outcome:       "success",
			IPAddress:     "127.0.0.1",
		})
		if err != nil {
			t.Fatalf("RecordAuditEvent failed: %v", err)
		}
	}

	// Page 1 with limit 5
	events, total, err := s.ListAuditEvents(5, 0)
	if err != nil {
		t.Fatalf("ListAuditEvents failed: %v", err)
	}
	if total != 15 {
		t.Fatalf("expected total 15, got %d", total)
	}
	if len(events) != 5 {
		t.Fatalf("expected 5 events on page 1, got %d", len(events))
	}

	// Page 2 with limit 5 offset 5
	events2, total2, err := s.ListAuditEvents(5, 5)
	if err != nil {
		t.Fatalf("ListAuditEvents page 2 failed: %v", err)
	}
	if total2 != 15 {
		t.Fatalf("expected total 15, got %d", total2)
	}
	if len(events2) != 5 {
		t.Fatalf("expected 5 events on page 2, got %d", len(events2))
	}

	// Page 4 with limit 5 offset 15 (empty)
	events4, total4, err := s.ListAuditEvents(5, 15)
	if err != nil {
		t.Fatalf("ListAuditEvents page 4 failed: %v", err)
	}
	if total4 != 15 {
		t.Fatalf("expected total 15, got %d", total4)
	}
	if len(events4) != 0 {
		t.Fatalf("expected 0 events on page 4, got %d", len(events4))
	}
}

func TestOAuthClientLauncherMetadataMigrates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-oauth-client.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`CREATE TABLE oauth_clients (
		id TEXT PRIMARY KEY, client_name TEXT NOT NULL,
		client_type TEXT NOT NULL CHECK (client_type IN ('public', 'confidential')),
		client_secret_hash TEXT, redirect_uris_json TEXT NOT NULL,
		allowed_scopes_json TEXT NOT NULL, launch_url TEXT,
		enabled BOOLEAN NOT NULL DEFAULT 1,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP);
		INSERT INTO oauth_clients (id, client_name, client_type, redirect_uris_json, allowed_scopes_json)
			VALUES ('kydns', 'KyDNS Server', 'confidential', '["https://dns.example.test/cb"]', '["openid"]');`)
	if err != nil {
		_ = legacy.Close()
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	client, err := s.GetOAuthClientByID("kydns")
	if err != nil {
		t.Fatal(err)
	}
	if client == nil {
		t.Fatal("pre-existing client disappeared across the migration")
	}
	if client.Description != "" || client.IconName != "" {
		t.Fatalf("migrated client should carry empty launcher metadata, got %q/%q", client.Description, client.IconName)
	}

	client.Description = "Homelab DNS with subnet views"
	client.IconName = "globe"
	if err := s.UpdateOAuthClient(client); err != nil {
		t.Fatal(err)
	}
	reloaded, err := s.GetOAuthClientByID("kydns")
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Description != "Homelab DNS with subnet views" || reloaded.IconName != "globe" {
		t.Fatalf("launcher metadata did not persist: %q/%q", reloaded.Description, reloaded.IconName)
	}

	listed, err := s.ListOAuthClients()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].Description != "Homelab DNS with subnet views" || listed[0].IconName != "globe" {
		t.Fatalf("list did not return launcher metadata: %+v", listed)
	}
}

func TestWebAuthnChallengeIsSingleUse(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()

	user := createTestUser(t, s)
	ch := &WebAuthnChallenge{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Challenge: "Q0hBTExFTkdF",
		Purpose:   "authenticate",
		ExpiresAt: time.Now().UTC().Add(2 * time.Minute),
	}
	if err := s.CreateWebAuthnChallenge(ch); err != nil {
		t.Fatalf("CreateWebAuthnChallenge: %v", err)
	}

	ok, err := s.ConsumeWebAuthnChallenge(ch.Challenge, "authenticate", user.ID)
	if err != nil || !ok {
		t.Fatalf("first consume: ok=%v err=%v", ok, err)
	}
	ok, err = s.ConsumeWebAuthnChallenge(ch.Challenge, "authenticate", user.ID)
	if err != nil {
		t.Fatalf("second consume errored: %v", err)
	}
	if ok {
		t.Fatal("a challenge must not be redeemable twice")
	}
}

func TestWebAuthnChallengeRejectsWrongPurposeUserAndExpiry(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()

	user := createTestUser(t, s)
	other := createTestUserNamed(t, s, "other-user")

	live := &WebAuthnChallenge{
		ID: uuid.New().String(), UserID: user.ID, Challenge: "TElWRQ",
		Purpose: "authenticate", ExpiresAt: time.Now().UTC().Add(2 * time.Minute),
	}
	expired := &WebAuthnChallenge{
		ID: uuid.New().String(), UserID: user.ID, Challenge: "T0xE",
		Purpose: "authenticate", ExpiresAt: time.Now().UTC().Add(-time.Second),
	}
	for _, ch := range []*WebAuthnChallenge{live, expired} {
		if err := s.CreateWebAuthnChallenge(ch); err != nil {
			t.Fatalf("CreateWebAuthnChallenge: %v", err)
		}
	}

	if ok, _ := s.ConsumeWebAuthnChallenge(live.Challenge, "register", user.ID); ok {
		t.Fatal("a challenge issued for authentication must not satisfy registration")
	}
	if ok, _ := s.ConsumeWebAuthnChallenge(live.Challenge, "authenticate", other.ID); ok {
		t.Fatal("a challenge must not be redeemable by another user")
	}
	if ok, _ := s.ConsumeWebAuthnChallenge(expired.Challenge, "authenticate", user.ID); ok {
		t.Fatal("an expired challenge must not be redeemable")
	}
}

func TestWebAuthnCredentialLifecycle(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()

	user := createTestUser(t, s)
	cred := &WebAuthnCredential{
		ID:             uuid.New().String(),
		UserID:         user.ID,
		CredentialID:   "Y3JlZC1vbmU",
		PublicKeySPKI:  "c3BraQ",
		Name:           "KyAuth on Pixel",
		SignCount:      3,
		BackupEligible: false,
	}
	if err := s.CreateWebAuthnCredential(cred, nil); err != nil {
		t.Fatalf("CreateWebAuthnCredential: %v", err)
	}

	got, err := s.GetWebAuthnCredential(user.ID, cred.CredentialID)
	if err != nil || got == nil {
		t.Fatalf("GetWebAuthnCredential: %v %v", got, err)
	}
	if got.SignCount != 3 || got.Name != "KyAuth on Pixel" {
		t.Fatalf("round trip lost data: %+v", got)
	}

	if err := s.RecordWebAuthnUse(cred.ID, 4, true, time.Now().UTC()); err != nil {
		t.Fatalf("RecordWebAuthnUse: %v", err)
	}
	got, _ = s.GetWebAuthnCredential(user.ID, cred.CredentialID)
	if got.SignCount != 4 || !got.BackupState || got.LastUsedAt == nil {
		t.Fatalf("use was not recorded: %+v", got)
	}

	list, err := s.ListUserWebAuthnCredentials(user.ID)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListUserWebAuthnCredentials = %d creds, %v", len(list), err)
	}

	deleted, err := s.DeleteWebAuthnCredential(cred.ID, "some-other-user", nil)
	if err != nil {
		t.Fatalf("DeleteWebAuthnCredential: %v", err)
	}
	if deleted {
		t.Fatal("a credential must not be deletable by a user who does not own it")
	}

	deleted, err = s.DeleteWebAuthnCredential(cred.ID, user.ID, nil)
	if err != nil || !deleted {
		t.Fatalf("owner delete: deleted=%v err=%v", deleted, err)
	}
}

func TestMFAWipesRemovePasskeys(t *testing.T) {
	// An administrator resetting MFA, and a user replacing their factors, must both strip
	// passkeys. A passkey that survives a reset is an attacker-planted factor that outlives
	// the response to the incident that triggered the reset.
	for _, tc := range []struct {
		name string
		wipe func(*Store, string) error
	}{
		{"ResetUserMFA", func(s *Store, uid string) error { return s.ResetUserMFA(uid, nil) }},
		{"DeleteUserMFAMethods", func(s *Store, uid string) error { return s.DeleteUserMFAMethods(uid) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, cleanup := setupTestStore(t)
			defer cleanup()

			user := createTestUser(t, s)
			if err := s.CreateWebAuthnCredential(&WebAuthnCredential{
				ID: uuid.New().String(), UserID: user.ID,
				CredentialID: "Y3JlZC0" + tc.name, PublicKeySPKI: "c3BraQ", Name: "key",
			}, nil); err != nil {
				t.Fatalf("CreateWebAuthnCredential: %v", err)
			}

			if err := tc.wipe(s, user.ID); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}

			list, err := s.ListUserWebAuthnCredentials(user.ID)
			if err != nil {
				t.Fatalf("ListUserWebAuthnCredentials: %v", err)
			}
			if len(list) != 0 {
				t.Fatalf("%s left %d passkeys behind", tc.name, len(list))
			}
		})
	}
}

func TestDeviceSignOnColumnsMigrate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(`CREATE TABLE native_devices (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		device_name TEXT NOT NULL, device_identifier TEXT NOT NULL, platform TEXT NOT NULL DEFAULT 'android',
		public_key TEXT, push_token TEXT, push_token_updated_at_ms INTEGER NOT NULL DEFAULT 0,
		is_mfa_approver BOOLEAN NOT NULL DEFAULT 0, last_seen_at DATETIME, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(user_id, device_identifier));
		CREATE TABLE device_pairing_tokens (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		token_hash TEXT NOT NULL UNIQUE, pin_hash TEXT NOT NULL, expires_at DATETIME NOT NULL, used_at DATETIME,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP);
		INSERT INTO native_devices(id,user_id,device_name,device_identifier) VALUES ('d1','u1','old phone','ident-1');`); err != nil {
		t.Fatal(err)
	}
	legacy.Close()

	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	for table, col := range map[string]string{"native_devices": "can_sign_on", "device_pairing_tokens": "sign_on"} {
		var n int
		if err := s.db.QueryRow(`SELECT count(*) FROM pragma_table_info(?) WHERE name = ?`, table, col).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("%s.%s missing after migration", table, col)
		}
	}
	dev, err := s.GetNativeDevice("d1")
	if err != nil || dev == nil {
		t.Fatalf("GetNativeDevice: %v %v", dev, err)
	}
	if dev.CanSignOn {
		t.Fatal("a pre-existing device must not gain sign-on by migration")
	}
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='device_signon_jtis'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("device_signon_jtis table missing: %d %v", n, err)
	}
}

func TestSignOnFlagsRoundTrip(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)

	tok := &DevicePairingToken{ID: "t1", UserID: u.ID, TokenHash: "h1", PINHash: "p1", SignOn: true, ExpiresAt: time.Now().UTC().Add(time.Minute)}
	if err := s.CreateDevicePairingToken(tok); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetValidDevicePairingToken("h1")
	if err != nil || got == nil || !got.SignOn {
		t.Fatalf("SignOn not persisted: %+v %v", got, err)
	}

	dev := &NativeDevice{ID: "d1", UserID: u.ID, DeviceName: "phone", DeviceIdentifier: "ident", CanSignOn: true}
	if err := s.UpsertNativeDevice(dev); err != nil {
		t.Fatal(err)
	}
	one, err := s.GetNativeDevice("d1")
	if err != nil || one == nil || !one.CanSignOn {
		t.Fatalf("GetNativeDevice CanSignOn: %+v %v", one, err)
	}
	list, err := s.ListUserNativeDevices(u.ID)
	if err != nil || len(list) != 1 || !list[0].CanSignOn {
		t.Fatalf("ListUserNativeDevices CanSignOn: %+v %v", list, err)
	}
}

func TestConsumeDeviceSignOnJTIIsSingleUse(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	exp := time.Now().UTC().Add(5 * time.Minute)
	ok, err := s.ConsumeDeviceSignOnJTI("j-1", exp)
	if err != nil || !ok {
		t.Fatalf("first use: %v %v", ok, err)
	}
	ok, err = s.ConsumeDeviceSignOnJTI("j-1", exp)
	if err != nil || ok {
		t.Fatalf("replay: %v %v", ok, err)
	}
	// Expired rows are swept so the table cannot grow without bound.
	if _, err := s.db.Exec(`UPDATE device_signon_jtis SET expires_at = ? WHERE jti = 'j-1'`, time.Now().UTC().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	ok, err = s.ConsumeDeviceSignOnJTI("j-2", exp)
	if err != nil || !ok {
		t.Fatal(err)
	}
	var n int
	_ = s.db.QueryRow(`SELECT count(*) FROM device_signon_jtis WHERE jti = 'j-1'`).Scan(&n)
	if n != 0 {
		t.Fatal("expired jti not swept")
	}
}

func TestAttestationColumnsMigrateAndRoundTrip(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	for _, col := range []string{"attested_level", "attested_at", "boot_state", "attestation_serials"} {
		var n int
		if err := s.db.QueryRow(`SELECT count(*) FROM pragma_table_info('native_devices') WHERE name = ?`, col).Scan(&n); err != nil || n != 1 {
			t.Fatalf("column %s missing: %d %v", col, n, err)
		}
	}
	u := createTestUser(t, s)
	dev := &NativeDevice{ID: "d1", UserID: u.ID, DeviceName: "p", DeviceIdentifier: "i", PublicKey: "pk", IsMFAApprover: true, CanSignOn: true}
	if err := s.UpsertNativeDevice(dev); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetNativeDevice("d1")
	if got.AttestedLevel != "none" || got.BootState != "unknown" || got.AttestedAt != nil {
		t.Fatalf("defaults: %+v", got)
	}
	at := time.Now().UTC().Truncate(time.Second)
	if ok, err := s.SetNativeDeviceAttestation("d1", "pk", "tee", "locked-verified", []string{"0a1b", "ff"}, at); err != nil || !ok {
		t.Fatal(ok, err)
	}
	got, _ = s.GetNativeDevice("d1")
	if got.AttestedLevel != "tee" || got.BootState != "locked-verified" || got.AttestedAt == nil || !got.AttestedAt.Equal(at) || len(got.AttestationSerials) != 2 {
		t.Fatalf("after set: %+v", got)
	}
	list, _ := s.ListUserNativeDevices(u.ID)
	if list[0].AttestedLevel != "tee" {
		t.Fatalf("list: %+v", list[0])
	}
	attested, _ := s.ListAttestedDevices()
	if len(attested) != 1 || attested[0].ID != "d1" {
		t.Fatalf("attested: %+v", attested)
	}
	if err := s.UpsertNativeDevice(&NativeDevice{ID: "d2", UserID: u.ID, DeviceName: "p", DeviceIdentifier: "i", PublicKey: "pk2"}); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.GetNativeDevice("d1"); got.AttestedLevel != "none" || got.AttestedAt != nil || got.BootState != "unknown" || len(got.AttestationSerials) != 0 {
		t.Fatalf("re-pair kept grade: %+v", got)
	}
	if ok, err := s.SetNativeDeviceAttestation("d1", "pk2", "tee", "locked-verified", nil, at); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if ok, err := s.SetNativeDeviceAttestation("d1", "pk2", "none", "unlocked", nil, at); err != nil || !ok {
		t.Fatal(ok, err)
	}
	attested, _ = s.ListAttestedDevices()
	if len(attested) != 0 {
		t.Fatal("downgraded device still listed")
	}
}

func TestAttestationWritesAreBoundToTheGradedKey(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	dev := &NativeDevice{ID: "d1", UserID: u.ID, DeviceName: "p", DeviceIdentifier: "i", PublicKey: "pk", IsMFAApprover: true,
		AttestedLevel: "strongbox", BootState: "locked-verified", AttestationSerials: []string{"1"}}
	if err := s.UpsertNativeDevice(dev); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetNativeDevice("d1")
	if got.AttestedLevel != "strongbox" || got.BootState != "locked-verified" || got.AttestedAt == nil || len(got.AttestationSerials) != 1 {
		t.Fatalf("enrolment grade not stored: %+v", got)
	}
	if ok, err := s.SetNativeDeviceAttestation("d1", "other-key", "none", "unknown", nil, time.Now()); err != nil || ok {
		t.Fatalf("write for a stale key: changed=%v err=%v", ok, err)
	}
	if got, _ = s.GetNativeDevice("d1"); got.AttestedLevel != "strongbox" {
		t.Fatalf("stale-key write landed: %+v", got)
	}
	if _, err := s.SetNativeDeviceAttestation("d1", "pk", "hardware", "unknown", nil, time.Now()); err == nil {
		t.Fatal("invalid level accepted")
	}
	if _, err := s.SetNativeDeviceAttestation("d1", "pk", "tee", "green", nil, time.Now()); err == nil {
		t.Fatal("invalid boot state accepted")
	}
	if err := s.UpsertNativeDevice(&NativeDevice{ID: "d2", UserID: u.ID, DeviceName: "p", DeviceIdentifier: "i", PublicKey: "pk", AttestedLevel: "tee", BootState: "green"}); err == nil {
		t.Fatal("upsert accepted an invalid boot state")
	}
}

func TestRecordIssuedTokenChecksAttestedLevel(t *testing.T) {
	s, u, a := appAccessFixture(t)
	if err := s.SetAppAssignment(a.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertNativeDevice(&NativeDevice{ID: "d1", UserID: u.ID, DeviceName: "p", DeviceIdentifier: "i", PublicKey: "pk", IsMFAApprover: true, CanSignOn: true}); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.SetNativeDeviceAttestation("d1", "pk", "tee", "locked-verified", nil, time.Now()); err != nil || !ok {
		t.Fatal(ok, err)
	}
	tok := func(id string) *IssuedToken {
		tk := accessToken(u, id, "")
		tk.Device = DeviceBinding{ID: "d1", UserID: u.ID, PublicKey: "pk", AttestedLevel: "tee"}
		return tk
	}
	if err := s.RecordIssuedToken(tok("t1")); err != nil {
		t.Fatalf("attested device refused: %v", err)
	}
	if ok, err := s.SetNativeDeviceAttestation("d1", "pk", "none", "unknown", nil, time.Now()); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if err := s.RecordIssuedToken(tok("t2")); !errors.Is(err, ErrAppAccessDenied) {
		t.Fatalf("downgraded device: got %v, want ErrAppAccessDenied", err)
	}
}
