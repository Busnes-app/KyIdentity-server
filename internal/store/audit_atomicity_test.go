package store

import (
	"path/filepath"
	"testing"
	"time"
)

// poisonedAudit is an audit row whose insert is guaranteed to fail, because a row with the
// same primary key already exists. It stands in for the real failure modes — disk full,
// database locked, read-only filesystem — without needing to break the database.
func poisonedAudit(t *testing.T, s *Store, action, targetID string) *AuditEvent {
	t.Helper()
	e := &AuditEvent{
		ID: "collides", Action: action, TargetID: targetID,
		Outcome: "success", CreatedAt: time.Now().UTC(),
	}
	if err := s.RecordAuditEvent(&AuditEvent{ID: "collides", Action: "seed", Outcome: "success"}); err != nil {
		t.Fatalf("seeding the colliding audit row failed: %v", err)
	}
	return e
}

func newStoreWithUser(t *testing.T, role string) (*Store, *User) {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "atomicity.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	u := &User{
		ID: "u1", Username: "ada", DisplayName: "Ada", Email: "ada@example.test",
		PasswordHash: "hash", Role: role, Status: "active",
	}
	if err := s.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	return s, u
}

// The contract the audit package documents: a security mutation and the record of who made
// it commit together or not at all. Recording afterwards cannot make them atomic, it only
// changes which half is lost — and reporting success for an unattributable privilege change
// is the half that matters.
func TestUserUpdateRollsBackWhenItsAuditRowCannotBeWritten(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	audit := poisonedAudit(t, s, "admin.user_updated", u.ID)

	u.DisplayName = "Renamed"
	u.Status = "disabled"
	if err := s.UpdateUserWithSyncEvents(u, true, audit); err == nil {
		t.Fatal("an unauditable user update reported success")
	}

	stored, err := s.GetUserByID(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.DisplayName != "Ada" || stored.Status != "active" {
		t.Fatalf("the mutation survived its failed audit write: %+v", stored)
	}
}

func TestPushTokenRefreshRollsBackWhenItsAuditRowCannotBeWritten(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	dev := &NativeDevice{ID: "phone", UserID: u.ID, DeviceName: "phone", DeviceIdentifier: "phone", PushToken: "old"}
	if err := s.UpsertNativeDevice(dev); err != nil {
		t.Fatal(err)
	}
	audit := poisonedAudit(t, s, "device.push_token_refreshed", dev.ID)
	if _, err := s.UpdateNativeDevicePushToken(dev.ID, PushTransportFCM, "new", "", "", 1, time.Now().UTC(), audit); err == nil {
		t.Fatal("an unauditable push-token refresh reported success")
	}
	stored, err := s.GetNativeDevice(dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.PushToken != "old" || stored.PushTokenUpdatedAtMS != 0 {
		t.Fatalf("refresh survived audit rollback: %+v", stored)
	}
}

func TestUserCreateRollsBackWhenItsAuditRowCannotBeWritten(t *testing.T) {
	s, _ := newStoreWithUser(t, "user")
	audit := poisonedAudit(t, s, "admin.user_created", "u2")

	u := &User{
		ID: "u2", Username: "grace", DisplayName: "Grace", Email: "grace@example.test",
		PasswordHash: "hash", Role: "admin", Status: "active",
	}
	if err := s.CreateUserWithSyncEvents(u, audit); err == nil {
		t.Fatal("an unauditable user creation reported success")
	}
	stored, err := s.GetUserByID("u2")
	if err != nil {
		t.Fatal(err)
	}
	if stored != nil {
		t.Fatal("an administrator was created with no durable record of who created it")
	}
}

func TestUserDeleteRollsBackWhenItsAuditRowCannotBeWritten(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	audit := poisonedAudit(t, s, "admin.user_deleted", u.ID)

	if err := s.DeleteUserWithSyncEvents(u.ID, audit); err == nil {
		t.Fatal("an unauditable user deletion reported success")
	}
	stored, err := s.GetUserByID(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored == nil {
		t.Fatal("the deletion survived its failed audit write")
	}
}

func TestMFAResetRollsBackWhenItsAuditRowCannotBeWritten(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	if err := s.SetMFAMethod(&MFAMethod{
		ID: "m1", UserID: u.ID, MethodType: "totp", EncryptedSecret: "x", IsPrimary: true,
	}, nil); err != nil {
		t.Fatal(err)
	}
	audit := poisonedAudit(t, s, "admin.user_mfa_reset", u.ID)

	if err := s.ResetUserMFA(u.ID, audit); err == nil {
		t.Fatal("an unauditable MFA reset reported success")
	}
	methods, err := s.ListUserMFAMethods(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(methods) != 1 {
		t.Fatalf("factors were stripped with no record of who stripped them: %d remain", len(methods))
	}
}

func TestFactorEnrollmentRollsBackWhenItsAuditRowCannotBeWritten(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	audit := poisonedAudit(t, s, "mfa.totp_enabled", u.ID)

	if err := s.SetMFAMethod(&MFAMethod{
		ID: "m1", UserID: u.ID, MethodType: "totp", EncryptedSecret: "x", IsPrimary: true,
	}, audit); err == nil {
		t.Fatal("an unauditable factor enrollment reported success")
	}
	methods, err := s.ListUserMFAMethods(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(methods) != 0 {
		t.Fatal("an authenticator was enrolled with no record of where it came from")
	}
}

func TestRecoveryCodeIssueRollsBackWhenItsAuditRowCannotBeWritten(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	if err := s.ReplaceRecoveryCodes(u.ID, []RecoveryCode{{ID: "r1", UserID: u.ID, CodeHash: "old"}}, nil); err != nil {
		t.Fatal(err)
	}
	audit := poisonedAudit(t, s, "mfa.recovery_codes_generated", u.ID)

	if err := s.ReplaceRecoveryCodes(u.ID, []RecoveryCode{{ID: "r2", UserID: u.ID, CodeHash: "new"}}, audit); err == nil {
		t.Fatal("an unauditable recovery-code rotation reported success")
	}
	// The old set must still work: a rotation that rolled back has not replaced anything,
	// and telling the user otherwise would strand them with codes that authenticate nothing.
	var hash string
	if err := s.db.QueryRow(`SELECT code_hash FROM recovery_codes WHERE user_id = ?`, u.ID).Scan(&hash); err != nil {
		t.Fatalf("the previous recovery codes were destroyed: %v", err)
	}
	if hash != "old" {
		t.Fatalf("recovery codes were rotated without a record: %q", hash)
	}
}

// Deleting something and revoking what it authorized also commit together.
func TestClientDeleteRollsBackWhenItsAuditRowCannotBeWritten(t *testing.T) {
	s, _ := newStoreWithUser(t, "user")
	if err := s.CreateOAuthClient(&OAuthClient{
		ID: "c1", ClientName: "App", ClientType: "public",
		RedirectURIsJSON: "[]", AllowedScopesJSON: "[]", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE app_registry SET access_mode='all_active_users' WHERE client_id='c1'`); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(&Session{ID: "s1", UserID: "u1", SessionTokenHash: "token", ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordIssuedToken(&IssuedToken{
		JTI: "jti-1", UserID: "u1", ClientID: "c1", SessionID: "s1",
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	audit := poisonedAudit(t, s, "admin.oauth_client_deleted", "c1")

	if _, err := s.DeleteOAuthClient("c1", audit); err == nil {
		t.Fatal("an unauditable client deletion reported success")
	}
	client, err := s.GetOAuthClientByID("c1")
	if err != nil {
		t.Fatal(err)
	}
	if client == nil {
		t.Fatal("the client was deleted with no record of who deleted it")
	}
	// The revocation is part of the same commit, so it must have rolled back too. Anything
	// else leaves the tokens dead while the client is reported alive.
	revoked, err := s.IsTokenRevoked("jti-1")
	if err != nil {
		t.Fatal(err)
	}
	if revoked {
		t.Fatal("tokens were revoked by a deletion that did not happen")
	}
}

// The successful path must actually write the row; a test that only proves rollback would
// pass just as well against a store that never wrote audit rows at all.
func TestSuccessfulMutationsCommitTheirAuditRow(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	u.DisplayName = "Renamed"
	audit := &AuditEvent{
		ID: "ok-1", Action: "admin.user_updated", TargetID: u.ID,
		ActorUsername: "root", Outcome: "success",
	}
	if err := s.UpdateUserWithSyncEvents(u, false, audit); err != nil {
		t.Fatal(err)
	}
	events, total, err := s.ListAuditEvents(10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(events) != 1 || events[0].ID != "ok-1" || events[0].Action != "admin.user_updated" {
		t.Fatalf("the audit row did not commit with its mutation: %d %+v", total, events)
	}
	if events[0].CreatedAt.IsZero() {
		t.Fatal("the committed audit row has no timestamp")
	}
}
