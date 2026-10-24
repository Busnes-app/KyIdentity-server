package store

import (
	"database/sql"
	"errors"
	"testing"
	"time"
)

// Guards the account lockout: below MaxFailedLogins the account is open, at the limit it
// is locked, and the lock lapses LockoutDuration after the last failure. Clearing
// failures (a successful sign-in) unlocks it.
func TestIsAccountLockedWindow(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	if locked, err := s.IsAccountLocked(u.ID); err != nil || locked {
		t.Fatal("fresh account locked", err)
	}
	for i := 1; i < MaxFailedLogins; i++ {
		if n, err := s.RecordFailedLogin(u.ID); err != nil || n != i {
			t.Fatalf("failure %d counted as %d, %v", i, n, err)
		}
	}
	if locked, _ := s.IsAccountLocked(u.ID); locked {
		t.Fatal("locked below the limit")
	}
	if _, err := s.RecordFailedLogin(u.ID); err != nil {
		t.Fatal(err)
	}
	if locked, err := s.IsAccountLocked(u.ID); err != nil || !locked {
		t.Fatal("limit reached but account open", err)
	}
	mustExec(t, s, `UPDATE login_failures SET last_failure_at=? WHERE user_id=?`, time.Now().UTC().Add(-LockoutDuration-time.Second), u.ID)
	if locked, _ := s.IsAccountLocked(u.ID); locked {
		t.Fatal("lock outlived LockoutDuration")
	}
	mustExec(t, s, `UPDATE login_failures SET last_failure_at=? WHERE user_id=?`, time.Now().UTC(), u.ID)
	if err := s.ClearFailedLogins(u.ID); err != nil {
		t.Fatal(err)
	}
	if locked, _ := s.IsAccountLocked(u.ID); locked {
		t.Fatal("cleared failures still locked")
	}
}

// Guards push approval races: a challenge moves out of pending exactly once, approval
// stamps verified_at, and a denied challenge cannot later be approved.
func TestTransitionMFAChallengeStatusOnce(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	for _, id := range []string{"c1", "c2"} {
		if err := s.CreateMFAChallenge(&MFAChallenge{ID: id, UserID: u.ID, MethodType: "push", Status: "pending", Purpose: "login", ExpiresAt: time.Now().UTC().Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	if ok, err := s.TransitionMFAChallengeStatus("c1", "pending", "approved"); err != nil || !ok {
		t.Fatal("approve", ok, err)
	}
	if ok, _ := s.TransitionMFAChallengeStatus("c1", "pending", "denied"); ok {
		t.Fatal("approved challenge transitioned again")
	}
	if ch, _ := s.GetMFAChallenge("c1"); ch.Status != "approved" || ch.VerifiedAt == nil {
		t.Fatalf("approval not stamped: %+v", ch)
	}
	if ok, _ := s.TransitionMFAChallengeStatus("c2", "pending", "denied"); !ok {
		t.Fatal("deny failed")
	}
	if ok, _ := s.TransitionMFAChallengeStatus("c2", "pending", "approved"); ok {
		t.Fatal("denied challenge approved")
	}
	if ch, _ := s.GetMFAChallenge("c2"); ch.Status != "denied" || ch.VerifiedAt != nil {
		t.Fatalf("denied challenge verified: %+v", ch)
	}
	if ok, err := s.TransitionMFAChallengeStatus("missing", "pending", "approved"); err != nil || ok {
		t.Fatal("unknown challenge transitioned", ok, err)
	}
}

// Guards TOTP replay protection: a counter is accepted once and never again, nor any
// earlier one; users without TOTP accept nothing.
func TestConsumeTOTPCounterRefusesReplay(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	if ok, _ := s.ConsumeTOTPCounter(u.ID, 5); ok {
		t.Fatal("counter accepted without a TOTP method")
	}
	if err := s.SetMFAMethod(&MFAMethod{ID: "totp", UserID: u.ID, MethodType: "totp", EncryptedSecret: "x"}, nil); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ConsumeTOTPCounter(u.ID, 5); err != nil || !ok {
		t.Fatal("first use refused", ok, err)
	}
	for _, c := range []int64{5, 4} {
		if ok, _ := s.ConsumeTOTPCounter(u.ID, c); ok {
			t.Fatalf("counter %d replayed", c)
		}
	}
	if ok, _ := s.ConsumeTOTPCounter(u.ID, 6); !ok {
		t.Fatal("next counter refused")
	}
}

// Guards device sign-on toggling: only an MFA approver may sign on, another user's device
// reads as missing, and success audits in the same transaction.
func TestSetNativeDeviceCanSignOnRules(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	other := createTestUser(t, s)
	if err := s.UpsertNativeDevice(&NativeDevice{ID: "plain", UserID: u.ID, DeviceIdentifier: "plain", DeviceName: "p", PublicKey: "k1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertNativeDevice(&NativeDevice{ID: "approver", UserID: u.ID, DeviceIdentifier: "approver", DeviceName: "a", PublicKey: "k2", IsMFAApprover: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNativeDeviceCanSignOn("plain", u.ID, true, nil); !errors.Is(err, ErrDeviceNotApprover) {
		t.Fatal("non-approver enabled for sign-on", err)
	}
	if err := s.SetNativeDeviceCanSignOn("approver", other.ID, true, nil); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("another user's device toggled", err)
	}
	if err := s.SetNativeDeviceCanSignOn("approver", u.ID, true, poisonedAudit(t, s, "user.device_sign_on", "approver")); err == nil {
		t.Fatal("toggle ignored audit failure")
	}
	if d, _ := s.GetNativeDevice("approver"); d.CanSignOn {
		t.Fatal("failed audit left sign-on enabled")
	}
	audit := &AuditEvent{ID: "sign-on", Action: "user.device_sign_on", Outcome: "success", CreatedAt: time.Now().UTC()}
	if err := s.SetNativeDeviceCanSignOn("approver", u.ID, true, audit); err != nil {
		t.Fatal(err)
	}
	if d, _ := s.GetNativeDevice("approver"); !d.CanSignOn || auditActions(t, s, "user.device_sign_on") != 1 {
		t.Fatal("sign-on not enabled with its audit row")
	}
	if d, _ := s.GetNativeDevice("plain"); d.CanSignOn {
		t.Fatal("non-approver changed")
	}
}

// Guards an MFA reset: every factor is removed, devices stop approving and signing on,
// and the user's sessions end.
func TestResetUserMFARemovesEveryFactor(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	if err := s.SetMFAMethod(&MFAMethod{ID: "totp", UserID: u.ID, MethodType: "totp", EncryptedSecret: "x"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceRecoveryCodes(u.ID, []RecoveryCode{{ID: "rc", UserID: u.ID, CodeHash: "h"}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertNativeDevice(&NativeDevice{ID: "d", UserID: u.ID, DeviceIdentifier: "d", DeviceName: "d", PublicKey: "k", IsMFAApprover: true, CanSignOn: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(&Session{ID: "sess", UserID: u.ID, SessionTokenHash: "sh", ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := s.ResetUserMFA(u.ID, &AuditEvent{ID: "reset", Action: "admin.mfa_reset", Outcome: "success", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if count(t, s, `SELECT COUNT(*) FROM mfa_methods WHERE user_id=?`, u.ID)+count(t, s, `SELECT COUNT(*) FROM recovery_codes WHERE user_id=?`, u.ID) != 0 {
		t.Fatal("reset kept a factor")
	}
	if d, _ := s.GetNativeDevice("d"); d.IsMFAApprover || d.CanSignOn {
		t.Fatalf("device still approves or signs on: %+v", d)
	}
	if count(t, s, `SELECT COUNT(*) FROM sessions WHERE user_id=?`, u.ID) != 0 || auditActions(t, s, "admin.mfa_reset") != 1 {
		t.Fatal("reset left a session or no audit row")
	}
}

// Guards account deletion: a missing account is sql.ErrNoRows, the last permanent admin
// cannot be deleted, and a deletion queues user.deleted for every live connector.
func TestDeleteUserWithSyncEventsRules(t *testing.T) {
	s, admin := newStoreWithUser(t, "admin")
	if err := s.DeleteUserWithSyncEvents("missing", nil); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("missing account", err)
	}
	if err := s.DeleteUserWithSyncEvents(admin.ID, nil); !errors.Is(err, ErrLastActiveAdmin) {
		t.Fatal("last admin deleted", err)
	}
	if u, _ := s.GetUserByID(admin.ID); u == nil {
		t.Fatal("refused deletion removed the admin")
	}
	if err := s.CreatePairedSystem(&PairedSystem{ID: "sys", Name: "Sys", SystemType: "scim", CallbackURL: "https://sys.example/scim", HMACSecretEncrypted: "x", Status: "active"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePairedSystem(&PairedSystem{ID: "off", Name: "Off", SystemType: "scim", CallbackURL: "https://off.example/scim", HMACSecretEncrypted: "x", Status: "disabled"}, nil); err != nil {
		t.Fatal(err)
	}
	u := createTestUser(t, s)
	if err := s.DeleteUserWithSyncEvents(u.ID, &AuditEvent{ID: "del", Action: "admin.user_deleted", TargetID: u.ID, Outcome: "success", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetUserByID(u.ID); got != nil {
		t.Fatal("user not deleted")
	}
	if count(t, s, `SELECT COUNT(*) FROM account_sync_events WHERE system_id='sys' AND event_type='user.deleted' AND user_id=?`, u.ID) != 1 {
		t.Fatal("deletion not queued for the live connector")
	}
	if count(t, s, `SELECT COUNT(*) FROM account_sync_events WHERE system_id='off'`) != 0 {
		t.Fatal("deletion queued for a disabled connector")
	}
	if auditActions(t, s, "admin.user_deleted") != 1 {
		t.Fatal("deletion not audited")
	}
}

// Guards client updates: disabling a client revokes its tokens, and a failed audit
// rolls back both the update and the revocation.
func TestUpdateOAuthClientWithAuditRevokesOnDisable(t *testing.T) {
	s, u, a := appAccessFixture(t)
	if err := s.SetAppAssignment(a.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordIssuedToken(accessToken(u, "tok", "")); err != nil {
		t.Fatal(err)
	}
	c, err := s.GetOAuthClientByID("client")
	if err != nil || c == nil {
		t.Fatal(err)
	}
	c.Enabled = false
	if err := s.UpdateOAuthClientWithAudit(c, false, poisonedAudit(t, s, "admin.client_updated", "client")); err == nil {
		t.Fatal("update ignored audit failure")
	}
	if got, _ := s.GetOAuthClientByID("client"); !got.Enabled {
		t.Fatal("failed update disabled the client")
	}
	assertRevoked(t, s, "tok", false)
	if err := s.UpdateOAuthClientWithAudit(c, false, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetOAuthClientByID("client"); got.Enabled || got.PostLogoutRedirectURIsJSON != "[]" {
		t.Fatalf("update not applied: %+v", got)
	}
	assertRevoked(t, s, "tok", true)
}

// Guards the plain listings used by the admin UI and exports: stable ordering and
// optional columns.
func TestListUsersApplicationsAndPairedSystemsOrdering(t *testing.T) {
	s, _ := newStoreWithUser(t, "user")
	createTestUserNamed(t, s, "zed")
	createTestUserNamed(t, s, "bob")
	users, err := s.ListUsers()
	if err != nil || len(users) != 3 || users[0].Username != "ada" || users[1].Username != "bob" || users[2].Username != "zed" {
		t.Fatalf("users not ordered by name: %+v %v", users, err)
	}
	if apps, err := s.ListApplications(); err != nil || len(apps) != 0 {
		t.Fatal("empty applications", apps, err)
	}
	for _, a := range []*Application{
		{ID: "b", Name: "Beta", URL: "https://b.example", SortOrder: 2, Enabled: true},
		{ID: "a2", Name: "Zulu", URL: "https://z.example", SortOrder: 1, Description: "last of first"},
		{ID: "a1", Name: "Alpha", URL: "https://a.example", SortOrder: 1, Enabled: true},
	} {
		if err := s.CreateApplication(a, nil); err != nil {
			t.Fatal(err)
		}
	}
	apps, err := s.ListApplications()
	if err != nil || len(apps) != 3 || apps[0].ID != "a1" || apps[1].ID != "a2" || apps[2].ID != "b" || apps[1].Description != "last of first" || apps[1].Enabled {
		t.Fatalf("applications not ordered by sort_order, name: %+v %v", apps, err)
	}
	for _, id := range []string{"first", "second"} {
		if err := s.CreatePairedSystem(&PairedSystem{ID: id, Name: id, SystemType: "scim", CallbackURL: "https://" + id + ".example", HMACSecretEncrypted: "x", Status: "active"}, nil); err != nil {
			t.Fatal(err)
		}
	}
	systems, err := s.ListAllPairedSystems()
	if err != nil || len(systems) != 2 || systems[0].ID != "first" || systems[1].ID != "second" {
		t.Fatalf("paired systems not in creation order: %+v %v", systems, err)
	}
}

// Guards the launcher's view of app access: only effective grants appear, keyed by
// source so client and custom ids cannot collide.
func TestLauncherAppAccessKeys(t *testing.T) {
	s, u, a := appAccessFixture(t)
	if err := s.CreateApplication(&Application{ID: "wiki", Name: "Wiki", URL: "https://wiki.example", Enabled: true}, nil); err != nil {
		t.Fatal(err)
	}
	if got, err := s.LauncherAppAccess(u.ID); err != nil || len(got) != 0 {
		t.Fatal("unassigned user sees apps", got, err)
	}
	if err := s.SetAppAssignment(a.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	got, err := s.LauncherAppAccess(u.ID)
	if err != nil || len(got) != 1 || !got["client:client"] {
		t.Fatalf("client grant = %v, %v", got, err)
	}
	recs, _, err := s.ListAppRecords("wiki", 25, 0)
	if err != nil || len(recs) != 1 {
		t.Fatal(err)
	}
	if err := s.SetAppPolicy(recs[0].ID, "all_active_users", true, recs[0].Revision, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.LauncherAppAccess(u.ID); len(got) != 2 || !got["custom:wiki"] {
		t.Fatalf("custom grant missing: %v", got)
	}
	if got, _ := s.LauncherAppAccess("nobody"); len(got) != 0 {
		t.Fatal("unknown user sees apps", got)
	}
}

// Guards the app-access group picker: an unknown app is ErrAppRecordMissing, the search
// filters and pages, and assignment flags reflect only this app.
func TestListAppAccessGroups(t *testing.T) {
	s, _, a := appAccessFixture(t)
	if _, _, err := s.ListAppAccessGroups("missing", "", 25, 0); !errors.Is(err, ErrAppRecordMissing) {
		t.Fatal("missing app", err)
	}
	for _, g := range []string{"Sales", "Support", "Engineering"} {
		if err := s.CreateGroup(&Group{ID: g, Name: g}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetAppAssignment(a.ID, "groups", "Support", true, nil); err != nil {
		t.Fatal(err)
	}
	groups, total, err := s.ListAppAccessGroups(a.ID, "s", 1, 1)
	if err != nil || total != 2 || len(groups) != 1 || groups[0].ID != "Support" || !groups[0].Assigned {
		t.Fatalf("search page = %+v %d %v", groups, total, err)
	}
	groups, total, _ = s.ListAppAccessGroups(a.ID, "", 25, 0)
	if total != 3 || groups[0].Name != "Engineering" || groups[0].Assigned || groups[1].Assigned {
		t.Fatalf("full list = %+v %d", groups, total)
	}
}

// Guards policy input validation: unknown modes and stale revisions are refused without
// touching access.
func TestSetAppPolicyRefusesBadInput(t *testing.T) {
	s, u, a := appAccessFixture(t)
	if err := s.SetAppPolicy(a.ID, "everyone", true, a.Revision, nil); !errors.Is(err, ErrAppLinkConflict) {
		t.Fatal("unknown mode", err)
	}
	if err := s.SetAppPolicy(a.ID, "all_active_users", true, a.Revision+1, nil); !errors.Is(err, ErrAppLinkConflict) {
		t.Fatal("stale revision", err)
	}
	if err := s.SetAppPolicy("missing", "all_active_users", true, 1, nil); !errors.Is(err, ErrAppRecordMissing) {
		t.Fatal("missing app", err)
	}
	if allowed, _ := s.ClientAccessAllowed(u.ID, "client"); allowed {
		t.Fatal("refused policy granted access")
	}
	if _, err := s.ListAppAccessUsers(a.ID, "", "everyone", nil, 25, 0); !errors.Is(err, ErrAppLinkConflict) {
		t.Fatal("unknown preview mode", err)
	}
	if _, err := s.ListAppAccessUsers("missing", "", "", nil, 25, 0); !errors.Is(err, ErrAppRecordMissing) {
		t.Fatal("missing app preview", err)
	}
	off := false
	p, err := s.ListAppAccessUsers(a.ID, "", "all_active_users", &off, 25, 0)
	if err != nil || p.GainingAccess != 0 || p.LosingAccess != 0 {
		t.Fatalf("disabled preview grants access: %+v %v", p, err)
	}
}
