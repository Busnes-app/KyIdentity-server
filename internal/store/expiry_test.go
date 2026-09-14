package store

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"
)

func future(d time.Duration) *time.Time {
	t := time.Now().UTC().Add(d).Truncate(time.Second)
	return &t
}

// Expiry is evaluated where access is decided, so an expired grant stops working with
// no worker running, and an alternate live grant keeps access alive.
func TestExpiredGrantsLoseAccessWithoutTheWorker(t *testing.T) {
	s, u, a := appAccessFixture(t)
	if err := s.SetAppPolicy(a.ID, "assigned_only", true, a.Revision, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppAssignmentUntil(a.ID, "users", u.ID, future(-time.Minute), nil); !errors.Is(err, ErrExpiryInPast) {
		t.Fatalf("past expiry accepted: %v", err)
	}
	until := future(time.Hour)
	if err := s.SetAppAssignmentUntil(a.ID, "users", u.ID, until, nil); err != nil {
		t.Fatal(err)
	}
	if allowed, _ := s.ClientAccessAllowed(u.ID, "client"); !allowed {
		t.Fatal("future expiry denied access")
	}
	if end, err := s.AccessEndsAt(u.ID, "client"); err != nil || end == nil || !end.Equal(*until) {
		t.Fatalf("access end = %v %v, want %v", end, err, until)
	}
	accessCode(t, s, u, "c1")
	if _, err := s.ConsumeAuthorizationCode("c1"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordIssuedToken(accessToken(u, "t1", "c1")); err != nil {
		t.Fatal(err)
	}
	// Time passes: the row's instant is behind us and no worker has run.
	if _, err := s.db.Exec(`UPDATE app_user_assignments SET expires_at=unixepoch()-1 WHERE user_id=?`, u.ID); err != nil {
		t.Fatal(err)
	}
	if allowed, _ := s.ClientAccessAllowed(u.ID, "client"); allowed {
		t.Fatal("expired grant still allows access")
	}
	if err := s.CreateAuthorizationCode(&AuthorizationCode{ID: "c2", CodeHash: "c2", ClientID: "client", UserID: u.ID, SessionID: "session", ExpiresAt: time.Now().UTC().Add(time.Minute)}); !errors.Is(err, ErrAppAccessDenied) {
		t.Fatalf("code issued on an expired grant: %v", err)
	}
	if err := s.RecordIssuedToken(accessToken(u, "t2", "c1")); !errors.Is(err, ErrAppAccessDenied) {
		t.Fatalf("token issued on an expired grant: %v", err)
	}
	// An unexpired group grant is an alternate source: access stays.
	if err := s.CreateGroup(&Group{ID: "staff", Name: "Staff"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppAssignment(a.ID, "groups", "staff", true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGroupMembershipUntil("staff", u.ID, future(time.Hour), "", nil); err != nil {
		t.Fatal(err)
	}
	if allowed, _ := s.ClientAccessAllowed(u.ID, "client"); !allowed {
		t.Fatal("live group grant did not preserve access")
	}
	if _, err := s.db.Exec(`UPDATE group_memberships SET expires_at=unixepoch()-1 WHERE user_id=?`, u.ID); err != nil {
		t.Fatal(err)
	}
	if allowed, _ := s.ClientAccessAllowed(u.ID, "client"); allowed {
		t.Fatal("expired membership still grants access")
	}
}

// The worker removes what has expired, revokes what depended on it and re-sends
// downstream state; a later extension is respected and a second run finds nothing.
func TestRunDueExpiriesRevokesAndDeprovisions(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	appID := provisioningFixture(t, s, "target")
	u := createTestUser(t, s)
	other := createTestUserNamed(t, s, "other")
	if err := s.CreateOAuthClient(&OAuthClient{ID: "client", ClientName: "App", ClientType: "public", RedirectURIsJSON: `["https://example.com/cb"]`, AllowedScopesJSON: `["openid"]`, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	clientApps, _, _ := s.ListAppRecords("client", 1, 0)
	if err := s.SetAppAssignmentUntil(appID, "users", u.ID, future(time.Hour), nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppAssignmentUntil(appID, "users", other.ID, future(time.Hour), nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppAssignmentUntil(clientApps[0].ID, "users", u.ID, future(time.Hour), nil); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateGroup(&Group{ID: "ops", Name: "Ops"}, nil); err != nil {
		t.Fatal(err)
	}
	role, _ := s.CreateAppRole(clientApps[0].ID, "operator", "", nil)
	if err := s.SetAppRoleAssignment(clientApps[0].ID, role.ID, "groups", "ops", true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGroupMembershipUntil("ops", u.ID, future(time.Hour), "", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(&Session{ID: "session", UserID: u.ID, SessionTokenHash: "hash", ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	accessCode(t, s, u, "c1")
	if _, err := s.ConsumeAuthorizationCode("c1"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordIssuedToken(accessToken(u, "t1", "c1")); err != nil {
		t.Fatal(err)
	}
	deliverAll(t, s)
	if claims, _ := s.UserAppClaims(u.ID, "client"); len(claims.Roles) != 1 {
		t.Fatalf("role not held before expiry: %+v", claims)
	}
	if run, err := s.RunDueExpiries(time.Now().UTC()); err != nil || run.Assignments+run.Memberships+run.Accounts != 0 {
		t.Fatalf("nothing is due yet: %+v %v", run, err)
	}
	// Everything of u's expires; other's grant is extended just before the run.
	if _, err := s.db.Exec(`UPDATE app_user_assignments SET expires_at=unixepoch()-5; UPDATE group_memberships SET expires_at=unixepoch()-5`); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppAssignmentUntil(appID, "users", other.ID, future(2*time.Hour), nil); err != nil {
		t.Fatal(err)
	}
	run, err := s.RunDueExpiries(time.Now().UTC())
	if err != nil || run.Assignments != 2 || run.Memberships != 1 || run.Accounts != 0 {
		t.Fatalf("run = %+v %v", run, err)
	}
	if revoked, _ := s.IsTokenRevoked("t1"); !revoked {
		t.Fatal("token outlived its grant")
	}
	if claims, _ := s.UserAppClaims(u.ID, "client"); len(claims.Roles) != 0 {
		t.Fatalf("role outlived the membership: %+v", claims)
	}
	var pendingInactive int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM account_sync_events WHERE user_id=? AND status='pending' AND payload_json LIKE '%"active":false%'`, u.ID).Scan(&pendingInactive); err != nil || pendingInactive != 1 {
		t.Fatalf("deprovisioning not queued: %d %v", pendingInactive, err)
	}
	var otherLeft int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM app_user_assignments WHERE user_id=?`, other.ID).Scan(&otherLeft); err != nil || otherLeft != 1 {
		t.Fatal("extension undone by the run", otherLeft, err)
	}
	events, _, _ := s.ListAuditEvents(20, 0)
	expired := 0
	for _, e := range events {
		if strings.HasSuffix(e.Action, "_expired") && e.ActorUsername == "expiry" {
			expired++
		}
	}
	if expired != 3 {
		t.Fatalf("expiry audit rows = %d", expired)
	}
	if run, err := s.RunDueExpiries(time.Now().UTC()); err != nil || run.Assignments+run.Memberships != 0 {
		t.Fatalf("second run repeated work: %+v %v", run, err)
	}
}

// An account end date ends the account: sessions and grants go, the profile is
// deprovisioned, and the last administrator can neither be scheduled nor ended.
func TestAccountEndDate(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	admin := createTestUserNamed(t, s, "root")
	admin.Role = "admin"
	if err := s.UpdateUserWithSyncEvents(admin, false, nil); err != nil {
		t.Fatal(err)
	}
	admin.EndsAt = future(time.Hour)
	if err := s.UpdateUserWithSyncEvents(admin, false, nil); !errors.Is(err, ErrLastActiveAdmin) {
		t.Fatalf("last administrator scheduled for removal: %v", err)
	}
	u := createTestUser(t, s)
	if err := s.CreateSession(&Session{ID: "session", UserID: u.ID, SessionTokenHash: "hash", ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	u.EndsAt = future(time.Hour)
	if err := s.UpdateUserWithSyncEvents(u, false, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetUserByID(u.ID); got.Status != "active" || got.EndsAt == nil {
		t.Fatalf("future end date changed status: %+v", got)
	}
	if _, err := s.db.Exec(`UPDATE users SET ends_at=unixepoch()-1 WHERE id=?`, u.ID); err != nil {
		t.Fatal(err)
	}
	// Ended: every read that decides access sees a disabled account, worker or not.
	if got, _ := s.GetUserByID(u.ID); got.Status != "disabled" {
		t.Fatal("ended account still reads active")
	}
	if sess, _ := s.GetSessionByTokenHash("hash", time.Hour); sess == nil {
		t.Fatal("fixture session missing")
	}
	run, err := s.RunDueExpiries(time.Now().UTC())
	if err != nil || run.Accounts != 1 {
		t.Fatalf("run = %+v %v", run, err)
	}
	if sess, _ := s.GetSessionByTokenHash("hash", time.Hour); sess != nil {
		t.Fatal("ended account kept its session")
	}
	var status string
	if err := s.db.QueryRow(`SELECT status FROM users WHERE id=?`, u.ID).Scan(&status); err != nil || status != "disabled" {
		t.Fatal("account not disabled on disk", status, err)
	}
	// The sole administrator reaching an end date is refused, audited, and kept.
	if _, err := s.db.Exec(`UPDATE users SET ends_at=unixepoch()-1 WHERE id=?`, admin.ID); err != nil {
		t.Fatal(err)
	}
	if run, err := s.RunDueExpiries(time.Now().UTC()); err != nil || run.Accounts != 0 {
		t.Fatalf("last admin ended: %+v %v", run, err)
	}
	got, _ := s.GetUserByID(admin.ID)
	if got.Status != "active" || got.EndsAt != nil {
		t.Fatalf("last admin not preserved: %+v", got)
	}
	events, _, _ := s.ListAuditEvents(10, 0)
	denied := false
	for _, e := range events {
		if e.Action == "account.end_refused" && e.Outcome == "denied" && e.TargetID == admin.ID {
			denied = true
		}
	}
	if !denied {
		t.Fatal("refusal not audited")
	}
	// A back-dated end is refused by the store itself and leaves the row untouched.
	var before sql.NullInt64
	if err := s.db.QueryRow(`SELECT ends_at FROM users WHERE id=?`, u.ID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	fresh, _ := s.GetUserByID(u.ID)
	fresh.EndsAt = future(-time.Minute)
	if err := s.UpdateUserWithSyncEvents(fresh, false, nil); !errors.Is(err, ErrExpiryInPast) {
		t.Fatalf("past end date accepted by the store: %v", err)
	}
	var stored sql.NullInt64
	if err := s.db.QueryRow(`SELECT ends_at FROM users WHERE id=?`, u.ID).Scan(&stored); err != nil || stored != before {
		t.Fatalf("refused write changed the row: %v -> %v %v", before, stored, err)
	}
}

// An administrator whose end has passed but who the follow-up has not yet processed is
// no administrator for the invariant: the other one cannot step down.
func TestEndedAdministratorDoesNotCount(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	first, second := createTestUserNamed(t, s, "first"), createTestUserNamed(t, s, "second")
	for _, a := range []*User{first, second} {
		a.Role = "admin"
		if err := s.UpdateUserWithSyncEvents(a, false, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec(`UPDATE users SET ends_at=unixepoch()-1 WHERE id=?`, second.ID); err != nil {
		t.Fatal(err)
	}
	stepDown, _ := s.GetUserByID(first.ID)
	stepDown.Role = "user"
	if err := s.UpdateUserWithSyncEvents(stepDown, false, nil); !errors.Is(err, ErrLastActiveAdmin) {
		t.Fatalf("phantom ended administrator satisfied the guard: %v", err)
	}
	if n, _ := s.CountAdmins(); n != 1 {
		t.Fatalf("CountAdmins counted the ended administrator: %d", n)
	}
}

// One item the pass cannot process is audited and retried later; everything else due
// is still applied in the same pass.
func TestRunDueExpiriesIsolatesFailures(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	if err := s.CreateOAuthClient(&OAuthClient{ID: "client", ClientName: "App", ClientType: "public", RedirectURIsJSON: `["https://example.com/cb"]`, AllowedScopesJSON: `["openid"]`, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	apps, _, _ := s.ListAppRecords("client", 1, 0)
	stuck, fine, ending := createTestUserNamed(t, s, "stuck"), createTestUserNamed(t, s, "fine"), createTestUserNamed(t, s, "ending")
	for _, u := range []*User{stuck, fine} {
		if err := s.SetAppAssignmentUntil(apps[0].ID, "users", u.ID, future(time.Hour), nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CreateGroup(&Group{ID: "staff", Name: "Staff"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGroupMembershipUntil("staff", fine.ID, future(time.Hour), "", nil); err != nil {
		t.Fatal(err)
	}
	ending.EndsAt = future(time.Hour)
	if err := s.UpdateUserWithSyncEvents(ending, false, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE app_user_assignments SET expires_at=unixepoch()-1; UPDATE group_memberships SET expires_at=unixepoch()-1; UPDATE users SET ends_at=unixepoch()-1 WHERE id=?`, ending.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER stuck_row BEFORE DELETE ON app_user_assignments WHEN OLD.user_id='` + stuck.ID + `' BEGIN SELECT RAISE(ABORT,'row is stuck'); END`); err != nil {
		t.Fatal(err)
	}
	run, err := s.RunDueExpiries(time.Now().UTC())
	if err == nil || !strings.Contains(err.Error(), "row is stuck") {
		t.Fatalf("stuck row not reported: %v", err)
	}
	if run.Assignments != 1 || run.Memberships != 1 || run.Accounts != 1 {
		t.Fatalf("other due items not applied: %+v", run)
	}
	var left int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM app_user_assignments`).Scan(&left); err != nil || left != 1 {
		t.Fatalf("assignments left = %d %v", left, err)
	}
	events, _, _ := s.ListAuditEvents(20, 0)
	failed := 0
	for _, e := range events {
		if e.Action == "app.assignment_expiry_failed" && e.Outcome == "failure" && e.TargetID == apps[0].ID {
			failed++
		}
	}
	if failed != 1 {
		t.Fatalf("failure audit rows = %d", failed)
	}
	if run, err = s.RunDueExpiries(time.Now().UTC()); err == nil || run.Assignments+run.Memberships+run.Accounts != 0 {
		t.Fatalf("second pass: %+v %v", run, err)
	}
	if _, err := s.db.Exec(`DROP TRIGGER stuck_row`); err != nil {
		t.Fatal(err)
	}
	if run, err = s.RunDueExpiries(time.Now().UTC()); err != nil || run.Assignments != 1 {
		t.Fatalf("recovered pass: %+v %v", run, err)
	}
}

// Effective access ends when the last live grant ends; an unbounded grant or policy
// means no bound, and the account end date caps everything.
func TestAccessEndsAtFollowsTheUnion(t *testing.T) {
	s, u, a := appAccessFixture(t)
	if err := s.SetAppPolicy(a.ID, "assigned_only", true, a.Revision, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateGroup(&Group{ID: "staff", Name: "Staff"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppAssignment(a.ID, "groups", "staff", true, nil); err != nil {
		t.Fatal(err)
	}
	direct, membership := future(time.Hour), future(3*time.Hour)
	if err := s.SetAppAssignmentUntil(a.ID, "users", u.ID, direct, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGroupMembershipUntil("staff", u.ID, membership, "", nil); err != nil {
		t.Fatal(err)
	}
	if end, err := s.AccessEndsAt(u.ID, "client"); err != nil || end == nil || !end.Equal(*membership) {
		t.Fatalf("union end = %v %v, want %v", end, err, membership)
	}
	if err := s.SetGroupMembershipUntil("staff", u.ID, nil, "", nil); err != nil {
		t.Fatal(err)
	}
	if end, _ := s.AccessEndsAt(u.ID, "client"); end != nil {
		t.Fatalf("unbounded membership still bounded: %v", end)
	}
	u.EndsAt = future(30 * time.Minute)
	if err := s.UpdateUserWithSyncEvents(u, false, nil); err != nil {
		t.Fatal(err)
	}
	if end, _ := s.AccessEndsAt(u.ID, "client"); end == nil || !end.Equal(*u.EndsAt) {
		t.Fatalf("account end date not applied: %v", end)
	}
}
