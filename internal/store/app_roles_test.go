package store

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func rolesFixture(t *testing.T) (*Store, *User, AppRecord, AppRecord) {
	t.Helper()
	s, cleanup := setupTestStore(t)
	t.Cleanup(cleanup)
	u := createTestUser(t, s)
	var apps []AppRecord
	for _, id := range []string{"billing", "hr"} {
		if err := s.CreateOAuthClient(&OAuthClient{ID: id, ClientName: id, ClientType: "public", RedirectURIsJSON: `["https://example.com/cb"]`, AllowedScopesJSON: `["openid","profile","email"]`, Enabled: true}); err != nil {
			t.Fatal(err)
		}
		rows, _, err := s.ListAppRecords(id, 25, 0)
		if err != nil || len(rows) != 1 {
			t.Fatal(err)
		}
		if err := s.SetAppPolicy(rows[0].ID, "all_active_users", true, rows[0].Revision, nil); err != nil {
			t.Fatal(err)
		}
		app, _ := s.GetAppRecord(rows[0].ID)
		apps = append(apps, app)
	}
	if err := s.CreateSession(&Session{ID: "session", UserID: u.ID, SessionTokenHash: "hash", ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	return s, u, apps[0], apps[1]
}

// A group mapped to one app's role grants that role there and nothing anywhere else.
func TestAppRolesAreScopedToTheirApp(t *testing.T) {
	s, u, billing, hr := rolesFixture(t)
	if err := s.CreateGroup(&Group{ID: "finance", Name: "Finance"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGroupMembership("finance", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	role, err := s.CreateAppRole(billing.ID, "billing.admin", "Runs invoices", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAppRole(billing.ID, "Billing.Admin", "", nil); !errors.Is(err, ErrAppRoleExists) {
		t.Fatalf("case-insensitive duplicate accepted: %v", err)
	}
	for _, bad := range []string{"", "has space", strings.Repeat("x", 65), "-leading"} {
		if _, err := s.CreateAppRole(billing.ID, bad, "", nil); !errors.Is(err, ErrAppRoleInvalid) {
			t.Fatalf("invalid role name %q accepted: %v", bad, err)
		}
	}
	if err := s.SetAppRoleAssignment(billing.ID, role.ID, "groups", "finance", true, nil); err != nil {
		t.Fatal(err)
	}
	claims, err := s.UserAppClaims(u.ID, "billing")
	if err != nil || len(claims.Roles) != 1 || claims.Roles[0] != "billing.admin" {
		t.Fatalf("billing claims: %+v %v", claims, err)
	}
	if claims.LegacyRole {
		t.Fatal("a new app started with the legacy role claim on")
	}
	other, _ := s.UserAppClaims(u.ID, "hr")
	if len(other.Roles) != 0 {
		t.Fatalf("role leaked into another app: %+v", other)
	}
	// A direct mapping and a group mapping to the same role yield the role once.
	if err := s.SetAppRoleAssignment(billing.ID, role.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if claims, _ = s.UserAppClaims(u.ID, "billing"); len(claims.Roles) != 1 {
		t.Fatalf("duplicate role: %+v", claims)
	}
	listed, _ := s.ListAppRoles(billing.ID)
	if len(listed) != 1 || len(listed[0].Users) != 1 || len(listed[0].Groups) != 1 || listed[0].Groups[0].Name != "Finance" {
		t.Fatalf("listing: %+v", listed)
	}
	// Mapping a role of one app through another app's id is refused.
	if err := s.SetAppRoleAssignment(hr.ID, role.ID, "users", u.ID, true, nil); !errors.Is(err, ErrAppRecordMissing) {
		t.Fatalf("cross-app mapping: %v", err)
	}
	if err := s.SetAppRoleAssignment(billing.ID, role.ID, "users", uuid.NewString(), true, nil); !errors.Is(err, ErrAppRecordMissing) {
		t.Fatalf("unknown principal: %v", err)
	}
	// Removing the group mapping leaves the direct one; removing that leaves nothing.
	if err := s.SetAppRoleAssignment(billing.ID, role.ID, "groups", "finance", false, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppRoleAssignment(billing.ID, role.ID, "users", u.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	if claims, _ = s.UserAppClaims(u.ID, "billing"); len(claims.Roles) != 0 {
		t.Fatalf("roles after unmapping: %+v", claims)
	}
	// A client with no app record only ever carries the legacy role.
	if claims, _ = s.UserAppClaims(u.ID, "unknown-client"); !claims.LegacyRole || len(claims.Roles) != 0 {
		t.Fatalf("unknown client claims: %+v", claims)
	}
}

// Role changes revoke the affected users' live grants for that app and only that app,
// and a code issued before the change cannot be exchanged after it.
func TestRoleChangesRevokeGrantsAndBlockStaleCodes(t *testing.T) {
	s, u, billing, hr := rolesFixture(t)
	other := createTestUser(t, s)
	if err := s.CreateSession(&Session{ID: "other-session", UserID: other.ID, SessionTokenHash: "hash2", ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	role, _ := s.CreateAppRole(billing.ID, "reader", "", nil)
	if err := s.SetAppRoleAssignment(billing.ID, role.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	code := func(id, client string, user *User, session string) {
		t.Helper()
		if err := s.CreateAuthorizationCode(&AuthorizationCode{ID: id, CodeHash: id, ClientID: client, UserID: user.ID, SessionID: session, ExpiresAt: time.Now().UTC().Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	code("c-billing", "billing", u, "session")
	code("c-hr", "hr", u, "session")
	code("c-other", "billing", other, "other-session")
	for _, tok := range []IssuedToken{{JTI: "t-billing", ClientID: "billing"}, {JTI: "t-hr", ClientID: "hr"}} {
		tok.UserID, tok.SessionID, tok.ExpiresAt = u.ID, "session", time.Now().UTC().Add(time.Hour)
		if err := s.RecordIssuedToken(&tok); err != nil {
			t.Fatal(err)
		}
	}
	// Spend the other user's code now: it must still be exchangeable until roles change.
	if ok, _ := s.ConsumeAuthorizationCode("c-other"); !ok {
		t.Fatal("consume")
	}

	if err := s.SetAppRoleAssignment(billing.ID, role.ID, "users", u.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	if revoked, _ := s.IsTokenRevoked("t-billing"); !revoked {
		t.Fatal("billing token survived the role change")
	}
	if revoked, _ := s.IsTokenRevoked("t-hr"); revoked {
		t.Fatal("hr token was revoked by a billing role change")
	}
	if n := count(t, s, `SELECT COUNT(*) FROM authorization_codes WHERE id='c-billing'`); n != 0 {
		t.Fatal("billing code survived the role change")
	}
	if n := count(t, s, `SELECT COUNT(*) FROM authorization_codes WHERE id='c-hr'`); n != 1 {
		t.Fatal("hr code was deleted by a billing role change")
	}
	// The other user's spent code carries the old role revision: exchange is refused.
	err := s.RecordIssuedToken(&IssuedToken{JTI: "t-stale", UserID: other.ID, ClientID: "billing", SessionID: "other-session", AuthorizationCodeID: "c-other", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if !errors.Is(err, ErrAppAccessDenied) {
		t.Fatalf("stale code exchanged after a role change: %v", err)
	}
	app, _ := s.GetAppRecord(billing.ID)
	if app.RoleRevision != 2 {
		t.Fatalf("role revision = %d, want 2 (map, unmap)", app.RoleRevision)
	}
	_ = hr

	// Claim settings are part of the token shape: changing them revokes every grant.
	code("c-billing-2", "billing", u, "session")
	if err := s.SetAppClaimSettings(billing.ID, true, true, app.Revision, nil); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM authorization_codes WHERE client_id='billing'`); n != 0 {
		t.Fatal("codes survived a claim-shape change")
	}
	if err := s.SetAppClaimSettings(billing.ID, true, true, app.Revision, nil); !errors.Is(err, ErrAppLinkConflict) {
		t.Fatalf("stale revision accepted: %v", err)
	}
	claims, _ := s.UserAppClaims(u.ID, "billing")
	if !claims.LegacyRole || !claims.GroupsClaim {
		t.Fatalf("claim settings not applied: %+v", claims)
	}
}

// A role held through a group reaches the app's provisioning connection as a SCIM role,
// and a role change re-sends the profile.
func TestAppRolesReachProvisioningAndDeletingARoleRevokesIt(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	appID := provisioningFixture(t, s, "target")
	u := createTestUser(t, s)
	if err := s.CreateGroup(&Group{ID: "ops", Name: "Ops"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGroupMembership("ops", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppAssignment(appID, "groups", "ops", true, nil); err != nil {
		t.Fatal(err)
	}
	deliverAll(t, s)
	role, err := s.CreateAppRole(appID, "operator", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppRoleAssignment(appID, role.ID, "groups", "ops", true, nil); err != nil {
		t.Fatal(err)
	}
	var payload string
	if err := s.db.QueryRow(`SELECT payload_json FROM account_sync_events WHERE user_id=? AND status='pending' ORDER BY rowid DESC LIMIT 1`, u.ID).Scan(&payload); err != nil {
		t.Fatalf("no desired-state event after mapping: %v", err)
	}
	if !strings.Contains(payload, `"operator"`) || strings.Contains(payload, `"value":"user"`) {
		t.Fatalf("payload carries the wrong roles: %s", payload)
	}
	deliverAll(t, s)
	if err := s.DeleteAppRole(appID, role.ID, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT payload_json FROM account_sync_events WHERE user_id=? AND status='pending' ORDER BY rowid DESC LIMIT 1`, u.ID).Scan(&payload); err != nil {
		t.Fatalf("no desired-state event after deleting the role: %v", err)
	}
	if strings.Contains(payload, `"operator"`) {
		t.Fatalf("deleted role still delivered: %s", payload)
	}
	if roles, _ := s.ListAppRoles(appID); len(roles) != 0 {
		t.Fatalf("role survived deletion: %+v", roles)
	}
	// Apps with roles cannot be linked or unlinked until the roles are removed.
	if err := s.CreateOAuthClient(&OAuthClient{ID: "portal", ClientName: "Portal", ClientType: "public", RedirectURIsJSON: `["https://p/cb"]`, AllowedScopesJSON: `["openid"]`, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAppRole(appID, "again", "", nil); err != nil {
		t.Fatal(err)
	}
	rows, _, _ := s.ListAppRecords("portal", 25, 0)
	target, _ := s.GetAppRecord(appID)
	if err := s.LinkAppRecords(target.ID, rows[0].ID, target.Revision, rows[0].Revision, nil); !errors.Is(err, ErrAppLinkConflict) {
		t.Fatalf("link with roles present: %v", err)
	}
}

// Leaving a group that is mapped to an app role is a role change: the user's live grants
// for that app end and the provisioned account is re-sent without the role, even while
// they keep access to the app on other grounds.
func TestLeavingAMappedGroupRevokesTheRoleDownstream(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	appID := provisioningFixture(t, s, "target")
	if err := s.SetAppPolicy(appID, "all_active_users", true, 1, nil); err != nil {
		t.Fatal(err)
	}
	u := createTestUser(t, s)
	if err := s.CreateGroup(&Group{ID: "ops", Name: "Ops"}, nil); err != nil {
		t.Fatal(err)
	}
	role, _ := s.CreateAppRole(appID, "operator", "", nil)
	if err := s.SetAppRoleAssignment(appID, role.ID, "groups", "ops", true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGroupMembership("ops", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	deliverAll(t, s)
	app, _ := s.GetAppRecord(appID)
	revisionBefore := app.RoleRevision
	if err := s.SetGroupMembership("ops", u.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	var payload string
	if err := s.db.QueryRow(`SELECT payload_json FROM account_sync_events WHERE user_id=? AND status='pending' ORDER BY rowid DESC LIMIT 1`, u.ID).Scan(&payload); err != nil {
		t.Fatalf("leaving the group queued nothing: %v", err)
	}
	if strings.Contains(payload, `"operator"`) {
		t.Fatalf("revoked role still delivered: %s", payload)
	}
	if app, _ = s.GetAppRecord(appID); app.RoleRevision != revisionBefore+1 {
		t.Fatalf("role revision not bumped by a membership change: %d -> %d", revisionBefore, app.RoleRevision)
	}
	// Deleting a mapped group does the same for every member.
	if err := s.SetGroupMembership("ops", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	deliverAll(t, s)
	if err := s.DeleteGroup("ops", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT payload_json FROM account_sync_events WHERE user_id=? AND status='pending' ORDER BY rowid DESC LIMIT 1`, u.ID).Scan(&payload); err != nil || strings.Contains(payload, `"operator"`) {
		t.Fatalf("group deletion did not revoke the role downstream: %s %v", payload, err)
	}
}

// Unmapping the last of a user's roles sends an explicit empty list, never an omitted
// attribute a merging receiver could read as unchanged.
func TestRevokedRolesAreSentAsAnEmptyList(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	appID := provisioningFixture(t, s, "target")
	u := createTestUser(t, s)
	if err := s.SetAppPolicy(appID, "all_active_users", true, 1, nil); err != nil {
		t.Fatal(err)
	}
	deliverAll(t, s)
	held, _ := s.CreateAppRole(appID, "held", "", nil)
	if _, err := s.CreateAppRole(appID, "other", "", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppRoleAssignment(appID, held.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	deliverAll(t, s)
	if err := s.SetAppRoleAssignment(appID, held.ID, "users", u.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	var payload string
	if err := s.db.QueryRow(`SELECT payload_json FROM account_sync_events WHERE user_id=? AND status='pending' ORDER BY rowid DESC LIMIT 1`, u.ID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload, `"roles":[]`) {
		t.Fatalf("revocation not stated explicitly: %s", payload)
	}
}
