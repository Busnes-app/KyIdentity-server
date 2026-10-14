package store

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func appAccessFixture(t *testing.T) (*Store, *User, AppRecord) {
	t.Helper()
	s, cleanup := setupTestStore(t)
	t.Cleanup(cleanup)
	u := createTestUser(t, s)
	if err := s.CreateOAuthClient(&OAuthClient{ID: "client", ClientName: "App", ClientType: "public", RedirectURIsJSON: `["https://example.com/cb"]`, AllowedScopesJSON: `["openid"]`, Enabled: true}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(&Session{ID: "session", UserID: u.ID, SessionTokenHash: "hash", ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	apps, _, err := s.ListAppRecords("client", 25, 0)
	if err != nil || len(apps) != 1 {
		t.Fatal(err)
	}
	return s, u, apps[0]
}
func accessCode(t *testing.T, s *Store, u *User, id string) {
	t.Helper()
	if err := s.CreateAuthorizationCode(&AuthorizationCode{ID: id, CodeHash: id, ClientID: "client", UserID: u.ID, SessionID: "session", ExpiresAt: time.Now().UTC().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
}
func accessToken(u *User, id, code string) *IssuedToken {
	return &IssuedToken{JTI: id, UserID: u.ID, ClientID: "client", SessionID: "session", AuthorizationCodeID: code, ExpiresAt: time.Now().UTC().Add(time.Hour)}
}
func TestAppAccessUnionAndRevocation(t *testing.T) {
	s, u, a := appAccessFixture(t)
	if allowed, err := s.ClientAccessAllowed(u.ID, "client"); err != nil || allowed {
		t.Fatal("new app allowed unassigned user", err)
	}
	if _, err := s.db.Exec(`UPDATE users SET role='admin' WHERE id=?`, u.ID); err != nil {
		t.Fatal(err)
	}
	if allowed, _ := s.ClientAccessAllowed(u.ID, "client"); allowed {
		t.Fatal("admin bypassed assignment")
	}
	for _, id := range []string{"a", "b"} {
		if err := s.CreateGroup(&Group{ID: id, Name: id}, nil); err != nil {
			t.Fatal(err)
		}
		if err := s.SetGroupMembership(id, u.ID, true, nil); err != nil {
			t.Fatal(err)
		}
		if err := s.SetAppAssignment(a.ID, "groups", id, true, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetAppAssignment(a.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	accessCode(t, s, u, "pending")
	accessCode(t, s, u, "spent")
	if ok, err := s.ConsumeAuthorizationCode("spent"); err != nil || !ok {
		t.Fatal(err)
	}
	if err := s.RecordIssuedToken(accessToken(u, "token", "spent")); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGroupMembership("a", u.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGroup("b", nil); err != nil {
		t.Fatal(err)
	}
	if revoked, err := s.IsTokenRevoked("token"); err != nil || revoked {
		t.Fatal("alternative grant lost token", err)
	}
	if err := s.SetAppAssignment(a.ID, "users", u.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	if allowed, _ := s.ClientAccessAllowed(u.ID, "client"); allowed {
		t.Fatal("final assignment removal kept access")
	}
	if revoked, err := s.IsTokenRevoked("token"); err != nil || !revoked {
		t.Fatal("lost access retained token", err)
	}
	if c, err := s.GetValidAuthorizationCode("pending"); err != nil || c != nil {
		t.Fatal("lost access retained code", err)
	}
	if err := s.SetAppAssignment(a.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordIssuedToken(accessToken(u, "raced-token", "spent")); !errors.Is(err, ErrAppAccessDenied) {
		t.Fatal("regrant revived in-flight code", err)
	}
	if revoked, _ := s.IsTokenRevoked("token"); !revoked {
		t.Fatal("regrant revived old token")
	}
}
func TestAppAccessPreviewAndAuditRollback(t *testing.T) {
	s, u, a := appAccessFixture(t)
	if err := s.SetAppPolicy(a.ID, "all_active_users", true, 1, nil); err != nil {
		t.Fatal(err)
	}
	p, err := s.ListAppAccessUsers(a.ID, "does-not-match", "assigned_only", nil, 25, 0)
	if err != nil || p.Total != 0 || p.LosingAccess != 1 {
		t.Fatalf("loss count depended on search: %+v %v", p, err)
	}
	p, err = s.ListAppAccessUsers(a.ID, "", "assigned_only", nil, 25, 0)
	if err != nil || !p.Users[0].Effective || p.Users[0].Preview || p.Users[0].Reason != "all_active_users" {
		t.Fatalf("wrong preview: %+v %v", p, err)
	}
	accessCode(t, s, u, "pending")
	if err := s.RecordIssuedToken(accessToken(u, "token", "")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER fail_access_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	audit := &AuditEvent{ID: "audit", Action: "admin.app_access_changed", Outcome: "success", CreatedAt: time.Now().UTC()}
	if err := s.SetAppPolicy(a.ID, "assigned_only", true, 2, audit); err == nil {
		t.Fatal("policy ignored audit failure")
	}
	if allowed, _ := s.ClientAccessAllowed(u.ID, "client"); !allowed {
		t.Fatal("failed policy changed access")
	}
	if revoked, _ := s.IsTokenRevoked("token"); revoked {
		t.Fatal("failed policy revoked token")
	}
	if c, _ := s.GetValidAuthorizationCode("pending"); c == nil {
		t.Fatal("failed policy removed code")
	}
	if err := s.SetAppAssignment(a.ID, "users", u.ID, true, audit); err == nil {
		t.Fatal("assignment ignored audit failure")
	}
	p, err = s.ListAppAccessUsers(a.ID, "", "", nil, 25, 0)
	if err != nil || p.Users[0].Direct {
		t.Fatal("failed audit retained assignment", err)
	}
	if _, err := s.db.Exec("DROP TRIGGER fail_access_audit"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppPolicy(a.ID, "all_active_users", false, 2, nil); err != nil {
		t.Fatal(err)
	}
	if allowed, _ := s.ClientAccessAllowed(u.ID, "client"); allowed {
		t.Fatal("disabled app allowed user")
	}
	if revoked, _ := s.IsTokenRevoked("token"); !revoked {
		t.Fatal("disabled app retained token")
	}
}
func TestAppAccessRegistrationRace(t *testing.T) {
	s, u, a := appAccessFixture(t)
	for i := 0; i < 20; i++ {
		if err := s.SetAppAssignment(a.ID, "users", u.ID, true, nil); err != nil {
			t.Fatal(err)
		}
		id := fmt.Sprint("race-", i)
		accessCode(t, s, u, id)
		if _, err := s.ConsumeAuthorizationCode(id); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Go(func() {
			if err := s.RecordIssuedToken(accessToken(u, id, id)); err != nil && !errors.Is(err, ErrAppAccessDenied) {
				t.Error(err)
			}
		})
		wg.Go(func() {
			if err := s.SetAppAssignment(a.ID, "users", u.ID, false, nil); err != nil {
				t.Error(err)
			}
			if err := s.SetAppAssignment(a.ID, "users", u.ID, true, nil); err != nil {
				t.Error(err)
			}
		})
		wg.Wait()
		if revoked, err := s.IsTokenRevoked(id); err != nil || !revoked {
			t.Fatalf("race left valid token %d: %v", i, err)
		}
	}
}
func TestAppAccessMigrationAndLinkSafety(t *testing.T) {
	s, u, a := appAccessFixture(t)
	// Reproduce the released PR04a registry, before access columns existed.
	if _, err := s.db.Exec(`DROP VIEW effective_app_access;DROP VIEW app_access_facts;ALTER TABLE app_registry DROP COLUMN access_mode;ALTER TABLE app_registry DROP COLUMN enabled;`); err != nil {
		t.Fatal(err)
	}
	if err := s.migrate(); err != nil {
		t.Fatal(err)
	}
	if allowed, err := s.ClientAccessAllowed(u.ID, "client"); err != nil || !allowed {
		t.Fatal("upgrade lost legacy access", err)
	}
	if err := s.CreateApplication(&Application{ID: "bookmark", Name: "Bookmark", URL: "https://example.com", IconName: "globe", Enabled: true}, nil); err != nil {
		t.Fatal(err)
	}
	bookmarks, _, err := s.ListAppRecords("bookmark", 25, 0)
	if err != nil || len(bookmarks) != 1 {
		t.Fatal(err)
	}
	b := bookmarks[0]
	if b.AccessMode != "assigned_only" {
		t.Fatal("new app defaulted broad")
	}
	if err := s.LinkAppRecords(a.ID, b.ID, 1, 1, nil); !errors.Is(err, ErrAppLinkConflict) {
		t.Fatal("link widened source access", err)
	}
	if err := s.SetAppPolicy(a.ID, "assigned_only", true, 1, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.LinkAppRecords(a.ID, b.ID, 2, 1, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppAssignment(a.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	newID, err := s.UnlinkAppRecord(a.ID, "client", 4, nil)
	if err != nil {
		t.Fatal(err)
	}
	if allowed, err := s.ClientAccessAllowed(u.ID, "client"); err != nil || !allowed {
		t.Fatal("unlink lost access", err)
	}
	if err := s.LinkAppRecords(a.ID, newID, 5, 1, nil); !errors.Is(err, ErrAppLinkConflict) {
		t.Fatal("linked assigned apps without review", err)
	}
	if err := s.migrate(); err != nil {
		t.Fatal(err)
	}
	p, err := s.ListAppAccessUsers(newID, "", "", nil, 25, 0)
	if err != nil || !p.Users[0].Direct || !p.Users[0].Effective {
		t.Fatal("restart lost assignments", err)
	}
}

func TestAppAccessGroupDeletionRevokesSoleGrant(t *testing.T) {
	s, u, a := appAccessFixture(t)
	if err := s.CreateGroup(&Group{ID: "c", Name: "Only grant"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGroupMembership("c", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppAssignment(a.ID, "groups", "c", true, nil); err != nil {
		t.Fatal(err)
	}
	accessCode(t, s, u, "pending")
	accessCode(t, s, u, "spent")
	if ok, err := s.ConsumeAuthorizationCode("spent"); err != nil || !ok {
		t.Fatalf("consume code: %v %v", ok, err)
	}
	if err := s.RecordIssuedToken(accessToken(u, "token", "spent")); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGroup("c", nil); err != nil {
		t.Fatal(err)
	}
	if revoked, err := s.IsTokenRevoked("token"); err != nil || !revoked {
		t.Errorf("group deletion retained token: revoked=%v err=%v", revoked, err)
	}
	if code, err := s.GetValidAuthorizationCode("pending"); err != nil || code != nil {
		t.Errorf("group deletion retained pending code: %+v err=%v", code, err)
	}
	if err := s.SetAppAssignment(a.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordIssuedToken(accessToken(u, "raced-token", "spent")); !errors.Is(err, ErrAppAccessDenied) {
		t.Fatalf("regrant revived spent code after group deletion: %v", err)
	}
}

func TestAppAccessEnabledPreview(t *testing.T) {
	s, _, a := appAccessFixture(t)
	if err := s.SetAppPolicy(a.ID, "all_active_users", true, a.Revision, nil); err != nil {
		t.Fatal(err)
	}
	for _, enabled := range []bool{false, true} {
		wantLoss := 1
		if enabled {
			wantLoss = 0
		}
		p, err := s.ListAppAccessUsers(a.ID, "", "", &enabled, 25, 0)
		if err != nil {
			t.Fatal(err)
		}
		if p.LosingAccess != wantLoss || len(p.Users) != 1 || !p.Users[0].Effective || p.Users[0].Preview != enabled || !p.App.Enabled {
			t.Fatalf("enabled=%v: wrong preview: %+v", enabled, p)
		}
		p, err = s.ListAppAccessUsers(a.ID, "does-not-match", "", &enabled, 25, 0)
		if err != nil || p.LosingAccess != wantLoss || p.Total != 0 {
			t.Fatalf("enabled=%v: filtered loss count: %+v err=%v", enabled, p, err)
		}
	}
}
