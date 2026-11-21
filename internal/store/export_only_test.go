package store

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func newSessionFor(s *Store, userID string) (*Session, error) {
	sess := &Session{ID: uuid.NewString(), UserID: userID, SessionTokenHash: uuid.NewString(), ExpiresAt: time.Now().UTC().Add(time.Hour)}
	return sess, s.CreateSession(sess)
}

func exportOnly(t *testing.T, s *Store, sess *Session) bool {
	t.Helper()
	on, err := s.SessionExportOnly(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	return on
}

// Who may sign in while an org is not active: only the export-only exception, and only
// as an export-only session.
func TestExportOnlySessions(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	// Billing scheduled this one: the holder exports, nobody else signs in.
	erasureOrg(t, s, "billed", map[string]string{"kid": "active", "invited": "pending"})
	tenancyExec(t, s, `UPDATE orgs SET status='deletion_scheduled', delete_after=4102444800 WHERE id='billed'`)
	// The holder asked for this one: every other activated member exports, the holder never.
	erasureOrg(t, s, "asked", map[string]string{"kid": "active"})
	if _, err := erase(t, s, "asked", "asked-holder", "totp"); err != nil {
		t.Fatal(err)
	}
	erasureOrg(t, s, "paused", map[string]string{"kid": "active"})
	tenancyExec(t, s, `UPDATE orgs SET status='suspended' WHERE id='paused'`)
	erasureOrg(t, s, "open", map[string]string{"kid": "active"})

	for user, want := range map[string]error{
		"billed-kid": ErrOrgSuspended, "asked-holder": ErrOrgSuspended,
		"paused-holder": ErrOrgSuspended, "paused-kid": ErrOrgSuspended,
	} {
		if _, err := newSessionFor(s, user); !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", user, err, want)
		}
	}
	if n := rowCount(t, s, `SELECT COUNT(*) FROM sessions WHERE user_id IN ('billed-kid','asked-holder','paused-holder','paused-kid')`); n != 0 {
		t.Fatalf("%d refused sessions were written", n)
	}
	for user, want := range map[string]bool{"billed-holder": true, "asked-kid": true, "open-holder": false, "open-kid": false} {
		sess, err := newSessionFor(s, user)
		if err != nil {
			t.Fatalf("%s: %v", user, err)
		}
		if got := exportOnly(t, s, sess); got != want {
			t.Errorf("%s: export_only %v, want %v", user, got, want)
		}
		status, err := s.SessionEnrollmentStatus(user, sess.ID)
		if err != nil || status.ExportOnly != want {
			t.Errorf("%s: status %+v %v", user, status, err)
		}
	}
	// An admitted user refused for another reason (the password changed after the sign-in
	// read it) gets that reason, not org_suspended.
	stale := &Session{ID: uuid.NewString(), UserID: "billed-holder", SessionTokenHash: uuid.NewString(), ExpiresAt: time.Now().UTC().Add(time.Hour), ProvenPasswordHash: "an-older-hash"}
	if err := s.CreateSession(stale); !errors.Is(err, ErrAppAccessDenied) {
		t.Errorf("export-eligible user with a changed password: %v, want ErrAppAccessDenied", err)
	}
	// The single-tenant default org is always active.
	u := createTestUserNamed(t, s, "alice")
	if sess, err := newSessionFor(s, u.ID); err != nil || exportOnly(t, s, sess) {
		t.Fatalf("default org: %v", err)
	}
}

// A grant from a full session of an org that stopped being active is refused at every
// choke point: a new code, a new token, and a check of a token already issued.
func TestGrantsNeedAnActiveOrgOrExportOnly(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	erasureOrg(t, s, "home", map[string]string{"kid": "active"})
	if err := s.CreateOAuthClient(&OAuthClient{ID: "c", ClientName: "c", ClientType: "public", RedirectURIsJSON: "[]", AllowedScopesJSON: "[]", Enabled: true}, nil); err != nil {
		t.Fatal(err)
	}
	tenancyExec(t, s, `UPDATE app_registry SET access_mode='all_active_users' WHERE client_id='c'`,
		`INSERT INTO org_apps(org_id,app_id,enabled) SELECT 'home',id,TRUE FROM app_registry WHERE client_id='c'`)
	full, err := newSessionFor(s, "home-kid")
	if err != nil {
		t.Fatal(err)
	}
	code := func() error {
		return s.CreateAuthorizationCode(&AuthorizationCode{ID: uuid.NewString(), CodeHash: uuid.NewString(), ClientID: "c", UserID: "home-kid", SessionID: full.ID, ExpiresAt: time.Now().UTC().Add(time.Minute)})
	}
	token := func() error {
		return s.RecordIssuedToken(&IssuedToken{JTI: uuid.NewString(), UserID: "home-kid", ClientID: "c", ExpiresAt: time.Now().UTC().Add(time.Minute), SessionID: full.ID})
	}
	if err := code(); err != nil {
		t.Fatalf("code in an active org: %v", err)
	}
	if err := token(); err != nil {
		t.Fatalf("token in an active org: %v", err)
	}
	jti := uuid.NewString()
	tenancyExec(t, s, `INSERT INTO issued_tokens(jti,user_id,client_id,expires_at,created_at,session_id) VALUES('`+jti+`','home-kid','c','2100-01-01 00:00:00','2026-01-01 00:00:00','`+full.ID+`')`)
	if revoked, err := s.IsTokenRevoked(jti); err != nil || revoked {
		t.Fatalf("an active org's token reads revoked: %v %v", revoked, err)
	}
	// Billing schedules deletion without revoking (as a stale replica might see it).
	tenancyExec(t, s, `UPDATE orgs SET status='deletion_scheduled', delete_after=4102444800 WHERE id='home'`)
	if revoked, err := s.IsTokenRevoked(jti); err != nil || !revoked {
		t.Fatalf("a token of a non-active org reads live: %v %v", revoked, err)
	}
	if err := token(); !errors.Is(err, ErrAppAccessDenied) {
		t.Fatalf("token from a full session of a non-active org: %v", err)
	}
	if err := code(); !errors.Is(err, ErrAppAccessDenied) {
		t.Fatalf("code from a full session of a non-active org: %v", err)
	}
	// The browser session itself is refused too; resuming the org restores it.
	if got, err := s.GetSessionByTokenHash(full.SessionTokenHash, time.Hour); err != nil || got != nil {
		t.Fatalf("browser session of a non-active org: %+v %v", got, err)
	}
	tenancyExec(t, s, `UPDATE orgs SET status='active', delete_after=NULL WHERE id='home'`)
	if got, err := s.GetSessionByTokenHash(full.SessionTokenHash, time.Hour); err != nil || got == nil {
		t.Fatalf("browser session after the resume: %+v %v", got, err)
	}
}

// A session that was export-only is whole again once billing resumes its org.
func TestExportOnlyEndsWhenTheOrgResumes(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	erasureOrg(t, s, "billed", map[string]string{"kid": "active"})
	tenancyExec(t, s, `UPDATE orgs SET status='deletion_scheduled', delete_after=4102444800 WHERE id='billed'`)
	sess, err := newSessionFor(s, "billed-holder")
	if err != nil || !exportOnly(t, s, sess) {
		t.Fatalf("scheduled: %v", err)
	}
	if got, err := s.GetSessionByTokenHash(sess.SessionTokenHash, time.Hour); err != nil || got == nil {
		t.Fatalf("export-only browser session: %+v %v", got, err)
	}
	tenancyExec(t, s, `UPDATE orgs SET status='active', delete_after=NULL WHERE id='billed'`)
	if exportOnly(t, s, sess) {
		t.Error("export_only outlived the resume")
	}
	if status, err := s.SessionEnrollmentStatus("billed-holder", sess.ID); err != nil || status.ExportOnly {
		t.Errorf("status after the resume: %+v %v", status, err)
	}
}
