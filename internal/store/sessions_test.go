package store

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func seedSession(t *testing.T, s *Store, userID string, expires, lastActive time.Time) string {
	t.Helper()
	id := uuid.NewString()
	if err := s.CreateSession(&Session{ID: id, UserID: userID, SessionTokenHash: uuid.NewString(), IPAddress: "10.0.0.1", UserAgent: "ua", ExpiresAt: expires}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE sessions SET last_active_at=? WHERE id=?`, lastActive, id); err != nil {
		t.Fatal(err)
	}
	return id
}

// seedGrants attaches one live token, one pending code and one unused step-up grant to a
// session, bypassing the app-access checks the API layer proves elsewhere.
func seedGrants(t *testing.T, s *Store, userID, sessionID, clientID string) (jti, codeID, stepUpID string) {
	t.Helper()
	now := time.Now().UTC()
	jti, codeID, stepUpID = uuid.NewString(), uuid.NewString(), uuid.NewString()
	if _, err := s.db.Exec(`INSERT OR IGNORE INTO oauth_clients (id, client_name, client_type, redirect_uris_json, allowed_scopes_json) VALUES (?,?,?,?,?)`, clientID, "App "+clientID, "public", "[]", "[]"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO issued_tokens (jti,user_id,client_id,expires_at,created_at,session_id) VALUES (?,?,?,?,?,?)`, jti, userID, clientID, now.Add(time.Hour), now, sessionID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO authorization_codes (id,code_hash,client_id,user_id,redirect_uri,scope,code_challenge,code_challenge_method,expires_at,created_at,session_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)`, codeID, uuid.NewString(), clientID, userID, "https://x/cb", "openid", "c", "S256", now.Add(time.Minute), now, sessionID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO step_up_tokens (id,user_id,session_id,token_hash,expires_at,created_at,operation,factor_method) VALUES (?,?,?,?,?,?,?,?)`, stepUpID, userID, sessionID, uuid.NewString(), now.Add(time.Minute), now, "POST /x", "totp"); err != nil {
		t.Fatal(err)
	}
	return jti, codeID, stepUpID
}

func count(t *testing.T, s *Store, query string, args ...any) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func assertGrantsRevoked(t *testing.T, s *Store, jti, codeID, stepUpID string, revoked bool) {
	t.Helper()
	live := 0
	if !revoked {
		live = 1
	}
	if n := count(t, s, `SELECT COUNT(*) FROM issued_tokens WHERE jti=? AND revoked_at IS NULL`, jti); n != live {
		t.Fatalf("token %s live=%d, want %d", jti, n, live)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM authorization_codes WHERE id=?`, codeID); n != live {
		t.Fatalf("code %s present=%d, want %d", codeID, n, live)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM step_up_tokens WHERE id=? AND used_at IS NULL`, stepUpID); n != live {
		t.Fatalf("step-up %s unused=%d, want %d", stepUpID, n, live)
	}
}

func TestListUserSessionsOmitsExpiredAndIdleSessions(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	now := time.Now().UTC()
	live := seedSession(t, s, u.ID, now.Add(time.Hour), now)
	seedSession(t, s, u.ID, now.Add(-time.Minute), now)
	seedSession(t, s, u.ID, now.Add(time.Hour), now.Add(-time.Hour))
	seedSession(t, s, createTestUser(t, s).ID, now.Add(time.Hour), now)

	got, err := s.ListUserSessions(u.ID, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != live {
		t.Fatalf("got %+v, want only %s", got, live)
	}
	if got[0].SessionTokenHash != "" {
		t.Fatal("listing must not expose the session token hash")
	}
}

func TestRevokeSessionLeavesTheUsersOtherSessionIntact(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	now := time.Now().UTC()
	a := seedSession(t, s, u.ID, now.Add(time.Hour), now)
	b := seedSession(t, s, u.ID, now.Add(time.Hour), now)
	aJTI, aCode, aStep := seedGrants(t, s, u.ID, a, "app-1")
	bJTI, bCode, bStep := seedGrants(t, s, u.ID, b, "app-1")

	audit := &AuditEvent{ID: uuid.NewString(), Action: "user.session_revoked", TargetID: a, Outcome: "success"}
	if err := s.RevokeSession(u.ID, a, audit); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM sessions WHERE id=?`, a); n != 0 {
		t.Fatal("revoked session still exists")
	}
	if n := count(t, s, `SELECT COUNT(*) FROM sessions WHERE id=?`, b); n != 1 {
		t.Fatal("other session was removed")
	}
	assertGrantsRevoked(t, s, aJTI, aCode, aStep, true)
	assertGrantsRevoked(t, s, bJTI, bCode, bStep, false)
	if n := count(t, s, `SELECT COUNT(*) FROM audit_events WHERE id=?`, audit.ID); n != 1 {
		t.Fatal("audit row missing")
	}
}

func TestRevokeSessionRejectsAnotherUsersSession(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	owner, other := createTestUser(t, s), createTestUser(t, s)
	now := time.Now().UTC()
	sid := seedSession(t, s, owner.ID, now.Add(time.Hour), now)
	jti, code, step := seedGrants(t, s, owner.ID, sid, "app-1")

	err := s.RevokeSession(other.ID, sid, &AuditEvent{ID: uuid.NewString(), Action: "x", Outcome: "success"})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM sessions WHERE id=?`, sid); n != 1 {
		t.Fatal("session was removed by a non-owner")
	}
	assertGrantsRevoked(t, s, jti, code, step, false)
	if n := count(t, s, `SELECT COUNT(*) FROM audit_events WHERE action='x'`); n != 0 {
		t.Fatal("a rejected revocation must not record success")
	}
}

func TestRevokeSessionRollsBackWithoutItsAuditRow(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	now := time.Now().UTC()
	sid := seedSession(t, s, u.ID, now.Add(time.Hour), now)
	jti, code, step := seedGrants(t, s, u.ID, sid, "app-1")

	if err := s.RevokeSession(u.ID, sid, poisonedAudit(t, s, "user.session_revoked", sid)); err == nil {
		t.Fatal("expected the poisoned audit row to fail the transaction")
	}
	if n := count(t, s, `SELECT COUNT(*) FROM sessions WHERE id=?`, sid); n != 1 {
		t.Fatal("session removed although its audit row was not written")
	}
	assertGrantsRevoked(t, s, jti, code, step, false)
}

func TestRevokeOtherSessionsKeepsTheCurrentOne(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	now := time.Now().UTC()
	keep := seedSession(t, s, u.ID, now.Add(time.Hour), now)
	gone := seedSession(t, s, u.ID, now.Add(time.Hour), now)
	kJTI, kCode, kStep := seedGrants(t, s, u.ID, keep, "app-1")
	gJTI, gCode, gStep := seedGrants(t, s, u.ID, gone, "app-1")

	if err := s.RevokeOtherSessions(u.ID, keep, &AuditEvent{ID: uuid.NewString(), Action: "user.other_sessions_revoked", Outcome: "success"}); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM sessions WHERE user_id=?`, u.ID); n != 1 {
		t.Fatalf("sessions left = %d, want 1", n)
	}
	assertGrantsRevoked(t, s, kJTI, kCode, kStep, false)
	assertGrantsRevoked(t, s, gJTI, gCode, gStep, true)
}

func TestRevokeUserClientAccessRevokesOnlyThatClient(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	now := time.Now().UTC()
	sid := seedSession(t, s, u.ID, now.Add(time.Hour), now)
	xJTI, xCode, xStep := seedGrants(t, s, u.ID, sid, "app-x")
	yJTI, yCode, _ := seedGrants(t, s, u.ID, sid, "app-y")

	if err := s.RevokeUserClientAccess(u.ID, "app-x", &AuditEvent{ID: uuid.NewString(), Action: "admin.app_access_revoked", Outcome: "success"}); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM issued_tokens WHERE jti=? AND revoked_at IS NULL`, xJTI); n != 0 {
		t.Fatal("app-x token still live")
	}
	if n := count(t, s, `SELECT COUNT(*) FROM authorization_codes WHERE id=?`, xCode); n != 0 {
		t.Fatal("app-x code still pending")
	}
	if n := count(t, s, `SELECT COUNT(*) FROM issued_tokens WHERE jti=? AND revoked_at IS NULL`, yJTI); n != 1 {
		t.Fatal("app-y token was revoked")
	}
	if n := count(t, s, `SELECT COUNT(*) FROM authorization_codes WHERE id=?`, yCode); n != 1 {
		t.Fatal("app-y code was removed")
	}
	if n := count(t, s, `SELECT COUNT(*) FROM step_up_tokens WHERE id=? AND used_at IS NULL`, xStep); n != 1 {
		t.Fatal("browser step-up grant must survive an app-scoped revocation")
	}
	if n := count(t, s, `SELECT COUNT(*) FROM sessions WHERE id=?`, sid); n != 1 {
		t.Fatal("browser session must survive an app-scoped revocation")
	}
}

func TestListUserAppGrantsGroupsLiveTokensByClient(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	now := time.Now().UTC()
	sid := seedSession(t, s, u.ID, now.Add(time.Hour), now)
	seedGrants(t, s, u.ID, sid, "app-x")
	seedGrants(t, s, u.ID, sid, "app-x")
	yJTI, _, _ := seedGrants(t, s, u.ID, sid, "app-y")
	if _, err := s.db.Exec(`UPDATE issued_tokens SET revoked_at=? WHERE jti=?`, now, yJTI); err != nil {
		t.Fatal(err)
	}
	seedGrants(t, s, createTestUser(t, s).ID, seedSession(t, s, u.ID, now.Add(time.Hour), now), "app-z")

	got, err := s.ListUserAppGrants(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ClientID != "app-x" || got[0].ClientName != "App app-x" || got[0].Tokens != 2 {
		t.Fatalf("got %+v, want one app-x grant with 2 tokens", got)
	}
	if got[0].ExpiresAt.Before(now.Add(59 * time.Minute)) {
		t.Fatalf("expiry %v should be the latest live token expiry", got[0].ExpiresAt)
	}
}

// Disabling an account routes through the same complete revocation as the emergency
// button, so pending codes and step-up grants do not outlive the sessions that made them.
func TestDisablingAUserRevokesPendingCodesAndStepUpGrants(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	now := time.Now().UTC()
	sid := seedSession(t, s, u.ID, now.Add(time.Hour), now)
	jti, code, step := seedGrants(t, s, u.ID, sid, "app-1")

	u.Status = "disabled"
	if err := s.UpdateUserWithSyncEvents(u, true, nil); err != nil {
		t.Fatal(err)
	}
	assertGrantsRevoked(t, s, jti, code, step, true)
}
