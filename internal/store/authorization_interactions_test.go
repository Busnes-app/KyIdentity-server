package store

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestAuthorizationInteractionAtomicity(t *testing.T) {
	s, u, a := appAccessFixture(t)
	if err := s.SetAppPolicy(a.ID, "all_active_users", true, a.Revision, nil); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	create := func(hash string) {
		t.Helper()
		if err := s.CreateAuthorizationInteraction(&AuthorizationInteraction{Hash: hash, BrowserHash: "browser", UserID: u.ID, OriginalSessionID: "session", CreatedAt: now, ExpiresAt: now.Add(time.Minute), Request: "client_id=client"}); err != nil {
			t.Fatal(err)
		}
	}
	session := func(id string) *Session {
		at := time.Now().UTC()
		return &Session{ID: id, UserID: u.ID, SessionTokenHash: id, ExpiresAt: now.Add(time.Hour), AuthenticationEvidence: AuthenticationEvidence{PrimaryAuthenticatedAt: &at}}
	}
	create("login")
	if err := s.CreateSessionForInteraction(session("wrong"), "login", "wrong-browser"); !errors.Is(err, ErrAuthorizationInteraction) {
		t.Fatal(err)
	}
	if got, _ := s.GetSessionByID("wrong"); got != nil {
		t.Fatal("failed binding left session")
	}
	// A failed session write rolls back the interaction's satisfied marker.
	stale := session("stale")
	stale.ProvenPasswordHash = "a password the account no longer has"
	if err := s.CreateSessionForInteraction(stale, "login", "browser"); !errors.Is(err, ErrAppAccessDenied) {
		t.Fatal("session for a changed password accepted", err)
	}
	i, err := s.GetAuthorizationInteraction("login", "browser")
	if err != nil || i.SessionID != "" {
		t.Fatal("failed session burned interaction", err)
	}
	sess := session("new")
	if err := s.CreateSessionForInteraction(sess, "login", "browser"); err != nil {
		t.Fatal(err)
	}
	// Atomic code consumption permits only one concurrent resume.
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for n := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := fmt.Sprint(n)
			results <- s.CreateAuthorizationCode(&AuthorizationCode{ID: id, CodeHash: id, ClientID: "client", UserID: u.ID, SessionID: sess.ID, InteractionHash: "login", ExpiresAt: now.Add(time.Minute), AuthenticationEvidence: sess.AuthenticationEvidence})
		}()
	}
	wg.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		} else if !errors.Is(err, ErrAuthorizationInteraction) {
			t.Fatal(err)
		}
	}
	if wins != 1 {
		t.Fatalf("%d resumes succeeded", wins)
	}
	create("expired")
	if _, err := s.db.Exec(`UPDATE authorization_interactions SET expires_at=? WHERE hash='expired'`, now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSessionForInteraction(session("late"), "expired", "browser"); !errors.Is(err, ErrAuthorizationInteraction) {
		t.Fatal("expired interaction accepted", err)
	}
	create("revoked")
	if err := s.DeleteSession("session"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSessionForInteraction(session("after-logout"), "revoked", "browser"); !errors.Is(err, ErrAuthorizationInteraction) {
		t.Fatal("logout revived interaction", err)
	}
}

func TestAuthorizationCodeMaximumAgeAtRegistration(t *testing.T) {
	s, u, a := appAccessFixture(t)
	if err := s.SetAppPolicy(a.ID, "all_active_users", true, a.Revision, nil); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		id   string
		ago  time.Duration
		want bool
	}{{"fresh", time.Second, true}, {"stale", time.Hour, false}} {
		at := time.Now().UTC().Add(-tt.ago)
		until := at.Add(time.Minute)
		if err := s.CreateAuthorizationCode(&AuthorizationCode{ID: tt.id, CodeHash: tt.id, ClientID: "client", UserID: u.ID, SessionID: "session", AuthenticationExpiresAt: &until, ExpiresAt: time.Now().UTC().Add(time.Minute), AuthenticationEvidence: AuthenticationEvidence{PrimaryAuthenticatedAt: &at}}); err != nil {
			t.Fatal(err)
		}
		if ok, err := s.ConsumeAuthorizationCode(tt.id); err != nil || !ok {
			t.Fatal(err)
		}
		err := s.RecordIssuedToken(accessToken(u, tt.id, tt.id))
		if tt.want && err != nil {
			t.Fatal(err)
		}
		if !tt.want && !errors.Is(err, ErrAppAccessDenied) {
			t.Fatal("stale proof registered", err)
		}
	}
}

func TestAuthorizationInteractionCapacityAndMigration(t *testing.T) {
	s, _, _ := appAccessFixture(t)
	now := time.Now().UTC()
	for n := range 11 {
		err := s.CreateAuthorizationInteraction(&AuthorizationInteraction{Hash: fmt.Sprint(n), BrowserHash: "browser", Request: "client_id=client", CreatedAt: now, ExpiresAt: now.Add(time.Minute)})
		if n < 10 && err != nil {
			t.Fatal(err)
		}
		if n == 10 && !errors.Is(err, ErrAuthorizationInteraction) {
			t.Fatal("browser capacity not enforced", err)
		}
	}
	if err := s.migrateAuthorizationInteractions(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetAuthorizationInteraction("0", "browser"); err != nil {
		t.Fatal("migration lost pending interaction", err)
	}
	if _, err := s.db.Exec(`UPDATE authorization_interactions SET expires_at=?`, now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAuthorizationInteraction(&AuthorizationInteraction{Hash: "new", BrowserHash: "browser", Request: "client_id=client", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal("expired rows consumed capacity", err)
	}
}

func TestAuthorizationInteractionEvictsOnlyAnonymousPending(t *testing.T) {
	s, _, _ := appAccessFixture(t)
	now := time.Now().UTC()
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	statement, err := tx.Prepare(`INSERT INTO authorization_interactions(hash,browser_hash,user_id,session_id,request,created_at,expires_at) VALUES(?,?,?,?,?,?,?)`)
	if err != nil {
		t.Fatal(err)
	}
	defer statement.Close()
	for n := range 10000 {
		id := fmt.Sprint(n)
		user, session := "", ""
		if n == 0 {
			user = "owned"
		}
		if n == 1 {
			session = "session"
		}
		if _, err := statement.Exec(id, id, user, session, "client_id=client", now.Add(time.Duration(n-10000)*time.Millisecond), now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAuthorizationInteraction(&AuthorizationInteraction{Hash: "new", BrowserHash: "new", Request: "client_id=client", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal("anonymous requests exhausted global capacity", err)
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM authorization_interactions`).Scan(&count); err != nil || count != 10000 {
		t.Fatal("capacity changed", count, err)
	}
	for _, id := range []string{"0", "1", "new"} {
		if _, err := s.GetAuthorizationInteraction(id, id); err != nil {
			t.Fatal("protected/new row lost", id, err)
		}
	}
	if _, err := s.GetAuthorizationInteraction("2", "2"); !errors.Is(err, ErrAuthorizationInteraction) {
		t.Fatal("oldest anonymous pending row retained", err)
	}
}

func TestCompletedLoginCannotCreateDisabledUserSession(t *testing.T) {
	s, u, _ := appAccessFixture(t)
	if _, err := s.db.Exec(`UPDATE users SET status='disabled' WHERE id=?`, u.ID); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	err := s.CreateSession(&Session{ID: "fallback", UserID: u.ID, SessionTokenHash: "fallback", ExpiresAt: at.Add(time.Hour), AuthenticationEvidence: AuthenticationEvidence{PrimaryAuthenticatedAt: &at}})
	if !errors.Is(err, ErrAppAccessDenied) {
		t.Fatal("disabled user signed in", err)
	}
	if sess, err := s.GetSessionByID("fallback"); err != nil || sess != nil {
		t.Fatal("disabled user retained session", err)
	}
}

func TestAuthorizationInteractionCapacityPerAccount(t *testing.T) {
	s, u, _ := appAccessFixture(t)
	now := time.Now().UTC()
	for n := range 11 {
		id := fmt.Sprint(n)
		err := s.CreateAuthorizationInteraction(&AuthorizationInteraction{Hash: id, BrowserHash: id, UserID: u.ID, Request: "client_id=client", CreatedAt: now, ExpiresAt: now.Add(time.Minute)})
		if n < 10 && err != nil {
			t.Fatal(err)
		}
		if n == 10 && !errors.Is(err, ErrAuthorizationInteraction) {
			t.Fatal("cookie rotation bypassed account capacity", err)
		}
	}
	// Completing an already-counted request must not consume an extra account slot.
	at := time.Now().UTC()
	if err := s.CreateSessionForInteraction(&Session{ID: "own-slot", UserID: u.ID, SessionTokenHash: "own-slot", ExpiresAt: now.Add(time.Hour), AuthenticationEvidence: AuthenticationEvidence{PrimaryAuthenticatedAt: &at}}, "0", "0"); err != nil {
		t.Fatal("existing account slot could not complete", err)
	}
	// An anonymous request must not bypass the same bound when login identifies its owner.
	if err := s.CreateAuthorizationInteraction(&AuthorizationInteraction{Hash: "anonymous", BrowserHash: "anonymous", Request: "client_id=client", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	at = time.Now().UTC()
	err := s.CreateSessionForInteraction(&Session{ID: "promoted", UserID: u.ID, SessionTokenHash: "promoted", ExpiresAt: now.Add(time.Hour), AuthenticationEvidence: AuthenticationEvidence{PrimaryAuthenticatedAt: &at}}, "anonymous", "anonymous")
	if !errors.Is(err, ErrAuthorizationInteraction) {
		t.Fatal("anonymous completion bypassed account capacity", err)
	}
}

func TestAuthorizationInteractionCapacityRepairsLegacyAccountFlood(t *testing.T) {
	s, u, _ := appAccessFixture(t)
	now := time.Now().UTC()
	_, err := s.db.Exec(`WITH RECURSIVE seq(n) AS (VALUES(0) UNION ALL SELECT n+1 FROM seq WHERE n<9999)
 INSERT INTO authorization_interactions(hash,browser_hash,user_id,request,created_at,expires_at)
 SELECT CAST(n AS TEXT),CAST(n AS TEXT),?,'client_id=client',?,? FROM seq`, u.ID, now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	other := createTestUser(t, s)
	if err := s.CreateAuthorizationInteraction(&AuthorizationInteraction{Hash: "new", BrowserHash: "new", UserID: other.ID, Request: "client_id=client", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal("legacy account flood blocked another user", err)
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM authorization_interactions WHERE user_id=?`, u.ID).Scan(&count); err != nil || count != 10 {
		t.Fatal("legacy overage not repaired", count, err)
	}
}

func TestAuthorizationInteractionCapacityMigrationOwnsCompletedRequests(t *testing.T) {
	s, u, _ := appAccessFixture(t)
	now := time.Now().UTC()
	_, err := s.db.Exec(`WITH RECURSIVE seq(n) AS (VALUES(0) UNION ALL SELECT n+1 FROM seq WHERE n<11)
 INSERT INTO authorization_interactions(hash,browser_hash,session_id,request,created_at,expires_at)
 SELECT CAST(n AS TEXT),CAST(n AS TEXT),'session','client_id=client',?,? FROM seq`, now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.migrateAuthorizationInteractions(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM authorization_interactions WHERE user_id=?`, u.ID).Scan(&count); err != nil || count != 10 {
		t.Fatal("completed requests escaped account capacity on upgrade", count, err)
	}
}

// prompt=login or max_age from a signed-in browser renews that session rather than
// leaving it running, with the apps signed in under it, behind a new one.
func TestReauthenticationRenewsTheOriginalSession(t *testing.T) {
	s, u, _ := appAccessFixture(t)
	now := time.Now().UTC()
	if err := s.CreateAuthorizationInteraction(&AuthorizationInteraction{Hash: "again", BrowserHash: "browser", UserID: u.ID, OriginalSessionID: "session", CreatedAt: now, ExpiresAt: now.Add(time.Minute), Request: "client_id=client"}); err != nil {
		t.Fatal(err)
	}
	// A restriction the old sign-in earned is decided afresh, as for a new session.
	if _, err := s.db.Exec(`UPDATE sessions SET enrollment_only=TRUE WHERE id='session'`); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	sess := &Session{ID: "new", UserID: u.ID, SessionTokenHash: "new-hash", ExpiresAt: now.Add(time.Hour), AuthenticationEvidence: AuthenticationEvidence{PrimaryAuthenticatedAt: &at}}
	if err := s.CreateSessionForInteraction(sess, "again", "browser"); err != nil {
		t.Fatal(err)
	}
	if sess.ID != "session" {
		t.Fatalf("session ID = %q, want the renewed original", sess.ID)
	}
	if got, _ := s.GetSessionByID("new"); got != nil {
		t.Fatal("a second session was created")
	}
	if got, _ := s.GetSessionByTokenHash("hash", time.Hour); got != nil {
		t.Fatal("the replaced cookie still authenticates")
	}
	got, err := s.GetSessionByTokenHash("new-hash", time.Hour)
	if err != nil || got == nil || got.ID != "session" || got.PrimaryAuthenticatedAt == nil || !got.PrimaryAuthenticatedAt.Equal(at) {
		t.Fatalf("renewed session = %+v, %v", got, err)
	}
	var restricted bool
	if err := s.db.QueryRow(`SELECT enrollment_only FROM sessions WHERE id='session'`).Scan(&restricted); err != nil || restricted {
		t.Fatalf("renewed session kept the old restriction: %v %v", restricted, err)
	}
}
