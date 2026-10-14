package store

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuthenticationEvidenceMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	user := createTestUser(t, s)
	if err := s.CreateSession(&Session{ID: "session", UserID: user.ID, SessionTokenHash: "hash", ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateOAuthClient(&OAuthClient{ID: "app", ClientName: "app", ClientType: "public", RedirectURIsJSON: "[]", AllowedScopesJSON: "[]", Enabled: true}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE app_registry SET access_mode='all_active_users' WHERE client_id='app'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DROP VIEW mfa_session_access`); err != nil {
		t.Fatal(err)
	}
	// Remove precisely the new columns to reproduce an existing installation.
	for table, columns := range map[string][]string{
		"sessions":            {"primary_authenticated_at", "factor_authenticated_at", "factor_method"},
		"authorization_codes": {"session_id", "primary_authenticated_at", "factor_authenticated_at", "factor_method"},
		"issued_tokens":       {"session_id"}, "mfa_tokens": {"primary_authenticated_at"}, "mfa_challenges": {"verified_at"},
	} {
		for _, col := range columns {
			if _, err := s.db.Exec("ALTER TABLE " + table + " DROP COLUMN " + col); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := s.db.Exec(`INSERT INTO authorization_codes (id, code_hash, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at) VALUES ('old', 'old', 'app', ?, '', '', '', '', ?)`, user.ID, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO mfa_tokens (id, user_id, token_hash, expires_at) VALUES ('old', ?, 'old', ?)`, user.ID, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO issued_tokens (jti, user_id, client_id, expires_at) VALUES ('legacy-token', ?, 'app', ?)`, user.ID, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	session, err := s.GetSessionByTokenHash("hash", time.Hour)
	if err != nil || session == nil {
		t.Fatalf("lost legacy session: %v", err)
	}
	if session.PrimaryAuthenticatedAt != nil || session.FactorAuthenticatedAt != nil || session.FactorMethod != "" {
		t.Fatal("invented legacy evidence")
	}
	if code, err := s.GetValidAuthorizationCode("old"); err != nil || code != nil {
		t.Fatalf("old code survived: %v", err)
	}
	if token, err := s.GetValidMFAToken("old", 5); err != nil || token != nil {
		t.Fatalf("old MFA flow survived: %v", err)
	}
	if revoked, err := s.IsTokenRevoked("legacy-token"); err != nil || revoked {
		t.Fatalf("legacy token compatibility lost: %v", err)
	}
	now := time.Now().UTC()
	if err := s.CreateAuthorizationCode(&AuthorizationCode{ID: "new", CodeHash: "new", ClientID: "app", UserID: user.ID, SessionID: session.ID, ExpiresAt: now.Add(time.Minute), AuthenticationEvidence: AuthenticationEvidence{PrimaryAuthenticatedAt: &now}}); err != nil {
		t.Fatal(err)
	}
	if err := s.migrate(); err != nil {
		t.Fatal(err)
	}
	code, err := s.GetValidAuthorizationCode("new")
	if err != nil || code == nil || !code.PrimaryAuthenticatedAt.Equal(now) {
		t.Fatalf("repeat migration lost new code: %v", err)
	}
}

// Parallel reservations on one token never grant more than maxAttempts, and spent or
// exhausted tokens grant none.
func TestReserveMFAAttemptIsAtomic(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	user := createTestUser(t, s)
	if err := s.CreateMFAToken(&MFAToken{ID: "tok", UserID: user.ID, TokenHash: "h", ExpiresAt: time.Now().UTC().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	const maxAttempts = 5
	var wg sync.WaitGroup
	var granted atomic.Int32
	start := make(chan struct{})
	for range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			n, err := s.ReserveMFAAttempt("tok", maxAttempts)
			if err != nil {
				t.Error(err)
			}
			if n > 0 {
				granted.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	var attempts int
	if err := s.db.QueryRow(`SELECT attempts FROM mfa_tokens WHERE id='tok'`).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if granted.Load() != maxAttempts || attempts != maxAttempts {
		t.Fatalf("granted %d reservations, stored %d attempts; want %d", granted.Load(), attempts, maxAttempts)
	}

	if err := s.CreateMFAToken(&MFAToken{ID: "spent", UserID: user.ID, TokenHash: "h2", ExpiresAt: time.Now().UTC().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeMFAToken("spent"); err != nil {
		t.Fatal(err)
	}
	if n, err := s.ReserveMFAAttempt("spent", maxAttempts); err != nil || n != 0 {
		t.Fatalf("spent token granted an attempt: %d %v", n, err)
	}
}
