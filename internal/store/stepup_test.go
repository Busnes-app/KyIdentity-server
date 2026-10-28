package store

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStepUpCompletionIsAtomicAndCancellable(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	user := createTestUser(t, s)
	now := time.Now().UTC()
	if err := s.CreateSession(&Session{ID: "session", UserID: user.ID, SessionTokenHash: "session", ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	newChallenge := func(id string) *StepUpChallenge {
		c := &StepUpChallenge{TokenHash: id, UserID: user.ID, SessionID: "session", Operation: "DELETE /api/user/passkeys/key", Method: "webauthn", Proof: "proof", PrimaryAuthenticatedAt: now, ExpiresAt: now.Add(time.Minute)}
		if err := s.CreateStepUpChallenge(c, nil); err != nil {
			t.Fatal(err)
		}
		return c
	}
	grant := func(c *StepUpChallenge) *StepUpToken {
		return &StepUpToken{ID: c.TokenHash, TokenHash: c.TokenHash, UserID: c.UserID, SessionID: c.SessionID, Operation: c.Operation, FactorMethod: c.Method, ExpiresAt: c.ExpiresAt}
	}
	c := newChallenge("audit")
	if _, err := s.db.Exec(`CREATE TRIGGER fail_step_up_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'audit failed'); END`); err != nil {
		t.Fatal(err)
	}
	rejected := *c
	rejected.TokenHash = "audit-start"
	if err := s.CreateStepUpChallenge(&rejected, &AuditEvent{ID: "start-event", Action: "auth.step_up_challenge", Outcome: "success", CreatedAt: now}); err == nil || !strings.Contains(err.Error(), "audit failed") {
		t.Fatalf("expected injected audit failure, got %v", err)
	}
	if saved, err := s.GetStepUpChallenge(rejected.TokenHash, rejected.UserID, rejected.SessionID); err != nil || saved != nil {
		t.Fatal("failed audit left pending challenge")
	}
	if ok, err := s.CompleteStepUpChallenge(c, grant(c), &AuditEvent{ID: "event", Action: "auth.step_up", Outcome: "success", CreatedAt: now}); err == nil || !strings.Contains(err.Error(), "audit failed") || ok {
		t.Fatalf("expected injected audit failure, got %v (completed %v)", err, ok)
	}
	if saved, err := s.GetStepUpChallenge(c.TokenHash, c.UserID, c.SessionID); err != nil || saved == nil {
		t.Fatal("failed audit consumed challenge")
	}
	if ok, err := s.HasValidStepUpToken(c.TokenHash, c.UserID, c.SessionID, c.Operation); err != nil || ok {
		t.Fatal("failed audit left grant")
	}
	if _, err := s.db.Exec("DROP TRIGGER fail_step_up_audit"); err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if ok, err := s.CompleteStepUpChallenge(c, grant(c), nil); err != nil {
				t.Error(err)
			} else if ok {
				wins.Add(1)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("completion winners: %d", wins.Load())
	}
	if err := s.CancelStepUp(c.TokenHash, c.UserID, c.SessionID); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ConsumeStepUpToken(c.TokenHash, c.UserID, c.SessionID, c.Operation); err != nil || ok {
		t.Fatal("late cancellation left spendable grant")
	}

	c = newChallenge("spend")
	if err := s.CreateStepUpToken(grant(c), nil); err != nil {
		t.Fatal(err)
	}
	wins.Store(0)
	for range 8 {
		wg.Go(func() {
			if ok, err := s.ConsumeStepUpToken(c.TokenHash, c.UserID, c.SessionID, c.Operation); err != nil {
				t.Error(err)
			} else if ok {
				wins.Add(1)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("spending winners: %d", wins.Load())
	}

	for _, id := range []string{"expired", "attempts", "revoked"} {
		c = newChallenge(id)
		switch id {
		case "expired":
			if _, err := s.db.Exec("UPDATE step_up_challenges SET expires_at = ? WHERE token_hash = ?", now.Add(-time.Second), id); err != nil {
				t.Fatal(err)
			}
		case "attempts":
			for range 5 {
				if err := s.FailStepUpChallenge(id); err != nil {
					t.Fatal(err)
				}
			}
		case "revoked":
			if err := s.DeleteSession("session"); err != nil {
				t.Fatal(err)
			}
		}
		if saved, err := s.GetStepUpChallenge(c.TokenHash, c.UserID, c.SessionID); err != nil || saved != nil {
			t.Fatalf("%s challenge survived: %v", id, err)
		}
		if ok, err := s.CompleteStepUpChallenge(c, grant(c), nil); err != nil || ok {
			t.Fatalf("%s completion accepted: %v", id, err)
		}
	}
}

func TestStepUpMigrationInvalidatesUnscopedGrants(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	user := createTestUser(t, s)
	now := time.Now().UTC()
	if err := s.CreateSession(&Session{ID: "session", UserID: user.ID, SessionTokenHash: "session", ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO step_up_tokens(id,user_id,session_id,token_hash,expires_at,created_at) VALUES ('legacy',?,'session','legacy',?,?)`, user.ID, now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	for _, column := range []string{"operation", "factor_method"} {
		if _, err := s.db.Exec("ALTER TABLE step_up_tokens DROP COLUMN " + column); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.migrateStepUpChallenges(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM step_up_tokens").Scan(&count); err != nil || count != 0 {
		t.Fatalf("legacy grant survived: %v", err)
	}
	if err := s.CreateStepUpToken(&StepUpToken{ID: "new", UserID: user.ID, SessionID: "session", TokenHash: "new", Operation: "POST /api/admin/users", ExpiresAt: now.Add(time.Minute)}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.migrateStepUpChallenges(); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.HasValidStepUpToken("new", user.ID, "session", "POST /api/admin/users"); err != nil || !ok {
		t.Fatalf("repeat migration removed scoped grant: %v", err)
	}
}

// A challenge started before a password change carries the old password's proof; it must not
// finish into a grant afterwards, even in the session that made the change (issue #136 review).
func TestPasswordChangeBurnsPendingStepUpChallenges(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	user := createTestUser(t, s)
	now := time.Now().UTC()
	if err := s.CreateSession(&Session{ID: "session", UserID: user.ID, SessionTokenHash: "session", ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	c := &StepUpChallenge{TokenHash: "pending", UserID: user.ID, SessionID: "session", Operation: "POST /api/user/password", Method: "push", Proof: "proof", PrimaryAuthenticatedAt: now, ExpiresAt: now.Add(time.Minute)}
	if err := s.CreateStepUpChallenge(c, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.ChangePassword(user.ID, "session", "changed", nil); err != nil {
		t.Fatal(err)
	}
	if saved, err := s.GetStepUpChallenge(c.TokenHash, c.UserID, c.SessionID); err != nil || saved != nil {
		t.Fatalf("challenge survived the password change: %v", err)
	}
	grant := &StepUpToken{ID: "grant", TokenHash: c.TokenHash, UserID: c.UserID, SessionID: c.SessionID, Operation: c.Operation, FactorMethod: c.Method, ExpiresAt: c.ExpiresAt}
	if ok, err := s.CompleteStepUpChallenge(c, grant, nil); err != nil || ok {
		t.Fatalf("pre-change challenge completed: %v %v", ok, err)
	}
}
