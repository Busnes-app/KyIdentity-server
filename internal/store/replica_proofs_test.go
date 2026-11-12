package store

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Concurrency proofs: several Store handles on one database stand in for replicas, and
// many goroutines per handle hit one guarded operation at the same instant. Every test
// here runs on SQLite and, with KYIDENTITY_TEST_DATABASE_URL set, on Postgres.

const proofHandles, proofPerHandle = 4, 4

// replicasOf returns s and n-1 more handles on the database s was opened on.
func replicasOf(t *testing.T, s *Store, n int) []*Store {
	t.Helper()
	out := []*Store{s}
	for len(out) < n {
		r, err := New(s.path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = r.Close() })
		out = append(out, r)
	}
	return out
}

// race runs fn perHandle times on every handle, all released at once, and returns
// fn's results in order.
func race[T any](stores []*Store, perHandle int, fn func(i int, s *Store) T) []T {
	out := make([]T, len(stores)*perHandle)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range out {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			out[i] = fn(i, stores[i%len(stores)])
		}()
	}
	close(start)
	wg.Wait()
	return out
}

type once struct {
	ok  bool
	err error
}

// exactlyOne fails unless one attempt succeeded and none errored.
func exactlyOne(t *testing.T, what string, results []once) {
	t.Helper()
	won := 0
	for i, r := range results {
		if r.err != nil {
			t.Fatalf("%s attempt %d: %v", what, i, r.err)
		}
		if r.ok {
			won++
		}
	}
	if won != 1 {
		t.Fatalf("%s succeeded %d times across %d concurrent attempts, want exactly 1", what, won, len(results))
	}
}

// claimAll drains claim from every handle at once and fails if any row is claimed twice.
func claimAll(t *testing.T, stores []*Store, claim func(s *Store) ([]string, error)) map[string]int {
	t.Helper()
	var mu sync.Mutex
	seen := map[string]int{}
	errs := race(stores, proofPerHandle, func(_ int, s *Store) error {
		for empty := 0; empty < 3; {
			ids, err := claim(s)
			if err != nil {
				return err
			}
			if len(ids) == 0 {
				empty++
				continue
			}
			mu.Lock()
			for _, id := range ids {
				seen[id]++
				if seen[id] > 1 {
					mu.Unlock()
					return fmt.Errorf("row %s was claimed twice", id)
				}
			}
			mu.Unlock()
		}
		return nil
	})
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("row %s was claimed %d times", id, n)
		}
	}
	return seen
}

func TestProofSyncEventsAreClaimedOnce(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	for _, system := range []string{"alpha", "beta"} {
		app := provisioningFixture(t, s, system)
		for range 12 {
			if err := s.SetAppAssignment(app, "users", createTestUser(t, s).ID, true, nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	pending := count(t, s, `SELECT COUNT(*) FROM account_sync_events WHERE status='pending'`)
	seen := claimAll(t, replicasOf(t, s, proofHandles), func(s *Store) ([]string, error) {
		events, err := s.ClaimDueSyncEvents(5, time.Minute)
		ids := make([]string, len(events))
		for i, ev := range events {
			ids[i] = ev.ID
		}
		return ids, err
	})
	if pending < 24 || len(seen) != pending {
		t.Fatalf("%d of %d pending events claimed", len(seen), pending)
	}
}

func TestProofReconcileJobsAreClaimedOnce(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	for i := range 10 {
		system := fmt.Sprintf("target-%d", i)
		provisioningFixture(t, s, system)
		if _, err := s.CreateReconcileJob(system, "repair", "test", nil); err != nil {
			t.Fatal(err)
		}
	}
	seen := claimAll(t, replicasOf(t, s, proofHandles), func(s *Store) ([]string, error) {
		job, err := s.ClaimReconcileJob(time.Minute)
		if job == nil || err != nil {
			return nil, err
		}
		return []string{job.ID}, nil
	})
	if len(seen) != 10 {
		t.Fatalf("%d of 10 jobs claimed", len(seen))
	}
}

// One delivery in flight per client, and no delivery twice.
func TestProofLogoutDeliveriesAreClaimedOnce(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	now := time.Now().UTC()
	for c := range 6 {
		client := fmt.Sprintf("client-%d", c)
		if err := s.CreateOAuthClient(&OAuthClient{ID: client, ClientName: client, ClientType: "public", RedirectURIsJSON: `["https://example.com/cb"]`, AllowedScopesJSON: `["openid"]`, Enabled: true}, nil); err != nil {
			t.Fatal(err)
		}
		for d := range 3 {
			if _, err := s.db.Exec(`INSERT INTO logout_deliveries(id,client_id,user_id,sid,status,attempts,next_attempt_at,created_at,updated_at) VALUES(?,?,?,?,'queued',0,?,?,?)`,
				fmt.Sprintf("%s-%d", client, d), client, u.ID, uuid.NewString(), now, now, now); err != nil {
				t.Fatal(err)
			}
		}
	}
	var mu sync.Mutex
	perClient := map[string]int{}
	seen := claimAll(t, replicasOf(t, s, proofHandles), func(s *Store) ([]string, error) {
		d, err := s.ClaimLogoutDelivery(time.Minute)
		if d == nil || err != nil {
			return nil, err
		}
		mu.Lock()
		perClient[d.ClientID]++
		mu.Unlock()
		return []string{d.ID}, nil
	})
	if len(seen) != 6 {
		t.Fatalf("%d deliveries claimed, want one per client (6)", len(seen))
	}
	for client, n := range perClient {
		if n != 1 {
			t.Fatalf("client %s has %d deliveries in flight", client, n)
		}
	}
}

func TestProofAuthorizationCodeIsSpentOnce(t *testing.T) {
	s, u, a := appAccessFixture(t)
	if err := s.SetAppAssignment(a.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	accessCode(t, s, u, "code")
	exactlyOne(t, "authorization code", race(replicasOf(t, s, proofHandles), proofPerHandle, func(_ int, s *Store) once {
		ok, err := s.ConsumeAuthorizationCode("code")
		return once{ok, err}
	}))
}

func TestProofMFATokenIsSpentOnce(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	if err := s.CreateMFAToken(&MFAToken{ID: "tok", UserID: u.ID, TokenHash: "h", ExpiresAt: time.Now().UTC().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	exactlyOne(t, "MFA token", race(replicasOf(t, s, proofHandles), proofPerHandle, func(_ int, s *Store) once {
		ok, err := s.ConsumeMFAToken("tok")
		return once{ok, err}
	}))
}

func TestProofRecoveryCodeIsSpentOnce(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	if err := s.ReplaceRecoveryCodes(u.ID, []RecoveryCode{{ID: "rc", UserID: u.ID, CodeHash: "hmac:code"}}, nil); err != nil {
		t.Fatal(err)
	}
	exactlyOne(t, "recovery code", race(replicasOf(t, s, proofHandles), proofPerHandle, func(_ int, s *Store) once {
		ok, err := s.ConsumeRecoveryCode(u.ID, "hmac:code", "legacy", &AuditEvent{ID: uuid.NewString(), Action: "auth.mfa_recovery_consumed", Outcome: "success", CreatedAt: time.Now().UTC()})
		return once{ok, err}
	}))
}

func TestProofTOTPStepIsAcceptedOnce(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	if err := s.SetMFAMethod(&MFAMethod{ID: "totp", UserID: u.ID, MethodType: "totp", EncryptedSecret: "x"}, nil); err != nil {
		t.Fatal(err)
	}
	exactlyOne(t, "TOTP step", race(replicasOf(t, s, proofHandles), proofPerHandle, func(_ int, s *Store) once {
		ok, err := s.ConsumeTOTPCounter(u.ID, 59000000)
		return once{ok, err}
	}))
}

func TestProofPairingTokenEnrolsOneDevice(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	livePairingTokens(t, s, u.ID, "pin")
	exactlyOne(t, "pairing token", race(replicasOf(t, s, proofHandles), proofPerHandle, func(i int, s *Store) once {
		dev, m := pairingDevice(u.ID, fmt.Sprintf("key-%d", i))
		dev.DeviceIdentifier = fmt.Sprintf("phone-%d", i)
		ok, err := s.RegisterNativeDeviceWithPairingToken(u.ID+"pin", dev, m, nil)
		return once{ok, err}
	}))
	if n := count(t, s, `SELECT COUNT(*) FROM native_devices WHERE user_id=?`, u.ID); n != 1 {
		t.Fatalf("%d devices enrolled from one token", n)
	}
}

func TestProofAccountTokenIsRedeemedOnce(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := &User{ID: uuid.NewString(), Username: "invited", DisplayName: "invited", Email: "invited@example.test", Role: "user", Status: "disabled", Pending: true}
	if err := s.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	link, err := s.IssueAccountToken(u.ID, "activation", "manual", time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	exactlyOne(t, "account token", race(replicasOf(t, s, proofHandles), proofPerHandle, func(i int, s *Store) once {
		_, err := s.RedeemAccountToken(link, "activation", fmt.Sprintf("hash-%d", i), nil)
		if errors.Is(err, ErrNotFound) {
			return once{}
		}
		return once{err == nil, err}
	}))
}

func TestProofRefreshTokenRotatesOnce(t *testing.T) {
	s, _, _ := refreshFixture(t, time.Hour, 24*time.Hour)
	exactlyOne(t, "refresh rotation", race(replicasOf(t, s, proofHandles), proofPerHandle, func(i int, s *Store) once {
		_, err := s.RotateRefreshToken("rt1", "client", fmt.Sprintf("rt2-%d", i), refreshAccess(fmt.Sprintf("at-%d", i)))
		if errors.Is(err, ErrRefreshReuse) || errors.Is(err, ErrNotFound) {
			return once{}
		}
		return once{err == nil, err}
	}))
	if n := count(t, s, `SELECT COUNT(*) FROM refresh_tokens WHERE family_jti='fam' AND token_hash<>'rt1'`); n > 1 {
		t.Fatalf("one spent token minted %d successors", n)
	}
}

func TestProofDeviceSignOnJTIIsAcceptedOnce(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	exactlyOne(t, "device sign-on jti", race(replicasOf(t, s, proofHandles), proofPerHandle, func(_ int, s *Store) once {
		ok, err := s.ConsumeDeviceSignOnJTI("jti-1", time.Now().UTC().Add(time.Minute))
		return once{ok, err}
	}))
}

func TestProofOneLiveLoginPushPerUser(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	exactlyOne(t, "login push", race(replicasOf(t, s, proofHandles), proofPerHandle, func(i int, s *Store) once {
		ok, err := s.CreateLoginPushChallenge(&MFAChallenge{ID: fmt.Sprintf("push-%d", i), UserID: u.ID, MethodType: "push", MatchDigits: "42", DecoyDigitsJSON: "[]", Status: "pending", Purpose: "login", ExpiresAt: time.Now().UTC().Add(time.Minute), CreatedAt: time.Now().UTC()})
		return once{ok, err}
	}))
}

// Names differing only in ASCII case collide; names differing only in non-ASCII case are
// different names, on both backends (SQLite NOCASE folds ASCII letters only).
func TestProofNamesCollideOnASCIICaseOnly(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	stores := replicasOf(t, s, proofHandles)
	user := func(name, email string) func(int, *Store) once {
		return func(_ int, s *Store) once {
			err := s.CreateUser(&User{ID: uuid.NewString(), Username: name, DisplayName: name, Email: email, PasswordHash: "x", Role: "user", Status: "active"})
			return once{ok: err == nil}
		}
	}
	variants := []string{"Casey", "CASEY", "casey", "cAsEy"}
	exactlyOne(t, "usernames differing in ASCII case", race(stores, 2, func(i int, s *Store) once {
		return user(variants[i%len(variants)], fmt.Sprintf("casey%d@example.test", i))(i, s)
	}))
	mails := []string{"Robin@Example.Test", "robin@example.test", "ROBIN@EXAMPLE.TEST"}
	exactlyOne(t, "emails differing in ASCII case", race(stores, 2, func(i int, s *Store) once {
		return user(fmt.Sprintf("robin%d", i), mails[i%len(mails)])(i, s)
	}))
	for _, pair := range [][2]string{{"émile", "Émile"}, {"øyvind", "Øyvind"}} {
		results := race(stores[:2], 1, func(i int, s *Store) once {
			return user(pair[i], fmt.Sprintf("%s-%d@example.test", uuid.NewString()[:8], i))(i, s)
		})
		if !results[0].ok || !results[1].ok {
			t.Fatalf("%q and %q differ outside ASCII and must both be accepted: %+v", pair[0], pair[1], results)
		}
	}
	group := func(s *Store, name string) once {
		err := s.CreateGroup(&Group{ID: uuid.NewString(), Name: name}, nil)
		return once{ok: err == nil}
	}
	groups := []string{"Staff", "STAFF", "staff"}
	exactlyOne(t, "group names differing in ASCII case", race(stores, 2, func(i int, s *Store) once { return group(s, groups[i%len(groups)]) }))
	if !group(stores[0], "Équipe").ok || !group(stores[1], "équipe").ok {
		t.Fatal("group names differing outside ASCII must both be accepted")
	}
}

// Concurrent demotions and deletions never leave zero administrators.
func TestProofLastAdministratorSurvivesConcurrentRemovals(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	stores := replicasOf(t, s, proofHandles)
	for round := range 5 {
		var admins []*User
		for i := range 4 {
			u := createTestUserNamed(t, s, fmt.Sprintf("admin-%d-%d", round, i))
			if _, err := s.EditUser(u.ID, nil, func(u *User) (bool, error) { u.Role = "admin"; return false, nil }); err != nil {
				t.Fatal(err)
			}
			admins = append(admins, u)
		}
		// Demote or delete every administrator of earlier rounds first, so these four are all there are.
		for _, row := range rows(t, s, `SELECT id FROM users WHERE role='admin' AND username NOT LIKE ?`, fmt.Sprintf("admin-%d-%%", round)) {
			if err := s.DeleteUserWithSyncEvents(row, nil); err != nil {
				t.Fatal(err)
			}
		}
		var refused atomic.Int32
		race(stores, 1, func(i int, s *Store) error {
			var err error
			if i%2 == 0 {
				err = s.DeleteUserWithSyncEvents(admins[i].ID, nil)
			} else {
				_, err = s.EditUser(admins[i].ID, nil, func(u *User) (bool, error) { u.Role = "user"; return false, nil })
			}
			if errors.Is(err, ErrLastActiveAdmin) {
				refused.Add(1)
			} else if err != nil {
				t.Errorf("removal %d: %v", i, err)
			}
			return nil
		})
		if n := count(t, s, `SELECT COUNT(*) FROM users WHERE role='admin' AND status='active'`); n != 1 || refused.Load() != 1 {
			t.Fatalf("round %d: %d administrators left, %d removals refused; want 1 and 1", round, n, refused.Load())
		}
	}
}

func rows(t *testing.T, s *Store, q string, args ...any) []string {
	t.Helper()
	r, err := s.db.Query(q, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var out []string
	for r.Next() {
		var v string
		if err := r.Scan(&v); err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	return out
}

// noErrors fails on any error a concurrent worker pass returned.
func noErrors(t *testing.T, what string, errs []error) {
	t.Helper()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("%s pass %d: %v", what, i, err)
		}
	}
}

func TestProofConcurrentWorkerPassesDoNotDuplicate(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	stores := replicasOf(t, s, proofHandles)
	now := time.Now().UTC()

	t.Run("EvaluateAlerts", func(t *testing.T) {
		var ids []string
		for i := range 3 {
			ids = append(ids, alertAdmin(t, s, fmt.Sprintf("root%d", i)).ID)
		}
		if err := s.SetAlertSettings(AlertSettings{LoginFailureThreshold: 3, LoginFailureWindowSeconds: 600, Recipients: ids}, nil); err != nil {
			t.Fatal(err)
		}
		for i := range 6 {
			audited(t, s, "admin.scim_token_issued", "root0", fmt.Sprintf("connector-%d", i), "scim_connector", "success", "")
			audited(t, s, "auth.login", "", ids[0], "user", "failure", "")
		}
		noErrors(t, "EvaluateAlerts", race(stores, 2, func(_ int, s *Store) error { return s.EvaluateAlerts(now) }))
		if n := count(t, s, `SELECT COUNT(*) FROM (SELECT rule, key FROM alerts WHERE status<>'resolved' GROUP BY rule, key HAVING COUNT(*)>1) d`); n != 0 {
			t.Fatalf("%d alerts raised twice", n)
		}
		if n := count(t, s, `SELECT COUNT(*) FROM (SELECT alert_id, user_id, kind FROM alert_deliveries GROUP BY alert_id, user_id, kind HAVING COUNT(*)>1) d`); n != 0 {
			t.Fatalf("%d alert mails queued twice", n)
		}
		if n := count(t, s, `SELECT COUNT(*) FROM alert_queue`); n != 0 {
			t.Fatalf("%d audit rows left in the alert queue", n)
		}
		if n := count(t, s, `SELECT COUNT(*) FROM alerts WHERE rule='connector_credentials'`); n == 0 {
			t.Fatal("no alert raised: the fixture tests nothing")
		}
	})

	t.Run("RunDueExpiries", func(t *testing.T) {
		app := provisioningFixture(t, s, "expiring")
		past := now.Add(-time.Minute)
		for range 8 {
			u := createTestUser(t, s)
			if err := s.SetAppAssignment(app, "users", u.ID, true, nil); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec(`UPDATE app_user_assignments SET expires_at=? WHERE app_id=? AND user_id=?`, past.Unix(), app, u.ID); err != nil {
				t.Fatal(err)
			}
		}
		var expired atomic.Int32
		noErrors(t, "RunDueExpiries", race(stores, 2, func(_ int, s *Store) error {
			run, err := s.RunDueExpiries(time.Now().UTC())
			expired.Add(int32(run.Assignments))
			return err
		}))
		if expired.Load() != 8 || count(t, s, `SELECT COUNT(*) FROM app_user_assignments WHERE app_id=?`, app) != 0 {
			t.Fatalf("%d assignment expiries reported for 8 due", expired.Load())
		}
	})

	t.Run("ReconcileProvisioning", func(t *testing.T) {
		app := provisioningFixture(t, s, "reconciled")
		for range 8 {
			if err := s.SetAppAssignment(app, "users", createTestUser(t, s).ID, true, nil); err != nil {
				t.Fatal(err)
			}
		}
		noErrors(t, "ReconcileProvisioning", race(stores, 2, func(_ int, s *Store) error { return s.ReconcileProvisioning() }))
		if n := count(t, s, `SELECT COUNT(*) FROM (SELECT user_id FROM account_sync_events WHERE system_id='reconciled' AND status='pending' GROUP BY user_id HAVING COUNT(*)>1) d`); n != 0 {
			t.Fatalf("%d accounts queued twice", n)
		}
	})

	t.Run("ScheduleReconcileJobs", func(t *testing.T) {
		for i := range 5 {
			provisioningFixture(t, s, fmt.Sprintf("scheduled-%d", i))
		}
		if _, err := s.db.Exec(`UPDATE paired_systems SET reconcile_hours=1 WHERE id LIKE 'scheduled-%'`); err != nil {
			t.Fatal(err)
		}
		noErrors(t, "ScheduleReconcileJobs", race(stores, 2, func(_ int, s *Store) error { return s.ScheduleReconcileJobs(now) }))
		for i := range 5 {
			if n := count(t, s, `SELECT COUNT(*) FROM sync_reconcile_jobs WHERE system_id=?`, fmt.Sprintf("scheduled-%d", i)); n != 1 {
				t.Fatalf("scheduled-%d has %d jobs, want 1", i, n)
			}
		}
	})
}
