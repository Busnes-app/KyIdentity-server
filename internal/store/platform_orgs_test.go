package store

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

var testCaller = PlatformCaller{TokenID: "tok", IP: "10.0.0.9", UserAgent: "billing"}

// platformOrg creates a customer org with a pending holder through the platform path and
// returns it with the holder.
func platformOrg(t *testing.T, s *Store, ref string) (*PlatformOrg, *User) {
	t.Helper()
	var org *PlatformOrg
	_, _, err := s.Platform().PlatformWrite("tok", "create-"+ref, "h-"+ref, func(tx *sql.Tx, now time.Time) (int, any, error) {
		status, o, _, err := s.Platform().CreateOrg(tx, now, testCaller, NewOrg{Name: "Org " + ref, HomeRegion: "us-east-2", Plan: "family", MaxSeats: 5,
			StorageBytes: 10 << 30, HolderEmail: ref + "-holder@example.test", HolderName: "H", BillingRef: ref, Revision: 1}, "hash-"+ref)
		org = o
		return status, o, err
	})
	if err != nil {
		t.Fatal(err)
	}
	h, err := s.GetUserByEmail(ref + "-holder@example.test")
	if err != nil || h == nil {
		t.Fatal(h, err)
	}
	return org, h
}

// lifecycle runs one platform write in its own transaction.
func lifecycle(s *Store, key string, fn func(tx *sql.Tx, now time.Time) (*PlatformOrg, error)) (*PlatformOrg, error) {
	var out *PlatformOrg
	_, _, err := s.Platform().PlatformWrite("tok", key, key, func(tx *sql.Tx, now time.Time) (int, any, error) {
		o, err := fn(tx, now)
		out = o
		return 200, o, err
	})
	return out, err
}

func platformTestTokenRow(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.db.Exec(`INSERT INTO platform_tokens(id,name,token_hash,scopes,created_at,expires_at) VALUES('tok','t','x','orgs:write',?,?)`, time.Now().UTC(), time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
}

// Suspension ends every grant of every member in its transaction (tenancy design,
// Suspension, steps 1-4): a table of the credential types, each live before and dead after.
func TestSuspendEndsEveryGrant(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	platformTestTokenRow(t, s)
	org, holder := platformOrg(t, s, "sus")
	member := &User{ID: uuid.NewString(), Username: "m@example.test", Email: "m@example.test", Role: "user", Status: "active"}
	if err := s.Org(holder.Org()).CreateUser(member); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	sess := seedSession(t, s, member.ID, now.Add(time.Hour), now)
	jti, codeID, stepUpID := seedGrants(t, s, member.ID, sess, "app")
	if _, err := s.db.Exec(`INSERT INTO mfa_tokens(id,user_id,token_hash,expires_at,created_at) VALUES(?,?,?,?,?)`, "mfa1", member.ID, "mfa-hash", now.Add(time.Minute), now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Org(holder.Org()).IssueAccountToken(member.ID, "reset", "email", time.Hour, nil); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM account_tokens WHERE user_id=? AND used_at IS NULL AND expires_at>?`, member.ID, time.Now().UTC()); n != 1 {
		t.Fatalf("reset link before: %d", n)
	}
	type check struct{ name, live string }
	checks := []check{
		{"browser session", `SELECT COUNT(*) FROM sessions WHERE user_id=?`},
		{"access token", `SELECT COUNT(*) FROM issued_tokens WHERE user_id=? AND revoked_at IS NULL`},
		{"authorization code", `SELECT COUNT(*) FROM authorization_codes WHERE user_id=?`},
		{"step-up grant", `SELECT COUNT(*) FROM step_up_tokens WHERE user_id=? AND used_at IS NULL`},
		{"second-factor challenge", `SELECT COUNT(*) FROM mfa_tokens WHERE user_id=? AND used_at IS NULL`},
	}
	for _, c := range checks {
		if n := count(t, s, c.live, member.ID); n != 1 {
			t.Fatalf("%s before: %d", c.name, n)
		}
	}
	if _, err := lifecycle(s, "suspend", func(tx *sql.Tx, now time.Time) (*PlatformOrg, error) {
		return s.Platform().SuspendOrg(tx, now, testCaller, org.ID, "payment", 2)
	}); err != nil {
		t.Fatal(err)
	}
	for _, c := range checks {
		if n := count(t, s, c.live, member.ID); n != 0 {
			t.Errorf("%s after suspension: %d live", c.name, n)
		}
	}
	assertGrantsRevoked(t, s, jti, codeID, stepUpID, true)
	if n := count(t, s, `SELECT COUNT(*) FROM account_tokens WHERE user_id=? AND used_at IS NULL AND expires_at>?`, member.ID, time.Now().UTC()); n != 0 {
		t.Errorf("reset link after suspension: %d live", n)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM platform_events WHERE org_id=? AND type='org.suspended'`, org.ID); n != 1 {
		t.Fatalf("org.suspended events: %d", n)
	}
	// Account flows refuse in a suspended org: issuance, and redemption of a link issued
	// before (the backstop: here the link outlives the suspension's own expiry).
	if _, err := s.Org(holder.Org()).IssueAccountToken(member.ID, "reset", "email", time.Hour, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("reset link in a suspended org: %v", err)
	}
	if _, err := s.Org(holder.Org()).IssueAccountToken(holder.ID, "activation", "email", time.Hour, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("activation link in a suspended org: %v", err)
	}
	if _, err := s.db.Exec(`UPDATE orgs SET status='active' WHERE id=?`, org.ID); err != nil {
		t.Fatal(err)
	}
	raw, err := s.Org(holder.Org()).IssueAccountToken(holder.ID, "activation", "email", time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE orgs SET status='suspended' WHERE id=?`, org.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RedeemAccountToken(raw, "activation", "hash", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a pending holder activated in a suspended org: %v", err)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM account_tokens WHERE user_id=? AND used_at IS NULL`, holder.ID); n == 0 {
		t.Fatal("the refused redemption spent the link")
	}
}

// Org lifecycle: the state each route needs, deletion only after delete_after, and the
// tombstone with every org row gone and a platform audit row.
func TestOrgLifecycleStates(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	platformTestTokenRow(t, s)
	org, _ := platformOrg(t, s, "life")
	rev := int64(1)
	next := func() int64 { rev++; return rev }
	step := func(name string, fn func(tx *sql.Tx, now time.Time) (*PlatformOrg, error)) (*PlatformOrg, error) {
		return lifecycle(s, name+uuid.NewString(), fn)
	}
	p := s.Platform()
	if _, err := step("resume", func(tx *sql.Tx, now time.Time) (*PlatformOrg, error) {
		return p.ResumeOrg(tx, now, testCaller, org.ID, next())
	}); !errors.Is(err, ErrOrgState) {
		t.Fatalf("resume of an active org: %v", err)
	}
	if _, err := step("delete", func(tx *sql.Tx, now time.Time) (*PlatformOrg, error) { return p.DeleteOrg(tx, now, testCaller, org.ID) }); !errors.Is(err, ErrOrgState) {
		t.Fatalf("delete of an active org: %v", err)
	}
	for _, g := range []int{6, 91} {
		if _, err := step("grace", func(tx *sql.Tx, now time.Time) (*PlatformOrg, error) {
			return p.ScheduleDeletion(tx, now, testCaller, org.ID, g, next())
		}); err == nil {
			t.Fatalf("grace %d accepted", g)
		}
	}
	o, err := step("schedule", func(tx *sql.Tx, now time.Time) (*PlatformOrg, error) {
		return p.ScheduleDeletion(tx, now, testCaller, org.ID, 7, next())
	})
	if err != nil || o.Status != "deletion_scheduled" || o.DeleteAfter == nil {
		t.Fatalf("schedule: %+v %v", o, err)
	}
	if _, err := step("suspend", func(tx *sql.Tx, now time.Time) (*PlatformOrg, error) {
		return p.SuspendOrg(tx, now, testCaller, org.ID, "abuse", next())
	}); !errors.Is(err, ErrOrgState) {
		t.Fatalf("suspend while scheduled: %v", err)
	}
	if _, err := step("delete", func(tx *sql.Tx, now time.Time) (*PlatformOrg, error) { return p.DeleteOrg(tx, now, testCaller, org.ID) }); !errors.Is(err, ErrOrgState) {
		t.Fatalf("delete before delete_after: %v", err)
	}
	// A resume before delete_after works; scheduling again, then the window passes.
	if o, err := step("resume", func(tx *sql.Tx, now time.Time) (*PlatformOrg, error) {
		return p.ResumeOrg(tx, now, testCaller, org.ID, next())
	}); err != nil || o.Status != "active" || o.DeleteAfter != nil {
		t.Fatalf("resume: %+v %v", o, err)
	}
	if _, err := step("schedule", func(tx *sql.Tx, now time.Time) (*PlatformOrg, error) {
		return p.ScheduleDeletion(tx, now, testCaller, org.ID, 7, next())
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE orgs SET delete_after=? WHERE id=?`, time.Now().Add(-time.Minute).Unix(), org.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := step("resume", func(tx *sql.Tx, now time.Time) (*PlatformOrg, error) {
		return p.ResumeOrg(tx, now, testCaller, org.ID, next())
	}); !errors.Is(err, ErrOrgState) {
		t.Fatalf("resume after delete_after: %v", err)
	}
	o, err = step("delete", func(tx *sql.Tx, now time.Time) (*PlatformOrg, error) { return p.DeleteOrg(tx, now, testCaller, org.ID) })
	if err != nil || o.Status != "deleted" || o.Name != "" || o.AccountHolderUserID != "" {
		t.Fatalf("delete: %+v %v", o, err)
	}
	for _, table := range append(append([]string{}, orgRowTables...), "users") {
		if n := count(t, s, `SELECT COUNT(*) FROM `+table+` WHERE org_id=?`, org.ID); n != 0 {
			t.Errorf("%s keeps %d rows of the deleted org", table, n)
		}
	}
	var details string
	if err := s.db.QueryRow(`SELECT details_json FROM audit_events WHERE action='platform.org_deleted' AND org_id IS NULL AND actor_id='tok'`).Scan(&details); err != nil || !strings.Contains(details, `"rows"`) {
		t.Fatalf("platform audit row: %q %v", details, err)
	}
	for name, fn := range map[string]func(tx *sql.Tx, now time.Time) (*PlatformOrg, error){
		"delete again": func(tx *sql.Tx, now time.Time) (*PlatformOrg, error) { return p.DeleteOrg(tx, now, testCaller, org.ID) },
		"late resume": func(tx *sql.Tx, now time.Time) (*PlatformOrg, error) {
			return p.ResumeOrg(tx, now, testCaller, org.ID, next())
		},
		"late patch": func(tx *sql.Tx, now time.Time) (*PlatformOrg, error) {
			return p.PatchOrg(tx, now, testCaller, org.ID, OrgPatch{Revision: next()})
		},
	} {
		if _, err := step(name, fn); !errors.Is(err, ErrOrgState) {
			t.Errorf("%s on a deleted org: %v", name, err)
		}
	}
}

// If the platform audit row of a deletion cannot be written, nothing is deleted.
func TestOrgDeletionFailsClosedWithoutItsAuditRow(t *testing.T) {
	if OnPostgresTest() {
		t.Skip("the refusing trigger is SQLite syntax; the transaction is the same code on both")
	}
	s, cleanup := setupTestStore(t)
	defer cleanup()
	platformTestTokenRow(t, s)
	org, holder := platformOrg(t, s, "closed")
	if _, err := s.db.Exec(`UPDATE orgs SET status='deletion_scheduled', delete_after=1 WHERE id=?`, org.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER refuse_deletion_audit BEFORE INSERT ON audit_events WHEN NEW.action='platform.org_deleted' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle(s, "del", func(tx *sql.Tx, now time.Time) (*PlatformOrg, error) {
		return s.Platform().DeleteOrg(tx, now, testCaller, org.ID)
	}); err == nil {
		t.Fatal("deleted without its audit row")
	}
	if o, _ := s.Platform().PlatformOrg(org.ID); o.Status != "deletion_scheduled" {
		t.Fatalf("status %s", o.Status)
	}
	if u, _ := s.PrincipalByID(holder.ID); u == nil {
		t.Fatal("the holder was deleted")
	}
	if _, err := s.db.Exec(`DROP TRIGGER refuse_deletion_audit`); err != nil {
		t.Fatal(err)
	}
	if o, err := lifecycle(s, "del2", func(tx *sql.Tx, now time.Time) (*PlatformOrg, error) {
		return s.Platform().DeleteOrg(tx, now, testCaller, org.ID)
	}); err != nil || o.Status != "deleted" {
		t.Fatalf("delete: %+v %v", o, err)
	}
}

// Idempotency rows: same key and hash replays, another hash conflicts, a refusal stores
// nothing, and two writers on one key run the change once.
func TestPlatformWriteIdempotency(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	platformTestTokenRow(t, s)
	runs := 0
	fn := func(tx *sql.Tx, now time.Time) (int, any, error) { runs++; return 201, map[string]int{"n": runs}, nil }
	a, replayed, err := s.Platform().PlatformWrite("tok", "k", "h1", fn)
	if err != nil || replayed || string(a.Body) != `{"n":1}` {
		t.Fatal(a, replayed, err)
	}
	b, replayed, err := s.Platform().PlatformWrite("tok", "k", "h1", fn)
	if err != nil || !replayed || string(b.Body) != `{"n":1}` || b.Status != 201 || runs != 1 {
		t.Fatal(b, replayed, err, runs)
	}
	if _, _, err := s.Platform().PlatformWrite("tok", "k", "h2", fn); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatal(err)
	}
	refuse := func(tx *sql.Tx, now time.Time) (int, any, error) { return 0, nil, ErrOrgState }
	if _, _, err := s.Platform().PlatformWrite("tok", "r", "h", refuse); !errors.Is(err, ErrOrgState) {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM platform_requests WHERE idempotency_key='r'`); n != 0 {
		t.Fatalf("a refusal was stored: %d", n)
	}
	// Past the window the key is free again, and the purge drops the row.
	if _, err := s.db.Exec(`UPDATE platform_requests SET created_at=? WHERE idempotency_key='k'`, time.Now().UTC().Add(-PlatformRequestTTL-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if c, replayed, err := s.Platform().PlatformWrite("tok", "k", "h2", fn); err != nil || replayed || string(c.Body) != `{"n":2}` {
		t.Fatal(c, replayed, err)
	}
	if _, err := s.db.Exec(`UPDATE platform_requests SET created_at=? WHERE idempotency_key='k'`, time.Now().UTC().Add(-PlatformRequestTTL-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.Platform().DeleteExpiredPlatformRequests(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM platform_requests`); n != 0 {
		t.Fatalf("expired answers kept: %d", n)
	}
}

// Platform tokens: hash only, one kind of scope, revocation and expiry end them.
func TestPlatformTokens(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	p := s.Platform()
	for _, bad := range [][]string{{}, {"orgs:read", "members:read"}, {"orgs:admin"}, {"orgs:read", "orgs:read"}} {
		if _, _, err := p.CreatePlatformToken("x", bad, time.Hour, nil); err == nil {
			t.Errorf("scopes %v accepted", bad)
		}
	}
	if _, _, err := p.CreatePlatformToken("x", []string{"orgs:read"}, MaxPlatformTokenTTL+time.Hour, nil); err == nil {
		t.Error("a token past two years accepted")
	}
	audit := &AuditEvent{ID: uuid.NewString(), ActorUsername: "cli", Outcome: "success"}
	raw, tok, err := p.CreatePlatformToken("billing", []string{ScopeOrgsRead, ScopeOrgsWrite}, time.Hour, audit)
	if err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM platform_tokens WHERE token_hash=? OR token_hash=?`, raw, strings.TrimPrefix(raw, "kyp_")); n != 0 {
		t.Fatal("the raw token is stored")
	}
	if n := count(t, s, `SELECT COUNT(*) FROM audit_events WHERE action='platform.token_created' AND org_id IS NULL AND details_json NOT LIKE ?`, "%"+raw[20:]+"%"); n != 1 {
		t.Fatalf("token_created audit rows without the secret: %d", n)
	}
	got, err := p.AuthenticatePlatformToken(raw)
	if err != nil || got == nil || got.ID != tok.ID || !got.Has(ScopeOrgsWrite) || got.Has(ScopeOrgsDelete) {
		t.Fatal(got, err)
	}
	for _, bad := range []string{"", raw + "0", strings.Replace(raw, "kyp_", "kyq_", 1), "kyp_" + tok.ID + "_" + strings.Repeat("0", 64)} {
		if got, err := p.AuthenticatePlatformToken(bad); got != nil || err != nil {
			t.Errorf("%q authenticated: %v %v", bad, got, err)
		}
	}
	if _, err := s.db.Exec(`UPDATE platform_tokens SET expires_at=? WHERE id=?`, time.Now().UTC().Add(-time.Second), tok.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := p.AuthenticatePlatformToken(raw); got != nil {
		t.Fatal("an expired token authenticated")
	}
	raw2, tok2, _ := p.CreatePlatformToken("portal", []string{ScopeMembersRead}, time.Hour, nil)
	if err := p.RevokePlatformToken(tok2.ID, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := p.AuthenticatePlatformToken(raw2); got != nil {
		t.Fatal("a revoked token authenticated")
	}
	if err := p.RevokePlatformToken(tok2.ID, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second revoke: %v", err)
	}
	list, err := p.ListPlatformTokens()
	if err != nil || len(list) != 2 {
		t.Fatal(list, err)
	}
}
