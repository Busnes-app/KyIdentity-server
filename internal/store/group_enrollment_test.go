package store

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func testEnrollmentGroup(t *testing.T, s *Store, id string) EnrollmentPolicy {
	t.Helper()
	if err := s.CreateGroup(&Group{ID: id, Name: id}, nil); err != nil {
		t.Fatal(err)
	}
	p, err := s.GroupEnrollmentPolicy(id)
	if err != nil {
		t.Fatal(err)
	}
	if p.Required || p.Revision != 1 {
		t.Fatal("unsafe group default", p)
	}
	return p
}
func testEnrollmentMember(t *testing.T, s *Store, group, user string, member bool) {
	t.Helper()
	if err := s.SetGroupMembershipForSession(group, user, member, "admin-session", nil); err != nil {
		t.Fatal(err)
	}
}

func TestGroupEnrollmentIntersectionDeadlinesAndPreview(t *testing.T) {
	s, u, _ := enrollmentFixture(t)
	a := testEnrollmentGroup(t, s, "a")
	b := testEnrollmentGroup(t, s, "b")
	testEnrollmentMember(t, s, "a", u.ID, true)
	testEnrollmentMember(t, s, "b", u.ID, true)
	a.Required = true
	a.AllowedMethods = []string{"totp", "webauthn"}
	a.GraceSeconds = 3600
	if _, err := s.PreviewEnrollmentPolicy(a, "admin-session"); err != nil {
		t.Fatal(err)
	}
	before, _ := s.SessionEnrollmentStatus(u.ID, "session")
	if before.Required {
		t.Fatal("preview persisted policy")
	}
	if err := s.SetEnrollmentPolicy(a, "admin-session", nil); err != nil {
		t.Fatal(err)
	}
	first, _ := s.SessionEnrollmentStatus(u.ID, "session")
	b.Required = true
	b.AllowedMethods = []string{"webauthn", "push"}
	b.GraceSeconds = 7200
	if err := s.SetEnrollmentPolicy(b, "admin-session", nil); err != nil {
		t.Fatal(err)
	}
	status, _ := s.SessionEnrollmentStatus(u.ID, "session")
	if status.Deadline != first.Deadline || len(status.AllowedMethods) != 1 || status.AllowedMethods[0] != "webauthn" {
		t.Fatal("wrong effective policy", status, first)
	}
	testEnrollmentMember(t, s, "a", u.ID, false)
	testEnrollmentMember(t, s, "a", u.ID, true)
	status, _ = s.SessionEnrollmentStatus(u.ID, "session")
	if status.Deadline != first.Deadline {
		t.Fatal("membership restarted grace")
	}
	a.Revision = 2
	a.Required = false
	if err := s.SetEnrollmentPolicy(a, "admin-session", nil); err != nil {
		t.Fatal(err)
	}
	a.Revision = 3
	a.Required = true
	a.GraceSeconds = 9000
	if err := s.SetEnrollmentPolicy(a, "admin-session", nil); err != nil {
		t.Fatal(err)
	}
	status, _ = s.SessionEnrollmentStatus(u.ID, "session")
	if status.Deadline != first.Deadline {
		t.Fatal("policy restarted grace")
	}
	if _, err := s.db.Exec(`UPDATE enrollment_deadlines SET due_at=unixepoch() WHERE user_id=? AND scope=?`, u.ID, a.Scope); err != nil {
		t.Fatal(err)
	}
	status, _ = s.SessionEnrollmentStatus(u.ID, "session")
	if !status.Restricted {
		t.Fatal("deadline ignored")
	}
	a.Revision = 4
	a.AllowedMethods = []string{"totp"}
	if err := s.SetEnrollmentPolicy(a, "admin-session", nil); !errors.Is(err, ErrEnrollmentPolicy) {
		t.Fatal("empty intersection accepted", err)
	}
	// Rejected policy and its tentative earlier deadlines both roll back.
	current, _ := s.GroupEnrollmentPolicy("a")
	if current.Revision != 4 || current.AllowedMethods[1] != "webauthn" {
		t.Fatal("failed edit persisted", current)
	}
}

func TestGroupEnrollmentMembershipConflictAndAdministrator(t *testing.T) {
	s, u, admin := enrollmentFixture(t)
	a := testEnrollmentGroup(t, s, "a")
	b := testEnrollmentGroup(t, s, "b")
	a.Required = true
	a.AllowedMethods = []string{"totp"}
	b.Required = true
	b.AllowedMethods = []string{"webauthn"}
	for _, p := range []EnrollmentPolicy{a, b} {
		if err := s.SetEnrollmentPolicy(p, "admin-session", nil); err != nil {
			t.Fatal(err)
		}
	}
	testEnrollmentMember(t, s, "a", u.ID, true)
	if err := s.SetGroupMembershipForSession("b", u.ID, true, "admin-session", nil); !errors.Is(err, ErrEnrollmentPolicy) {
		t.Fatal("conflicting membership", err)
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM group_memberships WHERE user_id=? AND group_id='b'`, u.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("membership persisted", err, count)
	}
	if err := s.SetGroupMembershipForSession("b", admin.ID, true, "admin-session", nil); !errors.Is(err, ErrEmergencyAdministrator) {
		t.Fatal("administrator locked out", err)
	}
	if err := s.SetGroupMembership("b", admin.ID, true, nil); !errors.Is(err, ErrEmergencyAdministrator) {
		t.Fatal("missing administrator session accepted", err)
	}
	// Group requirements also intersect the administrator-only requirement on promotion.
	adminPolicy := enrollmentPolicy("administrators", 0)
	adminPolicy.AllowedMethods = []string{"webauthn"}
	// Keep current activating admin compliant with that policy.
	if err := s.CreateWebAuthnCredential(&WebAuthnCredential{ID: "key", UserID: admin.ID, CredentialID: "key", PublicKeySPKI: "test", Name: "key"}, nil); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := s.CreateSession(&Session{ID: "passkey-admin", UserID: admin.ID, SessionTokenHash: "passkey-admin", ExpiresAt: now.Add(time.Hour), AuthenticationEvidence: AuthenticationEvidence{PrimaryAuthenticatedAt: &now, FactorAuthenticatedAt: &now, FactorMethod: "webauthn"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetEnrollmentPolicy(adminPolicy, "passkey-admin", nil); err != nil {
		t.Fatal(err)
	}
	u.Role = "admin"
	if err := s.UpdateUserWithSyncEvents(u, false, nil); err == nil {
		t.Fatal("promotion accepted conflicting factor masks")
	}
}

func TestGroupEnrollmentMutationRevokesAndNeverRevives(t *testing.T) {
	for _, remove := range []string{"membership", "group"} {
		t.Run(remove, func(t *testing.T) {
			s, u, _ := enrollmentFixture(t)
			apps, _, _ := s.ListAppRecords("client", 25, 0)
			if err := s.SetAppAssignment(apps[0].ID, "users", u.ID, true, nil); err != nil {
				t.Fatal(err)
			}
			p := testEnrollmentGroup(t, s, "a")
			p.Required = true
			p.GraceSeconds = 3600
			if err := s.SetEnrollmentPolicy(p, "admin-session", nil); err != nil {
				t.Fatal(err)
			}
			testEnrollmentMember(t, s, "a", u.ID, true)
			accessCode(t, s, u, "before")
			if _, err := s.ConsumeAuthorizationCode("before"); err != nil {
				t.Fatal(err)
			}
			if err := s.RecordIssuedToken(accessToken(u, "token", "before")); err != nil {
				t.Fatal(err)
			}
			if remove == "membership" {
				testEnrollmentMember(t, s, "a", u.ID, false)
			} else {
				if err := s.DeleteGroupForSession("a", "admin-session", nil); err != nil {
					t.Fatal(err)
				}
			}
			if revoked, err := s.IsTokenRevoked("token"); err != nil || !revoked {
				t.Fatal("token survived removal", err)
			}
			if remove == "membership" {
				testEnrollmentMember(t, s, "a", u.ID, true)
			}
			if err := s.RecordIssuedToken(accessToken(u, "late", "before")); !errors.Is(err, ErrAppAccessDenied) {
				t.Fatal("removed code revived", err)
			}
		})
	}
}

func TestGroupEnrollmentConcurrentConflictingMembership(t *testing.T) {
	s, u, _ := enrollmentFixture(t)
	for i, id := range []string{"a", "b"} {
		p := testEnrollmentGroup(t, s, id)
		p.Required = true
		p.AllowedMethods = []string{[]string{"totp", "push"}[i]}
		if err := s.SetEnrollmentPolicy(p, "admin-session", nil); err != nil {
			t.Fatal(err)
		}
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, id := range []string{"a", "b"} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			<-start
			results <- s.SetGroupMembershipForSession(id, u.ID, true, "admin-session", nil)
		}(id)
	}
	close(start)
	wg.Wait()
	close(results)
	accepted, denied := 0, 0
	for err := range results {
		if err == nil {
			accepted++
		} else if errors.Is(err, ErrEnrollmentPolicy) {
			denied++
		} else {
			t.Fatal(err)
		}
	}
	if accepted != 1 || denied != 1 {
		t.Fatal("conflicting concurrent memberships", accepted, denied)
	}
}

func TestGroupEnrollmentUpgradePreservesLegacyPolicy(t *testing.T) {
	s, u, _ := enrollmentFixture(t)
	testEnrollmentGroup(t, s, "existing-group")
	if err := s.SetEnrollmentPolicy(enrollmentPolicy("organization", 3600), "admin-session", nil); err != nil {
		t.Fatal(err)
	}
	before, err := s.SessionEnrollmentStatus(u.ID, "session")
	if err != nil {
		t.Fatal(err)
	}
	// Reconstruct the PR06a tables, including its scope CHECK and deadline foreign key.
	_, err = s.db.Exec(`DROP VIEW mfa_session_access; DROP VIEW enrollment_requirements; DROP VIEW applicable_enrollment_policies;
 DROP TRIGGER enrollment_new_user; DROP TRIGGER enrollment_user_role; DROP TRIGGER enrollment_new_group; DROP TRIGGER enrollment_new_member; DROP TRIGGER enrollment_role_compatibility;
 CREATE TEMP TABLE old_p AS SELECT scope,required,allowed_mask,grace_seconds,revision FROM enrollment_policies WHERE group_id IS NULL;
 CREATE TEMP TABLE old_d AS SELECT * FROM enrollment_deadlines WHERE scope IN ('organization','administrators');
 DROP TABLE enrollment_deadlines; DROP TABLE enrollment_policies;
 CREATE TABLE enrollment_policies(scope TEXT PRIMARY KEY CHECK(scope IN ('organization','administrators')),required BOOLEAN NOT NULL DEFAULT 0,allowed_mask INTEGER NOT NULL DEFAULT 7,grace_seconds INTEGER NOT NULL DEFAULT 0,revision INTEGER NOT NULL DEFAULT 1);
 CREATE TABLE enrollment_deadlines(user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,scope TEXT NOT NULL REFERENCES enrollment_policies(scope),due_at INTEGER NOT NULL,PRIMARY KEY(user_id,scope));
 INSERT INTO enrollment_policies SELECT * FROM old_p; INSERT INTO enrollment_deadlines SELECT * FROM old_d; DROP TABLE old_p; DROP TABLE old_d;`)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := s.migrateEnrollmentPolicy(); err != nil {
			t.Fatal(err)
		}
		after, err := s.SessionEnrollmentStatus(u.ID, "session")
		if err != nil || after.Deadline != before.Deadline || after.Restricted != before.Restricted || !after.Required {
			t.Fatal("upgrade changed obligation/session", after, err)
		}
		policies, err := s.ListEnrollmentPolicies()
		if err != nil || len(policies) != 2 {
			t.Fatal("global policy listing", policies, err)
		}
		p, err := s.GroupEnrollmentPolicy("existing-group")
		if err != nil || p.Required || p.Revision != 1 {
			t.Fatal("backfill", p, err)
		}
	}
}

func TestGroupEnrollmentMembershipAuditRollback(t *testing.T) {
	s, u, _ := enrollmentFixture(t)
	p := testEnrollmentGroup(t, s, "a")
	p.Required = true
	p.GraceSeconds = 3600
	if err := s.SetEnrollmentPolicy(p, "admin-session", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER reject_group_enrollment_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'audit failed'); END`); err != nil {
		t.Fatal(err)
	}
	err := s.SetGroupMembershipForSession("a", u.ID, true, "admin-session", &AuditEvent{ID: "failed", Action: "test", Outcome: "success", CreatedAt: time.Now().UTC()})
	if err == nil {
		t.Fatal("unaudited membership committed")
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM enrollment_deadlines WHERE scope=? AND user_id=?`, p.Scope, u.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("deadline survived rollback", count, err)
	}
	status, err := s.SessionEnrollmentStatus(u.ID, "session")
	if err != nil || status.Required {
		t.Fatal("membership survived rollback", status, err)
	}
}

func TestGroupEnrollmentMembershipTokenRace(t *testing.T) {
	s, u, _ := enrollmentFixture(t)
	apps, _, _ := s.ListAppRecords("client", 25, 0)
	if err := s.SetAppAssignment(apps[0].ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	p := testEnrollmentGroup(t, s, "a")
	p.Required = true
	if err := s.SetEnrollmentPolicy(p, "admin-session", nil); err != nil {
		t.Fatal(err)
	}
	accessCode(t, s, u, "racing-code")
	if _, err := s.ConsumeAuthorizationCode("racing-code"); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	go func() { <-start; results <- s.RecordIssuedToken(accessToken(u, "racing-token", "racing-code")) }()
	go func() { <-start; results <- s.SetGroupMembershipForSession("a", u.ID, true, "admin-session", nil) }()
	close(start)
	for i := 0; i < 2; i++ {
		err := <-results
		if err != nil && !errors.Is(err, ErrAppAccessDenied) {
			t.Fatal(err)
		}
	}
	if revoked, err := s.IsTokenRevoked("racing-token"); err != nil || !revoked {
		t.Fatal("race escaped group requirement", err)
	}
}

func TestGroupEnrollmentPreviewCountsOnlyGroupMembers(t *testing.T) {
	s, u, _ := enrollmentFixture(t)
	p := testEnrollmentGroup(t, s, "a")
	testEnrollmentMember(t, s, "a", u.ID, true)
	if err := s.SetEnrollmentPolicy(enrollmentPolicy("organization", 3600), "admin-session", nil); err != nil {
		t.Fatal(err)
	}
	p.Required = true
	p.GraceSeconds = 0
	preview, err := s.PreviewEnrollmentPolicy(p, "admin-session")
	if err != nil || preview.Affected != 1 || preview.MissingFactor != 1 || preview.RestrictedSessions != 1 || !preview.CanActivate {
		t.Fatal("unscoped group impact", preview, err)
	}
	status, err := s.SessionEnrollmentStatus(u.ID, "session")
	if err != nil || status.Restricted {
		t.Fatal("preview mutated deadline", status, err)
	}
}

func TestGroupEnrollmentDeletionRequiresLogin(t *testing.T) {
	s, u, _ := enrollmentFixture(t)
	p := testEnrollmentGroup(t, s, "delete-proof")
	testEnrollmentMember(t, s, "delete-proof", u.ID, true)
	p.Required = true
	if err := s.SetEnrollmentPolicy(p, "admin-session", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGroup("delete-proof", nil); !errors.Is(err, ErrEmergencyAdministrator) {
		t.Fatalf("deletion without login proof: %v", err)
	}
	if err := s.SetEnrollmentPolicy(enrollmentPolicy("organization", 3600), "admin-session", nil); err != nil {
		t.Fatal(err)
	}
	stale := time.Now().UTC().Add(-6 * time.Minute)
	if _, err := s.db.Exec(`UPDATE sessions SET primary_authenticated_at=?,factor_authenticated_at=? WHERE id='admin-session'`, stale, stale); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGroupForSession("delete-proof", "admin-session", nil); !errors.Is(err, ErrEmergencyAdministrator) {
		t.Fatalf("stale login accepted: %v", err)
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM directory_groups WHERE id='delete-proof'`).Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	now := time.Now().UTC()
	if _, err := s.db.Exec(`UPDATE sessions SET primary_authenticated_at=?,factor_authenticated_at=? WHERE id='admin-session'`, now, now); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGroupForSession("delete-proof", "admin-session", nil); err != nil {
		t.Fatal(err)
	}
}

func TestGroupEnrollmentSessionQueryPlan(t *testing.T) {
	s, _, _ := enrollmentFixture(t)
	if _, err := s.db.Exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<3000) INSERT INTO users(id,username,email,password_hash,role,status,display_name) SELECT 'plan-'||i,'plan-'||i,'plan-'||i||'@example.com','test','user','active','Plan user' FROM n`); err != nil {
		t.Fatal(err)
	}
	rows, err := s.db.Query(`EXPLAIN QUERY PLAN SELECT allowed FROM mfa_session_access WHERE id=?`, "admin-session")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		t.Log(detail)
		if strings.Contains(detail, "MATERIALIZE enrollment_requirements") || strings.Contains(detail, "SCAN u") {
			t.Errorf("directory scan on session lookup: %s", detail)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}
