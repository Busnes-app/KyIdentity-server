package store

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func enrollmentFixture(t *testing.T) (*Store, *User, *User) {
	t.Helper()
	s, u, _ := appAccessFixture(t)
	admin := &User{ID: "emergency", Username: "emergency", Email: "emergency@example.com", PasswordHash: "test", Role: "admin", Status: "active"}
	if err := s.CreateUser(admin); err != nil {
		t.Fatal(err)
	}
	if err := s.SetMFAMethod(&MFAMethod{ID: "admin-totp", UserID: admin.ID, MethodType: "totp", EncryptedSecret: "test"}, nil); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	if err := s.CreateSession(&Session{ID: "admin-session", UserID: admin.ID, SessionTokenHash: "admin-session", ExpiresAt: at.Add(time.Hour), AuthenticationEvidence: AuthenticationEvidence{PrimaryAuthenticatedAt: &at, FactorAuthenticatedAt: &at, FactorMethod: "totp"}}); err != nil {
		t.Fatal(err)
	}
	return s, u, admin
}
func enrollmentPolicy(scope string, grace int64) EnrollmentPolicy {
	return EnrollmentPolicy{Scope: scope, Required: true, AllowedMethods: []string{"totp", "webauthn"}, GraceSeconds: grace, Revision: 1}
}

func TestEnrollmentGracePersistsAndExpiresWithoutWorker(t *testing.T) {
	s, u, _ := enrollmentFixture(t)
	p := enrollmentPolicy("organization", 3600)
	preview, err := s.PreviewEnrollmentPolicy(p, "admin-session")
	if err != nil || preview.MissingFactor != 1 || !preview.CanActivate {
		t.Fatalf("preview: %+v %v", preview, err)
	}
	var deadlines int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM enrollment_deadlines`).Scan(&deadlines); err != nil || deadlines != 0 {
		t.Fatal("preview persisted deadlines", err)
	}
	if err := s.SetEnrollmentPolicy(p, "admin-session", nil); err != nil {
		t.Fatal(err)
	}
	status, err := s.SessionEnrollmentStatus(u.ID, "session")
	if err != nil || status.Restricted || !status.Required || status.Enrolled {
		t.Fatalf("grace: %+v %v", status, err)
	}
	firstDeadline := status.Deadline
	if err := s.migrateEnrollmentPolicy(); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(&Session{ID: "again", UserID: u.ID, SessionTokenHash: "again", ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	status, _ = s.SessionEnrollmentStatus(u.ID, "again")
	if status.Deadline != firstDeadline {
		t.Fatal("login restarted grace")
	}
	p.GraceSeconds = 7200
	p.Revision = 2
	if err := s.SetEnrollmentPolicy(p, "admin-session", nil); err != nil {
		t.Fatal(err)
	}
	status, _ = s.SessionEnrollmentStatus(u.ID, "again")
	if status.Deadline != firstDeadline {
		t.Fatal("longer grace extended existing deadline")
	}
	if _, err := s.db.Exec(`UPDATE enrollment_deadlines SET due_at=unixepoch() WHERE user_id=?`, u.ID); err != nil {
		t.Fatal(err)
	}
	status, _ = s.SessionEnrollmentStatus(u.ID, "again")
	if !status.Restricted {
		t.Fatal("deadline boundary did not restrict session")
	}
	p.Required = false
	p.Revision = 3
	if err := s.SetEnrollmentPolicy(p, "admin-session", nil); err != nil {
		t.Fatal(err)
	}
	p.Required = true
	p.Revision = 4
	if err := s.SetEnrollmentPolicy(p, "admin-session", nil); err != nil {
		t.Fatal(err)
	}
	status, _ = s.SessionEnrollmentStatus(u.ID, "again")
	if !status.Restricted {
		t.Fatal("reenabling restarted grace")
	}
	// Newly-created users get a persisted deadline at creation, not at first login.
	next := &User{ID: "new", Username: "new", Email: "new@example.com", PasswordHash: "test", Role: "user", Status: "active"}
	if err := s.CreateUser(next); err != nil {
		t.Fatal(err)
	}
	status, err = s.SessionEnrollmentStatus(next.ID, "")
	if err != nil || status.Deadline <= time.Now().Unix() {
		t.Fatal("new user deadline missing", err)
	}
}

func TestEnrollmentRestrictedSessionCannotUpgradeOrExchange(t *testing.T) {
	s, u, _ := enrollmentFixture(t)
	apps, _, _ := s.ListAppRecords("client", 25, 0)
	if err := s.SetAppAssignment(apps[0].ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	accessCode(t, s, u, "old")
	if _, err := s.ConsumeAuthorizationCode("old"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetEnrollmentPolicy(enrollmentPolicy("organization", 0), "admin-session", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordIssuedToken(accessToken(u, "raced", "old")); !errors.Is(err, ErrAppAccessDenied) {
		t.Fatal("old code exchanged", err)
	}
	at := time.Now().UTC()
	restricted := &Session{ID: "restricted", UserID: u.ID, SessionTokenHash: "restricted", ExpiresAt: at.Add(time.Hour), AuthenticationEvidence: AuthenticationEvidence{PrimaryAuthenticatedAt: &at}}
	if err := s.CreateSession(restricted); err != nil {
		t.Fatal(err)
	}
	if err := s.SetMFAMethod(&MFAMethod{ID: "user-totp", UserID: u.ID, MethodType: "totp", EncryptedSecret: "test"}, nil); err != nil {
		t.Fatal(err)
	}
	status, _ := s.SessionEnrollmentStatus(u.ID, restricted.ID)
	if !status.Restricted || !status.Enrolled {
		t.Fatal("enrollment silently upgraded session", status)
	}
	code := &AuthorizationCode{ID: "bypass", CodeHash: "bypass", ClientID: "client", UserID: u.ID, SessionID: restricted.ID, ExpiresAt: at.Add(time.Minute)}
	if err := s.CreateAuthorizationCode(code); !errors.Is(err, ErrAppAccessDenied) {
		t.Fatal("restricted session minted code", err)
	}
	restricted.ID = "compliant"
	restricted.SessionTokenHash = "compliant"
	restricted.FactorAuthenticatedAt = &at
	restricted.FactorMethod = "totp"
	if err := s.CreateSession(restricted); err != nil {
		t.Fatal(err)
	}
	status, _ = s.SessionEnrollmentStatus(u.ID, "compliant")
	if status.Restricted {
		t.Fatal("compliant fresh login restricted")
	}
	// Recovery cannot create an unrestricted session, even while grace remains.
	restricted.ID = "recovery"
	restricted.SessionTokenHash = "recovery"
	restricted.FactorMethod = "recovery"
	if err := s.CreateSession(restricted); err != nil {
		t.Fatal(err)
	}
	status, _ = s.SessionEnrollmentStatus(u.ID, "recovery")
	if !status.Restricted {
		t.Fatal("recovery satisfied MFA policy")
	}
}

func TestEnrollmentActivationAndAuditRollback(t *testing.T) {
	s, u, _ := enrollmentFixture(t)
	p := enrollmentPolicy("organization", 0)
	if err := s.SetEnrollmentPolicy(p, "session", nil); !errors.Is(err, ErrEmergencyAdministrator) {
		t.Fatal("ordinary user activated policy", err)
	}
	if _, err := s.db.Exec(`UPDATE sessions SET factor_authenticated_at=NULL WHERE id='admin-session'`); err != nil {
		t.Fatal(err)
	}
	if err := s.SetEnrollmentPolicy(p, "admin-session", nil); !errors.Is(err, ErrEmergencyAdministrator) {
		t.Fatal("unproven administrator activated policy", err)
	}
	now := time.Now().UTC()
	if _, err := s.db.Exec(`UPDATE sessions SET factor_authenticated_at=? WHERE id='admin-session'`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER fail_enrollment_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.SetEnrollmentPolicy(p, "admin-session", &AuditEvent{ID: "failed", Action: "policy", Outcome: "success"}); err == nil {
		t.Fatal("audit failure committed")
	}
	status, _ := s.SessionEnrollmentStatus(u.ID, "session")
	if status.Required || status.Restricted {
		t.Fatal("policy escaped rollback")
	}
	if _, err := s.db.Exec(`DROP TRIGGER fail_enrollment_audit`); err != nil {
		t.Fatal(err)
	}
	if err := s.SetEnrollmentPolicy(p, "admin-session", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetEnrollmentPolicy(p, "admin-session", nil); !errors.Is(err, ErrAppLinkConflict) {
		t.Fatal("stale policy accepted", err)
	}
	// Organization and administrator method sets intersect; empty intersections fail.
	adminPolicy := enrollmentPolicy("administrators", 0)
	adminPolicy.AllowedMethods = []string{"push"}
	if err := s.SetEnrollmentPolicy(adminPolicy, "admin-session", nil); !errors.Is(err, ErrEnrollmentPolicy) {
		t.Fatal("incompatible factors accepted", err)
	}
}

func TestEnrollmentLastFactorRemovalAndReset(t *testing.T) {
	s, u, _ := enrollmentFixture(t)
	if err := s.SetMFAMethod(&MFAMethod{ID: "user-totp", UserID: u.ID, MethodType: "totp", EncryptedSecret: "test"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetEnrollmentPolicy(enrollmentPolicy("organization", 3600), "admin-session", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUserMFAMethods(u.ID); !errors.Is(err, ErrLastCompliantFactor) {
		t.Fatal("last factor removed", err)
	}
	if err := s.CreateWebAuthnCredential(&WebAuthnCredential{ID: "key", UserID: u.ID, CredentialID: "key", PublicKeySPKI: "test", Name: "key"}, nil); err != nil {
		t.Fatal(err)
	}
	if deleted, err := s.DeleteWebAuthnCredential("key", u.ID, nil); err != nil || !deleted {
		t.Fatal("alternative factor did not permit removal", err)
	}
	if err := s.ResetUserMFA(u.ID, nil); err != nil {
		t.Fatal(err)
	}
	status, _ := s.SessionEnrollmentStatus(u.ID, "")
	if !status.Required || status.Enrolled || status.Deadline != 0 {
		t.Fatal("reset bypassed reenrollment", status)
	}
}

func TestEnrollmentDeadlineBlocksOnlineTokenAndRegistration(t *testing.T) {
	s, u, _ := enrollmentFixture(t)
	apps, _, _ := s.ListAppRecords("client", 25, 0)
	if err := s.SetAppAssignment(apps[0].ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetEnrollmentPolicy(enrollmentPolicy("organization", 3600), "admin-session", nil); err != nil {
		t.Fatal(err)
	}
	accessCode(t, s, u, "grace")
	if _, err := s.ConsumeAuthorizationCode("grace"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordIssuedToken(accessToken(u, "grace-token", "grace")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE enrollment_deadlines SET due_at=0 WHERE user_id=?`, u.ID); err != nil {
		t.Fatal(err)
	}
	if revoked, err := s.IsTokenRevoked("grace-token"); err != nil || !revoked {
		t.Fatal("deadline left online token usable", err)
	}
	if err := s.RecordIssuedToken(accessToken(u, "late-token", "grace")); !errors.Is(err, ErrAppAccessDenied) {
		t.Fatal("late registration escaped deadline", err)
	}
}

func TestEnrollmentPolicyTokenRace(t *testing.T) {
	s, u, _ := enrollmentFixture(t)
	apps, _, _ := s.ListAppRecords("client", 25, 0)
	if err := s.SetAppAssignment(apps[0].ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	accessCode(t, s, u, "race")
	if _, err := s.ConsumeAuthorizationCode("race"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	start := make(chan struct{})
	go func() {
		defer wg.Done()
		<-start
		if err := s.SetEnrollmentPolicy(enrollmentPolicy("organization", 0), "admin-session", nil); err != nil {
			t.Error(err)
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		if err := s.RecordIssuedToken(accessToken(u, "race-token", "race")); err != nil && !errors.Is(err, ErrAppAccessDenied) {
			t.Error(err)
		}
	}()
	close(start)
	wg.Wait()
	if revoked, err := s.IsTokenRevoked("race-token"); err != nil || !revoked {
		t.Fatal("racing token survived", err)
	}
}

func TestEnrollmentRecoveryDuringGraceAndPromotionDeadline(t *testing.T) {
	s, u, _ := enrollmentFixture(t)
	p := enrollmentPolicy("organization", 3600)
	if err := s.SetEnrollmentPolicy(p, "admin-session", nil); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := s.CreateSession(&Session{ID: "recovery-grace", UserID: u.ID, SessionTokenHash: "recovery-grace", ExpiresAt: now.Add(time.Hour), AuthenticationEvidence: AuthenticationEvidence{PrimaryAuthenticatedAt: &now, FactorAuthenticatedAt: &now, FactorMethod: "recovery"}}); err != nil {
		t.Fatal(err)
	}
	status, _ := s.SessionEnrollmentStatus(u.ID, "recovery-grace")
	if !status.Restricted {
		t.Fatal("recovery got unrestricted grace session")
	}
	adminPolicy := enrollmentPolicy("administrators", 0)
	if err := s.SetEnrollmentPolicy(adminPolicy, "admin-session", nil); err != nil {
		t.Fatal(err)
	}
	u.Role = "admin"
	promotionStartedAt := time.Now().Unix()
	if err := s.UpdateUser(u); err != nil {
		t.Fatal(err)
	}
	status, err := s.SessionEnrollmentStatus(u.ID, "session")
	if err != nil || !status.Restricted || status.Deadline < promotionStartedAt || status.Deadline > time.Now().Unix() {
		t.Fatal("promotion missed shorter admin deadline", status, err)
	}
}

func TestEnrollmentLastPushApproverAndConcurrentPasskeys(t *testing.T) {
	s, u, _ := enrollmentFixture(t)
	dev := &NativeDevice{ID: "phone", UserID: u.ID, DeviceIdentifier: "phone", DeviceName: "Phone", PublicKey: "test-key", IsMFAApprover: true}
	if err := s.UpsertNativeDevice(dev); err != nil {
		t.Fatal(err)
	}
	p := enrollmentPolicy("organization", 0)
	p.AllowedMethods = []string{"totp", "push", "webauthn"}
	if err := s.SetEnrollmentPolicy(p, "admin-session", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNativeDeviceMFAApprover(dev.ID, u.ID, false, nil); !errors.Is(err, ErrLastCompliantFactor) {
		t.Fatal("last push approver disabled", err)
	}
	if err := s.DeleteNativeDevice(dev.ID, u.ID, nil); !errors.Is(err, ErrLastCompliantFactor) {
		t.Fatal("last push approver deleted", err)
	}
	dev.PublicKey = ""
	if err := s.UpsertNativeDevice(dev); !errors.Is(err, ErrLastCompliantFactor) {
		t.Fatal("upsert removed last signing key", err)
	}
	for _, id := range []string{"one", "two"} {
		if err := s.CreateWebAuthnCredential(&WebAuthnCredential{ID: id, UserID: u.ID, CredentialID: id, Name: id, PublicKeySPKI: "test"}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DeleteNativeDevice(dev.ID, u.ID, nil); err != nil {
		t.Fatal("alternative did not permit push removal", err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, id := range []string{"one", "two"} {
		go func(id string) { <-start; _, err := s.DeleteWebAuthnCredential(id, u.ID, nil); results <- err }(id)
	}
	close(start)
	failed := 0
	for range 2 {
		err := <-results
		if errors.Is(err, ErrLastCompliantFactor) {
			failed++
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if failed != 1 {
		t.Fatal("concurrent removals did not preserve one factor", failed)
	}
}

// Login offers push from mfa_methods; removing the last approver must take that offer away.
func TestPushMethodFollowsApproverDevices(t *testing.T) {
	s, u, _ := enrollmentFixture(t)
	hasPush := func() bool {
		t.Helper()
		methods, err := s.ListUserMFAMethods(u.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range methods {
			if m.MethodType == "push" {
				return true
			}
		}
		return false
	}
	if err := s.SetMFAMethod(&MFAMethod{ID: "push", UserID: u.ID, MethodType: "push"}, nil); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"one", "two"} {
		if err := s.UpsertNativeDevice(&NativeDevice{ID: id, UserID: u.ID, DeviceIdentifier: id, DeviceName: id, PublicKey: "key-" + id, IsMFAApprover: true}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DeleteNativeDevice("one", u.ID, nil); err != nil || !hasPush() {
		t.Fatal("removing one of two approvers dropped push", err)
	}
	if err := s.SetNativeDeviceMFAApprover("two", u.ID, false, nil); err != nil || hasPush() {
		t.Fatal("push still offered with no approver", err)
	}
	if err := s.SetNativeDeviceMFAApprover("two", u.ID, true, nil); err != nil || !hasPush() {
		t.Fatal("re-enabled approver did not restore push", err)
	}

	// Push is the user's only compliant factor: the guard refuses, and the rollback keeps the row.
	p := enrollmentPolicy("organization", 0)
	p.AllowedMethods = []string{"totp", "push"}
	if err := s.SetEnrollmentPolicy(p, "admin-session", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteNativeDevice("two", u.ID, nil); !errors.Is(err, ErrLastCompliantFactor) || !hasPush() {
		t.Fatal("last compliant push device removed", err)
	}
	p.Required, p.Revision = false, 2
	if err := s.SetEnrollmentPolicy(p, "admin-session", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteNativeDevice("two", u.ID, nil); err != nil || hasPush() {
		t.Fatal("deleting the last approver left push offered", err)
	}
}
