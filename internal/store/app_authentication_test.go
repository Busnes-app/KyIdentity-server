package store

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestAppAuthenticationEvidence(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	old, recent, future := now.Add(-2*time.Hour), now.Add(-30*time.Second), now.Add(time.Second)
	for _, tt := range []struct {
		name   string
		p      AppAuthenticationPolicy
		e      AuthenticationEvidence
		reason string
	}{
		{"legacy SSO", AppAuthenticationPolicy{Mode: "reuse", Factor: "password"}, AuthenticationEvidence{}, ""},
		{"unknown freshness", AppAuthenticationPolicy{Mode: "max_age", PrimaryMaxAge: 3600, Factor: "password"}, AuthenticationEvidence{}, "password_required"},
		{"old password", AppAuthenticationPolicy{Mode: "max_age", PrimaryMaxAge: 3600, Factor: "password"}, AuthenticationEvidence{PrimaryAuthenticatedAt: &old}, "password_expired"},
		{"future password", AppAuthenticationPolicy{Mode: "fresh", Factor: "password"}, AuthenticationEvidence{PrimaryAuthenticatedAt: &future}, "password_required"},
		{"independent factor expiry", AppAuthenticationPolicy{Mode: "reuse", Factor: "mfa", FactorMaxAge: 60}, AuthenticationEvidence{PrimaryAuthenticatedAt: &recent, FactorAuthenticatedAt: &old, FactorMethod: "totp"}, "factor_expired"},
		{"old password recent factor", AppAuthenticationPolicy{Mode: "reuse", Factor: "mfa", FactorMaxAge: 60}, AuthenticationEvidence{PrimaryAuthenticatedAt: &old, FactorAuthenticatedAt: &recent, FactorMethod: "push"}, ""},
		{"recovery", AppAuthenticationPolicy{Mode: "reuse", Factor: "mfa"}, AuthenticationEvidence{PrimaryAuthenticatedAt: &recent, FactorAuthenticatedAt: &recent, FactorMethod: "recovery"}, "factor_required"},
		{"TOTP cannot satisfy passkey", AppAuthenticationPolicy{Mode: "reuse", Factor: "passkey"}, AuthenticationEvidence{PrimaryAuthenticatedAt: &recent, FactorAuthenticatedAt: &recent, FactorMethod: "totp"}, "passkey_required"},
		{"push cannot satisfy passkey", AppAuthenticationPolicy{Mode: "reuse", Factor: "passkey"}, AuthenticationEvidence{PrimaryAuthenticatedAt: &recent, FactorAuthenticatedAt: &recent, FactorMethod: "push"}, "passkey_required"},
		{"passkey", AppAuthenticationPolicy{Mode: "reuse", Factor: "passkey"}, AuthenticationEvidence{PrimaryAuthenticatedAt: &recent, FactorAuthenticatedAt: &recent, FactorMethod: "webauthn"}, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.EvidenceReason(tt.e, now); got != tt.reason {
				t.Fatalf("got %q want %q", got, tt.reason)
			}
		})
	}
}

func TestAppAuthenticationRevocationAndRollback(t *testing.T) {
	s, u, a := appAccessFixture(t)
	if err := s.SetAppAssignment(a.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	apps, _, _ := s.ListAppRecords("client", 25, 0)
	a = apps[0]
	accessCode(t, s, u, "pending")
	accessCode(t, s, u, "spent")
	if ok, err := s.ConsumeAuthorizationCode("spent"); err != nil || !ok {
		t.Fatal(err)
	}
	if err := s.RecordIssuedToken(accessToken(u, "token", "spent")); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := s.CreateAuthorizationInteraction(&AuthorizationInteraction{Hash: "interaction", BrowserHash: "browser", ClientID: "client", Request: "client_id=client", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	p := AppAuthenticationPolicy{Mode: "fresh", Factor: "passkey", FactorMaxAge: 60}
	if _, err := s.db.Exec(`CREATE TRIGGER fail_policy_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppAuthenticationPolicy(a.ID, p, a.Revision, &AuditEvent{ID: "audit", Action: "policy", Outcome: "success"}); err == nil {
		t.Fatal("audit failure committed")
	}
	if got, _ := s.ClientAuthenticationPolicy("client"); got != a.Authentication {
		t.Fatal("policy escaped rollback")
	}
	if revoked, _ := s.IsTokenRevoked("token"); revoked {
		t.Fatal("revocation escaped rollback")
	}
	if c, _ := s.GetValidAuthorizationCode("pending"); c == nil {
		t.Fatal("code deletion escaped rollback")
	}
	if _, err := s.GetAuthorizationInteraction("interaction", "browser"); err != nil {
		t.Fatal("interaction deletion escaped rollback", err)
	}
	if _, err := s.db.Exec(`DROP TRIGGER fail_policy_audit`); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppAuthenticationPolicy(a.ID, p, a.Revision, &AuditEvent{ID: "audit", Action: "policy", Outcome: "success"}); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.GetValidAuthorizationCode("pending"); c != nil {
		t.Fatal("old code survives")
	}
	if revoked, _ := s.IsTokenRevoked("token"); !revoked {
		t.Fatal("old token survives")
	}
	if _, err := s.GetAuthorizationInteraction("interaction", "browser"); !errors.Is(err, ErrAuthorizationInteraction) {
		t.Fatal("old interaction survives", err)
	}
	if err := s.SetAppAuthenticationPolicy(a.ID, a.Authentication, a.Revision, nil); !errors.Is(err, ErrAppLinkConflict) {
		t.Fatal("stale policy overwrite", err)
	}
	if err := s.SetAppAuthenticationPolicy(a.ID, a.Authentication, a.Revision+1, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordIssuedToken(accessToken(u, "raced", "spent")); !errors.Is(err, ErrAppAccessDenied) {
		t.Fatal("relaxation revived code", err)
	}
	if err := s.migrateAppAuthentication(); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ClientAuthenticationPolicy("client"); got != a.Authentication {
		t.Fatal("restart changed policy")
	}
}

func TestAppAuthenticationFinalCodeCheck(t *testing.T) {
	s, u, a := appAccessFixture(t)
	if err := s.SetAppAssignment(a.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	apps, _, _ := s.ListAppRecords("client", 25, 0)
	a = apps[0]
	p := AppAuthenticationPolicy{Mode: "reuse", Factor: "passkey", FactorMaxAge: 60}
	if err := s.SetAppAuthenticationPolicy(a.ID, p, a.Revision, nil); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	past := now.Add(-time.Hour)
	code := &AuthorizationCode{ID: "code", CodeHash: "code", ClientID: "client", UserID: u.ID, SessionID: "session", ExpiresAt: now.Add(time.Minute), AuthenticationEvidence: AuthenticationEvidence{PrimaryAuthenticatedAt: &now, FactorAuthenticatedAt: &now, FactorMethod: "totp"}}
	if err := s.CreateAuthorizationCode(code); !errors.Is(err, ErrAppAuthentication) {
		t.Fatal("stale/weaker handler decision issued code", err)
	}
	code.FactorMethod = "webauthn"
	code.FactorAuthenticatedAt = &past
	if err := s.CreateAuthorizationCode(code); !errors.Is(err, ErrAppAuthentication) {
		t.Fatal("expired factor issued code", err)
	}
	code.FactorAuthenticatedAt = &now
	if err := s.CreateAuthorizationCode(code); err != nil {
		t.Fatal(err)
	}
	if code.AuthenticationExpiresAt == nil || !code.AuthenticationExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatal("factor deadline not snapshotted")
	}
	if ok, err := s.ConsumeAuthorizationCode("code"); err != nil || !ok {
		t.Fatal(err)
	}
	// Explicit revision comparison must also fail closed if invalidation were missed.
	if _, err := s.db.Exec(`UPDATE app_registry SET auth_revision=auth_revision+1 WHERE id=?`, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordIssuedToken(accessToken(u, "revision-race", "code")); !errors.Is(err, ErrAppAccessDenied) {
		t.Fatal("stale revision registered token", err)
	}
	// Factor deadline is independently checked at registration under unchanged policy.
	if _, err := s.db.Exec(`UPDATE authorization_codes SET auth_policy_revision=auth_policy_revision+1,authentication_expires_at=? WHERE id='code'`, past); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordIssuedToken(accessToken(u, "age-race", "code")); !errors.Is(err, ErrAppAccessDenied) {
		t.Fatal("expired factor registered token", err)
	}
}

func TestAppAuthenticationExchangeRace(t *testing.T) {
	s, u, a := appAccessFixture(t)
	if err := s.SetAppAssignment(a.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	apps, _, _ := s.ListAppRecords("client", 25, 0)
	a = apps[0]
	accessCode(t, s, u, "spent")
	if _, err := s.ConsumeAuthorizationCode("spent"); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		if err := s.SetAppAuthenticationPolicy(a.ID, AppAuthenticationPolicy{Mode: "fresh", Factor: "password"}, a.Revision, nil); err != nil {
			t.Error(err)
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		if err := s.RecordIssuedToken(accessToken(u, "racing", "spent")); err != nil && !errors.Is(err, ErrAppAccessDenied) {
			t.Error(err)
		}
	}()
	close(start)
	wg.Wait()
	if revoked, err := s.IsTokenRevoked("racing"); err != nil || !revoked {
		t.Fatal("racing token escaped policy change", err)
	}
}

func TestAppAuthenticationUpgradeAndLinks(t *testing.T) {
	s, u, a := appAccessFixture(t)
	if err := s.SetAppAssignment(a.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	accessCode(t, s, u, "preupgrade")
	if err := s.RecordIssuedToken(accessToken(u, "existing", "")); err != nil {
		t.Fatal(err)
	}
	// Model the previous schema without copying a second frozen schema definition.
	for _, col := range []string{"auth_mode", "auth_primary_max_age", "auth_factor", "auth_factor_max_age", "auth_revision"} {
		if _, err := s.db.Exec(`ALTER TABLE app_registry DROP COLUMN ` + col); err != nil {
			t.Fatal(err)
		}
	}
	for _, col := range []string{"auth_app_id", "auth_policy_revision"} {
		if _, err := s.db.Exec(`ALTER TABLE authorization_codes DROP COLUMN ` + col); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if err := s.migrateAppAuthentication(); err != nil {
			t.Fatal(err)
		}
	}
	if c, _ := s.GetValidAuthorizationCode("preupgrade"); c != nil {
		t.Fatal("legacy code survived migration")
	}
	if sess, _ := s.GetSessionByID("session"); sess == nil {
		t.Fatal("upgrade removed session")
	}
	if revoked, _ := s.IsTokenRevoked("existing"); revoked {
		t.Fatal("upgrade revoked existing token")
	}
	if p, _ := s.ClientAuthenticationPolicy("client"); p != a.Authentication {
		t.Fatal("upgrade changed default SSO")
	}
	if err := s.SetAppAssignment(a.ID, "users", u.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateApplication(&Application{ID: "launcher", Name: "Card", URL: "https://example.com", Enabled: true}, nil); err != nil {
		t.Fatal(err)
	}
	apps, _, _ := s.ListAppRecords("client", 25, 0)
	a = apps[0]
	launchers, _, _ := s.ListAppRecords("launcher", 25, 0)
	l := launchers[0]
	if err := s.LinkAppRecords(a.ID, l.ID, a.Revision, l.Revision, nil); err != nil {
		t.Fatal(err)
	}
	p := AppAuthenticationPolicy{Mode: "max_age", PrimaryMaxAge: 3600, Factor: "passkey", FactorMaxAge: 120}
	if err := s.SetAppAuthenticationPolicy(a.ID, p, a.Revision+1, nil); err != nil {
		t.Fatal(err)
	}
	id, err := s.UnlinkAppRecord(a.ID, "client", a.Revision+2, nil)
	if err != nil {
		t.Fatal(err)
	}
	records, _, err := s.ListAppRecords("", 25, 0)
	if err != nil || len(records) != 2 {
		t.Fatal(err)
	}
	for _, record := range records {
		if record.Authentication != p {
			t.Fatal("unlink weakened policy", record)
		}
	}
	if got, _ := s.ClientAuthenticationPolicy("client"); got != p {
		t.Fatal("client lost policy")
	}
	// A conflicting policy on the other identity cannot weaken the client on link.
	if _, err := s.db.Exec(`UPDATE app_registry SET auth_factor='password',auth_factor_max_age=0 WHERE id=?`, a.ID); err != nil {
		t.Fatal(err)
	}
	var target, source AppRecord
	for _, record := range records {
		if record.ID == id {
			target = record
		} else {
			source = record
		}
	}
	if err := s.LinkAppRecords(target.ID, source.ID, target.Revision, source.Revision, nil); !errors.Is(err, ErrAppLinkConflict) {
		t.Fatal("link ignored authentication mismatch", err)
	}
}
