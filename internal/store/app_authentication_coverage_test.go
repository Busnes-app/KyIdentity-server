package store

import (
	"errors"
	"testing"
	"time"
)

// Guards policy validation: malformed modes, factors, ages and refresh windows are all
// refused before anything is written.
func TestAppAuthenticationPolicyValid(t *testing.T) {
	for _, tt := range []struct {
		name string
		p    AppAuthenticationPolicy
		ok   bool
	}{
		{"default", AppAuthenticationPolicy{Mode: "reuse", Factor: "password"}, true},
		{"unknown mode", AppAuthenticationPolicy{Mode: "never", Factor: "password"}, false},
		{"unknown factor", AppAuthenticationPolicy{Mode: "reuse", Factor: "sms"}, false},
		{"max_age without age", AppAuthenticationPolicy{Mode: "max_age", Factor: "password"}, false},
		{"age without max_age", AppAuthenticationPolicy{Mode: "reuse", PrimaryMaxAge: 60, Factor: "password"}, false},
		{"password factor age", AppAuthenticationPolicy{Mode: "reuse", Factor: "password", FactorMaxAge: 60}, false},
		{"negative factor age", AppAuthenticationPolicy{Mode: "reuse", Factor: "mfa", FactorMaxAge: -1}, false},
		{"refresh ok", AppAuthenticationPolicy{Mode: "reuse", Factor: "mfa", RefreshIdle: MinRefreshIdle, RefreshLifetime: MaxRefreshLifetime}, true},
		{"refresh idle too short", AppAuthenticationPolicy{Mode: "reuse", Factor: "mfa", RefreshIdle: MinRefreshIdle - 1, RefreshLifetime: MinRefreshLifetime}, false},
		{"refresh lifetime too long", AppAuthenticationPolicy{Mode: "reuse", Factor: "mfa", RefreshIdle: MinRefreshIdle, RefreshLifetime: MaxRefreshLifetime + 1}, false},
		{"refresh idle beyond lifetime", AppAuthenticationPolicy{Mode: "reuse", Factor: "mfa", RefreshIdle: MaxRefreshIdle, RefreshLifetime: MinRefreshLifetime}, false},
		{"half refresh", AppAuthenticationPolicy{Mode: "reuse", Factor: "mfa", RefreshLifetime: MinRefreshLifetime}, false},
	} {
		if got := tt.p.Valid(); got != tt.ok {
			t.Errorf("%s: Valid() = %v, want %v", tt.name, got, tt.ok)
		}
	}
}

// Guards the code's authentication deadline: it is the earlier of the primary and the
// factor age limits, and absent when neither applies.
func TestAppAuthenticationDeadline(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	primary, factor := now.Add(-10*time.Minute), now.Add(-time.Minute)
	e := AuthenticationEvidence{PrimaryAuthenticatedAt: &primary, FactorAuthenticatedAt: &factor}
	if d := (AppAuthenticationPolicy{Mode: "reuse", Factor: "mfa"}).Deadline(e); d != nil {
		t.Fatal("deadline without age limits", d)
	}
	if d := (AppAuthenticationPolicy{Mode: "max_age", PrimaryMaxAge: 3600, Factor: "mfa"}).Deadline(e); d == nil || !d.Equal(primary.Add(time.Hour)) {
		t.Fatal("primary deadline", d)
	}
	if d := (AppAuthenticationPolicy{Mode: "max_age", PrimaryMaxAge: 3600, Factor: "mfa", FactorMaxAge: 60}).Deadline(e); d == nil || !d.Equal(factor.Add(time.Minute)) {
		t.Fatal("earlier factor deadline not chosen", d)
	}
	if d := (AppAuthenticationPolicy{Mode: "max_age", PrimaryMaxAge: 60, Factor: "mfa", FactorMaxAge: 3600}).Deadline(e); d == nil || !d.Equal(primary.Add(time.Minute)) {
		t.Fatal("earlier primary deadline not kept", d)
	}
	if r := (AppAuthenticationPolicy{Mode: "reuse", Factor: "mfa"}).EvidenceReason(AuthenticationEvidence{PrimaryAuthenticatedAt: &primary}, now); r != "factor_required" {
		t.Fatal("missing factor", r)
	}
}

// Guards SetAppAuthenticationPolicy refusals: invalid policies, apps without an OAuth
// client, stale revisions and refresh on a public client change nothing and keep tokens.
func TestSetAppAuthenticationPolicyRefusals(t *testing.T) {
	s, u, a := appAccessFixture(t)
	if err := s.SetAppAssignment(a.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordIssuedToken(accessToken(u, "tok", "")); err != nil {
		t.Fatal(err)
	}
	apps, _, _ := s.ListAppRecords("client", 25, 0)
	a = apps[0]
	refresh := AppAuthenticationPolicy{Mode: "reuse", Factor: "mfa", RefreshIdle: MinRefreshIdle, RefreshLifetime: MinRefreshLifetime}
	if err := s.SetAppAuthenticationPolicy(a.ID, AppAuthenticationPolicy{Mode: "never"}, a.Revision, nil); !errors.Is(err, ErrAppAuthentication) {
		t.Fatal("invalid policy", err)
	}
	if err := s.SetAppAuthenticationPolicy(a.ID, refresh, a.Revision, nil); !errors.Is(err, ErrRefreshNeedsConfidential) {
		t.Fatal("refresh on public client", err)
	}
	if err := s.SetAppAuthenticationPolicy(a.ID, AppAuthenticationPolicy{Mode: "fresh", Factor: "mfa"}, a.Revision-1, nil); !errors.Is(err, ErrAppLinkConflict) {
		t.Fatal("stale revision", err)
	}
	if err := s.CreateApplication(&Application{ID: "wiki", Name: "Wiki", URL: "https://wiki.example", Enabled: true}, nil); err != nil {
		t.Fatal(err)
	}
	wiki, _, _ := s.ListAppRecords("wiki", 25, 0)
	if err := s.SetAppAuthenticationPolicy(wiki[0].ID, AppAuthenticationPolicy{Mode: "fresh", Factor: "mfa"}, wiki[0].Revision, nil); !errors.Is(err, ErrAppAuthentication) {
		t.Fatal("launcher-only app accepted an authentication policy", err)
	}
	after, _, _ := s.ListAppRecords("client", 25, 0)
	if after[0].AuthenticationRevision != a.AuthenticationRevision || after[0].Authentication != a.Authentication {
		t.Fatal("refused policy changed the app")
	}
	assertRevoked(t, s, "tok", false)
}

// Guards the no-op edit: saving the current policy is audited as unchanged and neither
// bumps the policy revision nor revokes tokens; a confidential client may enable refresh.
func TestSetAppAuthenticationPolicyUnchangedAndRefresh(t *testing.T) {
	s, u, a := appAccessFixture(t)
	if err := s.SetAppAssignment(a.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordIssuedToken(accessToken(u, "tok", "")); err != nil {
		t.Fatal(err)
	}
	apps, _, _ := s.ListAppRecords("client", 25, 0)
	a = apps[0]
	audit := &AuditEvent{ID: "same", Action: "admin.app_authentication_changed", Outcome: "success", CreatedAt: time.Now().UTC()}
	if err := s.SetAppAuthenticationPolicy(a.ID, a.Authentication, a.Revision, audit); err != nil {
		t.Fatal(err)
	}
	if count(t, s, `SELECT COUNT(*) FROM audit_events WHERE id='same' AND details_json LIKE '%"unchanged":true%'`) != 1 {
		t.Fatal("unchanged edit not audited as unchanged")
	}
	if after, _, _ := s.ListAppRecords("client", 25, 0); after[0].AuthenticationRevision != a.AuthenticationRevision {
		t.Fatal("unchanged edit bumped the policy revision")
	}
	assertRevoked(t, s, "tok", false)
	if err := s.SetAppAuthenticationPolicy(a.ID, a.Authentication, a.Revision, poisonedAudit(t, s, "admin.app_authentication_changed", a.ID)); err == nil {
		t.Fatal("unchanged edit ignored audit failure")
	}
	mustExec(t, s, `UPDATE oauth_clients SET client_type='confidential' WHERE id='client'`)
	refresh := AppAuthenticationPolicy{Mode: "reuse", Factor: "mfa", RefreshIdle: MinRefreshIdle, RefreshLifetime: MinRefreshLifetime}
	if err := s.SetAppAuthenticationPolicy(a.ID, refresh, a.Revision, nil); err != nil {
		t.Fatal(err)
	}
	if p, err := s.ClientAuthenticationPolicy("client"); err != nil || p != refresh {
		t.Fatalf("policy = %+v, %v", p, err)
	}
	assertRevoked(t, s, "tok", true)
}
