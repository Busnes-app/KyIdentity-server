package store

import (
	"errors"
	"testing"
	"time"
)

// disableFixture is an active user "ada" with a live session, plus a permanent admin
// "guard" that DisableUserByName can name.
func disableFixture(t *testing.T) (*Store, *User, *User) {
	t.Helper()
	s, u := newStoreWithUser(t, "user")
	g := createTestUserNamed(t, s, "guard")
	mustExec(t, s, `UPDATE users SET role='admin' WHERE id=?`, g.ID)
	if err := s.CreateSession(&Session{ID: "ada-session", UserID: u.ID, SessionTokenHash: "ada-hash", ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	return s, u, g
}

func disableAudit() *AuditEvent {
	return &AuditEvent{ID: "disable-audit", Action: "admin.user_disabled", Outcome: "success", CreatedAt: time.Now().UTC()}
}

// Guards the CLI disable: status only changes to disabled, sessions end, and the audit
// row names the target and the guard in the same transaction.
func TestDisableUserByNameDisablesAndAudits(t *testing.T) {
	s, u, _ := disableFixture(t)
	audit := disableAudit()
	changed, err := s.DisableUserByName("ADA", "Guard", audit)
	if err != nil || !changed {
		t.Fatalf("disable = %v, %v", changed, err)
	}
	got, _ := s.GetUserByID(u.ID)
	if got.Status != "disabled" || got.Role != "user" || got.PasswordHash != "hash" {
		t.Fatalf("disable changed more than status: %+v", got)
	}
	if count(t, s, `SELECT COUNT(*) FROM sessions WHERE user_id=?`, u.ID) != 0 {
		t.Fatal("disabled account kept its session")
	}
	if audit.TargetID != u.ID || count(t, s, `SELECT COUNT(*) FROM audit_events WHERE id='disable-audit' AND target_id=? AND details_json LIKE '%"guard":"Guard"%'`, u.ID) != 1 {
		t.Fatalf("audit row missing or incomplete: %+v", audit)
	}
	// A second run has nothing left to revoke: false, no new audit row.
	before := auditCount(t, s)
	again := disableAudit()
	again.ID = "disable-again"
	if changed, err := s.DisableUserByName("ada", "guard", again); err != nil || changed {
		t.Fatalf("rerun = %v, %v", changed, err)
	}
	if auditCount(t, s) != before {
		t.Fatal("no-op disable wrote an audit row")
	}
}

// Guards the guard-administrator rule: the guard must be a different, active admin with
// no end date, and every refusal leaves the account untouched with no audit row.
func TestDisableUserByNameRefusesBadGuards(t *testing.T) {
	s, u, g := disableFixture(t)
	other := createTestUserNamed(t, s, "plain")
	for name, guard := range map[string]string{
		"self":            "ada",
		"self any case":   "Ada",
		"non-admin guard": other.Username,
		"unknown guard":   "nobody",
	} {
		if _, err := s.DisableUserByName("ada", guard, disableAudit()); !errors.Is(err, ErrGuardAdministrator) {
			t.Fatalf("%s: got %v, want ErrGuardAdministrator", name, err)
		}
	}
	mustExec(t, s, `UPDATE users SET ends_at=? WHERE id=?`, time.Now().Add(time.Hour).Unix(), g.ID)
	if _, err := s.DisableUserByName("ada", "guard", disableAudit()); !errors.Is(err, ErrGuardAdministrator) {
		t.Fatal("expiring admin accepted as guard", err)
	}
	mustExec(t, s, `UPDATE users SET ends_at=NULL, status='disabled' WHERE id=?`, g.ID)
	if _, err := s.DisableUserByName("ada", "guard", disableAudit()); !errors.Is(err, ErrGuardAdministrator) {
		t.Fatal("disabled admin accepted as guard", err)
	}
	got, _ := s.GetUserByID(u.ID)
	if got.Status != "active" || count(t, s, `SELECT COUNT(*) FROM sessions WHERE user_id=?`, u.ID) != 1 || auditActions(t, s, "admin.user_disabled") != 0 {
		t.Fatal("refused disable changed state or audited")
	}
	if _, err := s.DisableUserByName("ghost", "guard", nil); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown account", err)
	}
}

// Guards that an audit failure rolls the disable back: the account stays active.
func TestDisableUserByNameAuditFailureRollsBack(t *testing.T) {
	s, u, _ := disableFixture(t)
	if _, err := s.DisableUserByName("ada", "guard", poisonedAudit(t, s, "admin.user_disabled", u.ID)); err == nil {
		t.Fatal("disable ignored audit failure")
	}
	got, _ := s.GetUserByID(u.ID)
	if got.Status != "active" || count(t, s, `SELECT COUNT(*) FROM sessions WHERE user_id=?`, u.ID) != 1 {
		t.Fatal("failed audit left the account disabled")
	}
}

// Guards the "nothing left to revoke" shortcut: an already-disabled account holding a
// live activation link is still processed, so the link is retired.
func TestDisableUserByNameRetiresLiveLinkOfDisabledAccount(t *testing.T) {
	s, u, _ := disableFixture(t)
	mustExec(t, s, `UPDATE users SET status='disabled' WHERE id=?`, u.ID)
	now := time.Now().UTC()
	mustExec(t, s, `INSERT INTO account_tokens(id,user_id,kind,token_hash,delivery,expires_at,created_at) VALUES('link',?,'activation','link-hash','email',?,?)`, u.ID, now.Add(time.Hour), now)
	if changed, err := s.DisableUserByName("ada", "guard", disableAudit()); err != nil || !changed {
		t.Fatalf("disabled account with live link = %v, %v", changed, err)
	}
	if count(t, s, `SELECT COUNT(*) FROM account_tokens WHERE id='link' AND used_at IS NULL AND expires_at>?`, time.Now().UTC()) != 0 {
		t.Fatal("live link survived disable")
	}
}

// Guards source-owned accounts: an upstream-disabled account still gets the local
// override, which the upstream can then not lift.
func TestDisableUserByNameSetsLocalOverrideOnUpstreamAccount(t *testing.T) {
	s, _, _ := disableFixture(t)
	c, err := s.CreateSCIMConnector("Upstream", nil)
	if err != nil {
		t.Fatal(err)
	}
	up := upstream(t, s, c.ID, "ext-1", "sourced")
	mustExec(t, s, `UPDATE users SET status='disabled', source_active=0 WHERE id=?`, up.ID)
	if changed, err := s.DisableUserByName("sourced", "guard", nil); err != nil || !changed {
		t.Fatalf("upstream-disabled account = %v, %v", changed, err)
	}
	got, _ := s.GetUserByID(up.ID)
	if !got.LocallyDisabled || got.Status != "disabled" {
		t.Fatalf("local override not set: %+v", got)
	}
	up.SourceActive = true
	if err := upstreamWrite(s, up); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetUserByID(up.ID); got.Status != "disabled" {
		t.Fatal("upstream lifted the local disable")
	}
	if changed, err := s.DisableUserByName("sourced", "guard", nil); err != nil || changed {
		t.Fatalf("overridden account rerun = %v, %v", changed, err)
	}
}
