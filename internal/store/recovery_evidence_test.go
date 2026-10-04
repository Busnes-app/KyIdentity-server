package store

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func recoveryFixture(t *testing.T, s *Store) string {
	t.Helper()
	app := provisioningFixture(t, s, "mail")
	if _, err := s.db.Exec(`UPDATE paired_systems SET system_type='kypost',hmac_secret_encrypted='encrypted-test-credential' WHERE id='mail'`); err != nil {
		t.Fatal(err)
	}
	return app
}
func readRecovery(t *testing.T, s *Store, ids ...string) RecoveryEvidence {
	t.Helper()
	b, err := s.ExportRecoveryEvidence("mail", "https://identity.test", strings.Repeat("a", 64), ids, nil, func(*PairedSystem, []byte, time.Time) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	var e RecoveryEvidence
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatal(err)
	}
	return e
}
func assertRecoveryInactive(t *testing.T, e RecoverySubject) {
	t.Helper()
	var p map[string]any
	if err := json.Unmarshal(e.Profile, &p); err != nil {
		t.Fatal(err)
	}
	roles, ok := p["roles"].([]any)
	if len(p) != 4 || p["id"] != e.ID || p["externalId"] != e.ID || p["active"] != false || !ok || len(roles) != 0 {
		t.Fatalf("negative leaks or omits attributes: %s", e.Profile)
	}
}

func TestRecoveryEvidenceIncludesAcknowledgedLossAndDeletion(t *testing.T) {
	for _, deleted := range []bool{false, true} {
		t.Run(map[bool]string{false: "unassigned", true: "deleted"}[deleted], func(t *testing.T) {
			s, cleanup := setupTestStore(t)
			defer cleanup()
			app := recoveryFixture(t, s)
			current, lost, unknown := createTestUser(t, s), createTestUser(t, s), createTestUser(t, s)
			for _, u := range []*User{current, lost} {
				if err := s.SetAppAssignment(app, "users", u.ID, true, nil); err != nil {
					t.Fatal(err)
				}
			}
			if len(deliverAll(t, s)) != 2 {
				t.Fatal("create acknowledgements missing")
			}
			var err error
			if deleted {
				err = s.DeleteUserWithSyncEvents(lost.ID, nil)
			} else {
				err = s.SetAppAssignment(app, "users", lost.ID, false, nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(deliverAll(t, s)) != 1 {
				t.Fatal("loss acknowledgement missing")
			}
			if err := s.ResyncSystem("mail"); err != nil {
				t.Fatal(err)
			}
			if got := pendingFor(t, s, "mail", lost.ID); len(got) != 0 {
				t.Fatal("fixture unexpectedly re-sends loss", got)
			}
			e := readRecovery(t, s, current.ID, lost.ID, unknown.ID, "never-existed")
			if e.Version != 1 || e.SystemID != "mail" || e.Issuer != "https://identity.test" || e.Nonce != strings.Repeat("a", 64) || e.ExpiresAt.Sub(e.IssuedAt) != 5*time.Minute || len(e.Subjects) != 4 {
				t.Fatalf("envelope: %+v", e)
			}
			var p struct{ Active bool }
			if err := json.Unmarshal(e.Subjects[0].Profile, &p); err != nil || !p.Active {
				t.Fatalf("current: %s %v", e.Subjects[0].Profile, err)
			}
			if e.Subjects[0].Revision == nil || *e.Subjects[0].Revision != 2 || e.Subjects[1].Revision == nil || *e.Subjects[1].Revision != 2 {
				t.Fatalf("revision fence: %+v", e.Subjects)
			}
			for i := 1; i < 4; i++ {
				assertRecoveryInactive(t, e.Subjects[i])
			}
			if e.Subjects[2].Revision != nil || e.Subjects[3].Revision != nil {
				t.Fatal("unknown ledger revision invented")
			}
		})
	}
}

func TestRecoveryEvidenceProjectsLiveRolesAndExpiry(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	app := recoveryFixture(t, s)
	u := createTestUser(t, s)
	g := &Group{ID: uuid.NewString(), Name: "staff"}
	if err := s.CreateGroup(g, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGroupMembership(g.ID, u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppAssignment(app, "groups", g.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"reader", "writer"} {
		role, err := s.CreateAppRole(app, name, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		kind, principal := "users", u.ID
		if name == "writer" {
			kind, principal = "groups", g.ID
		}
		if err := s.SetAppRoleAssignment(app, role.ID, kind, principal, true, nil); err != nil {
			t.Fatal(err)
		}
	}
	var p struct {
		Active bool
		Roles  []struct{ Value string }
	}
	e := readRecovery(t, s, u.ID)
	if err := json.Unmarshal(e.Subjects[0].Profile, &p); err != nil || !p.Active || len(p.Roles) != 2 || p.Roles[0].Value != "reader" || p.Roles[1].Value != "writer" {
		t.Fatalf("role projection: %s %v", e.Subjects[0].Profile, err)
	}
	for _, change := range []string{
		`UPDATE group_memberships SET expires_at=unixepoch()-1`,
		`UPDATE group_memberships SET expires_at=NULL; UPDATE users SET ends_at=unixepoch()-1`,
		`UPDATE users SET ends_at=NULL,status='disabled'`,
		`UPDATE users SET status='active'; UPDATE app_registry SET enabled=0`,
	} {
		if _, err := s.db.Exec(change); err != nil {
			t.Fatal(err)
		}
		assertRecoveryInactive(t, readRecovery(t, s, u.ID).Subjects[0])
	}
}

func TestRecoveryEvidenceFailsClosedWithoutPartialOutput(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	app := recoveryFixture(t, s)
	u := createTestUser(t, s)
	if err := s.SetAppAssignment(app, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	export := func(audit *AuditEvent, sign func(*PairedSystem, []byte, time.Time) error) ([]byte, error) {
		return s.ExportRecoveryEvidence("mail", "https://identity.test", strings.Repeat("a", 64), []string{u.ID}, audit, sign)
	}
	noop := func(*PairedSystem, []byte, time.Time) error { return nil }
	for _, change := range []string{`status='disabled'`, `status='failing'`, `provisioning_hold=1`, `system_type='scim'`, `system_type='suite_webhook'`, `hmac_secret_encrypted=''`} {
		if _, err := s.db.Exec(`UPDATE paired_systems SET ` + change + ` WHERE id='mail'`); err != nil {
			t.Fatal(err)
		}
		if b, err := export(nil, noop); b != nil || !errors.Is(err, ErrRecoveryEvidenceUnavailable) {
			t.Fatalf("%s: %s %v", change, b, err)
		}
		if _, err := s.db.Exec(`UPDATE paired_systems SET status='active',provisioning_hold=0,system_type='kypost',hmac_secret_encrypted='encrypted-test-credential' WHERE id='mail'`); err != nil {
			t.Fatal(err)
		}
	}
	audit := poisonedAudit(t, s, "admin.recovery_evidence_exported", "mail")
	if b, err := export(audit, noop); err == nil || b != nil {
		t.Fatal("audit failure released evidence")
	}
	signErr := errors.New("signing failed")
	if b, err := export(nil, func(*PairedSystem, []byte, time.Time) error { return signErr }); b != nil || !errors.Is(err, signErr) {
		t.Fatal("signing failure released evidence", err)
	}
	if _, err := s.db.Exec(`UPDATE users SET display_name=? WHERE id=?`, strings.Repeat("x", MaxRecoveryEvidenceBytes), u.ID); err != nil {
		t.Fatal(err)
	}
	called := false
	if b, err := export(nil, func(*PairedSystem, []byte, time.Time) error { called = true; return nil }); b != nil || !errors.Is(err, ErrRecoveryEvidenceTooLarge) || called {
		t.Fatal("oversized snapshot signed or returned", err)
	}
}

func TestRecoveryEvidenceSerializesConcurrentAuthorityMutation(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	app := recoveryFixture(t, s)
	u := createTestUser(t, s)
	if err := s.SetAppAssignment(app, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	started, done := make(chan struct{}), make(chan error, 1)
	b, err := s.ExportRecoveryEvidence("mail", "https://identity.test", strings.Repeat("a", 64), []string{u.ID}, nil, func(*PairedSystem, []byte, time.Time) error {
		go func() { close(started); done <- s.SetAppAssignment(app, "users", u.ID, false, nil) }()
		<-started
		select {
		case err := <-done:
			t.Fatalf("authority mutated inside snapshot: %v", err)
		case <-time.After(50 * time.Millisecond):
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("mutation did not resume")
	}
	if !strings.Contains(string(b), `"active":true`) {
		t.Fatalf("mixed snapshot: %s", b)
	}
	assertRecoveryInactive(t, readRecovery(t, s, u.ID).Subjects[0])
}
