package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func hrFixture(t *testing.T) (*Store, string) {
	t.Helper()
	s, err := NewTest(filepath.Join(t.TempDir(), "hr.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	c, err := s.CreateSCIMConnector("HR", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePairedSystem(&PairedSystem{ID: "post", Name: "KyPost", SystemType: "kypost", CallbackURL: "https://post.example/api/sync/webhook", Status: "active"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfigureHR(HRConnection{ConnectorID: c.ID, SystemID: "post", Domain: "example.test", WritebackURL: "https://hr.example/writeback", WritebackSecret: "encrypted"}, nil); err != nil {
		t.Fatal(err)
	}
	return s, c.ID
}

func TestHRStagingVersionsAndLifecycle(t *testing.T) {
	s, c := hrFixture(t)
	in := HRInput{SourceUID: "WID-123", PreferredName: "alice.adams", DisplayName: "Alice", Active: true, SourceVersion: 1}
	w, err := s.ImportHR(c, in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if u, _ := s.DefaultOrg().GetUserByID(w.ID); u != nil {
		t.Fatal("identity created before KyPost assigned email")
	}
	if retry, err := s.ImportHR(c, in, nil); err != nil || retry.ID != w.ID {
		t.Fatal("duplicate import", err)
	}
	job, err := s.ClaimHR()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimHR(); !errors.Is(err, ErrNotFound) {
		t.Fatal("job claimed twice", err)
	}
	if err := s.FinishHR(job, "alice.adams@example.test", ""); err != nil {
		t.Fatal(err)
	}
	u, err := s.DefaultOrg().GetUserByID(w.ID)
	if err != nil || u == nil || u.Username != "alice.adams@example.test" || u.Email != u.Username || u.SourceConnectorID != c || u.ExternalID != in.SourceUID || u.Status != "disabled" || !u.Pending || u.Role != "user" {
		t.Fatal(u, err)
	}
	job, err = s.ClaimHR()
	if err != nil || job.State != "writeback_pending" {
		t.Fatal(job, err)
	}
	if err := s.FinishHR(job, job.Email, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimHR(); !errors.Is(err, ErrNotFound) {
		t.Fatal("completed job reclaimed", err)
	}
	// Activate through the real account-token path, then verify HR departure.
	raw, err := s.IssueAccountToken(w.ID, "activation", "manual", time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RedeemAccountToken(raw, "activation", "new-password-hash", nil); err != nil {
		t.Fatal(err)
	}
	in.SourceVersion = 2
	in.Active = false
	if _, err := s.ImportHR(c, in, nil); err != nil {
		t.Fatal(err)
	}
	u, _ = s.DefaultOrg().GetUserByID(w.ID)
	if u.Status != "disabled" || u.SourceActive || u.Pending {
		t.Fatal("departure failed", u)
	}
	in.SourceVersion = 1
	in.Active = true
	if _, err := s.ImportHR(c, in, nil); !errors.Is(err, ErrHRConflict) {
		t.Fatal("stale reactivation accepted", err)
	}
	in.SourceVersion = 3
	if _, err := s.ImportHR(c, in, nil); err != nil {
		t.Fatal(err)
	}
	u, _ = s.DefaultOrg().GetUserByID(w.ID)
	if u.Status != "active" || u.Email != "alice.adams@example.test" {
		t.Fatal("rehire changed identity/address", u)
	}
}

func TestHRLeaseSupersessionAuditAndRestore(t *testing.T) {
	s, c := hrFixture(t)
	in := HRInput{SourceUID: "123", PreferredName: "alice", Active: true, SourceVersion: 1}
	w, err := s.ImportHR(c, in, nil)
	if err != nil {
		t.Fatal(err)
	}
	job, err := s.ClaimHR()
	if err != nil {
		t.Fatal(err)
	}
	in.SourceVersion = 2
	in.Active = false
	if _, err := s.ImportHR(c, in, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishHR(job, "alice@example.test", ""); err != nil {
		t.Fatal(err)
	}
	if u, _ := s.DefaultOrg().GetUserByID(w.ID); u != nil {
		t.Fatal("stale allocation created departed account")
	}
	in.SourceVersion = 3
	in.Active = true
	if _, err := s.ImportHR(c, in, nil); err != nil {
		t.Fatal(err)
	}
	job, err = s.ClaimHR()
	if err != nil {
		t.Fatal(err)
	}
	// Fail atomic audit persistence and verify identity creation rolls back.
	trigger := `CREATE TRIGGER reject_hr_audit BEFORE INSERT ON audit_events WHEN NEW.action LIKE 'hr.%' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`
	if s.postgres {
		trigger = `CREATE FUNCTION reject_hr_audit_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action LIKE 'hr.%' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END $$;
CREATE TRIGGER reject_hr_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_hr_audit_fn()`
	}
	if _, err := s.db.Exec(trigger); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishHR(job, "alice@example.test", ""); err == nil {
		t.Fatal("audit failure ignored")
	}
	if u, _ := s.DefaultOrg().GetUserByID(w.ID); u != nil {
		t.Fatal("unaudited identity persisted")
	}
	drop := `DROP TRIGGER reject_hr_audit`
	if s.postgres {
		drop += ` ON audit_events`
	}
	if _, err := s.db.Exec(drop); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishHR(job, "alice@example.test", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyRestoredState(time.Now().UTC(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimHR(); !errors.Is(err, ErrNotFound) {
		t.Fatal("restored HR job delivered", err)
	}
	connection, err := s.HRConnection(c)
	if err != nil || !connection.Held {
		t.Fatal("restore did not hold HR", err)
	}
}

func TestHRRestartAndWritebackRetry(t *testing.T) {
	s, c := hrFixture(t)
	w, err := s.ImportHR(c, HRInput{SourceUID: "restart-worker", PreferredName: "alice", Active: true, SourceVersion: 1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	job, err := s.ClaimHR()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.FinishHR(job, "alice@example.test", ""); err != nil {
		t.Fatal(err)
	}
	job, err = s.ClaimHR()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.FinishHR(job, "", "endpoint_unavailable"); err != nil {
		t.Fatal(err)
	}
	filename := s.path
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewTest(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	w, err = reopened.HRWorker(c, w.SourceUID)
	if err != nil || w.Email != "alice@example.test" || w.State != "writeback_pending" || w.Attempts != 1 || w.LastError != "endpoint_unavailable" {
		t.Fatal("job lost at restart", w, err)
	}
	if _, err := reopened.ClaimHR(); !errors.Is(err, ErrNotFound) {
		t.Fatal("backoff lost at restart", err)
	}
	if _, err := reopened.db.Exec(`UPDATE hr_workers SET next_attempt=? WHERE id=?`, time.Now().UTC().Add(-time.Second), w.ID); err != nil {
		t.Fatal(err)
	}
	job, err = reopened.ClaimHR()
	if err != nil || job.State != "writeback_pending" {
		t.Fatal("mailbox allocation repeated", job, err)
	}
	if err := reopened.FinishHR(job, job.Email, ""); err != nil {
		t.Fatal(err)
	}
	users, err := reopened.DefaultOrg().ListUsers()
	if err != nil || len(users) != 1 || users[0].ID != w.ID {
		t.Fatal("duplicate identity", users, err)
	}
}

func TestHRRefusesPreviouslyAuthorizedSCIMWrites(t *testing.T) {
	s, c := hrFixture(t)
	// These calls represent SCIM handlers that authenticated before an empty
	// connector was configured for HR. The store must recheck at commit time.
	u := &User{Username: "in-flight-scim", Email: "arbitrary@example.test", SourceConnectorID: c, ExternalID: "foreign", SourceActive: true}
	if err := s.CreateUpstreamUser(u, nil); !errors.Is(err, ErrHRConflict) {
		t.Fatal("in-flight SCIM create bypassed HR staging", err)
	}
	if err := s.CreateUpstreamGroup(&Group{Name: "in-flight-group", SourceConnectorID: c}, nil, nil); !errors.Is(err, ErrHRConflict) {
		t.Fatal("in-flight group create bypassed source ownership", err)
	}
	w, err := s.ImportHR(c, HRInput{SourceUID: "employee", PreferredName: "alice", Active: true, SourceVersion: 1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	job, err := s.ClaimHR()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.FinishHR(job, "alice@example.test", ""); err != nil {
		t.Fatal(err)
	}
	u, err = s.DefaultOrg().GetUserByID(w.ID)
	if err != nil {
		t.Fatal(err)
	}
	u.Email = "overwritten@example.test"
	if _, err := s.UpdateUpstreamUser(c, u.ID, nil, func(current *User) error { current.Email = u.Email; return nil }); !errors.Is(err, ErrHRConflict) {
		t.Fatal("SCIM overwrite bypassed versioning", err)
	}
	stored, _ := s.DefaultOrg().GetUserByID(w.ID)
	if stored.Email != "alice@example.test" {
		t.Fatal("HR email overwritten")
	}
}
