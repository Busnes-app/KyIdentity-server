package store

import (
	"database/sql"
	"errors"
	"testing"
	"time"
)

var errRestoreTestRun = errors.New("reconciliation failed")

// ephemeral is every table holding a credential or a queued task that a restored
// snapshot must not bring back to life, with one row each.
func seedEphemeral(t *testing.T, s *Store, userID, clientID string) {
	t.Helper()
	soon := time.Now().UTC().Add(time.Hour)
	now := time.Now().UTC()
	for _, seed := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO sessions(id,user_id,session_token_hash,ip_address,user_agent,expires_at) VALUES('sess-1',?,'hash-1','::1','ua',?)`, []any{userID, soon}},
		{`INSERT INTO oidc_client_sessions(sid,client_id,session_id,user_id,created_at) VALUES('sid-1',?,'sess-1',?,?)`, []any{clientID, userID, now}},
		{`INSERT INTO issued_tokens(jti,user_id,client_id,expires_at) VALUES('jti-1',?,?,?)`, []any{userID, clientID, soon}},
		{`INSERT INTO authorization_codes(id,code_hash,client_id,user_id,redirect_uri,scope,code_challenge,code_challenge_method,expires_at) VALUES('code-1','ch-1',?,?,'https://app.test/cb','openid','c','S256',?)`, []any{clientID, userID, soon}},
		{`INSERT INTO authorization_interactions(hash,browser_hash,user_id,request,created_at,expires_at) VALUES('int-1','bh-1',?,'{}',?,?)`, []any{userID, now, soon}},
		{`INSERT INTO mfa_tokens(id,user_id,token_hash,expires_at) VALUES('mt-1',?,'mth-1',?)`, []any{userID, soon}},
		{`INSERT INTO mfa_challenges(id,user_id,method_type,match_digits,decoy_digits_json,status,expires_at) VALUES('mc-1',?,'push','12','[]','pending',?)`, []any{userID, soon}},
		{`INSERT INTO webauthn_challenges(id,user_id,challenge,purpose,expires_at,created_at) VALUES('wc-1',?,'chal-1','login',?,?)`, []any{userID, soon, now}},
		{`INSERT INTO step_up_challenges(token_hash,user_id,session_id,operation,method,proof,primary_authenticated_at,expires_at) VALUES('suc-1',?,'sess-1','GET /x','password','p',?,?)`, []any{userID, now, soon}},
		{`INSERT INTO step_up_tokens(id,user_id,session_id,token_hash,operation,expires_at,created_at) VALUES('sut-1',?,'sess-1','suth-1','GET /x',?,?)`, []any{userID, soon, now}},
		{`INSERT INTO account_tokens(id,user_id,kind,token_hash,delivery,expires_at,created_at) VALUES('at-1',?,'activation','ath-1','email',?,?)`, []any{userID, soon, now}},
		{`INSERT INTO device_pairing_tokens(id,user_id,token_hash,pin_hash,expires_at) VALUES('dpt-1',?,'dpth-1','pin',?)`, []any{userID, soon}},
		{`INSERT INTO login_failures(user_id,failures,last_failure_at) VALUES(?,4,?)`, []any{userID, now}},
		{`INSERT INTO logout_deliveries(id,client_id,user_id,sid,status,next_attempt_at,created_at,updated_at) VALUES('ld-1',?,?,'sid-1','queued',?,?,?)`, []any{clientID, userID, now, now, now}},
	} {
		if _, err := s.db.Exec(seed.query, seed.args...); err != nil {
			t.Fatalf("seed %s: %v", seed.query[:40], err)
		}
	}
}

func restoreFixture(t *testing.T) (*Store, func()) {
	t.Helper()
	s, cleanup := setupTestStore(t)
	u := createTestUserNamed(t, s, "staff")
	if err := s.CreateOAuthClient(&OAuthClient{ID: "client-1", ClientName: "App", ClientType: "public", RedirectURIsJSON: `["https://app.test/cb"]`, AllowedScopesJSON: `["openid"]`, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	seedEphemeral(t, s, u.ID, "client-1")
	provisioningFixture(t, s, "hr")
	if _, err := s.db.Exec(`INSERT INTO account_sync_events(id,user_id,system_id,event_type,payload_json,status) VALUES('ev-old',?,'hr','user.created','{}','pending')`, u.ID); err != nil {
		t.Fatal(err)
	}
	return s, cleanup
}

// Restoring a snapshot must not revive the logins, tokens, invitations and queued
// deliveries it happens to contain, and must not let stale outbound work run before an
// operator has reconciled the connector against what is really there.
func TestRestoreInvalidatesEphemeralCredentialsAndHoldsProvisioning(t *testing.T) {
	s, cleanup := restoreFixture(t)
	defer cleanup()
	report, err := s.ApplyRestoredState(time.Now().UTC(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range restoredCleared {
		if n := countRows(t, s, `SELECT COUNT(*) FROM `+table); n != 0 {
			t.Errorf("%s survived the restore with %d row(s)", table, n)
		}
	}
	// Twelve of the fourteen seeded rows are deleted directly; the client session and
	// the step-up challenge hang off the session and go with it by cascade.
	if report.Credentials != 12 || report.QueuedDeliveries != 1 || report.HeldConnectors != 1 {
		t.Fatalf("report: %+v", report)
	}
	if len(report.Connectors) != 1 || report.Connectors[0] != "hr" {
		t.Fatalf("the report must name the connectors whose credentials to review: %+v", report.Connectors)
	}
	// The queued delivery is not merely unsent: it is closed out, with a reason an
	// operator reading the outbox can act on.
	var status, lastErr string
	if err := s.db.QueryRow(`SELECT status, COALESCE(last_error,'') FROM account_sync_events WHERE id='ev-old'`).Scan(&status, &lastErr); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || lastErr == "" {
		t.Fatalf("queued delivery after restore: %q %q", status, lastErr)
	}
	// Nothing may be dispatched to a held connector.
	held, err := s.ClaimDueSyncEvents(10, time.Minute)
	if err != nil || len(held) != 0 {
		t.Fatalf("held connector still dispatched %d event(s): %v", len(held), err)
	}
	sys, err := s.GetPairedSystemByID("hr")
	if err != nil || sys == nil || !sys.ProvisioningHold {
		t.Fatalf("hold not visible on the connector: %+v %v", sys, err)
	}

	// Applying it again is harmless: nothing left to clear, the hold stays.
	second, err := s.ApplyRestoredState(time.Now().UTC(), nil)
	if err != nil || second.Credentials != 0 || second.QueuedDeliveries != 0 {
		t.Fatalf("second apply: %+v %v", second, err)
	}
	if sys, _ := s.GetPairedSystemByID("hr"); sys == nil || !sys.ProvisioningHold {
		t.Fatal("second apply released the hold")
	}
}

// The hold is released by reconciling the connector, not by waiting: that is what makes
// a restored outbox safe to resume.
func TestProvisioningHoldIsReleasedByReconciliation(t *testing.T) {
	s, cleanup := restoreFixture(t)
	defer cleanup()
	if _, err := s.ApplyRestoredState(time.Now().UTC(), nil); err != nil {
		t.Fatal(err)
	}
	// A held connector can still be reconciled; that is the way out.
	job, err := s.CreateReconcileJob("hr", "repair", "root", nil)
	if err != nil || job == nil {
		t.Fatal("held connector refused reconciliation:", err)
	}
	claimed, err := s.ClaimReconcileJob(time.Minute)
	if err != nil || claimed == nil {
		t.Fatal("claim:", err)
	}
	// A run that compared nothing keeps the hold, whatever it was called. A connector
	// whose kind cannot be listed reports Supported false; a listing that failed or
	// truncated reports an error and Repaired false. Neither is evidence.
	for _, attempt := range []struct {
		what   string
		report *DriftReport
		err    error
	}{
		{"a failed run", nil, errRestoreTestRun},
		{"an unsupported listing", &DriftReport{}, nil},
		{"a partial listing", &DriftReport{Supported: true, ListingError: "unreachable"}, nil},
		{"a listing that was read but not written through", &DriftReport{Supported: true, Complete: true}, nil},
	} {
		if err := s.FinishReconcileJob(claimed, attempt.report, attempt.err); err != nil {
			t.Fatal(attempt.what, err)
		}
		if sys, _ := s.GetPairedSystemByID("hr"); sys == nil || !sys.ProvisioningHold {
			t.Fatalf("%s released the hold", attempt.what)
		}
		if _, err := s.CreateReconcileJob("hr", "repair", "root", nil); err != nil {
			t.Fatal(attempt.what, err)
		}
		if claimed, err = s.ClaimReconcileJob(time.Minute); err != nil || claimed == nil {
			t.Fatal("claim:", err)
		}
	}
	// A repair that listed the far side completely and wrote through is the evidence.
	if err := s.FinishReconcileJob(claimed, &DriftReport{Supported: true, Complete: true, Repaired: true}, nil); err != nil {
		t.Fatal(err)
	}
	sys, err := s.GetPairedSystemByID("hr")
	if err != nil || sys == nil || sys.ProvisioningHold {
		t.Fatalf("a completed repair must release the hold: %+v %v", sys, err)
	}
	// A preview does not: it reads the far side without repairing it.
	if _, err := s.db.Exec(`UPDATE paired_systems SET provisioning_hold=1 WHERE id='hr'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateReconcileJob("hr", "preview", "root", nil); err != nil {
		t.Fatal(err)
	}
	claimed, err = s.ClaimReconcileJob(time.Minute)
	if err != nil || claimed == nil {
		t.Fatal("claim:", err)
	}
	if err := s.FinishReconcileJob(claimed, &DriftReport{Supported: true, Complete: true}, nil); err != nil {
		t.Fatal(err)
	}
	if sys, _ := s.GetPairedSystemByID("hr"); sys == nil || !sys.ProvisioningHold {
		t.Fatal("a preview released the hold")
	}
}

// Not every connector can be listed: a suite webhook has no directory to read back.
// Reconciliation can never produce evidence for one, so the operator accepts the risk
// themselves, once, and that act is recorded.
func TestProvisioningHoldCanBeResumedDeliberately(t *testing.T) {
	s, cleanup := restoreFixture(t)
	defer cleanup()
	if _, err := s.ApplyRestoredState(time.Now().UTC(), nil); err != nil {
		t.Fatal(err)
	}
	if err := s.ResumeProvisioning("nope", nil); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("unknown connector:", err)
	}
	audit := &AuditEvent{ID: "a-resume", Action: "admin.provisioning_resumed", ActorUsername: "root", TargetID: "hr", TargetType: "system", Outcome: "success", CreatedAt: time.Now().UTC()}
	if err := s.ResumeProvisioning("hr", audit); err != nil {
		t.Fatal(err)
	}
	if sys, _ := s.GetPairedSystemByID("hr"); sys == nil || sys.ProvisioningHold {
		t.Fatal("the hold survived a deliberate resume")
	}
	events, _, err := s.SearchAuditEvents(AuditFilter{Action: "admin.provisioning_resumed", Limit: 5})
	if err != nil || len(events) != 1 {
		t.Fatalf("resume audit: %d %v", len(events), err)
	}
	// Resuming is not reconciling: the queue that was closed out stays closed out.
	var status string
	if err := s.db.QueryRow(`SELECT status FROM account_sync_events WHERE id='ev-old'`).Scan(&status); err != nil || status != "failed" {
		t.Fatalf("resume revived the capsule's queue: %q %v", status, err)
	}
}

// A connector that was disabled when the snapshot was taken still carries queued work
// from before it was disabled. Re-enabling it must not deliver that work without a
// reconciliation, so the restore holds it too even though the operator is not asked to
// act on it yet.
func TestRestoreHoldsAConnectorThatWasDisabled(t *testing.T) {
	s, cleanup := restoreFixture(t)
	defer cleanup()
	provisioningFixture(t, s, "old")
	if _, err := s.db.Exec(`UPDATE paired_systems SET status='disabled' WHERE id='old'`); err != nil {
		t.Fatal(err)
	}
	u := createTestUserNamed(t, s, "left-since")
	if _, err := s.db.Exec(`INSERT INTO account_sync_events(id,user_id,system_id,event_type,payload_json,status) VALUES('ev-disabled',?,'old','user.created','{}','pending')`, u.ID); err != nil {
		t.Fatal(err)
	}
	report, err := s.ApplyRestoredState(time.Now().UTC(), nil)
	if err != nil {
		t.Fatal(err)
	}
	// The report names only what the operator must act on now.
	if len(report.Connectors) != 1 || report.Connectors[0] != "hr" {
		t.Fatalf("a disabled connector should not be in the operator's list: %+v", report.Connectors)
	}
	if _, err := s.db.Exec(`UPDATE paired_systems SET status='active' WHERE id='old'`); err != nil {
		t.Fatal(err)
	}
	due, err := s.ClaimDueSyncEvents(10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 0 {
		t.Fatalf("re-enabling a connector delivered capsule-era work without a reconciliation: %+v", due)
	}
	held, err := s.HeldConnectors()
	if err != nil || len(held) != 2 {
		t.Fatalf("held connectors once it is back: %v %v", held, err)
	}
}
