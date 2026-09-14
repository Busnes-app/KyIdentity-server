package store

import (
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
	// A failed run leaves the hold in place.
	if err := s.FinishReconcileJob(claimed, nil, errRestoreTestRun); err != nil {
		t.Fatal(err)
	}
	if sys, _ := s.GetPairedSystemByID("hr"); sys == nil || !sys.ProvisioningHold {
		t.Fatal("a failed reconciliation released the hold")
	}
	job, err = s.CreateReconcileJob("hr", "repair", "root", nil)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err = s.ClaimReconcileJob(time.Minute)
	if err != nil || claimed == nil {
		t.Fatal("claim:", err)
	}
	if err := s.FinishReconcileJob(claimed, &DriftReport{}, nil); err != nil {
		t.Fatal(err)
	}
	sys, err := s.GetPairedSystemByID("hr")
	if err != nil || sys == nil || sys.ProvisioningHold {
		t.Fatalf("a completed repair must release the hold: %+v %v", sys, err)
	}
	// A preview does not: it proves nothing was repaired.
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
	if err := s.FinishReconcileJob(claimed, &DriftReport{}, nil); err != nil {
		t.Fatal(err)
	}
	if sys, _ := s.GetPairedSystemByID("hr"); sys == nil || !sys.ProvisioningHold {
		t.Fatal("a preview released the hold")
	}
}
