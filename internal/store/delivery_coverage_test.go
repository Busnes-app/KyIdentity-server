package store

import (
	"errors"
	"testing"
	"time"
)

// deliverySystem is an active SCIM connector "target" with one pending update for userID,
// claimed and begun, so it holds a sync_delivery_attempts fence.
func deliverySystem(t *testing.T, s *Store, userID string) AccountSyncEvent {
	t.Helper()
	if err := s.CreatePairedSystem(&PairedSystem{ID: "target", Name: "Target", SystemType: "scim", CallbackURL: "https://example.com/scim", Status: "active"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAccountSyncEvent(&AccountSyncEvent{ID: "ev", SystemID: "target", UserID: userID, EventType: "user.updated", PayloadJSON: `{"active":true}`, Status: "pending"}); err != nil {
		t.Fatal(err)
	}
	events, err := s.ClaimDueSyncEvents(10, time.Minute)
	if err != nil || len(events) != 1 {
		t.Fatal(events, err)
	}
	if ok, err := s.BeginSyncDelivery(events[0], time.Minute); err != nil || !ok {
		t.Fatal(ok, err)
	}
	return events[0]
}

// Guards the uncertain-outcome path: only the current claim marks the event, and the
// connector is flagged failing (never re-enabled if an operator disabled it) so an
// operator must recover it.
func TestMarkSyncDeliveryUncertain(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	ev := deliverySystem(t, s, u.ID)
	stale := ev
	stale.ClaimToken = "stale"
	if err := s.MarkSyncDeliveryUncertain(stale); err != nil {
		t.Fatal(err)
	}
	if ps, _ := s.GetPairedSystemByID("target"); ps.Status != "active" || count(t, s, `SELECT COUNT(*) FROM account_sync_events WHERE last_error<>''`) != 0 {
		t.Fatal("stale claim marked the delivery uncertain")
	}
	if err := s.MarkSyncDeliveryUncertain(ev); err != nil {
		t.Fatal(err)
	}
	if ps, _ := s.GetPairedSystemByID("target"); ps.Status != "failing" {
		t.Fatalf("connector status = %s, want failing", ps.Status)
	}
	if count(t, s, `SELECT COUNT(*) FROM account_sync_events WHERE id='ev' AND last_error LIKE '%operator recovery required%'`) != 1 {
		t.Fatal("event not marked uncertain")
	}
	// The fence stays: the outcome is unknown, so the event must not be resent.
	if got, _ := s.ClaimDueSyncEvents(10, time.Minute); len(got) != 0 {
		t.Fatal("uncertain delivery reclaimed", got)
	}
	mustExec(t, s, `UPDATE paired_systems SET status='disabled' WHERE id='target'`)
	if err := s.MarkSyncDeliveryUncertain(ev); err != nil {
		t.Fatal(err)
	}
	if ps, _ := s.GetPairedSystemByID("target"); ps.Status != "disabled" {
		t.Fatal("uncertain delivery re-enabled a disabled connector")
	}
}

// Guards FinishSyncDelivery: an update out of budget becomes failed (and is listed as
// failing with its error and next attempt), and a second finish of the same attempt is
// refused instead of overwriting a newer outcome.
func TestFinishSyncDeliveryBudgetAndFailingList(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	ev := deliverySystem(t, s, u.ID)
	if got, err := s.ListFailingSyncEvents("target"); err != nil || len(got) != 0 {
		t.Fatal("healthy queue listed as failing", got, err)
	}
	next := time.Now().UTC().Add(time.Hour)
	if err := s.FinishSyncDelivery(ev, "pending", "HTTP 500", SyncAttemptBudget, &next); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishSyncDelivery(ev, "delivered", "", SyncAttemptBudget+1, nil); err == nil {
		t.Fatal("finished attempt finished twice")
	}
	got, err := s.ListFailingSyncEvents("target")
	if err != nil || len(got) != 1 || got[0].Status != "failed" || got[0].LastError != "HTTP 500" || got[0].Attempts != SyncAttemptBudget || got[0].NextAttempt == nil || got[0].UserID != u.ID {
		t.Fatalf("failing list = %+v, %v", got, err)
	}
	if other, _ := s.ListFailingSyncEvents("other"); len(other) != 0 {
		t.Fatal("failing list leaked across connectors")
	}
}

func logoutRow(t *testing.T, s *Store, id, userID, status string) {
	t.Helper()
	now := time.Now().UTC()
	mustExec(t, s, `INSERT INTO logout_deliveries(id,client_id,user_id,sid,status,attempts,claim_token,next_attempt_at,created_at,updated_at) VALUES(?,?,?,?,?,5,'old-claim',?,?,?)`,
		id, "app", userID, "sid-"+id, status, now.Add(time.Hour), now, now)
}

// Guards the operator retry of a back-channel logout: only the owner's undelivered rows
// are retried, with a fresh budget and no stale claim, and the retry commits with its
// audit row or not at all.
func TestRetryLogoutDeliveryNow(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	other := createTestUser(t, s)
	seedLogoutClient(t, s, "app", "https://app.example/bc")
	logoutRow(t, s, "failed", u.ID, "failed")
	logoutRow(t, s, "done", u.ID, "delivered")
	if ok, err := s.RetryLogoutDeliveryNow(other.ID, "failed", nil); err != nil || ok {
		t.Fatal("another user's delivery retried", ok, err)
	}
	if ok, err := s.RetryLogoutDeliveryNow(u.ID, "done", nil); err != nil || ok {
		t.Fatal("delivered logout retried", ok, err)
	}
	if ok, err := s.RetryLogoutDeliveryNow(u.ID, "failed", poisonedAudit(t, s, "user.logout_retry", "failed")); err == nil || ok {
		t.Fatal("retry ignored audit failure", ok, err)
	}
	if countDeliveries(t, s, `id='failed' AND status='failed' AND attempts=5`) != 1 {
		t.Fatal("failed audit left the retry applied")
	}
	audit := &AuditEvent{ID: "retry", Action: "user.logout_retry", Outcome: "success", CreatedAt: time.Now().UTC()}
	if ok, err := s.RetryLogoutDeliveryNow(u.ID, "failed", audit); err != nil || !ok {
		t.Fatal("retry", ok, err)
	}
	if countDeliveries(t, s, `id='failed' AND status='queued' AND attempts=0 AND claim_token='' AND next_attempt_at<=?`, time.Now().UTC()) != 1 || auditActions(t, s, "user.logout_retry") != 1 {
		t.Fatal("retry not due now with fresh budget and audit")
	}
	d, err := s.ClaimLogoutDelivery(time.Minute)
	if err != nil || d == nil || d.ID != "failed" {
		t.Fatalf("retried delivery not claimable: %+v %v", d, err)
	}
	// A finish with a forged claim token is refused.
	forged := *d
	forged.ClaimToken = "forged"
	if err := s.FinishLogoutDelivery(&forged, nil); !errors.Is(err, ErrNotFound) {
		t.Fatal("forged claim finished delivery", err)
	}
}

// Guards the SCIM connector list: every connector is listed, sorted by name ignoring case.
func TestListSCIMConnectorsOrdering(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	if got, err := s.ListSCIMConnectors(); err != nil || len(got) != 0 {
		t.Fatal("empty list", got, err)
	}
	for _, n := range []string{"zeta", "Alpha", "beta"} {
		if _, err := s.CreateSCIMConnector(n, nil); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.ListSCIMConnectors()
	if err != nil || len(got) != 3 || got[0].Name != "Alpha" || got[1].Name != "beta" || got[2].Name != "zeta" {
		t.Fatalf("connectors = %+v, %v", got, err)
	}
}

// Guards the logout-outage alert: a back-channel logout that was given up opens one
// critical alert for its client (sessions there may outlive the sign-out), and it
// resolves once the delivery succeeds.
func TestLogoutOutageAlertOpensAndResolves(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	seedLogoutClient(t, s, "app", "https://app.example/bc")
	logoutRow(t, s, "lost", u.ID, "failed")
	logoutRow(t, s, "lost-too", u.ID, "failed")
	evaluate(t, s)
	evaluate(t, s)
	got := openAlerts(t, s)
	a, ok := got["logout_outage/app"]
	if !ok || len(got) != 1 || a.Severity != "critical" || a.Status != "open" {
		t.Fatalf("logout outage alerts = %+v", got)
	}
	mustExec(t, s, `UPDATE logout_deliveries SET status='delivered'`)
	evaluate(t, s)
	if len(openAlerts(t, s)) != 0 {
		t.Fatal("delivered logouts did not resolve the outage")
	}
}

// Guards the connector backlog summary the admin UI shows: an uncertain in-flight write
// counts as failed (operator work), and the blocked reason names disabled, held or
// unsupported connectors. Unknown connectors are ErrNotFound.
func TestSyncBacklogStates(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	if _, err := s.SyncBacklog("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing connector", err)
	}
	if _, err := s.SystemForClient("no-client"); !errors.Is(err, ErrNotFound) {
		t.Fatal("client without connector", err)
	}
	ev := deliverySystem(t, s, u.ID)
	if b, err := s.SyncBacklog("target"); err != nil || b != (SyncBacklog{Pending: 1}) {
		t.Fatalf("in-flight backlog = %+v, %v", b, err)
	}
	if err := s.MarkSyncDeliveryUncertain(ev); err != nil {
		t.Fatal(err)
	}
	if b, _ := s.SyncBacklog("target"); b.Failed != 1 {
		t.Fatalf("uncertain write not counted as failed: %+v", b)
	}
	for blocked, q := range map[string]string{
		"held":        `UPDATE paired_systems SET status='active', provisioning_hold=1 WHERE id='target'`,
		"unsupported": `UPDATE paired_systems SET provisioning_hold=0, system_type='ldap' WHERE id='target'`,
		"disabled":    `UPDATE paired_systems SET status='disabled' WHERE id='target'`,
	} {
		mustExec(t, s, q)
		if b, _ := s.SyncBacklog("target"); b.Blocked != blocked {
			t.Fatalf("blocked = %q, want %q", b.Blocked, blocked)
		}
	}
}

// Guards operator resume: an attempt still inside its delivery window cannot be resumed
// (one by one or in bulk), so a write that may still land is never duplicated.
func TestResumeSyncDeliveryRefusesLiveAttempt(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	ev := deliverySystem(t, s, u.ID)
	audit := &AuditEvent{ID: "resume", Action: "admin.sync_delivery_resumed", Outcome: "success"}
	if err := s.ResumeSyncDelivery("target", ev.ClaimToken, false, audit); err == nil {
		t.Fatal("live attempt resumed")
	}
	if n, err := s.ResumeSyncDeliveries("target", audit); err == nil || n != 0 {
		t.Fatal("bulk resume released a live attempt", n, err)
	}
	if attempts, _ := s.ListSyncDeliveryAttempts("target"); len(attempts) != 1 || attempts[0].Token != ev.ClaimToken || attempts[0].UserID != u.ID {
		t.Fatalf("live fence lost: %+v", attempts)
	}
	if auditActions(t, s, "admin.sync_delivery_resumed") != 0 {
		t.Fatal("refused resume audited")
	}
}

// A process that stopped between BeginSyncDelivery and the outcome leaves a fence with
// nothing recorded. Past its recovery time, it and the work held behind it count as
// failed, so resync-system reports operator work instead of timing out on "pending".
// A removal's own expired fence is released by the next claim, so it never counts.
func TestSyncBacklogFailsWorkBehindAbandonedAttempt(t *testing.T) {
	s, u := newStoreWithUser(t, "user")
	ev := deliverySystem(t, s, u.ID)
	if err := s.CreateAccountSyncEvent(&AccountSyncEvent{ID: "held", SystemID: "target", UserID: u.ID, EventType: "user.updated", PayloadJSON: `{"active":true}`, Status: "pending"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAccountSyncEvent(&AccountSyncEvent{ID: "removal", SystemID: "target", UserID: "other", EventType: "user.deleted", PayloadJSON: `{}`, Status: "pending"}); err != nil {
		t.Fatal(err)
	}
	removals, err := s.ClaimDueSyncEvents(10, time.Minute)
	if err != nil || len(removals) != 1 || removals[0].ID != "removal" {
		t.Fatal(removals, err)
	}
	if ok, err := s.BeginSyncDelivery(removals[0], time.Minute); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if b, _ := s.SyncBacklog("target"); b != (SyncBacklog{Pending: 3}) {
		t.Fatalf("attempts inside their window = %+v, want plain pending", b)
	}
	mustExec(t, s, `UPDATE sync_delivery_attempts SET recover_after=?`, time.Now().UTC().Add(-time.Second))
	if b, _ := s.SyncBacklog("target"); b != (SyncBacklog{Pending: 3, Failed: 2}) {
		t.Fatalf("abandoned attempt backlog = %+v, want the write and the event behind it failed", b)
	}
	// The operator recovery path clears it.
	audit := &AuditEvent{ID: "resume", Action: "admin.sync_delivery_resumed", Outcome: "success"}
	if err := s.ResumeSyncDelivery("target", ev.ClaimToken, false, audit); err != nil {
		t.Fatal(err)
	}
	if b, _ := s.SyncBacklog("target"); b.Failed != 0 {
		t.Fatalf("resumed backlog = %+v", b)
	}
}
