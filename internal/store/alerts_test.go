package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func audited(t *testing.T, s *Store, action, actorName, targetID, targetType, outcome string, details string) {
	t.Helper()
	auditedFrom(t, s, "198.51.100.7", action, actorName, targetID, targetType, outcome, details)
}

func auditedFrom(t *testing.T, s *Store, ip, action, actorName, targetID, targetType, outcome string, details string) {
	t.Helper()
	auditedAt(t, s, time.Now().UTC(), ip, action, actorName, targetID, targetType, outcome, details)
}

func auditedAt(t *testing.T, s *Store, at time.Time, ip, action, actorName, targetID, targetType, outcome string, details string) {
	t.Helper()
	if err := s.RecordAuditEvent(&AuditEvent{ID: uuid.NewString(), ActorUsername: actorName, Action: action, TargetID: targetID, TargetType: targetType, IPAddress: ip, Outcome: outcome, DetailsJSON: details, CreatedAt: at}); err != nil {
		t.Fatal(err)
	}
}

func alertAdmin(t *testing.T, s *Store, name string) *User {
	t.Helper()
	u := createTestUserNamed(t, s, name)
	u.Role = "admin"
	if err := s.UpdateUser(u); err != nil {
		t.Fatal(err)
	}
	return u
}

func countRows(t *testing.T, s *Store, query string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(query).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func evaluate(t *testing.T, s *Store) {
	t.Helper()
	if err := s.EvaluateAlerts(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
}

func openAlerts(t *testing.T, s *Store) map[string]Alert {
	t.Helper()
	all, _, err := s.ListAlerts("all", 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]Alert{}
	for _, a := range all {
		if a.Status != "resolved" {
			out[a.Rule+"/"+a.Key] = a
		}
	}
	return out
}

func TestAlertRulesFromAuditEvents(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUserNamed(t, s, "target")
	audited(t, s, "admin.user_updated", "root", u.ID, "user", "success", `{"username":"target","role":"admin","roleChanged":true}`)
	audited(t, s, "admin.user_updated", "root", u.ID, "user", "success", `{"username":"target","role":"admin","roleChanged":false}`)
	audited(t, s, "auth.mfa_recovery_consumed", "target", u.ID, "user", "success", "")
	audited(t, s, "auth.mfa_recovery_consumed", "target", u.ID, "user", "success", "")
	audited(t, s, "auth.mfa_recovery", "target", u.ID, "user", "failure", `{"attempts":1}`)
	audited(t, s, "admin.scim_token_issued", "root", "conn-1", "scim_connector", "success", `{"scope":"users"}`)
	audited(t, s, "account.end_failed", "expiry", u.ID, "user", "failure", `{"error":"disk full SECRET-DETAIL"}`)
	audited(t, s, "oauth.token_exchange", "target", "", "client", "failure", `{"reason":"invalid_grant"}`)
	evaluate(t, s)
	got := openAlerts(t, s)
	want := map[string]int{"privilege_change/" + u.ID: 1, "recovery_use/" + u.ID: 2, "connector_credentials/conn-1": 1, "access_removal_failed/" + u.ID: 1}
	if len(got) != len(want) {
		t.Fatalf("alerts %+v", got)
	}
	for k, n := range want {
		a, ok := got[k]
		if !ok || a.Count != n || a.Status != "open" {
			t.Fatalf("%s: %+v", k, a)
		}
		if strings.Contains(a.Title+a.Summary, "SECRET-DETAIL") {
			t.Fatal("details leaked into the alert text", a)
		}
	}
	if got["recovery_use/"+u.ID].Summary == "" || !strings.Contains(got["recovery_use/"+u.ID].Summary, "target") {
		t.Fatal("summary should name the account", got["recovery_use/"+u.ID])
	}
	var queued int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM alert_queue`).Scan(&queued); err != nil || queued != 0 {
		t.Fatal("queue not drained", queued, err)
	}
	evaluate(t, s)
	if again := openAlerts(t, s); len(again) != len(got) || again["recovery_use/"+u.ID].Count != 2 {
		t.Fatal("second pass changed alerts", again)
	}
}

func TestAlertQueueSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.db")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	u := createTestUser(t, s)
	audited(t, s, "admin.user_mfa_reset", "root", u.ID, "user", "success", `{"username":"x"}`)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if s, err = New(path); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	evaluate(t, s)
	if a, ok := openAlerts(t, s)["recovery_use/"+u.ID]; !ok || a.Count != 1 {
		t.Fatal("event recorded before the restart was not alerted", a)
	}
}

func TestLoginFailureThreshold(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	if err := s.SetAlertSettings(AlertSettings{LoginFailureThreshold: 3, LoginFailureWindowSeconds: 600}, nil); err != nil {
		t.Fatal(err)
	}
	alice, bob := createTestUserNamed(t, s, "alice"), createTestUserNamed(t, s, "bob")
	fail := func(u *User) {
		audited(t, s, "auth.login", u.Username, u.ID, "user", "failure", `{"reason":"invalid_password"}`)
	}
	fail(alice)
	fail(alice)
	fail(bob)
	evaluate(t, s)
	if got := openAlerts(t, s); len(got) != 0 {
		t.Fatal("below threshold", got)
	}
	fail(alice)
	evaluate(t, s)
	got := openAlerts(t, s)
	if a, ok := got["login_failures/"+alice.ID]; !ok || a.Count != 3 || len(got) != 1 || !strings.Contains(a.Title, "alice") {
		t.Fatalf("threshold alert %+v", got)
	}
	fail(alice)
	evaluate(t, s)
	if a := openAlerts(t, s)["login_failures/"+alice.ID]; a.Count != 4 {
		t.Fatal("later failures should fold into the open alert", a)
	}
	// Names that match no account are the attacker's choice, so they never become a key:
	// those failures are keyed by source address. A burst evaluated in one pass opens
	// once at the threshold and counts each failure once, and the chosen name is not
	// display or header material.
	unknown := func(ip, name string) {
		auditedFrom(t, s, ip, "auth.login", name, "", "user", "failure", `{"reason":"user_not_found"}`)
	}
	unknown("203.0.113.5", "evil\r\nBcc: x")
	unknown("203.0.113.5", "evil\r\nBcc: x")
	unknown("203.0.113.5", "other-name")
	evaluate(t, s)
	got = openAlerts(t, s)
	if a := got["login_failures/203.0.113.5"]; a.Count != 3 || len(got) != 2 {
		t.Fatalf("source-keyed alert %+v", got)
	}
	for k, a := range got {
		if strings.ContainsAny(a.Title+a.Summary+a.Key, "\r\n") || strings.Contains(a.Title+a.Summary, "evil") {
			t.Fatal("attacker-chosen name in alert text", k, a)
		}
	}
}

// An unauthenticated attacker cycling usernames or addresses cannot mint alerts and
// mail without bound: unknown names share their address's alert, and past a ceiling of
// live login alerts further sources fold into one.
func TestLoginFailureFloodIsBounded(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	admin := alertAdmin(t, s, "root")
	if err := s.SetAlertSettings(AlertSettings{LoginFailureThreshold: 3, LoginFailureWindowSeconds: 600, Recipients: []string{admin.ID}}, nil); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		for j := 0; j < 3; j++ {
			auditedFrom(t, s, "203.0.113.9", "auth.login", fmt.Sprintf("guess-%d", i), "", "user", "failure", `{"reason":"user_not_found"}`)
		}
	}
	evaluate(t, s)
	if n := countRows(t, s, `SELECT COUNT(*) FROM alerts WHERE rule='login_failures'`); n != 1 {
		t.Fatal("one address, one alert; got", n)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM alert_deliveries`); n != 1 {
		t.Fatal("one address, one mail; got", n)
	}
	for i := 0; i < 3*loginAlertCeiling; i++ {
		for j := 0; j < 3; j++ {
			auditedFrom(t, s, fmt.Sprintf("198.51.100.%d", i), "auth.login", "root", "", "user", "failure", `{"reason":"user_not_found"}`)
		}
	}
	evaluate(t, s)
	alerts := countRows(t, s, `SELECT COUNT(*) FROM alerts WHERE rule='login_failures'`)
	if alerts > loginAlertCeiling+2 {
		t.Fatal("alerts grew with the number of sources:", alerts)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM alert_deliveries`); n != 1 {
		t.Fatal("login mail is one mailing per cooldown, whatever the sources:", n)
	}
	many := openAlerts(t, s)["login_failures/many-sources"]
	if many.ID == "" || many.Count < 2*loginAlertCeiling {
		t.Fatalf("further sources should fold into one alert: %+v", many)
	}
}

// The ceiling bounds live login alerts absolutely, not per window, and a login alert
// whose source has gone quiet for a window resolves, so retention can reclaim it and
// a later burst opens a fresh alert.
func TestLoginFailureAlertsResolveAndStayBounded(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	window := 600 * time.Second
	if err := s.SetAlertSettings(AlertSettings{LoginFailureThreshold: 3, LoginFailureWindowSeconds: 600}, nil); err != nil {
		t.Fatal(err)
	}
	burst := func(at time.Time, prefix string) {
		for i := 0; i < 3*loginAlertCeiling; i++ {
			for j := 0; j < 3; j++ {
				auditedAt(t, s, at, fmt.Sprintf("%s.%d", prefix, i), "auth.login", "x", "", "user", "failure", `{"reason":"user_not_found"}`)
			}
		}
	}
	live := func() int {
		return countRows(t, s, `SELECT COUNT(*) FROM alerts WHERE rule='login_failures' AND status<>'resolved'`)
	}
	t0 := time.Now().UTC().Add(-3 * window)
	burst(t0, "203.0.113")
	if err := s.EvaluateAlerts(t0); err != nil {
		t.Fatal(err)
	}
	if n := live(); n != loginAlertCeiling+1 {
		t.Fatal("first burst live alerts:", n)
	}
	// Half a window later the sources are still inside their window: nothing resolves,
	// and new sources cannot push past the ceiling just because time moved on.
	burst(t0.Add(window/2), "198.51.100")
	if err := s.EvaluateAlerts(t0.Add(window / 2)); err != nil {
		t.Fatal(err)
	}
	if n := live(); n != loginAlertCeiling+1 {
		t.Fatal("ceiling is per window, not absolute:", n)
	}
	// Two windows later the old sources are quiet: their alerts resolve, a new burst
	// opens fresh ones, and the live bound still holds.
	t2 := t0.Add(2 * window)
	burst(t2, "192.0.2")
	if err := s.EvaluateAlerts(t2); err != nil {
		t.Fatal(err)
	}
	if n := live(); n != loginAlertCeiling+1 {
		t.Fatal("live alerts after resolution and a new burst:", n)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM alerts WHERE rule='login_failures' AND status='resolved' AND resolved_at IS NOT NULL`); n != loginAlertCeiling {
		t.Fatal("quiet sources should have resolved:", n)
	}
	if err := s.EvaluateAlerts(t2.Add(2 * window)); err != nil {
		t.Fatal(err)
	}
	if n := live(); n != 0 {
		t.Fatal("all quiet, still live:", n)
	}
	if err := s.DeleteAlertsOlderThan(t2.Add(3 * window)); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM alerts`); n != 0 {
		t.Fatal("retention could not reclaim login alerts:", n)
	}
}

// Resolving quiet login alerts must not turn quiet-then-burst cycles, or rotating
// addresses, into a mail source: login mail is one mailing per cooldown.
func TestLoginFailureReopenIsNotRemailed(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	window := 600 * time.Second
	admin := alertAdmin(t, s, "root")
	if err := s.SetAlertSettings(AlertSettings{LoginFailureThreshold: 3, LoginFailureWindowSeconds: 600, Recipients: []string{admin.ID}}, nil); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Add(-40 * window)
	for cycle := 0; cycle < 10; cycle++ {
		for i := 0; i < 3*loginAlertCeiling; i++ {
			for j := 0; j < 3; j++ {
				auditedAt(t, s, at, fmt.Sprintf("203.0.113.%d", i), "auth.login", "x", "", "user", "failure", `{"reason":"user_not_found"}`)
			}
		}
		if err := s.EvaluateAlerts(at); err != nil {
			t.Fatal(err)
		}
		at = at.Add(2 * window)
		if err := s.EvaluateAlerts(at); err != nil {
			t.Fatal(err)
		}
		if n := countRows(t, s, `SELECT COUNT(*) FROM alerts WHERE rule='login_failures' AND status<>'resolved'`); n != 0 {
			t.Fatal("cycle", cycle, "left live alerts:", n)
		}
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM alert_deliveries`); n != 1 {
		t.Fatal("mail grew with the cycles:", n)
	}
	// After a genuinely quiet cooldown a new burst is news again.
	at = at.Add(loginAlertCooldown)
	for j := 0; j < 3; j++ {
		auditedAt(t, s, at, "203.0.113.1", "auth.login", "x", "", "user", "failure", `{"reason":"user_not_found"}`)
	}
	if err := s.EvaluateAlerts(at); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM alert_deliveries`); n != 2 {
		t.Fatal("a burst after the cooldown should be mailed:", n)
	}
}

func TestDeliverAlertsStopsAtDeadline(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	var ids []string
	for i := 0; i < 5; i++ {
		ids = append(ids, alertAdmin(t, s, fmt.Sprintf("root%d", i)).ID)
	}
	if err := s.SetAlertSettings(AlertSettings{LoginFailureThreshold: 10, LoginFailureWindowSeconds: 600, Recipients: ids}, nil); err != nil {
		t.Fatal(err)
	}
	audited(t, s, "admin.scim_token_issued", "root0", "c1", "scim_connector", "success", "")
	evaluate(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	slow := func(string, string, string) error { time.Sleep(50 * time.Millisecond); return nil }
	n, err := s.DeliverAlerts(ctx, time.Now().UTC(), slow)
	if err != nil || n == 0 || n >= 5 {
		t.Fatal("a pass must stop at its deadline and leave the rest pending:", n, err)
	}
	if a := openAlerts(t, s)["connector_credentials/c1"]; a.Delivery.Delivered != n || a.Delivery.Pending != 5-n {
		t.Fatalf("%+v", a.Delivery)
	}
}

func TestAlertRetention(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	admin := alertAdmin(t, s, "root")
	if err := s.SetAlertSettings(AlertSettings{LoginFailureThreshold: 10, LoginFailureWindowSeconds: 600, Recipients: []string{admin.ID}}, nil); err != nil {
		t.Fatal(err)
	}
	provisioningFixture(t, s, "hr")
	if _, err := s.db.Exec(`UPDATE paired_systems SET status='failing' WHERE id='hr'`); err != nil {
		t.Fatal(err)
	}
	u := createTestUser(t, s)
	audited(t, s, "admin.user_mfa_reset", "root", u.ID, "user", "success", "")
	evaluate(t, s)
	if _, err := s.db.Exec(`UPDATE paired_systems SET status='active' WHERE id='hr'`); err != nil {
		t.Fatal(err)
	}
	evaluate(t, s)
	if _, err := s.DeliverAlerts(context.Background(), time.Now().UTC(), func(string, string, string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-48 * time.Hour)
	if _, err := s.db.Exec(`UPDATE alerts SET resolved_at=? WHERE status='resolved'`, old); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE alert_deliveries SET updated_at=?`, old); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAlertsOlderThan(time.Now().UTC().Add(-24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM alerts WHERE status='resolved'`); n != 0 {
		t.Fatal("old resolved alert kept")
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM alerts`); n != 1 {
		t.Fatal("live alert lost", n)
	}
	// The live alert keeps its row; its old, finished deliveries are trimmed.
	if n := countRows(t, s, `SELECT COUNT(*) FROM alert_deliveries`); n != 0 {
		t.Fatal("finished deliveries kept", n)
	}
}

func TestAlertAcknowledgeAndReopen(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	admin := createTestUserNamed(t, s, "root")
	audited(t, s, "admin.delegations_updated", "root", u.ID, "user", "success", "")
	evaluate(t, s)
	a := openAlerts(t, s)["privilege_change/"+u.ID]
	if err := s.AcknowledgeAlert(a.ID, admin.ID, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.AcknowledgeAlert(a.ID, admin.ID, nil); !errors.Is(err, ErrAlertNotOpen) {
		t.Fatal("second acknowledgement", err)
	}
	if err := s.AcknowledgeAlert("nope", admin.ID, nil); !errors.Is(err, ErrAlertMissing) {
		t.Fatal("missing alert", err)
	}
	if got := openAlerts(t, s)["privilege_change/"+u.ID]; got.Status != "acknowledged" || got.AcknowledgedBy != "root" || got.AcknowledgedAt == nil {
		t.Fatal("acknowledged", got)
	}
	audited(t, s, "admin.delegations_updated", "root", u.ID, "user", "success", "")
	evaluate(t, s)
	got := openAlerts(t, s)["privilege_change/"+u.ID]
	if got.ID != a.ID || got.Status != "open" || got.Count != 2 {
		t.Fatal("a new occurrence must reopen the acknowledged alert", got)
	}
}

func TestProvisioningOutageOpensOnceAndResolves(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	provisioningFixture(t, s, "hr")
	set := func(status string) {
		if _, err := s.db.Exec(`UPDATE paired_systems SET status=? WHERE id='hr'`, status); err != nil {
			t.Fatal(err)
		}
	}
	set("failing")
	evaluate(t, s)
	evaluate(t, s)
	got := openAlerts(t, s)
	if a, ok := got["provisioning_outage/hr"]; !ok || a.Status != "open" || len(got) != 1 {
		t.Fatalf("outage %+v", got)
	}
	set("active")
	evaluate(t, s)
	if len(openAlerts(t, s)) != 0 {
		t.Fatal("recovered connector should resolve the alert")
	}
	all, _, err := s.ListAlerts("resolved", 10, 0)
	if err != nil || len(all) != 1 || all[0].ResolvedAt == nil {
		t.Fatal("resolved history", all, err)
	}
	set("failing")
	evaluate(t, s)
	if all, total, _ := s.ListAlerts("all", 10, 0); total != 2 || all[0].Status != "open" {
		t.Fatal("a new outage after resolution is a new alert", all)
	}
	set("disabled")
	evaluate(t, s)
	if len(openAlerts(t, s)) != 0 {
		t.Fatal("a disabled connector is not an outage")
	}
}

func TestAlertSettingsRecipientsMustBeAllowedToRead(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	admin := createTestUserNamed(t, s, "root")
	admin.Role = "admin"
	if err := s.UpdateUser(admin); err != nil {
		t.Fatal(err)
	}
	auditor := createTestUserNamed(t, s, "auditor")
	if err := s.SetDelegations(auditor.ID, Delegations{Auditor: true}, nil); err != nil {
		t.Fatal(err)
	}
	plain := createTestUserNamed(t, s, "plain")
	if err := s.SetAlertSettings(AlertSettings{LoginFailureThreshold: 10, LoginFailureWindowSeconds: 600, Recipients: []string{admin.ID, plain.ID}}, nil); !errors.Is(err, ErrAlertRecipient) {
		t.Fatal("plain user accepted as recipient", err)
	}
	if err := s.SetAlertSettings(AlertSettings{LoginFailureThreshold: 0, LoginFailureWindowSeconds: 600}, nil); !errors.Is(err, ErrAlertSettings) {
		t.Fatal("zero threshold accepted", err)
	}
	if err := s.SetAlertSettings(AlertSettings{LoginFailureThreshold: 10, LoginFailureWindowSeconds: 600, Recipients: []string{admin.ID, auditor.ID}}, nil); err != nil {
		t.Fatal(err)
	}
	got, err := s.AlertSettings()
	if err != nil || len(got.Recipients) != 2 || got.LoginFailureThreshold != 10 {
		t.Fatal(got, err)
	}
}

func TestAlertDeliveriesRetryAndRecheckRecipients(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	admin := createTestUserNamed(t, s, "root")
	admin.Role = "admin"
	if err := s.UpdateUser(admin); err != nil {
		t.Fatal(err)
	}
	later := createTestUserNamed(t, s, "later")
	later.Role = "admin"
	if err := s.UpdateUser(later); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAlertSettings(AlertSettings{LoginFailureThreshold: 10, LoginFailureWindowSeconds: 600, Recipients: []string{admin.ID, later.ID}}, nil); err != nil {
		t.Fatal(err)
	}
	u := createTestUserNamed(t, s, "victim")
	audited(t, s, "auth.mfa_recovery_consumed", "victim", u.ID, "user", "success", `{"code":"RECOVERY-CODE-VALUE"}`)
	evaluate(t, s)
	a := openAlerts(t, s)["recovery_use/"+u.ID]
	if a.Delivery.Pending != 2 {
		t.Fatalf("two deliveries queued: %+v", a.Delivery)
	}
	// Recipients are re-checked when the mail is sent, not only when configured.
	later.Role = "user"
	if err := s.UpdateUser(later); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	var sent []string
	send := func(to, subject, body string) error {
		sent = append(sent, to+"|"+subject+"|"+body)
		return errors.New("smtp: 451 try later")
	}
	if n, err := s.DeliverAlerts(context.Background(), now, send); err != nil || n != 1 {
		t.Fatal("first pass", n, err, sent)
	}
	a = openAlerts(t, s)["recovery_use/"+u.ID]
	if a.Delivery.Pending != 1 || a.Delivery.Skipped != 1 || !strings.Contains(a.Delivery.LastError, "451") {
		t.Fatalf("after a failed send: %+v", a.Delivery)
	}
	if n, _ := s.DeliverAlerts(context.Background(), now.Add(10*time.Second), send); n != 0 {
		t.Fatal("retried before the backoff elapsed")
	}
	send = func(to, subject, body string) error {
		sent = append(sent, to+"|"+subject+"|"+body)
		return nil
	}
	if n, err := s.DeliverAlerts(context.Background(), now.Add(time.Hour), send); err != nil || n != 1 {
		t.Fatal("retry", n, err)
	}
	a = openAlerts(t, s)["recovery_use/"+u.ID]
	if a.Delivery.Delivered != 1 || a.Delivery.Pending != 0 {
		t.Fatalf("after retry: %+v", a.Delivery)
	}
	last := sent[len(sent)-1]
	if !strings.HasPrefix(last, admin.Email+"|") || !strings.Contains(last, "victim") || strings.Contains(last, "RECOVERY-CODE-VALUE") {
		t.Fatal("mail content", last)
	}
	if err := s.AcknowledgeAlert(a.ID, admin.ID, nil); err != nil {
		t.Fatal(err)
	}
	if a := openAlerts(t, s)["recovery_use/"+u.ID]; a.Delivery.Pending != 0 {
		t.Fatal("acknowledgement is not mailed")
	}
}

func TestAlertDeliveryGivesUpVisibly(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	admin := createTestUserNamed(t, s, "root")
	admin.Role = "admin"
	if err := s.UpdateUser(admin); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAlertSettings(AlertSettings{LoginFailureThreshold: 10, LoginFailureWindowSeconds: 600, Recipients: []string{admin.ID}}, nil); err != nil {
		t.Fatal(err)
	}
	audited(t, s, "admin.scim_token_issued", "root", "c1", "scim_connector", "success", "")
	evaluate(t, s)
	now := time.Now().UTC()
	broken := func(string, string, string) error { return errors.New("mail delivery is not configured") }
	for i := 0; i < alertDeliveryAttempts; i++ {
		if n, err := s.DeliverAlerts(context.Background(), now, broken); err != nil || n != 1 {
			t.Fatal(i, n, err)
		}
		now = now.Add(24 * time.Hour)
	}
	if n, _ := s.DeliverAlerts(context.Background(), now, broken); n != 0 {
		t.Fatal("kept retrying after giving up")
	}
	a := openAlerts(t, s)["connector_credentials/c1"]
	if a.Delivery.Failed != 1 || a.Delivery.Pending != 0 || !strings.Contains(a.Delivery.LastError, "not configured") {
		t.Fatalf("%+v", a.Delivery)
	}
}

func TestOutageResolutionIsMailed(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	admin := createTestUserNamed(t, s, "root")
	admin.Role = "admin"
	if err := s.UpdateUser(admin); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAlertSettings(AlertSettings{LoginFailureThreshold: 10, LoginFailureWindowSeconds: 600, Recipients: []string{admin.ID}}, nil); err != nil {
		t.Fatal(err)
	}
	provisioningFixture(t, s, "hr")
	if _, err := s.db.Exec(`UPDATE paired_systems SET status='failing' WHERE id='hr'`); err != nil {
		t.Fatal(err)
	}
	evaluate(t, s)
	evaluate(t, s)
	var subjects []string
	send := func(_, subject, _ string) error { subjects = append(subjects, subject); return nil }
	if _, err := s.DeliverAlerts(context.Background(), time.Now().UTC(), send); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE paired_systems SET status='active' WHERE id='hr'`); err != nil {
		t.Fatal(err)
	}
	evaluate(t, s)
	if _, err := s.DeliverAlerts(context.Background(), time.Now().UTC(), send); err != nil {
		t.Fatal(err)
	}
	if len(subjects) != 2 || !strings.Contains(subjects[1], "resolved") || strings.Contains(subjects[0], "resolved") {
		t.Fatal("one opening mail and one resolution mail", subjects)
	}
}
