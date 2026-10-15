package api

import (
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
)

func TestSyncDeliveryRecoveryRequiresStepUpAndConfirmation(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	sys := &store.PairedSystem{ID: "recovery-target", Name: "Recovery target", SystemType: "suite_webhook", CallbackURL: "https://example.com/hook", Status: "active"}
	if err := db.CreatePairedSystem(sys, nil); err != nil {
		t.Fatal(err)
	}
	insertSyncEvent(t, srv.cfg.DBPath, store.AccountSyncEvent{ID: "attempt", UserID: admin.ID, SystemID: sys.ID, EventType: "user.updated", Status: "pending", PayloadJSON: `{}`})
	events, err := db.ClaimDueSyncEvents(50, time.Minute)
	if err != nil || len(events) != 1 {
		t.Fatal(events, err)
	}
	if ok, err := db.BeginSyncDelivery(events[0], -time.Second); err != nil || !ok {
		t.Fatal(ok, err)
	}
	base := "/api/admin/systems/" + sys.ID + "/deliveries"
	rr := adminRequest(t, srv, "GET", base, cookie, "")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), events[0].ClaimToken) {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = adminRequest(t, srv, "POST", base+"/"+events[0].ClaimToken+"/read-back", cookie, "")
	if rr.Code != 200 {
		t.Fatal(rr.Code, rr.Body.String())
	}
	// A local credential failure exercises the failed probe without sending a token
	// to an external service. Its error/credential text must never enter audit details.
	if err := db.ConfigureSystem(sys.ID, "suite_webhook", "scim", "sensitive-credential-fixture", false, 0, nil); err != nil {
		t.Fatal(err)
	}
	rr = adminRequest(t, srv, "POST", base+"/"+events[0].ClaimToken+"/read-back", cookie, "")
	if rr.Code != 502 {
		t.Fatal(rr.Code, rr.Body.String())
	}
	if err := db.ConfigureSystem(sys.ID, "scim", "suite_webhook", "", false, 0, nil); err != nil {
		t.Fatal(err)
	}
	path := base + "/" + events[0].ClaimToken + "/resume"
	if rr := adminRequestNoStepUp(t, srv, "POST", path, cookie, `{"confirmedQuiescent":true}`); rr.Code != 403 {
		t.Fatal("no step-up", rr.Code)
	}
	for _, body := range []string{`{}`, `{"confirmedQuiescent":false}`, `{"confirmedQuiescent":"true"}`} {
		if rr := adminRequest(t, srv, "POST", path, cookie, body); rr.Code != 400 {
			t.Fatal(body, rr.Code)
		}
	}
	if rr := adminRequest(t, srv, "POST", path, cookie, `{"confirmedQuiescent":true,"allowCreateRetry":true}`); rr.Code != 409 {
		t.Fatal("suite create reset accepted", rr.Code)
	}
	rr = adminRequest(t, srv, "POST", path, cookie, `{"confirmedQuiescent":true}`)
	if rr.Code != 200 {
		t.Fatal(rr.Code, rr.Body.String())
	}
	if rr := adminRequest(t, srv, "POST", path, cookie, `{"confirmedQuiescent":true}`); rr.Code != 409 {
		t.Fatal("stale attempt replay", rr.Code)
	}
	audit, _, err := db.ListAuditEvents(100, 0)
	if err != nil {
		t.Fatal(err)
	}
	successes, probes, failedProbes := 0, 0, 0
	failures := map[string]int{}
	for _, a := range audit {
		if a.Action != "admin.sync_delivery_resumed" && a.Action != "admin.sync_delivery_read_back" {
			continue
		}
		var details map[string]any
		if err := json.Unmarshal([]byte(a.DetailsJSON), &details); err != nil {
			t.Fatal(err)
		}
		if details["systemName"] != sys.Name || details["attemptToken"] != events[0].ClaimToken || a.ActorID != admin.ID || a.TargetID != sys.ID {
			t.Fatalf("incomplete audit: %+v", a)
		}
		if strings.Contains(a.DetailsJSON, "sensitive-credential-fixture") {
			t.Fatal("credential/error text entered audit")
		}
		if a.Action == "admin.sync_delivery_read_back" {
			if len(details) != 3 || details["userId"] != admin.ID {
				t.Fatal("probe details contain nonlocal information", details)
			}
			if a.Outcome == "success" {
				probes++
			} else if a.Outcome == "failure" {
				failedProbes++
			}
		}
		if a.Action == "admin.sync_delivery_resumed" {
			if a.Outcome == "success" {
				successes++
			} else {
				reason, ok := details["reason"].(string)
				if !ok {
					t.Fatal("missing rejection reason", a)
				}
				failures[reason]++
			}
		}
	}
	if failedProbes != 1 {
		t.Errorf("failed read-back audit count=%d", failedProbes)
	}
	if probes != 1 {
		t.Errorf("read-back audit count=%d", probes)
	}
	if successes != 1 {
		t.Errorf("recovery success audit count=%d", successes)
	}
	want := map[string]int{"confirm_remote_quiescence": 3, "create_retry_requires_absent_remote_user": 1, "attempt_changed_or_still_running": 1}
	for reason, count := range want {
		if failures[reason] != count {
			t.Errorf("%s: got %d failures, want %d", reason, failures[reason], count)
		}
	}
	if len(failures) != len(want) {
		t.Errorf("unexpected/unbounded rejection reasons: %v", failures)
	}
}

func TestBulkSyncDeliveryResumeKeepsEveryGate(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	for _, id := range []string{"bulk-target", "bulk-other"} {
		if err := db.CreatePairedSystem(&store.PairedSystem{ID: id, Name: id, SystemType: "suite_webhook", CallbackURL: "https://example.com/hook", Status: "active"}, nil); err != nil {
			t.Fatal(err)
		}
	}
	window := map[string]time.Duration{"a": -time.Second, "b": -time.Second, "running": time.Minute, "other": -time.Second}
	for id := range window {
		system := "bulk-target"
		if id == "other" {
			system = "bulk-other"
		}
		insertSyncEvent(t, srv.cfg.DBPath, store.AccountSyncEvent{ID: id, UserID: id, SystemID: system, EventType: "user.updated", Status: "pending", PayloadJSON: `{}`})
	}
	events, err := db.ClaimDueSyncEvents(50, time.Minute)
	if err != nil || len(events) != 4 {
		t.Fatal(events, err)
	}
	for _, ev := range events {
		if ok, err := db.BeginSyncDelivery(ev, window[ev.ID]); err != nil || !ok {
			t.Fatal(ok, err)
		}
	}
	path := "/api/admin/systems/bulk-target/deliveries/resume"
	if rr := adminRequestNoStepUp(t, srv, "POST", path, cookie, `{"confirmedQuiescent":true}`); rr.Code != 403 {
		t.Fatal("no step-up", rr.Code)
	}
	for _, body := range []string{`{}`, `{"confirmedQuiescent":"true"}`} {
		if rr := adminRequest(t, srv, "POST", path, cookie, body); rr.Code != 400 {
			t.Fatal(body, rr.Code)
		}
	}
	if rr := adminRequest(t, srv, "POST", path, cookie, `{"confirmedQuiescent":true,"allowCreateRetry":true}`); rr.Code != 400 {
		t.Fatal("bulk create reset accepted", rr.Code)
	}
	rr := adminRequest(t, srv, "POST", path, cookie, `{"confirmedQuiescent":true}`)
	if rr.Code != 200 || strings.TrimSpace(rr.Body.String()) != `{"resumed":2}` {
		t.Fatal(rr.Code, rr.Body.String())
	}
	if rr := adminRequest(t, srv, "POST", path, cookie, `{"confirmedQuiescent":true}`); rr.Code != 409 {
		t.Fatal("empty resume", rr.Code)
	}
	for system, want := range map[string]string{"bulk-target": "running", "bulk-other": "other"} {
		left, err := db.ListSyncDeliveryAttempts(system)
		if err != nil || len(left) != 1 || left[0].EventID != want {
			t.Fatal(system, left, err)
		}
	}
	audit, _, err := db.ListAuditEvents(100, 0)
	if err != nil {
		t.Fatal(err)
	}
	successes := 0
	failures := map[string]int{}
	for _, a := range audit {
		if a.Action != "admin.sync_deliveries_resumed" {
			continue
		}
		var details struct {
			SystemName    string
			Reason        string
			AttemptTokens []string
		}
		if err := json.Unmarshal([]byte(a.DetailsJSON), &details); err != nil || details.SystemName != "bulk-target" || a.ActorID != admin.ID {
			t.Fatalf("incomplete audit: %+v", a)
		}
		if a.Outcome == "success" {
			successes++
			if len(details.AttemptTokens) != 2 {
				t.Fatal("audit tokens", details.AttemptTokens)
			}
		} else {
			failures[details.Reason]++
		}
	}
	want := map[string]int{"confirm_remote_quiescence": 2, "create_retry_requires_single_attempt": 1, "no_expired_attempts": 1}
	if successes != 1 || len(failures) != len(want) {
		t.Fatal(successes, failures)
	}
	for reason, n := range want {
		if failures[reason] != n {
			t.Errorf("%s: %d", reason, failures[reason])
		}
	}
}

// insertSyncEvent writes an outbox row directly: recovery needs an attempt on a connector
// the mutation paths would only queue after configuring scope.
func insertSyncEvent(t *testing.T, dbPath string, ev store.AccountSyncEvent) {
	t.Helper()
	raw, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	now := time.Now().UTC()
	if _, err := raw.Exec(`INSERT INTO account_sync_events (id, user_id, system_id, event_type, payload_json, attempts, status, created_at, updated_at, revision) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.ID, ev.UserID, ev.SystemID, ev.EventType, ev.PayloadJSON, ev.Attempts, ev.Status, now, now, ev.Revision); err != nil {
		t.Fatal(err)
	}
}
