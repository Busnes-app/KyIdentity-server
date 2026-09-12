package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kysignon-server/internal/store"
)

func TestSyncDeliveryRecoveryRequiresStepUpAndConfirmation(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	sys := &store.PairedSystem{ID: "recovery-target", Name: "Recovery target", SystemType: "suite_webhook", CallbackURL: "https://example.com/hook", Status: "active"}
	if err := db.CreatePairedSystem(sys); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateAccountSyncEvent(&store.AccountSyncEvent{ID: "attempt", UserID: admin.ID, SystemID: sys.ID, EventType: "user.updated", Status: "pending", PayloadJSON: `{}`}); err != nil {
		t.Fatal(err)
	}
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
