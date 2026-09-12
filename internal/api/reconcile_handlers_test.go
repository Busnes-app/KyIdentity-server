package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/Busness-app/kysignon-server/internal/sync"
)

func TestReconciliationAdministration(t *testing.T) {
	srv, db, engine, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	user := newUser(t, db, "user")
	sys, _, err := engine.CreateSystem(&sync.CreateSystemRequest{Name: "SCIM", SystemType: "scim", CallbackURL: "https://example.com/scim/v2", BearerToken: "target-secret"})
	if err != nil {
		t.Fatal(err)
	}
	allowTestAppAccess(t, db, sys.ID)
	base := "/api/admin/systems/" + sys.ID

	rr := adminRequestNoStepUp(t, srv, "GET", base+"/provisioning?q=&limit=25&offset=0", cookie, "")
	if rr.Code != 200 {
		t.Fatalf("provisioning list: %d %s", rr.Code, rr.Body.String())
	}
	var page struct {
		Users []struct {
			UserID   string `json:"userId"`
			Desired  bool   `json:"desired"`
			Recorded bool   `json:"recorded"`
		} `json:"users"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &page); err != nil || page.Total < 2 {
		t.Fatalf("%v %s", err, rr.Body.String())
	}
	for _, row := range page.Users {
		if !row.Desired || !row.Recorded {
			t.Fatalf("scoped user not desired/queued: %+v", row)
		}
	}
	if rr = adminRequestNoStepUp(t, srv, "GET", base+"/provisioning?limit=0", cookie, ""); rr.Code != 400 {
		t.Fatalf("bad paging accepted: %d", rr.Code)
	}
	if rr = adminRequestNoStepUp(t, srv, "GET", "/api/admin/systems/missing/provisioning", cookie, ""); rr.Code != 404 {
		t.Fatalf("unknown system: %d", rr.Code)
	}
	if rr = adminRequestNoStepUp(t, srv, "POST", base+"/provisioning/"+user.ID+"/retry", cookie, ""); rr.Code != 200 {
		t.Fatalf("retry: %d %s", rr.Code, rr.Body.String())
	}
	if rr = adminRequestNoStepUp(t, srv, "POST", base+"/provisioning/nobody/retry", cookie, ""); rr.Code != 404 {
		t.Fatalf("retry for unknown user: %d", rr.Code)
	}

	// Preview needs no step-up; repair does. One job at a time per connector.
	if rr = adminRequestNoStepUp(t, srv, "POST", base+"/reconcile/repair", cookie, ""); rr.Code != http.StatusForbidden {
		t.Fatalf("repair without step-up: %d", rr.Code)
	}
	if rr = adminRequestNoStepUp(t, srv, "POST", base+"/reconcile/preview", cookie, ""); rr.Code != 200 {
		t.Fatalf("preview: %d %s", rr.Code, rr.Body.String())
	}
	if rr = adminRequest(t, srv, "POST", base+"/reconcile/repair", cookie, ""); rr.Code != http.StatusConflict {
		t.Fatalf("second job while one is queued: %d %s", rr.Code, rr.Body.String())
	}
	rr = adminRequestNoStepUp(t, srv, "GET", base+"/reconcile", cookie, "")
	var jobs struct {
		Jobs []struct {
			Kind, Status, RequestedBy string
			ClaimToken                string `json:"claimToken"`
		} `json:"jobs"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &jobs); err != nil || len(jobs.Jobs) != 1 || jobs.Jobs[0].Kind != "preview" || jobs.Jobs[0].Status != "queued" || jobs.Jobs[0].RequestedBy != admin.Username || jobs.Jobs[0].ClaimToken != "" {
		t.Fatalf("%v %s", err, rr.Body.String())
	}
	// A schedule is part of the connection settings and limited to generic SCIM.
	if rr = adminRequest(t, srv, "PUT", base+"/connection", cookie, `{"systemType":"scim","reconcileHours":24}`); rr.Code != 200 {
		t.Fatalf("schedule: %d %s", rr.Code, rr.Body.String())
	}
	if loaded, _ := db.GetPairedSystemByID(sys.ID); loaded.ReconcileHours != 24 {
		t.Fatal("schedule not stored")
	}
	if rr = adminRequest(t, srv, "PUT", base+"/connection", cookie, `{"systemType":"scim","reconcileHours":9999}`); rr.Code != 400 {
		t.Fatalf("absurd schedule accepted: %d", rr.Code)
	}
	events, _, err := db.ListAuditEvents(100, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, ev := range events {
		seen[ev.Action] = true
	}
	for _, action := range []string{"admin.provisioning_retried", "admin.reconcile_requested"} {
		if !seen[action] {
			t.Fatalf("missing audit %s", action)
		}
	}
}
