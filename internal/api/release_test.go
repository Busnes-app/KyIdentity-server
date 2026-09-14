package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kysignon-server/internal/store"
)

// The release scenario for a restore, driven through the routes an operator and a
// browser actually use. The upgrade half of the release check lives in the store
// package, where a pre-feature database is migrated twice and compared with a fresh
// one; what this adds is the behaviour on the far side of a restore.
//
// What must hold: the directory, its policy and its ownership come back; the logins and
// tokens the capsule happens to contain do not; and outbound provisioning stays held
// until the connector has been reconciled against what is really there.
func TestReleaseRestoreScenario(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	adminUser := newUser(t, db, "admin")
	staff := newUser(t, db, "user")

	// Ownership and policy an operator set up before the snapshot.
	group := &store.Group{ID: "g-team", Name: "Team"}
	if err := db.CreateGroup(group, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.SetGroupMembership(group.ID, staff.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.SetDelegations(staff.ID, store.Delegations{Auditor: true}, nil); err != nil {
		t.Fatal(err)
	}

	// A live login and a live token, exactly what a capsule carries.
	rec := login(t, srv, adminUser.Username, "correct-horse-battery")
	cookie := sessionCookie(rec)
	if cookie == nil {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}
	stale := cookie.Value
	if res := call(t, srv, stale, "GET", "/api/auth/me"); res.Code != http.StatusOK {
		t.Fatalf("session before the restore: %d", res.Code)
	}

	// A connector with work waiting for it.
	res := adminRequest(t, srv, "POST", "/api/admin/systems", stale, `{"name":"HR","systemType":"scim","callbackUrl":"https://hr.test/scim/v2","bearerToken":"connector-secret"}`)
	if res.Code != http.StatusOK {
		t.Fatalf("create connector: %d %s", res.Code, res.Body.String())
	}
	var created struct{ System store.PairedSystem }
	if err := json.Unmarshal(res.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.System.ProvisioningHold {
		t.Fatal("a new connector starts held")
	}

	// The next start after `kysignon restore` applies the capsule's state.
	report, err := db.ApplyRestoredState(time.Now().UTC(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.HeldConnectors != 1 || len(report.Connectors) != 1 {
		t.Fatalf("restore report: %+v", report)
	}

	// Stale credentials cannot log in, through the same route a browser would use.
	if res := call(t, srv, stale, "GET", "/api/auth/me"); res.Code != http.StatusUnauthorized {
		t.Fatalf("a session from the capsule still works: %d %s", res.Code, res.Body.String())
	}
	if res := adminRequestNoStepUp(t, srv, "GET", "/api/admin/users", stale, ""); res.Code != http.StatusUnauthorized {
		t.Fatalf("a stale session still reached an admin route: %d", res.Code)
	}

	// The directory, its policy and its ownership are intact: the operator logs in
	// again with the password they had, and finds what they configured.
	rec = login(t, srv, adminUser.Username, "correct-horse-battery")
	fresh := sessionCookie(rec)
	if fresh == nil {
		t.Fatalf("login after the restore: %d %s", rec.Code, rec.Body.String())
	}
	if res := call(t, srv, fresh.Value, "GET", "/api/admin/groups?limit=25&offset=0"); res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "Team") {
		t.Fatalf("groups after the restore: %d %s", res.Code, res.Body.String())
	}
	res = call(t, srv, fresh.Value, "GET", "/api/admin/users/"+staff.ID+"/delegations")
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"auditor":true`) {
		t.Fatalf("delegated administration after the restore: %d %s", res.Code, res.Body.String())
	}

	// Outbound provisioning is held, visibly, until the connector is reconciled.
	systems := func() store.PairedSystem {
		t.Helper()
		res := call(t, srv, fresh.Value, "GET", "/api/admin/systems")
		if res.Code != http.StatusOK {
			t.Fatalf("systems: %d %s", res.Code, res.Body.String())
		}
		var body struct {
			Systems []store.PairedSystem `json:"systems"`
		}
		if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil || len(body.Systems) != 1 {
			t.Fatalf("systems body: %s %v", res.Body.String(), err)
		}
		return body.Systems[0]
	}
	if !systems().ProvisioningHold {
		t.Fatal("the operator cannot see that provisioning is held")
	}

	// Reconciling is the way out, through the route the console uses.
	if res := adminRequest(t, srv, "POST", "/api/admin/systems/"+created.System.ID+"/reconcile/repair", fresh.Value, `{}`); res.Code != http.StatusOK {
		t.Fatalf("repair reconciliation refused for a held connector: %d %s", res.Code, res.Body.String())
	}
	job, err := db.ClaimReconcileJob(time.Minute)
	if err != nil || job == nil {
		t.Fatal("claim:", err)
	}
	if err := db.FinishReconcileJob(job, &store.DriftReport{Supported: true, Complete: true, Repaired: true}, nil); err != nil {
		t.Fatal(err)
	}
	if systems().ProvisioningHold {
		t.Fatal("a completed repair left provisioning held")
	}

	// And the restore is in the trail, with what it invalidated.
	events, _, err := db.SearchAuditEvents(store.AuditFilter{Action: "admin.reconcile_requested", Limit: 5})
	if err != nil || len(events) == 0 {
		t.Fatalf("reconciliation audit: %d %v", len(events), err)
	}
}
