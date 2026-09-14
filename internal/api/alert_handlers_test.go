package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kysignon-server/internal/store"
)

type alertPage struct {
	Alerts []struct {
		ID, Rule, Key, Status, Title, Summary string
		Count                                 int
		Delivery                              struct{ Pending, Failed int }
	}
	Total int
}

func alerts(t *testing.T, srv *Server, cookie, status string) alertPage {
	t.Helper()
	res := adminRequest(t, srv, "GET", "/api/admin/alerts?status="+status, cookie, "")
	if res.Code != http.StatusOK {
		t.Fatalf("list %s: %d %s", status, res.Code, res.Body.String())
	}
	var page alertPage
	if err := json.Unmarshal(res.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	return page
}

func auditRows(t *testing.T, db *store.Store, action string) []store.AuditEvent {
	t.Helper()
	rows, _, err := db.SearchAuditEvents(store.AuditFilter{Action: action, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// Auditors read the inbox, only administrators acknowledge, and both actions leave an
// audit row. Privilege and credential changes made through the real routes raise alerts.
func TestAlertInboxAndAcknowledgement(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	exp := time.Now().UTC().Add(time.Hour)
	admin := newSession(t, db, newUser(t, db, "admin"), exp)
	auditor := newUser(t, db, "user")
	auditorCookie := newSession(t, db, auditor, exp)
	if err := db.SetDelegations(auditor.ID, store.Delegations{Auditor: true}, nil); err != nil {
		t.Fatal(err)
	}
	target := newUser(t, db, "user")
	// A role change through the API carries roleChanged; an unchanged role does not.
	if res := adminRequest(t, srv, "PUT", "/api/admin/users/"+target.ID, admin, `{"role":"admin"}`); res.Code != http.StatusOK {
		t.Fatalf("promote: %d %s", res.Code, res.Body.String())
	}
	if res := adminRequest(t, srv, "PUT", "/api/admin/users/"+target.ID, admin, `{"displayName":"renamed"}`); res.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", res.Code, res.Body.String())
	}
	// A rotated connector credential carries credentialRotated; a review without one does not.
	res := adminRequest(t, srv, "POST", "/api/admin/systems", admin, `{"name":"HR","systemType":"scim","callbackUrl":"https://example.com/scim/v2","bearerToken":"first-secret"}`)
	if res.Code != http.StatusOK {
		t.Fatalf("create system: %d %s", res.Code, res.Body.String())
	}
	var created struct{ System store.PairedSystem }
	if err := json.Unmarshal(res.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	sysPath := "/api/admin/systems/" + created.System.ID + "/connection"
	if res := adminRequest(t, srv, "PUT", sysPath, admin, `{"systemType":"scim","groups":true}`); res.Code != http.StatusOK {
		t.Fatalf("review: %d %s", res.Code, res.Body.String())
	}
	if res := adminRequest(t, srv, "PUT", sysPath, admin, `{"systemType":"scim","bearerToken":"second-secret"}`); res.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", res.Code, res.Body.String())
	}
	if err := db.EvaluateAlerts(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	page := alerts(t, srv, auditorCookie, "open")
	counts := map[string]int{}
	for _, a := range page.Alerts {
		counts[a.Rule+"/"+a.Key] = a.Count
		if strings.Contains(a.Title+a.Summary, "secret") {
			t.Fatal("credential material in alert text", a)
		}
	}
	// One promotion; creation plus one rotation of the same connector fold into one alert.
	if counts["privilege_change/"+target.ID] != 1 || counts["connector_credentials/"+created.System.ID] != 2 || page.Total != 2 {
		t.Fatalf("alerts: %+v", counts)
	}
	var id string
	for _, a := range page.Alerts {
		if a.Rule == "privilege_change" {
			id = a.ID
		}
	}
	ack := "/api/admin/alerts/" + id + "/acknowledge"
	if res := adminRequest(t, srv, "POST", ack, auditorCookie, ""); res.Code != http.StatusForbidden {
		t.Fatalf("auditor acknowledged: %d", res.Code)
	}
	if res := adminRequestNoStepUp(t, srv, "POST", ack, admin, ""); res.Code != http.StatusOK {
		t.Fatalf("acknowledge: %d %s", res.Code, res.Body.String())
	}
	if res := adminRequestNoStepUp(t, srv, "POST", ack, admin, ""); res.Code != http.StatusConflict {
		t.Fatalf("second acknowledgement: %d", res.Code)
	}
	if res := adminRequestNoStepUp(t, srv, "POST", "/api/admin/alerts/missing/acknowledge", admin, ""); res.Code != http.StatusNotFound {
		t.Fatalf("missing alert: %d", res.Code)
	}
	if got := alerts(t, srv, auditorCookie, "acknowledged"); got.Total != 1 || got.Alerts[0].ID != id {
		t.Fatalf("acknowledged page: %+v", got)
	}
	if rows := auditRows(t, db, "admin.alert_acknowledged"); len(rows) != 1 || rows[0].TargetID != id || rows[0].Outcome != "success" {
		t.Fatalf("acknowledgement audit: %+v", rows)
	}
	if res := adminRequest(t, srv, "GET", "/api/admin/alerts?status=bogus", admin, ""); res.Code != http.StatusBadRequest {
		t.Fatalf("bogus status: %d", res.Code)
	}
}

// Settings need step-up, reject recipients who cannot read alerts, take usernames on
// the wire and are audited without the recipient list leaking anything but names.
func TestAlertSettings(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	exp := time.Now().UTC().Add(time.Hour)
	adminUser := newUser(t, db, "admin")
	admin := newSession(t, db, adminUser, exp)
	auditor := newUser(t, db, "user")
	auditorCookie := newSession(t, db, auditor, exp)
	if err := db.SetDelegations(auditor.ID, store.Delegations{Auditor: true}, nil); err != nil {
		t.Fatal(err)
	}
	plain := newUser(t, db, "user")
	res := adminRequest(t, srv, "GET", "/api/admin/alerts/settings", auditorCookie, "")
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"loginFailureThreshold":10`) {
		t.Fatalf("defaults: %d %s", res.Code, res.Body.String())
	}
	body := `{"loginFailureThreshold":5,"loginFailureWindowSeconds":300,"recipients":["` + adminUser.Username + `","` + auditor.Username + `"]}`
	if res := adminRequestNoStepUp(t, srv, "PUT", "/api/admin/alerts/settings", admin, body); res.Code != http.StatusForbidden {
		t.Fatalf("settings without step-up: %d", res.Code)
	}
	if res := adminRequest(t, srv, "PUT", "/api/admin/alerts/settings", auditorCookie, body); res.Code != http.StatusForbidden {
		t.Fatalf("auditor changed settings: %d", res.Code)
	}
	bad := `{"loginFailureThreshold":5,"loginFailureWindowSeconds":300,"recipients":["` + plain.Username + `"]}`
	if res := adminRequest(t, srv, "PUT", "/api/admin/alerts/settings", admin, bad); res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "alert_recipient") {
		t.Fatalf("plain recipient: %d %s", res.Code, res.Body.String())
	}
	if res := adminRequest(t, srv, "PUT", "/api/admin/alerts/settings", admin, `{"loginFailureThreshold":0,"loginFailureWindowSeconds":300,"recipients":[]}`); res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "invalid_settings") {
		t.Fatalf("zero threshold: %d %s", res.Code, res.Body.String())
	}
	if res := adminRequest(t, srv, "PUT", "/api/admin/alerts/settings", admin, `{"loginFailureThreshold":5,"loginFailureWindowSeconds":300,"recipients":["nobody-here"]}`); res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "alert_recipient") {
		t.Fatalf("unknown recipient: %d %s", res.Code, res.Body.String())
	}
	if res := adminRequest(t, srv, "PUT", "/api/admin/alerts/settings", admin, body); res.Code != http.StatusOK {
		t.Fatalf("save: %d %s", res.Code, res.Body.String())
	}
	res = adminRequest(t, srv, "GET", "/api/admin/alerts/settings", admin, "")
	var got struct {
		LoginFailureThreshold int
		Recipients            []struct{ ID, Username string }
	}
	if err := json.Unmarshal(res.Body.Bytes(), &got); err != nil || got.LoginFailureThreshold != 5 || len(got.Recipients) != 2 || got.Recipients[1].Username != auditor.Username {
		t.Fatalf("saved settings: %s %v", res.Body.String(), err)
	}
	rows := auditRows(t, db, "admin.alerts_configured")
	if len(rows) != 1 || !strings.Contains(rows[0].DetailsJSON, auditor.Username) || !strings.Contains(rows[0].DetailsJSON, `"loginFailureThreshold":5`) {
		t.Fatalf("settings audit: %+v", rows)
	}
	// The threshold is live: five failures for one name open an alert.
	for i := 0; i < 5; i++ {
		if err := srv.audit.Record("auth.login", "", "mallory", "", "user", "203.0.113.9", "ua", "failure", map[string]any{"reason": "user_not_found"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.EvaluateAlerts(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	page := alerts(t, srv, admin, "open")
	if page.Total != 1 || page.Alerts[0].Rule != "login_failures" || page.Alerts[0].Delivery.Pending != 2 {
		t.Fatalf("threshold alert: %+v", page)
	}
}
