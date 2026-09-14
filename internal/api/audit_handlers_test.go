package api

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kysignon-server/internal/store"
)

// The listing and the export share one filter, an auditor may use both, formula-shaped
// cells cannot execute, secrets are redacted, and each export is itself audited.
func TestAuditSearchAndExport(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	exp := time.Now().UTC().Add(time.Hour)
	admin := newSession(t, db, newUser(t, db, "admin"), exp)
	auditor := newUser(t, db, "user")
	auditorCookie := newSession(t, db, auditor, exp)
	if err := db.SetDelegations(auditor.ID, store.Delegations{Auditor: true}, nil); err != nil {
		t.Fatal(err)
	}
	// Seed three events, one with a formula-shaped actor name and a secret-shaped detail.
	for _, e := range []struct {
		action, actor, outcome string
		details                map[string]any
	}{
		{"oauth.authorize", "=cmd|' /C calc'!A0", "denied", map[string]any{"reason": "not_assigned", "refreshToken": "abc"}},
		{"admin.user_updated", "root", "success", map[string]any{"endsAt": nil}},
		{"scim.user_replaced", "connector", "failure", nil},
	} {
		if err := srv.audit.Record(e.action, "", e.actor, "t1", "user", "::1", "ua", e.outcome, e.details); err != nil {
			t.Fatal(err)
		}
	}

	list := call(t, srv, auditorCookie, "GET", "/api/admin/audit-events?action=oauth.&outcome=denied")
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"total":1`) || !strings.Contains(list.Body.String(), "oauth.authorize") {
		t.Fatalf("filtered listing: %d %s", list.Code, list.Body.String())
	}
	if res := call(t, srv, auditorCookie, "GET", "/api/admin/audit-events?outcome=maybe"); res.Code != http.StatusBadRequest {
		t.Fatalf("unknown outcome accepted: %d", res.Code)
	}
	if res := call(t, srv, auditorCookie, "GET", "/api/admin/audit-events?from=2030-01-01T00:00:00Z&to=2020-01-01T00:00:00Z"); res.Code != http.StatusBadRequest {
		t.Fatalf("empty range accepted: %d", res.Code)
	}
	if res := call(t, srv, auditorCookie, "GET", "/api/admin/audit-events/export?format=xlsx"); res.Code != http.StatusBadRequest {
		t.Fatalf("unknown format accepted: %d", res.Code)
	}

	csvRes := call(t, srv, auditorCookie, "GET", "/api/admin/audit-events/export?format=csv&action=oauth.")
	if csvRes.Code != http.StatusOK || !strings.HasPrefix(csvRes.Header().Get("Content-Type"), "text/csv") || !strings.Contains(csvRes.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("csv export: %d %v", csvRes.Code, csvRes.Header())
	}
	records, err := csv.NewReader(strings.NewReader(csvRes.Body.String())).ReadAll()
	if err != nil || len(records) != 2 {
		t.Fatalf("csv rows: %d %v", len(records), err)
	}
	row := records[1]
	if !strings.HasPrefix(row[5], "'=") {
		t.Fatalf("formula cell not neutralised: %q", row[5])
	}
	if strings.Contains(row[10], "abc") || !strings.Contains(row[10], "[redacted]") || !strings.Contains(row[10], "not_assigned") {
		t.Fatalf("csv details not redacted: %q", row[10])
	}
	if csvRes.Header().Get("X-KySignOn-Export-Total") != "1" || csvRes.Header().Get("X-KySignOn-Export-Truncated") != "" {
		t.Fatalf("export headers: %v", csvRes.Header())
	}

	jsonl := call(t, srv, admin, "GET", "/api/admin/audit-events/export?format=jsonl")
	lines := strings.Split(strings.TrimSpace(jsonl.Body.String()), "\n")
	if jsonl.Code != http.StatusOK || len(lines) < 4 || strings.Contains(jsonl.Body.String(), `"refreshToken":"abc"`) {
		t.Fatalf("jsonl export: %d lines=%d %s", jsonl.Code, len(lines), jsonl.Body.String())
	}
	// The auditor's CSV export was itself audited, intent and completion, and both show
	// up in the admin's JSONL.
	if !strings.Contains(jsonl.Body.String(), `"action":"admin.audit_export_started"`) || !strings.Contains(jsonl.Body.String(), `"action":"admin.audit_exported"`) || !strings.Contains(jsonl.Body.String(), `\"format\":\"csv\"`) {
		t.Fatalf("export not audited: %s", jsonl.Body.String())
	}
	// A helpdesk delegate is not an audit reader.
	helpdesk := newUser(t, db, "user")
	if err := db.SetDelegations(helpdesk.ID, store.Delegations{Helpdesk: true}, nil); err != nil {
		t.Fatal(err)
	}
	if res := call(t, srv, newSession(t, db, helpdesk, exp), "GET", "/api/admin/audit-events/export?format=csv"); res.Code != http.StatusForbidden {
		t.Fatalf("helpdesk exported the audit log: %d", res.Code)
	}
}

// failingWriter accepts headers and refuses every body write, like a client that hung up.
type failingWriter struct {
	httptest.ResponseRecorder
}

func (f *failingWriter) Write([]byte) (int, error) { return 0, errors.New("connection reset") }

// An export that stopped short of the filtered set says so in the file, whatever
// stopped it, and a write failure is recorded as a failure rather than a success.
func TestAuditExportMarksIncompleteOutput(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newSession(t, db, newUser(t, db, "admin"), time.Now().UTC().Add(time.Hour))
	for i := 0; i < 10; i++ {
		if err := srv.audit.Record("oauth.authorize", "", "u", "t", "user", "::1", "ua", "denied", nil); err != nil {
			t.Fatal(err)
		}
	}
	lastLine := func(body string) map[string]any {
		lines := strings.Split(strings.TrimSpace(body), "\n")
		var m map[string]any
		if err := json.Unmarshal([]byte(lines[len(lines)-1]), &m); err != nil {
			t.Fatalf("last line is not JSON: %q", lines[len(lines)-1])
		}
		return m
	}
	// Row bound: three rows, then the marker.
	auditExportMaxRows = 3
	defer func() { auditExportMaxRows = 50000 }()
	res := call(t, srv, admin, "GET", "/api/admin/audit-events/export?format=jsonl&action=oauth.")
	m := lastLine(res.Body.String())
	if res.Code != http.StatusOK || m["_export"] != "incomplete" || m["reason"] != "limit" || m["rows"] != float64(3) || res.Header().Get("X-KySignOn-Export-Truncated") != "true" {
		t.Fatalf("limit marker = %v (%d)", m, res.Code)
	}
	if lines := strings.Split(strings.TrimSpace(res.Body.String()), "\n"); len(lines) != 4 {
		t.Fatalf("expected 3 rows plus a marker, got %d lines", len(lines))
	}
	csvRes := call(t, srv, admin, "GET", "/api/admin/audit-events/export?format=csv&action=oauth.")
	records, err := csv.NewReader(strings.NewReader(csvRes.Body.String())).ReadAll()
	if err != nil || len(records) != 5 || records[4][0] != "_export" || records[4][3] != "limit" {
		t.Fatalf("csv marker rows = %d %v: %v", len(records), err, records)
	}
	auditExportMaxRows = 50000
	// Deadline already passed: nothing streams, the marker says timeout.
	auditExportTimeout = 0
	defer func() { auditExportTimeout = 30 * time.Second }()
	res = call(t, srv, admin, "GET", "/api/admin/audit-events/export?format=jsonl&action=oauth.")
	auditExportTimeout = 30 * time.Second
	if res.Code != http.StatusOK && res.Code != http.StatusInternalServerError {
		t.Fatalf("timeout export: %d %s", res.Code, res.Body.String())
	}
	if res.Code == http.StatusOK {
		if m := lastLine(res.Body.String()); m["_export"] != "incomplete" || m["reason"] != "timeout" {
			t.Fatalf("timeout marker = %v", m)
		}
	}
	// A client that refuses the bytes: the completion row is a failure, not a success.
	req := httptest.NewRequest("GET", "/api/admin/audit-events/export?format=csv&action=oauth.", nil)
	req.AddCookie(&http.Cookie{Name: "kysignon_session", Value: admin})
	fw := &failingWriter{ResponseRecorder: *httptest.NewRecorder()}
	srv.httpServer.Handler.ServeHTTP(fw, req)
	events, _, _ := db.SearchAuditEvents(store.AuditFilter{Action: "admin.audit_exported", Limit: 5})
	if len(events) == 0 || events[0].Outcome != "failure" || !strings.Contains(events[0].DetailsJSON, `"incomplete":"error"`) {
		t.Fatalf("failed write recorded as: %+v", events)
	}
	started, _, _ := db.SearchAuditEvents(store.AuditFilter{Action: "admin.audit_export_started", Limit: 1})
	if len(started) == 0 {
		t.Fatal("export intent not recorded before streaming")
	}
}
