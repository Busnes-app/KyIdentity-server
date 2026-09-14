package api

import (
	"encoding/csv"
	"net/http"
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
	// The auditor's CSV export was itself audited, and shows up in the admin's JSONL.
	if !strings.Contains(jsonl.Body.String(), `"action":"admin.audit_exported"`) || !strings.Contains(jsonl.Body.String(), `\"format\":\"csv\"`) {
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
