package api

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestAttestationSettings(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	exp := time.Now().UTC().Add(time.Hour)
	admin := newSession(t, db, newUser(t, db, "admin"), exp)
	path := "/api/admin/attestation/settings"
	if res := adminRequest(t, srv, "GET", path, admin, ""); res.Code != http.StatusOK || strings.TrimSpace(res.Body.String()) != `{"requireLockedBootloader":false}` {
		t.Fatalf("default: %d %s", res.Code, res.Body.String())
	}
	on := `{"requireLockedBootloader":true}`
	if res := adminRequestNoStepUp(t, srv, "PUT", path, admin, on); res.Code != http.StatusForbidden {
		t.Fatalf("without step-up: %d", res.Code)
	}
	for _, bad := range []string{`{"requireLockedBootloader":"yes"}`, `{"requireLockedBootloader":true,"x":1}`, `{}`} {
		if res := adminRequest(t, srv, "PUT", path, admin, bad); res.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d", bad, res.Code)
		}
	}
	if res := adminRequest(t, srv, "PUT", path, admin, on); res.Code != http.StatusOK {
		t.Fatalf("save: %d %s", res.Code, res.Body.String())
	}
	if res := adminRequest(t, srv, "GET", path, admin, ""); !strings.Contains(res.Body.String(), `true`) {
		t.Fatalf("saved: %s", res.Body.String())
	}
	rows := auditRows(t, db, "admin.attestation_configured")
	if len(rows) != 1 || !strings.Contains(rows[0].DetailsJSON, `"old":false`) || !strings.Contains(rows[0].DetailsJSON, `"new":true`) {
		t.Fatalf("audit: %+v", rows)
	}
}
