package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

type healthResponse struct {
	Schema  string `json:"schema"`
	Service string `json:"service"`
	Status  string `json:"status"`
	Checks  []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Reason string `json:"reason"`
	} `json:"checks"`
}

func requestHealth(t *testing.T, srv *Server) (int, healthResponse, string) {
	t.Helper()
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, httptest.NewRequest("GET", "/healthz", nil))
	var body healthResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return rr.Code, body, rr.Body.String()
}

func checkHealth(t *testing.T, body healthResponse, name, status, reason string) {
	t.Helper()
	for _, check := range body.Checks {
		if check.Name == name {
			if check.Status != status || check.Reason != reason {
				t.Errorf("%s = %s/%s, want %s/%s", name, check.Status, check.Reason, status, reason)
			}
			return
		}
	}
	t.Errorf("missing %s check: %+v", name, body.Checks)
}

func TestHealthPublicSchemaAndSafeChecks(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	code, body, raw := requestHealth(t, srv)
	if code != http.StatusOK || body.Schema != "ky.health/1" || body.Service != "kyidentity" || body.Status != "ok" {
		t.Fatalf("health = %d %+v", code, body)
	}
	if len(body.Checks) != 4 {
		t.Fatalf("checks = %+v", body.Checks)
	}
	for _, name := range []string{"database", "signing_key", "encryption_key", "audit"} {
		checkHealth(t, body, name, "ok", "")
	}
	if strings.Contains(raw, srv.cfg.DBPath) || strings.Contains(raw, srv.cfg.IssuerURL) {
		t.Fatalf("health disclosed deployment details: %s", raw)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	code, _, cached := requestHealth(t, srv)
	if code != http.StatusOK || cached != raw {
		t.Fatalf("second request did not reuse cached health: %d %s", code, cached)
	}
}

func TestHealthDatabaseDownOnFreshHandler(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	code, body, raw := requestHealth(t, srv)
	if code != http.StatusServiceUnavailable || body.Status != "down" {
		t.Fatalf("health = %d %+v", code, body)
	}
	checkHealth(t, body, "database", "down", "")
	if strings.Contains(raw, srv.cfg.DBPath) || strings.Contains(raw, "closed") {
		t.Fatalf("health disclosed database error: %s", raw)
	}
	code, _, cached := requestHealth(t, srv)
	if code != http.StatusServiceUnavailable || cached != raw {
		t.Fatalf("second request did not reuse cached failure: %d %s", code, cached)
	}
}

func TestHealthAuditDegradedWithFixedReason(t *testing.T) {
	srv, _, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	rawDB, err := sql.Open("sqlite", srv.cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer rawDB.Close()
	if _, err := rawDB.Exec(`DROP TABLE audit_events`); err != nil {
		t.Fatal(err)
	}
	if err := srv.audit.Record("health.test", "", "", "", "", "", "", "failure", nil); err == nil {
		t.Fatal("expected audit persistence failure")
	}
	_, _, lastErr, _ := srv.audit.Health()
	code, body, raw := requestHealth(t, srv)
	if code != http.StatusOK || body.Status != "degraded" {
		t.Fatalf("health = %d %+v", code, body)
	}
	checkHealth(t, body, "audit", "degraded", "append_disabled")
	if strings.Contains(raw, lastErr) || strings.Contains(raw, srv.cfg.DBPath) {
		t.Fatalf("health disclosed audit error: %s", raw)
	}
}
