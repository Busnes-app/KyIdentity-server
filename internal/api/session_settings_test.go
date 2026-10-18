package api

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSessionSettings(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newSession(t, db, newUser(t, db, "admin"), time.Now().UTC().Add(time.Hour))
	user := newSession(t, db, newUser(t, db, "user"), time.Now().UTC().Add(24*time.Hour))
	path := "/api/admin/session-settings"
	if res := adminRequest(t, srv, "GET", path, admin, ""); strings.TrimSpace(res.Body.String()) != `{"absolute":86400,"idle":28800}` {
		t.Fatalf("default: %d %s", res.Code, res.Body.String())
	}
	short := `{"absolute":3600,"idle":600}`
	if res := adminRequestNoStepUp(t, srv, "PUT", path, admin, short); res.Code != http.StatusForbidden {
		t.Fatalf("without step-up: %d", res.Code)
	}
	for _, bad := range []string{
		`{"absolute":60,"idle":60}`,        // under an hour
		`{"absolute":2592000,"idle":3600}`, // 30 days
		`{"absolute":3600,"idle":60}`,      // idle under five minutes
		`{"absolute":3600,"idle":7200}`,    // idle longer than lifetime
		`{"absolute":86400,"idle":172800}`, // idle over a day
		`{"absolute":3600}`, `{"absolute":3600,"idle":600,"x":1}`,
	} {
		if res := adminRequest(t, srv, "PUT", path, admin, bad); res.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d", bad, res.Code)
		}
	}
	if res := adminRequest(t, srv, "PUT", path, admin, short); res.Code != http.StatusOK {
		t.Fatalf("save: %d %s", res.Code, res.Body.String())
	}
	if rows := auditRows(t, db, "admin.session_limits_configured"); len(rows) != 1 || !strings.Contains(rows[0].DetailsJSON, `"new":{"absolute":3600,"idle":600}`) {
		t.Fatalf("audit: %+v", rows)
	}

	// The new limits apply to sessions that already exist.
	raw, err := sql.Open("sqlite", srv.cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	me := func(cookie string) int {
		req := httptest.NewRequest("GET", "/api/auth/me", nil)
		req.AddCookie(&http.Cookie{Name: "kyidentity_session", Value: cookie})
		r := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(r, req)
		return r.Code
	}
	if me(user) != http.StatusOK {
		t.Fatal("fresh session refused")
	}
	if _, err := raw.Exec(`UPDATE sessions SET last_active_at=? WHERE session_token_hash<>''`, time.Now().UTC().Add(-11*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if me(user) != http.StatusUnauthorized {
		t.Fatal("shorter idle limit did not end an idle session")
	}
	fresh := newSession(t, db, newUser(t, db, "user"), time.Now().UTC().Add(24*time.Hour))
	if me(fresh) != http.StatusOK {
		t.Fatal("fresh session refused")
	}
	if _, err := raw.Exec(`UPDATE sessions SET created_at=?`, time.Now().UTC().Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if me(fresh) != http.StatusUnauthorized {
		t.Fatal("shorter absolute limit did not end an older session")
	}
}
