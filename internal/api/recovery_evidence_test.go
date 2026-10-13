package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/syncauth"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/Busnes-app/kyidentity-server/internal/sync"
)

func TestRecoveryEvidenceAdminExportAndSignature(t *testing.T) {
	srv, db, engine, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	sys, secret, err := engine.CreateSystem(&sync.CreateSystemRequest{Name: "mail", SystemType: "kypost", CallbackURL: "https://mail.example.test/api/sync/events"})
	if err != nil {
		t.Fatal(err)
	}
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	user := newUser(t, db, "user")
	apps, _, err := db.ListAppRecords("mail", 100, 0)
	if err != nil || len(apps) != 1 {
		t.Fatal("app", apps, err)
	}
	if err := db.SetAppAssignment(apps[0].ID, "users", user.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	path := "/api/admin/systems/" + sys.ID + "/recovery-evidence"
	body := `{"nonce":"` + strings.Repeat("a", 64) + `","subjects":["` + user.ID + `","unknown"]}`
	if res := adminRequestNoStepUp(t, srv, "POST", path, cookie, body); res.Code != http.StatusForbidden || !strings.Contains(res.Body.String(), "step_up_required") {
		t.Fatalf("missing step-up: %d %s", res.Code, res.Body.String())
	}
	wrong := mintStepUp(t, srv, cookie, "POST /api/admin/systems/another/recovery-evidence")
	if res := adminRequestWithStepUp(t, srv, "POST", path, cookie, body, wrong); res.Code != http.StatusForbidden {
		t.Fatalf("wrong operation admitted: %d", res.Code)
	}
	grant := mintStepUp(t, srv, cookie, "POST "+path)
	res := adminRequestWithStepUp(t, srv, "POST", path, cookie, body, grant)
	if res.Code != 200 || res.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("export: %d %s", res.Code, res.Body.String())
	}
	raw := append([]byte(nil), res.Body.Bytes()...)
	headers := syncauth.Headers{Signature: res.Header().Get(syncauth.HeaderSignature), Timestamp: res.Header().Get(syncauth.HeaderTimestamp), EventType: res.Header().Get(syncauth.HeaderEventType), EventID: res.Header().Get(syncauth.HeaderEventID)}
	ev, err := syncauth.Verify([]byte(secret), headers, raw, syncauth.Options{})
	if err != nil || ev.Type != "recovery.evidence" || ev.ID != strings.Repeat("a", 64) {
		t.Fatal("signature", ev, err)
	}
	var evidence store.RecoveryEvidence
	if err := json.Unmarshal(raw, &evidence); err != nil || evidence.Issuer != srv.cfg.IssuerURL || evidence.SystemID != sys.ID || evidence.Nonce != ev.ID || len(evidence.Subjects) != 2 || evidence.Subjects[1].Revision != nil {
		t.Fatalf("envelope: %+v %v", evidence, err)
	}
	if strings.Contains(string(raw), secret) || strings.Contains(string(raw), "password") {
		t.Fatal("credential leaked")
	}
	if _, err := syncauth.Verify([]byte(secret), headers, append(raw, ' '), syncauth.Options{}); err == nil {
		t.Fatal("changed exact bytes admitted")
	}
	headers.EventType = "user.updated"
	if _, err := syncauth.Verify([]byte(secret), headers, raw, syncauth.Options{}); err == nil {
		t.Fatal("evidence converted to directory update")
	}
	if res := adminRequestWithStepUp(t, srv, "POST", path, cookie, body, grant); res.Code != 403 {
		t.Fatal("spent step-up reused", res.Code)
	}
	if n := countAudit(t, db, "admin.recovery_evidence_exported"); n != 1 {
		t.Fatal("audit count", n)
	}
}

func TestRecoveryEvidenceValidationAndUnavailableAuthority(t *testing.T) {
	srv, db, engine, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	sys, _, err := engine.CreateSystem(&sync.CreateSystemRequest{Name: "mail", SystemType: "kypost", CallbackURL: "https://mail.example.test/api/sync/events"})
	if err != nil {
		t.Fatal(err)
	}
	cookie := newSession(t, db, newUser(t, db, "admin"), time.Now().UTC().Add(time.Hour))
	path := "/api/admin/systems/" + sys.ID + "/recovery-evidence"
	valid := `{"nonce":"` + strings.Repeat("a", 64) + `","subjects":["subject"]}`
	bodies := []string{`{}`, valid + `{}`, strings.Replace(valid, strings.Repeat("a", 64), "short", 1), strings.Replace(valid, "[\"subject\"]", "[]", 1), strings.Replace(valid, "[\"subject\"]", "[\"subject\",\"subject\"]", 1), strings.Replace(valid, "subject", "bad/id", 1), strings.Replace(valid, "a", "A", 1), strings.Replace(valid, "}", `,"extra":true}`, 1), `{"nonce":"` + strings.Repeat("a", 65536) + `"}`}
	ids := make([]string, 257)
	for i := range ids {
		ids[i] = "subject-" + strconv.Itoa(i)
	}
	b, _ := json.Marshal(map[string]any{"nonce": strings.Repeat("a", 64), "subjects": ids})
	bodies = append(bodies, string(b))
	for _, body := range bodies {
		if res := adminRequest(t, srv, "POST", path, cookie, body); res.Code != 400 || res.Header().Get(syncauth.HeaderSignature) != "" {
			t.Fatalf("invalid request: %d %s", res.Code, res.Body.String())
		}
	}
	raw, err := sql.Open("sqlite", srv.cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for _, change := range []string{`provisioning_hold=1`, `status='disabled'`, `system_type='scim'`, `hmac_secret_encrypted='broken'`} {
		if _, err := raw.Exec(`UPDATE paired_systems SET `+change+` WHERE id=?`, sys.ID); err != nil {
			t.Fatal(err)
		}
		res := adminRequest(t, srv, "POST", path, cookie, valid)
		if res.Code != 409 || res.Header().Get(syncauth.HeaderSignature) != "" {
			t.Fatalf("unavailable %s: %d %s", change, res.Code, res.Body.String())
		}
		if _, err := raw.Exec(`UPDATE paired_systems SET provisioning_hold=0,status='active',system_type='kypost',hmac_secret_encrypted=? WHERE id=?`, sys.HMACSecretEncrypted, sys.ID); err != nil {
			t.Fatal(err)
		}
	}
	if res := adminRequest(t, srv, "POST", "/api/admin/systems/missing/recovery-evidence", cookie, valid); res.Code != 404 {
		t.Fatal("missing system", res.Code)
	}
	if n := countAudit(t, db, "admin.recovery_evidence_exported"); n != 0 {
		t.Fatal("failed export success audited", n)
	}
	// Mint before breaking audit so step-up setup itself remains real and successful.
	grant := mintStepUp(t, srv, cookie, "POST "+path)
	if _, err := raw.Exec(`DROP TABLE audit_events`); err != nil {
		t.Fatal(err)
	}
	res := adminRequestWithStepUp(t, srv, "POST", path, cookie, valid, grant)
	if res.Code != 500 || res.Header().Get(syncauth.HeaderSignature) != "" || strings.Contains(res.Body.String(), "subjects") {
		t.Fatalf("unaudited evidence disclosed: %d %s", res.Code, res.Body.String())
	}
}
