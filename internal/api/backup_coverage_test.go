package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/keyfile"
	"github.com/Busnes-app/ky-primitives/recoveryclient"
	"github.com/Busnes-app/ky-primitives/recoverykey"
	"github.com/Busnes-app/kyidentity-server/internal/backup"
	"github.com/Busnes-app/kyidentity-server/internal/config"
)

// covBackupServer is a test server whose KyRecovery client is fake, with an admin session.
func covBackupServer(t *testing.T, fake *fakeRecovery) (*Server, string, func()) {
	t.Helper()
	prev := newRecoveryClient
	newRecoveryClient = func(*config.Config) recoveryClient { return fake }
	t.Cleanup(func() { newRecoveryClient = prev })
	srv, db, _, _, _, cleanup := setupTestServer(t)
	return srv, newSession(t, db, newUser(t, db, "admin"), time.Now().UTC().Add(time.Hour)), cleanup
}

func covBackupError(t *testing.T, rr *httptest.ResponseRecorder, status int, fragment string) {
	t.Helper()
	if rr.Code != status {
		t.Fatalf("want %d, got %d: %s", status, rr.Code, rr.Body.String())
	}
	if msg := decodeAPIError(t, rr)["error"]; !strings.Contains(msg, fragment) {
		t.Fatalf("error %q does not mention %q", msg, fragment)
	}
}

func covStatus(t *testing.T, srv *Server, cookie string) map[string]any {
	t.Helper()
	rr := call(t, srv, cookie, "GET", "/api/admin/backup/status")
	var out map[string]any
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &out) != nil {
		t.Fatalf("status: %d %s", rr.Code, rr.Body.String())
	}
	return out
}

// A recovery.pub swapped on disk for a different key must never be sealed to: the pin in the
// settings decides, so export and deposit refuse and the status names the mismatch.
func TestBackupRefusesSwappedRecoveryKey(t *testing.T) {
	srv, cookie, cleanup := covBackupServer(t, &fakeRecovery{})
	defer cleanup()
	srv.cfg.BackupDir = t.TempDir()
	pinned, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	attacker, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"public_key": base64.StdEncoding.EncodeToString(pinned.Public().Bytes()), "threshold": 2, "total_shares": 3})
	if rr := adminRequest(t, srv, "POST", "/api/admin/backup/pin-key", cookie, string(body)); rr.Code != http.StatusOK {
		t.Fatalf("pin: %d %s", rr.Code, rr.Body.String())
	}
	path := recoveryclient.RecoveryKeyPath(srv.cfg.DataDir)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := keyfile.Store(path, attacker.Public().Bytes(), keyfile.Raw); err != nil {
		t.Fatal(err)
	}

	covBackupError(t, adminRequest(t, srv, "GET", "/api/admin/backup/export-capsule", cookie, ""), http.StatusConflict, "does not match the pinned key")
	covBackupError(t, adminRequest(t, srv, "POST", "/api/admin/backup/deposit", cookie, ""), http.StatusConflict, "does not match the pinned key")
	if entries, _ := os.ReadDir(srv.cfg.BackupDir); len(entries) != 0 {
		t.Fatalf("a capsule was written under the swapped key: %v", entries)
	}
	st := covStatus(t, srv, cookie)
	if st["key_pinned"] != false || !strings.Contains(st["recovery_key_error"].(string), "does not match") {
		t.Fatalf("status hides the swapped key: %v", st)
	}
}

// Once paired, a missing recovery.pub stops deposits with a precondition error, the status
// says what to restore, and nothing reaches KyRecovery.
func TestBackupPairedButKeyFileMissing(t *testing.T) {
	priv, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeRecovery{result: backup.PairingResult{APIToken: "kyrec_live_t", Key: backup.RecoveryKey{Public: priv.Public(), Threshold: 2, TotalShares: 3}}}
	srv, cookie, cleanup := covBackupServer(t, fake)
	defer cleanup()
	if rr := adminRequest(t, srv, "POST", "/api/admin/backup/pair-remote", cookie, `{"recovery_url":"https://recovery.example.com","pairing_code":"123456"}`); rr.Code != http.StatusOK {
		t.Fatalf("pair: %d %s", rr.Code, rr.Body.String())
	}
	if err := os.Remove(recoveryclient.RecoveryKeyPath(srv.cfg.DataDir)); err != nil {
		t.Fatal(err)
	}
	st := covStatus(t, srv, cookie)
	if msg, _ := st["recovery_key_error"].(string); !strings.Contains(msg, "recovery.pub is missing") {
		t.Fatalf("status: %v", st)
	}
	covBackupError(t, adminRequest(t, srv, "POST", "/api/admin/backup/deposit", cookie, ""), http.StatusPreconditionFailed, "recovery public key is missing")
	covBackupError(t, adminRequest(t, srv, "GET", "/api/admin/backup/export-capsule", cookie, ""), http.StatusPreconditionFailed, "Not paired")
	if fake.got != nil {
		t.Fatal("a capsule reached KyRecovery without its pinned key file")
	}
}

// Malformed bodies are refused before anything is stored, and a pairing KyRecovery
// rejects is audited as a failed attempt rather than silently dropped.
func TestBackupRequestValidation(t *testing.T) {
	fake := &fakeRecovery{claimErr: errors.New("pairing code expired")}
	srv, cookie, cleanup := covBackupServer(t, fake)
	defer cleanup()
	covBackupError(t, adminRequest(t, srv, "POST", "/api/admin/backup/pair-remote", cookie, `{`), 400, "Invalid JSON")
	covBackupError(t, adminRequest(t, srv, "POST", "/api/admin/backup/pin-key", cookie, `{`), 400, "Invalid JSON")
	covBackupError(t, adminRequest(t, srv, "PUT", "/api/admin/backup/schedule", cookie, `{"interval_sec":"x"}`), 400, "Invalid JSON")
	covBackupError(t, adminRequest(t, srv, "POST", "/api/admin/backup/pair-remote", cookie, `{"recovery_url":"https://recovery.example.com","pairing_code":"654321"}`), 400, "pairing code expired")
	failures := 0
	for _, e := range auditRows(t, srv.store, "admin.backup_remote_pair") {
		if e.Outcome == "failure" && strings.Contains(e.DetailsJSON, "pairing code expired") {
			failures++
		}
	}
	if failures != 1 {
		t.Fatalf("rejected pairing audited %d times", failures)
	}
	if st := covStatus(t, srv, cookie); st["paired"] != false || st["key_pinned"] != false {
		t.Fatalf("a rejected pairing left state behind: %v", st)
	}
}

// Each backup handler refuses a method it does not serve, independent of the router.
func TestBackupHandlersRefuseWrongMethod(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	h := NewBackupHandler(srv.cfg, db, srv.audit, srv.middleware)
	for name, fn := range map[string]http.HandlerFunc{
		"drill": h.RunDrill, "pair": h.PairRemote, "deposit": h.Deposit,
		"unpair": h.Unpair, "pin": h.PinKey, "schedule": h.SetSchedule,
	} {
		rr := httptest.NewRecorder()
		fn(rr, httptest.NewRequest("PATCH", "/api/admin/backup/"+name, strings.NewReader("{}")))
		if rr.Code != http.StatusMethodNotAllowed || decodeAPIError(t, rr)["error"] != "method_not_allowed" {
			t.Errorf("%s: %d %s", name, rr.Code, rr.Body.String())
		}
	}
}
