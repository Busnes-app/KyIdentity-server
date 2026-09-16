package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/auth"
	"github.com/Busnes-app/kyidentity-server/internal/backup"
	"github.com/Busnes-app/kyidentity-server/internal/config"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/google/uuid"
)

// fakeRecovery stands in for KyRecovery: the real client refuses non-HTTPS and private hosts,
// so the handlers cannot be exercised against a test listener.
type fakeRecovery struct {
	result   backup.PairingResult
	claimErr error
	deposit  error
	got      []byte
}

func (f *fakeRecovery) ClaimPairing(context.Context, string, string, string, string) (backup.PairingResult, error) {
	return f.result, f.claimErr
}

func (f *fakeRecovery) Deposit(_ context.Context, _, _ string, container []byte) (backup.Receipt, error) {
	f.got = container
	if f.deposit != nil {
		return backup.Receipt{}, f.deposit
	}
	m, err := capsule.ReadUnverifiedManifest(container)
	if err != nil {
		return backup.Receipt{}, err
	}
	sum := sha256.Sum256(container)
	return backup.Receipt{CapsuleID: m.CapsuleID, Digest: hex.EncodeToString(sum[:]), SizeBytes: int64(len(container)), DepositedAt: time.Now().UTC()}, nil
}

func TestAdminBackupEndpoints(t *testing.T) {
	priv, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeRecovery{result: backup.PairingResult{APIToken: "kyrec_live_t", Key: backup.RecoveryKey{Public: priv.Public(), Threshold: 2, TotalShares: 3}}}
	prev := newRecoveryClient
	newRecoveryClient = func(*config.Config) recoveryClient { return fake }
	t.Cleanup(func() { newRecoveryClient = prev })

	srv, dbStore, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()

	adminPass := "AdminPassword123!"
	passHash, _ := auth.HashPassword(adminPass)
	adminUser := &store.User{
		ID: uuid.New().String(), Username: "admin_backup_test", DisplayName: "Admin Backup", Email: "admin@backup.test",
		PasswordHash: passHash, Role: "admin", Status: "active",
	}
	if err := dbStore.CreateUser(adminUser); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	adminSessionToken, _ := crypto.GenerateRandomHex(32)
	_ = dbStore.CreateSession(&store.Session{
		ID: uuid.New().String(), UserID: adminUser.ID, SessionTokenHash: crypto.HashSHA256(adminSessionToken),
		IPAddress: "127.0.0.1", UserAgent: "Go-Test", ExpiresAt: time.Now().Add(24 * time.Hour),
	})
	csrfToken := srv.middleware.IssueCSRFToken(adminSessionToken)
	adminCookie := &http.Cookie{Name: "kyidentity_session", Value: adminSessionToken}
	csrfCookie := &http.Cookie{Name: "kyidentity_csrf", Value: csrfToken}
	stepUp := func(method, path string) string { return mintStepUp(t, srv, adminSessionToken, method+" "+path) }

	do := func(method, path string, body []byte, withStepUp bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.AddCookie(adminCookie)
		req.AddCookie(csrfCookie)
		req.Header.Set("X-CSRF-Token", csrfToken)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if withStepUp {
			req.Header.Set(StepUpHeader, stepUp(method, path))
		}
		w := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(w, req)
		return w
	}
	auditHas := func(action, outcome string) bool {
		events, _, err := dbStore.ListAuditEvents(100, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range events {
			if e.Action == action && e.Outcome == outcome && e.ActorID == adminUser.ID {
				return true
			}
		}
		return false
	}

	t.Run("status before pairing", func(t *testing.T) {
		w := do("GET", "/api/admin/backup/status", nil, false)
		if w.Code != http.StatusOK {
			t.Fatalf("got %d: %s", w.Code, w.Body.String())
		}
		var resp map[string]any
		_ = json.NewDecoder(w.Body).Decode(&resp)
		if resp["app_name"] != "KySignOn" || resp["paired"] != false {
			t.Errorf("status %v", resp)
		}
	})

	t.Run("drill runs unpaired and says so", func(t *testing.T) {
		w := do("POST", "/api/admin/backup/drill", nil, false)
		if w.Code != http.StatusOK {
			t.Fatalf("got %d: %s", w.Code, w.Body.String())
		}
		var result backup.DrillResult
		_ = json.NewDecoder(w.Body).Decode(&result)
		if result.Passed {
			t.Error("unpaired drill passed")
		}
	})

	t.Run("export and deposit refuse while unpaired", func(t *testing.T) {
		if w := do("GET", "/api/admin/backup/export-capsule", nil, true); w.Code != http.StatusPreconditionFailed {
			t.Errorf("export: got %d: %s", w.Code, w.Body.String())
		}
		if w := do("POST", "/api/admin/backup/deposit", nil, true); w.Code != http.StatusPreconditionFailed {
			t.Errorf("deposit: got %d: %s", w.Code, w.Body.String())
		}
		if fake.got != nil {
			t.Error("bytes were sent while unpaired")
		}
	})

	t.Run("pairing refuses internal and non-https recovery URLs", func(t *testing.T) {
		for _, target := range []string{"http://recovery.example.test", "https://127.0.0.1:8095", "https://10.0.0.5", "https://user:pw@recovery.example.test", "https://recovery.example.test/#frag", "https://recovery.example.test/?a=b"} {
			body, _ := json.Marshal(map[string]string{"recovery_url": target, "pairing_code": "123456"})
			if w := do("POST", "/api/admin/backup/pair-remote", body, true); w.Code != http.StatusBadRequest {
				t.Errorf("%s: got %d: %s", target, w.Code, w.Body.String())
			}
		}
		if auditHas("admin.backup_remote_pair", "success") {
			t.Error("a refused URL was audited as a pairing")
		}
	})

	t.Run("pairing pins the key and stores the sealed token", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"recovery_url": "https://recovery.example.test", "pairing_code": "123456"})
		w := do("POST", "/api/admin/backup/pair-remote", body, true)
		if w.Code != http.StatusOK {
			t.Fatalf("got %d: %s", w.Code, w.Body.String())
		}
		var resp map[string]any
		_ = json.NewDecoder(w.Body).Decode(&resp)
		if resp["recovery_key_id"] != priv.Public().ID() {
			t.Errorf("pair response %v", resp)
		}
		if !auditHas("admin.backup_remote_pair", "success") {
			t.Error("pairing not audited")
		}
		if v, _ := dbStore.GetSetting("kyrecovery_token_enc"); v == "" || strings.Contains(v, "kyrec_live_t") {
			t.Errorf("token stored as %q", v)
		}
		// Re-pairing to a different key must not silently re-point the instance.
		other, _ := recoverykey.Generate()
		fake.result = backup.PairingResult{APIToken: "tok2", Key: backup.RecoveryKey{Public: other.Public(), Threshold: 2, TotalShares: 3}}
		if w := do("POST", "/api/admin/backup/pair-remote", body, true); w.Code != http.StatusConflict {
			t.Errorf("re-pair: got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("deposit seals to the pinned key, records the receipt, audits", func(t *testing.T) {
		w := do("POST", "/api/admin/backup/deposit", nil, true)
		if w.Code != http.StatusOK {
			t.Fatalf("got %d: %s", w.Code, w.Body.String())
		}
		var res backup.Result
		_ = json.NewDecoder(w.Body).Decode(&res)
		if res.Receipt == nil || res.LocalPath != "" {
			t.Fatalf("result %+v", res)
		}
		rcpt := *res.Receipt
		if _, files, err := capsule.Open(fake.got, priv, t.TempDir()); err != nil || len(files) < 5 {
			t.Fatalf("what the store received does not open with the suite key: %v", err)
		}
		if last, ok, _ := backup.LastDeposit(dbStore); !ok || last.CapsuleID != rcpt.CapsuleID {
			t.Errorf("last deposit %+v %v", last, ok)
		}
		if !auditHas("admin.backup_run", "success") {
			t.Error("backup not audited")
		}
		fake.deposit = errors.New(backup.ErrRemote.Error() + ": deposit rejected (429)")
		fake.deposit = errors.Join(backup.ErrRemote, fake.deposit)
		if w := do("POST", "/api/admin/backup/deposit", nil, true); w.Code != http.StatusBadGateway {
			t.Errorf("refused deposit: got %d: %s", w.Code, w.Body.String())
		}
		if again, _, _ := backup.LastDeposit(dbStore); again.CapsuleID != rcpt.CapsuleID {
			t.Error("a refused deposit replaced the last receipt")
		}
		fake.deposit = nil
	})

	t.Run("export is a sealed capsule and is audited", func(t *testing.T) {
		w := do("GET", "/api/admin/backup/export-capsule", nil, true)
		if w.Code != http.StatusOK {
			t.Fatalf("got %d: %s", w.Code, w.Body.String())
		}
		if _, _, err := capsule.Open(w.Body.Bytes(), priv, t.TempDir()); err != nil {
			t.Fatalf("export does not open with the suite key: %v", err)
		}
		if w.Header().Get("X-Recovery-Key-ID") != priv.Public().ID() {
			t.Errorf("header %q", w.Header().Get("X-Recovery-Key-ID"))
		}
		if !auditHas("admin.backup_capsule_export", "success") {
			t.Error("export not audited")
		}
	})

	t.Run("status after pairing", func(t *testing.T) {
		w := do("GET", "/api/admin/backup/status", nil, false)
		var resp map[string]any
		_ = json.NewDecoder(w.Body).Decode(&resp)
		if resp["paired"] != true || resp["recovery_key_id"] != priv.Public().ID() || resp["last_deposit"] == nil {
			t.Errorf("status %v", resp)
		}
	})

	t.Run("schedule is set in the UI and shows up in status", func(t *testing.T) {
		if w := do("PUT", "/api/admin/backup/schedule", []byte(`{"interval_sec":60}`), true); w.Code != http.StatusBadRequest {
			t.Errorf("below the floor: got %d: %s", w.Code, w.Body.String())
		}
		if w := do("PUT", "/api/admin/backup/schedule", []byte(`{"interval_sec":3600}`), true); w.Code != http.StatusOK {
			t.Fatalf("got %d: %s", w.Code, w.Body.String())
		}
		// 2^55 seconds wraps to exactly zero as a Duration; it must not read as "off".
		if w := do("PUT", "/api/admin/backup/schedule", []byte(`{"interval_sec":36028797018963968}`), true); w.Code != http.StatusBadRequest {
			t.Errorf("overflowing interval: got %d: %s", w.Code, w.Body.String())
		}
		w := do("GET", "/api/admin/backup/status", nil, false)
		var resp map[string]any
		_ = json.NewDecoder(w.Body).Decode(&resp)
		if resp["interval_sec"] != float64(3600) || resp["next_run_at"] == nil || resp["key_pinned"] != true {
			t.Errorf("status %v", resp)
		}
		if !auditHas("admin.backup_schedule", "success") {
			t.Error("schedule change not audited")
		}
		if w := do("PUT", "/api/admin/backup/schedule", []byte(`{"interval_sec":0}`), true); w.Code != http.StatusOK {
			t.Fatalf("off: got %d: %s", w.Code, w.Body.String())
		}
		w = do("GET", "/api/admin/backup/status", nil, false)
		resp = nil
		_ = json.NewDecoder(w.Body).Decode(&resp)
		if resp["interval_sec"] != float64(0) || resp["next_run_at"] != nil {
			t.Errorf("off status %v", resp)
		}
	})

	t.Run("a second key is refused by hand as well as by pairing", func(t *testing.T) {
		other, _ := recoverykey.Generate()
		body, _ := json.Marshal(map[string]any{"public_key": base64.StdEncoding.EncodeToString(other.Public().Bytes()), "threshold": 2, "total_shares": 3})
		if w := do("POST", "/api/admin/backup/pin-key", body, true); w.Code != http.StatusConflict {
			t.Errorf("got %d: %s", w.Code, w.Body.String())
		}
		if !auditHas("admin.backup_key_pin", "failure") {
			t.Error("refused pin not audited")
		}
	})

	t.Run("unpair forgets the token and the URL, keeps the key pin", func(t *testing.T) {
		if w := do("DELETE", "/api/admin/backup/pairing", nil, true); w.Code != http.StatusOK {
			t.Fatalf("got %d: %s", w.Code, w.Body.String())
		}
		if !auditHas("admin.backup_unpair", "success") {
			t.Error("unpair not audited")
		}
		w := do("GET", "/api/admin/backup/status", nil, false)
		var resp map[string]any
		_ = json.NewDecoder(w.Body).Decode(&resp)
		if resp["paired"] != false || resp["key_pinned"] != true || resp["recovery_key_id"] != priv.Public().ID() || resp["recovery_url"] != nil {
			t.Errorf("status after unpair %v", resp)
		}
		if _, err := dbStore.GetSetting("kyrecovery_token_enc"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("token still stored: %v", err)
		}
		fake.got = nil
		if w := do("POST", "/api/admin/backup/deposit", nil, true); w.Code != http.StatusPreconditionFailed || fake.got != nil {
			t.Errorf("deposit after unpair: got %d sent=%v: %s", w.Code, fake.got != nil, w.Body.String())
		}
		if w := do("DELETE", "/api/admin/backup/pairing", nil, true); w.Code != http.StatusPreconditionFailed {
			t.Errorf("second unpair: got %d", w.Code)
		}
		// Unpairing does not unpin: a different key is still refused, the same key is the way back.
		body, _ := json.Marshal(map[string]string{"recovery_url": "https://recovery.example.test", "pairing_code": "123456"})
		if w := do("POST", "/api/admin/backup/pair-remote", body, true); w.Code != http.StatusConflict {
			t.Fatalf("re-pair to another key after unpair: got %d: %s", w.Code, w.Body.String())
		}
		fake.result = backup.PairingResult{APIToken: "kyrec_live_t2", Key: backup.RecoveryKey{Public: priv.Public(), Threshold: 2, TotalShares: 3}}
		if w := do("POST", "/api/admin/backup/pair-remote", body, true); w.Code != http.StatusOK {
			t.Fatalf("re-pair to the same key: got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("step-up is required on the secret-bearing routes", func(t *testing.T) {
		for _, tc := range []struct{ method, path string }{{"GET", "/api/admin/backup/export-capsule"}, {"POST", "/api/admin/backup/deposit"}, {"POST", "/api/admin/backup/pair-remote"}, {"DELETE", "/api/admin/backup/pairing"}, {"POST", "/api/admin/backup/pin-key"}, {"PUT", "/api/admin/backup/schedule"}} {
			if w := do(tc.method, tc.path, []byte(`{}`), false); w.Code != http.StatusForbidden && w.Code != http.StatusUnauthorized {
				t.Errorf("%s %s without step-up: got %d", tc.method, tc.path, w.Code)
			}
		}
	})
}

// An instance with no KyRecovery pins the ceremony's public key by hand and backs up to a
// local directory. Nothing is sent anywhere, and the copy opens only with the suite shares.
func TestPinnedKeyBacksUpLocallyWithoutKyRecovery(t *testing.T) {
	priv, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeRecovery{}
	prev := newRecoveryClient
	newRecoveryClient = func(*config.Config) recoveryClient { return fake }
	t.Cleanup(func() { newRecoveryClient = prev })

	srv, dbStore, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	srv.cfg.BackupDir = filepath.Join(t.TempDir(), "capsules")
	srv.cfg.BackupKeep = 3
	admin := newUser(t, dbStore, "admin")
	cookie := newSession(t, dbStore, admin, time.Now().UTC().Add(time.Hour))

	bad, _ := json.Marshal(map[string]any{"public_key": "AAAA", "threshold": 2, "total_shares": 3})
	if w := adminRequest(t, srv, "POST", "/api/admin/backup/pin-key", cookie, string(bad)); w.Code != http.StatusBadRequest {
		t.Errorf("garbage key: got %d: %s", w.Code, w.Body.String())
	}
	pub := base64.StdEncoding.EncodeToString(priv.Public().Bytes())
	body, _ := json.Marshal(map[string]any{"public_key": pub, "threshold": 1, "total_shares": 1})
	if w := adminRequest(t, srv, "POST", "/api/admin/backup/pin-key", cookie, string(body)); w.Code != http.StatusBadRequest {
		t.Errorf("1-of-1: got %d: %s", w.Code, w.Body.String())
	}
	body, _ = json.Marshal(map[string]any{"public_key": pub, "threshold": 2, "total_shares": 3})
	if w := adminRequest(t, srv, "POST", "/api/admin/backup/pin-key", cookie, string(body)); w.Code != http.StatusOK {
		t.Fatalf("pin: got %d: %s", w.Code, w.Body.String())
	}
	w := adminRequest(t, srv, "POST", "/api/admin/backup/deposit", cookie, "")
	if w.Code != http.StatusOK {
		t.Fatalf("run: got %d: %s", w.Code, w.Body.String())
	}
	var res backup.Result
	_ = json.NewDecoder(w.Body).Decode(&res)
	if res.Receipt != nil || res.LocalPath == "" || fake.got != nil {
		t.Fatalf("unpaired run %+v sent=%v", res, fake.got != nil)
	}
	raw, err := os.ReadFile(res.LocalPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, files, err := capsule.Open(raw, priv, t.TempDir()); err != nil || len(files) < 5 {
		t.Fatalf("local copy does not open with the suite key: %v", err)
	}
	w = adminRequest(t, srv, "GET", "/api/admin/backup/status", cookie, "")
	var status map[string]any
	_ = json.NewDecoder(w.Body).Decode(&status)
	copies, _ := status["local_copies"].([]any)
	if status["paired"] != false || status["key_pinned"] != true || len(copies) != 1 {
		t.Errorf("status %v", status)
	}
}
