package backup_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busnes-app/kyidentity-server/internal/backup"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/mail"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	_ "modernc.org/sqlite"
)

func drillChecks(t *testing.T, dataDir string, payload *backup.Payload, files []backup.File) map[string]backup.CheckItem {
	t.Helper()
	result, err := backup.RunRestoreDrill(context.Background(), dataDir, payload.ServiceName, payload.AppVersion, files, payload.Dependencies, payload.VerificationRecipe, backup.RecoveryKey{})
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string]backup.CheckItem{}
	for _, c := range result.Checks {
		checks[c.Name] = c
	}
	return checks
}

// A restore that can authenticate but has lost policy, group membership, app linkage,
// remote identity mappings, job state or the encrypted relay configuration is not a
// restore of this directory. The drill has to say so.
func TestDrillCoversLifecycleStateAndEncryptedConfiguration(t *testing.T) {
	cfg, st := instance(t)
	if err := mail.Save(st, cfg.EncryptionKey, &mail.Settings{Host: "smtp.example.test", Port: 587, Username: "sso", Password: "relay-password", From: "sso@example.test", Security: "starttls"}); err != nil {
		t.Fatal(err)
	}
	payload, err := backup.CollectSealable(cfg, st, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}

	checks := drillChecks(t, cfg.DataDir, payload, payload.Files)
	if c := checks["Mail Settings Decryption"]; !c.Passed || strings.Contains(c.Message, "not configured") {
		t.Fatalf("configured relay was not proven readable: %+v", c)
	}
	for name, c := range checks {
		if strings.HasPrefix(name, "Table Present") && !c.Passed {
			t.Errorf("%s: %s", name, c.Message)
		}
	}

	// Losing one lifecycle table must fail the drill by name, not pass quietly because
	// the users table happens to be intact.
	for _, table := range []string{"app_user_assignments", "enrollment_policies", "scim_user_links", "sync_resource_state"} {
		files := withoutTable(t, payload.Files, table)
		checks := drillChecks(t, cfg.DataDir, payload, files)
		c, ok := checks["Table Present: "+table]
		if !ok || c.Passed {
			t.Errorf("a restore missing %s drilled clean: %+v", table, c)
		}
	}
}

// A capsule taken before row-bound sealing carries legacy secrets: it must drill clean,
// restore, and be sealed by the startup migration. Once a database is sealed, a legacy
// blob planted in it fails the drill, as it fails the service's read path.
func TestDrillAndRestoreOfALegacyCapsule(t *testing.T) {
	cfg, st := instance(t)
	legacy := func(plain string) string {
		c, err := crypto.EncryptAESGCM(cfg.EncryptionKey, []byte(plain))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if err := st.CreateUser(&store.User{ID: "u1", Username: "u1", DisplayName: "U", Email: "u1@example.test", PasswordHash: "x", Role: "user", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetMFAMethod(&store.MFAMethod{ID: "m1", UserID: "u1", MethodType: "totp", EncryptedSecret: legacy("JBSWY3DPEHPK3PXP")}, nil); err != nil {
		t.Fatal(err)
	}
	if err := st.CreatePairedSystem(&store.PairedSystem{ID: "sys1", Name: "sys1", SystemType: "scim", CallbackURL: "https://a.example.test", HMACSecretEncrypted: legacy("token"), Status: "active"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting(store.MailSettingKey, legacy(`{"host":"smtp.example.test","port":587,"from":"sso@example.test","security":"starttls"}`)); err != nil {
		t.Fatal(err)
	}
	secretChecks := []string{"MFA Secret Decryption", "Paired System Token Decryption", "Mail Settings Decryption"}
	payload, err := backup.CollectSealable(cfg, st, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	checks := drillChecks(t, cfg.DataDir, payload, payload.Files)
	for _, name := range secretChecks {
		if c := checks[name]; !c.Passed || !strings.Contains(c.Message, "All 1") {
			t.Fatalf("legacy capsule %s: %+v", name, c)
		}
	}

	// Restore: the capsule's database reopened and sealed as startup does.
	var dbBytes []byte
	for _, f := range payload.Files {
		if strings.HasSuffix(f.Path, ".db") {
			dbBytes = f.Data
		}
	}
	restoredPath := filepath.Join(t.TempDir(), "restored.db")
	if err := os.WriteFile(restoredPath, dbBytes, 0600); err != nil {
		t.Fatal(err)
	}
	restored, err := store.New(restoredPath)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if err := restored.SealLegacySecrets(cfg.EncryptionKey); err != nil {
		t.Fatal(err)
	}
	if got, err := mail.Load(restored, cfg.EncryptionKey); err != nil || got.Host != "smtp.example.test" {
		t.Fatalf("restored mail settings: %+v %v", got, err)
	}
	m, err := restored.GetMFAMethod("u1", "totp")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := crypto.Open(cfg.EncryptionKey, store.SealTOTP, "u1", m.EncryptedSecret); err != nil || string(got) != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("restored TOTP: %v", err)
	}

	// The live instance migrates too; then a planted legacy TOTP blob fails the drill.
	if err := st.SealLegacySecrets(cfg.EncryptionKey); err != nil {
		t.Fatal(err)
	}
	if err := st.SetMFAMethod(&store.MFAMethod{ID: "m1", UserID: "u1", MethodType: "totp", EncryptedSecret: legacy("JBSWY3DPEHPK3PXP")}, nil); err != nil {
		t.Fatal(err)
	}
	payload, err = backup.CollectSealable(cfg, st, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	checks = drillChecks(t, cfg.DataDir, payload, payload.Files)
	if c := checks["MFA Secret Decryption"]; c.Passed {
		t.Fatalf("planted legacy blob drilled clean: %+v", c)
	}
	for _, name := range secretChecks[1:] {
		if c := checks[name]; !c.Passed {
			t.Fatalf("sealed %s: %+v", name, c)
		}
	}
}

// withoutTable returns the payload with one table dropped from the database file, which
// is what a partial or wrongly filtered backup would produce.
func withoutTable(t *testing.T, files []backup.File, table string) []backup.File {
	t.Helper()
	out := make([]backup.File, len(files))
	copy(out, files)
	for i, f := range out {
		if !strings.HasSuffix(f.Path, ".db") {
			continue
		}
		path := filepath.Join(t.TempDir(), "damaged.db")
		if err := os.WriteFile(path, f.Data, 0600); err != nil {
			t.Fatal(err)
		}
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`DROP TABLE IF EXISTS ` + table); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		out[i].Data = data
		return out
	}
	t.Fatal("payload carries no database")
	return nil
}
