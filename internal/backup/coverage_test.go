package backup_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busness-app/kyidentity-server/internal/backup"
	"github.com/Busness-app/kyidentity-server/internal/mail"
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
