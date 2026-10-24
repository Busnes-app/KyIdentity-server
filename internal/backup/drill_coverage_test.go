package backup_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busnes-app/kyidentity-server/internal/backup"
	"github.com/Busnes-app/kyidentity-server/internal/config"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// recipeDrill runs the drill over the given files with a hand-written recipe and returns
// the checks by name and whether the drill passed.
func recipeDrill(t *testing.T, files []backup.File, recipe map[string]any) (map[string]backup.CheckItem, bool) {
	t.Helper()
	result, err := backup.RunRestoreDrill(context.Background(), t.TempDir(), config.DefaultAppName, "1.0.0", files, nil, recipe, backup.RecoveryKey{})
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string]backup.CheckItem{}
	for _, c := range result.Checks {
		checks[c.Name] = c
	}
	return checks, result.Passed
}

// mustFail asserts the named check exists, failed, and says why.
func mustFail(t *testing.T, checks map[string]backup.CheckItem, name, why string) {
	t.Helper()
	c, ok := checks[name]
	if !ok || c.Passed || !strings.Contains(c.Message, why) {
		t.Fatalf("%s: %+v (present %v), want a failure mentioning %q; all checks: %+v", name, c, ok, why, checks)
	}
}

// fileData returns the payload member at path.
func fileData(t *testing.T, files []backup.File, path string) []byte {
	t.Helper()
	for _, f := range files {
		if f.Path == path {
			return f.Data
		}
	}
	t.Fatalf("payload has no %s", path)
	return nil
}

// replaceFile returns files with path's content replaced, or the member dropped when data
// is nil.
func replaceFile(files []backup.File, path string, data []byte) []backup.File {
	out := make([]backup.File, 0, len(files))
	for _, f := range files {
		if f.Path == path {
			if data == nil {
				continue
			}
			f.Data = data
		}
		out = append(out, f)
	}
	return out
}

// A capsule that lost a member, carries a corrupt database or a damaged key must fail the
// drill by name. Each of these is a backup that would look fine until the day it is needed.
func TestDrillFailsADamagedCapsuleByName(t *testing.T) {
	cfg, st := instance(t)
	payload, err := backup.CollectSealable(cfg, st, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	recipe := payload.VerificationRecipe

	t.Run("missing signing key", func(t *testing.T) {
		checks, passed := recipeDrill(t, replaceFile(payload.Files, "data/jwt_rs256.key", nil), recipe)
		mustFail(t, checks, "Required File: data/jwt_rs256.key", "missing or empty")
		mustFail(t, checks, "Token Signing", "missing or empty")
		if passed {
			t.Fatal("a capsule without its signing key passed")
		}
	})
	t.Run("garbage signing key", func(t *testing.T) {
		checks, _ := recipeDrill(t, replaceFile(payload.Files, "data/jwt_rs256.key", []byte("not a PEM key")), recipe)
		mustFail(t, checks, "Token Signing", "will not load")
	})
	t.Run("truncated session secret", func(t *testing.T) {
		checks, _ := recipeDrill(t, replaceFile(payload.Files, "data/secret.key", []byte("short")), recipe)
		mustFail(t, checks, "Session Secret Restored", "not 32 bytes")
	})
	t.Run("truncated encryption key", func(t *testing.T) {
		checks, _ := recipeDrill(t, replaceFile(payload.Files, "data/encryption.key", []byte("short")), recipe)
		mustFail(t, checks, "MFA Secret Decryption", "no usable data/encryption.key")
	})
	t.Run("wrong encryption key", func(t *testing.T) {
		if err := st.SetMFAMethod(&store.MFAMethod{ID: "m1", UserID: mustAdminID(t, st), MethodType: "totp", EncryptedSecret: sealedTOTP(t, cfg, mustAdminID(t, st))}, nil); err != nil {
			t.Fatal(err)
		}
		p, err := backup.CollectSealable(cfg, st, "1.0.0")
		if err != nil {
			t.Fatal(err)
		}
		other := make([]byte, config.KeyLength)
		copy(other, "an entirely different 32-byte k")
		checks, _ := recipeDrill(t, replaceFile(p.Files, "data/encryption.key", other), p.VerificationRecipe)
		mustFail(t, checks, "MFA Secret Decryption", "1 of 1 restored secrets did not decrypt")
	})
	t.Run("corrupt database", func(t *testing.T) {
		checks, _ := recipeDrill(t, replaceFile(payload.Files, "data/kyidentity.db", []byte(strings.Repeat("not a database ", 100))), recipe)
		mustFail(t, checks, "DB Integrity Check: data/kyidentity.db", "Integrity failure")
		mustFail(t, checks, "MFA Secret Decryption", "Could not read the restored ciphertext")
	})
}

// mustAdminID returns the instance fixture's administrator.
func mustAdminID(t *testing.T, st *store.Store) string {
	t.Helper()
	u, err := st.GetUserByUsername("admin")
	if err != nil || u == nil {
		t.Fatal(err)
	}
	return u.ID
}

// A restored directory with no active administrator, or no user table at all, cannot be
// signed into; the drill must say which.
func TestDrillRequiresAnAdministrator(t *testing.T) {
	cfg, st := instance(t)
	payload, err := backup.CollectSealable(cfg, st, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	db := fileData(t, payload.Files, "data/kyidentity.db")
	recipe := map[string]any{"check_sqlite_integrity": true, "sqlite_paths": []string{"data/kyidentity.db"}, "require_any_admin": true}

	demoted := editDB(t, db, `UPDATE users SET status = 'disabled'`)
	checks, passed := recipeDrill(t, replaceFile(payload.Files, "data/kyidentity.db", demoted), recipe)
	mustFail(t, checks, "Administrator Directory: data/kyidentity.db", "no active administrator")
	if passed {
		t.Fatal("a directory nobody can sign into passed the drill")
	}

	noUsers := editDB(t, db, `DROP TABLE users`)
	checks, _ = recipeDrill(t, replaceFile(payload.Files, "data/kyidentity.db", noUsers), recipe)
	mustFail(t, checks, "Administrator Directory: data/kyidentity.db", "Could not read the restored user directory")
}

// editDB applies stmt to a copy of a database image and returns the new image.
func editDB(t *testing.T, image []byte, stmt string) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "edit.db")
	if err := os.WriteFile(path, image, 0600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(stmt); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// A recipe that asks for a proof but omits what the proof needs fails that check rather
// than skipping it: a silently skipped check reads as a passed one.
func TestDrillFailsAnIncompleteRecipe(t *testing.T) {
	files := []backup.File{{Path: "data/a.txt", Data: []byte("a"), Mode: 0600}}
	cases := []struct {
		name   string
		recipe map[string]any
		check  string
		why    string
	}{
		{"integrity without database", map[string]any{"check_sqlite_integrity": true}, "SQLite Verification", "names no database"},
		{"decryption without key", map[string]any{"prove_secret_decryption": true}, "MFA Secret Decryption", "names no encryption key"},
		{"decryption without database", map[string]any{"prove_secret_decryption": true, "encryption_key_file": "data/k"}, "MFA Secret Decryption", "names no database"},
		{"signing without key", map[string]any{"prove_token_signing": true}, "Token Signing", "names no signing key"},
		{"required file missing", map[string]any{"required_files": []any{"data/a.txt", "data/b.txt"}}, "Required File: data/b.txt", "missing or empty"},
	}
	key := []backup.File{{Path: "data/k", Data: make([]byte, config.KeyLength), Mode: 0600}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			checks, passed := recipeDrill(t, append(append([]backup.File{}, files...), key...), c.recipe)
			mustFail(t, checks, c.check, c.why)
			if passed {
				t.Fatal("an incomplete recipe passed the drill")
			}
		})
	}
	// A recipe list that survived a JSON round trip ([]any) is honoured like a []string,
	// and a recipe whose list has the wrong type is ignored rather than crashing the drill.
	checks, _ := recipeDrill(t, files, map[string]any{"required_files": []any{"data/a.txt"}})
	if c := checks["Required Files"]; !c.Passed || !strings.Contains(c.Message, "All 1 required files") {
		t.Fatalf("[]any recipe list: %+v", checks)
	}
	checks, _ = recipeDrill(t, files, map[string]any{"required_files": "data/a.txt"})
	if _, ok := checks["Required Files"]; ok {
		t.Fatalf("a string was treated as a file list: %+v", checks)
	}
}

// A drill with no recipe still proves the capsule seals and opens, but an unpaired
// instance never passes: the Recovery Key check fails and names the cause.
func TestDrillWithoutRecipeOrPin(t *testing.T) {
	files := []backup.File{{Path: "data/a.txt", Data: []byte("a"), Mode: 0600}}
	result, err := backup.RunRestoreDrill(context.Background(), t.TempDir(), config.DefaultAppName, "1.0.0", files, nil, nil, backup.RecoveryKey{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Passed || len(result.Checks) == 0 || result.Checks[0].Name != "Recovery Key" || result.Checks[0].Passed {
		t.Fatalf("unpaired drill: %+v", result)
	}
	if !strings.Contains(result.ErrorMessage, backup.ErrNotPaired.Error()) {
		t.Fatalf("error message %q does not name the missing pin", result.ErrorMessage)
	}
}

// A drill that cannot run at all is an error, not a failed result that could be mistaken
// for a damaged capsule.
func TestDrillExecutionErrors(t *testing.T) {
	files := []backup.File{{Path: "data/a.txt", Data: []byte("a"), Mode: 0600}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if res, err := backup.RunRestoreDrill(ctx, t.TempDir(), config.DefaultAppName, "1.0.0", files, nil, nil, backup.RecoveryKey{}); !errors.Is(err, context.Canceled) || res != nil {
		t.Fatalf("cancelled drill: %+v %v", res, err)
	}
	if res, err := backup.RunRestoreDrill(context.Background(), "", config.DefaultAppName, "1.0.0", files, nil, nil, backup.RecoveryKey{}); err == nil || res != nil {
		t.Fatalf("drill without a scratch root: %+v %v", res, err)
	}
}

// sealedTOTP is a TOTP secret sealed to its row the way the store writes it.
func sealedTOTP(t *testing.T, cfg *config.Config, userID string) string {
	t.Helper()
	c, err := crypto.Seal(cfg.EncryptionKey, store.SealTOTP, userID, []byte("JBSWY3DPEHPK3PXP"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}
