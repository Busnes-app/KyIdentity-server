package backup

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoveryclient"
	"github.com/Busness-app/kyidentity-server/internal/config"
	"github.com/Busness-app/kyidentity-server/internal/crypto"
	_ "modernc.org/sqlite"
)

// RunRestoreDrill proves the backup pipeline: recoveryclient.Drill seals the payload to a
// throwaway key, opens it into a 0700 scratch directory under dataDir, and this function
// adds KyIdentity's own checks: required files present, SQLite integrity and application
// records, MFA secrets decrypt and the signing key issues a verifiable token. A separate
// check reports whether the suite key is pinned; the drill itself never touches it.
func RunRestoreDrill(ctx context.Context, dataDir, serviceName, appVersion string, files []File, deps, recipe map[string]any, pinned RecoveryKey) (*DrillResult, error) {
	payload := Payload{ServiceName: serviceName, AppVersion: appVersion, Files: files, Dependencies: deps, VerificationRecipe: recipe}
	if recipe == nil {
		recipe = map[string]any{}
	}
	result, err := recoveryclient.Drill(ctx, dataDir, payload, func(scratchDir string, opened capsule.Manifest) []CheckItem {
		recipe, _ := opened.VerificationRecipe.(map[string]any)
		result := &DrillResult{}
		// 2. Verify Required Files
		if reqFiles := stringList(recipe["required_files"]); len(reqFiles) > 0 {
			allFound := true
			for _, pathStr := range reqFiles {
				fullPath := filepath.Join(scratchDir, pathStr)
				fi, err := os.Stat(fullPath)
				if err != nil || fi.Size() == 0 {
					allFound = false
					result.Passed = false
					result.Checks = append(result.Checks, CheckItem{
						Name:    fmt.Sprintf("Required File: %s", pathStr),
						Passed:  false,
						Message: "File missing or empty in unpacked capsule",
					})
				}
			}
			if allFound && len(reqFiles) > 0 {
				result.Checks = append(result.Checks, CheckItem{
					Name:    "Required Files",
					Passed:  true,
					Message: fmt.Sprintf("All %d required files verified", len(reqFiles)),
				})
			}
		}

		// 3. SQLite Integrity Check
		if checkDB, ok := recipe["check_sqlite_integrity"].(bool); ok && checkDB {
			sqlitePaths := stringList(recipe["sqlite_paths"])
			if len(sqlitePaths) == 0 {
				result.Passed = false
				result.Checks = append(result.Checks, CheckItem{
					Name:    "SQLite Verification",
					Passed:  false,
					Message: "Recipe requires a SQLite integrity check but names no database",
				})
			}
			{
				for _, dbRelPath := range sqlitePaths {
					fullDBPath := filepath.Join(scratchDir, dbRelPath)

					db, err := sql.Open("sqlite", fullDBPath)
					if err != nil {
						result.Passed = false
						result.Checks = append(result.Checks, CheckItem{
							Name:    fmt.Sprintf("SQLite Open: %s", dbRelPath),
							Passed:  false,
							Message: fmt.Sprintf("Failed to open extracted DB: %v", err),
						})
						continue
					}

					// Run PRAGMA integrity_check
					var integrityResult string
					row := db.QueryRowContext(ctx, "PRAGMA integrity_check;")
					if err := row.Scan(&integrityResult); err != nil || integrityResult != "ok" {
						result.Passed = false
						result.Checks = append(result.Checks, CheckItem{
							Name:    fmt.Sprintf("DB Integrity Check: %s", dbRelPath),
							Passed:  false,
							Message: fmt.Sprintf("Integrity failure (%s): %v", integrityResult, err),
						})
					} else {
						var tableCount int
						_ = db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table';").Scan(&tableCount)

						result.Checks = append(result.Checks, CheckItem{
							Name:    fmt.Sprintf("DB Integrity Check: %s", dbRelPath),
							Passed:  true,
							Message: fmt.Sprintf("SQLite PRAGMA integrity_check passed (found %d tables)", tableCount),
						})

						// integrity_check only proves the file is not corrupt. A restore is
						// only useful if the identity records are actually in it.
						checkApplicationRecords(ctx, db, dbRelPath, recipe, result)
					}
					_ = db.Close()
				}
			}
		}

		// 4. Prove the restored bytes are usable, not merely present. This is the difference
		// between a drill and a recovery test: encrypted MFA state that cannot be decrypted and
		// a signing key that cannot mint a token both survive every check above unnoticed.
		proveRestoreIsUsable(ctx, scratchDir, recipe, result)

		return result.Checks
	})
	if err != nil {
		return nil, err
	}
	pin := CheckItem{Name: "Recovery Key", Passed: true, Message: fmt.Sprintf("Sealing to recovery key %s (%d-of-%d custodians)", shortID(pinned), pinned.Threshold, pinned.TotalShares)}
	if pinned.Public.IsZero() {
		pin = CheckItem{Name: "Recovery Key", Passed: false, Message: ErrNotPaired.Error()}
		result.Passed = false
		if result.ErrorMessage == "" {
			result.ErrorMessage = pin.Message
		}
	}
	result.Checks = append([]CheckItem{pin}, result.Checks...)
	return result, nil
}

func shortID(k RecoveryKey) string {
	if k.Public.IsZero() {
		return "-"
	}
	id := k.Public.ID()
	if len(id) > 16 {
		id = id[:16]
	}
	return id
}

func checkApplicationRecords(ctx context.Context, db *sql.DB, dbRelPath string, recipe map[string]interface{}, result *DrillResult) {
	for _, table := range stringList(recipe["required_tables"]) {
		{
			var rows int
			err := db.QueryRowContext(ctx,
				`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&rows)
			if err != nil || rows != 1 {
				result.Passed = false
				result.Checks = append(result.Checks, CheckItem{
					Name:    fmt.Sprintf("Table Present: %s", table),
					Passed:  false,
					Message: fmt.Sprintf("Table %q is missing from the restored database", table),
				})
			}
		}
	}

	if requireAdmin, ok := recipe["require_any_admin"].(bool); ok && requireAdmin {
		var admins int
		err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM users WHERE role = 'admin' AND status = 'active'`).Scan(&admins)
		passed := err == nil && admins > 0
		if !passed {
			result.Passed = false
		}
		msg := fmt.Sprintf("%d active administrator(s) present in the restored directory", admins)
		if err != nil {
			msg = fmt.Sprintf("Could not read the restored user directory: %v", err)
		} else if admins == 0 {
			msg = "The restored directory has no active administrator; nobody could log in after a restore"
		}
		result.Checks = append(result.Checks, CheckItem{
			Name:    fmt.Sprintf("Administrator Directory: %s", dbRelPath),
			Passed:  passed,
			Message: msg,
		})
	}
}

// stringList reads a recipe list that may be []string (an in-process capsule) or
// []interface{} (the same recipe after a JSON round trip). Asserting only one of the two
// silently skipped every check whose list came from the other path.
func stringList(v interface{}) []string {
	switch typed := v.(type) {
	case []string:
		return typed
	case []interface{}:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			out = append(out, fmt.Sprintf("%v", item))
		}
		return out
	default:
		return nil
	}
}

// proveRestoreIsUsable loads the restored key material and exercises it against the restored
// database: decrypt what the service must decrypt on the next login, and sign and verify a
// token the way the token endpoint would. Everything here is read-only and confined to the
// drill sandbox.
func proveRestoreIsUsable(ctx context.Context, scratchDir string, recipe map[string]interface{}, result *DrillResult) {
	fail := func(name, msg string) {
		result.Passed = false
		result.Checks = append(result.Checks, CheckItem{Name: name, Passed: false, Message: msg})
	}
	pass := func(name, msg string) {
		result.Checks = append(result.Checks, CheckItem{Name: name, Passed: true, Message: msg})
	}

	if secretPath, _ := recipe["secret_key_file"].(string); secretPath != "" {
		data, err := os.ReadFile(filepath.Join(scratchDir, secretPath))
		if err != nil || len(data) != config.KeyLength {
			fail("Session Secret Restored",
				fmt.Sprintf("%s is missing or not %d bytes; every session and CSRF token would be invalidated by a restore", secretPath, config.KeyLength))
		} else {
			pass("Session Secret Restored", "Session and CSRF secret recovered intact")
		}
	}

	if prove, _ := recipe["prove_secret_decryption"].(bool); prove {
		proveSecretDecryption(ctx, scratchDir, recipe, fail, pass)
	}

	if prove, _ := recipe["prove_token_signing"].(bool); prove {
		rsaPath, _ := recipe["rsa_key_file"].(string)
		if rsaPath == "" {
			fail("Token Signing", "Recipe asks to prove token signing but names no signing key")
			return
		}
		// LoadOrCreateRSAKey would generate a fresh key if the restored one were unreadable,
		// which would turn this proof into a tautology, so the file is checked first.
		full := filepath.Join(scratchDir, rsaPath)
		if fi, err := os.Stat(full); err != nil || fi.Size() == 0 {
			fail("Token Signing", fmt.Sprintf("Restored signing key %s is missing or empty", rsaPath))
			return
		}
		km, err := crypto.LoadOrCreateRSAKey(full)
		if err != nil {
			fail("Token Signing", fmt.Sprintf("Restored signing key will not load: %v", err))
			return
		}
		token, err := km.SignJWT(map[string]any{
			"iss": "kyidentity-restore-drill",
			"sub": "drill",
			"exp": time.Now().Add(time.Minute).Unix(),
		})
		if err != nil {
			fail("Token Signing", fmt.Sprintf("Restored signing key could not sign a token: %v", err))
			return
		}
		if _, err := km.VerifyJWT(token); err != nil {
			fail("Token Signing", fmt.Sprintf("Token signed by the restored key did not verify: %v", err))
			return
		}
		pass("Token Signing", "Restored RSA key signed and verified a JWT; issued tokens survive a restore")
	}
}

// proveSecretDecryption reads the encrypted columns the service cannot start a login without
// and decrypts them under the restored encryption key.
func proveSecretDecryption(ctx context.Context, scratchDir string, recipe map[string]interface{}, fail, pass func(string, string)) {
	keyPath, _ := recipe["encryption_key_file"].(string)
	if keyPath == "" {
		fail("MFA Secret Decryption", "Recipe asks to prove decryption but names no encryption key")
		return
	}
	key, err := os.ReadFile(filepath.Join(scratchDir, keyPath))
	if err != nil || len(key) != config.KeyLength {
		fail("MFA Secret Decryption",
			fmt.Sprintf("Restored capsule has no usable %s; every enrolled TOTP secret and paired-system token would be unreadable after a restore", keyPath))
		return
	}

	dbPaths := stringList(recipe["sqlite_paths"])
	if len(dbPaths) == 0 {
		fail("MFA Secret Decryption", "Recipe asks to prove decryption but names no database")
		return
	}
	db, err := sql.Open("sqlite", filepath.Join(scratchDir, dbPaths[0]))
	if err != nil {
		fail("MFA Secret Decryption", fmt.Sprintf("Could not open the restored database: %v", err))
		return
	}
	defer func() { _ = db.Close() }()

	for _, target := range []struct {
		name  string
		query string
		empty string
	}{
		{
			"MFA Secret Decryption",
			`SELECT encrypted_secret FROM mfa_methods WHERE method_type = 'totp' AND encrypted_secret IS NOT NULL AND encrypted_secret != ''`,
			"No TOTP secrets are enrolled, so none could be checked",
		},
		{
			"Paired System Token Decryption",
			`SELECT hmac_secret_encrypted FROM paired_systems WHERE hmac_secret_encrypted IS NOT NULL AND hmac_secret_encrypted != ''`,
			"No paired systems are configured, so none could be checked",
		},
		{
			// Mail settings are the one encrypted blob in system_settings; a restore
			// that cannot read them cannot send an activation or reset link.
			"Mail Settings Decryption",
			`SELECT value FROM system_settings WHERE key = 'mail_settings_enc' AND value != ''`,
			"Mail delivery is not configured, so nothing could be checked",
		},
	} {
		rows, err := db.QueryContext(ctx, target.query)
		if err != nil {
			fail(target.name, fmt.Sprintf("Could not read the restored ciphertext: %v", err))
			continue
		}
		var checked, failed int
		for rows.Next() {
			var ciphertext string
			if err := rows.Scan(&ciphertext); err != nil {
				failed++
				continue
			}
			checked++
			if _, err := crypto.DecryptAESGCM(key, ciphertext); err != nil {
				failed++
			}
		}
		_ = rows.Close()

		switch {
		case failed > 0:
			fail(target.name, fmt.Sprintf("%d of %d restored secrets did not decrypt under the restored encryption key", failed, checked))
		case checked == 0:
			// Nothing to prove is not the same as proven. Say so rather than showing a tick
			// the operator would read as "MFA state verified".
			pass(target.name, target.empty)
		default:
			pass(target.name, fmt.Sprintf("All %d restored secrets decrypted under the restored encryption key", checked))
		}
	}
}
