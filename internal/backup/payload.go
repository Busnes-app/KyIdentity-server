package backup

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Busness-app/ky-primitives/recoveryclient"
	"github.com/Busness-app/kyidentity-server/internal/config"
)

// Relative paths inside a capsule. The restore drill and the restore command both have to
// find the same files the collector wrote.
const (
	dbRelPath        = "data/kyidentity.db"
	keyRelPath       = "data/jwt_rs256.key"
	encKeyRelPath    = "data/encryption.key"
	secretKeyRelPath = "data/secret.key"
	recoveryPubPath  = "data/recovery.pub"
	configRelPath    = "config/kyidentity.json"
)

// Snapshotter produces a transactionally consistent copy of the live database. The store
// implements it with VACUUM INTO through the live connection: copying the main file misses
// every commit still in the -wal.
type Snapshotter interface {
	SnapshotTo(destPath string) error
}

// Members lists what a capsule from this instance carries, in the order CollectSealable
// packs it, so the admin screen can say what is being backed up without sealing anything.
func Members(cfg *config.Config) []string {
	m := []string{dbRelPath, keyRelPath, encKeyRelPath, secretKeyRelPath}
	if _, err := os.Stat(RecoveryKeyPath(cfg.DataDir)); err == nil {
		m = append(m, recoveryPubPath)
	}
	return append(m, configRelPath)
}

// CollectSealable gathers everything a restore needs. Every member is secret or the means to
// one, so the payload leaves the process only inside a sealed capsule.
//
// A missing database, signing key or deployment key is fatal. A well-formed capsule that
// cannot restore the service is worse than no capsule: the drill passes, the operator
// believes they are covered, and the gap surfaces only when production is already gone.
func CollectSealable(cfg *config.Config, snap Snapshotter, appVersion string) (*recoveryclient.Payload, error) {
	if cfg.DBPath == "" {
		return nil, errors.New("backup requires a database path; none is configured")
	}
	if snap == nil {
		return nil, errors.New("backup requires a live database handle to snapshot")
	}
	var files []recoveryclient.File

	scratch, err := os.MkdirTemp(cfg.DataDir, "snapshot-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create snapshot scratch directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	snapPath := filepath.Join(scratch, "kyidentity.db")
	if err := snap.SnapshotTo(snapPath); err != nil {
		return nil, err
	}
	dbBytes, err := os.ReadFile(snapPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read database snapshot: %w", err)
	}
	if len(dbBytes) == 0 {
		return nil, errors.New("database snapshot is empty")
	}
	files = append(files, recoveryclient.File{Path: dbRelPath, Data: dbBytes, Mode: 0600})

	// The RSA signing key: without it every issued token and OIDC client breaks on restore.
	if cfg.RSAKeyPath == "" {
		return nil, errors.New("backup requires an RSA signing key path; none is configured")
	}
	keyBytes, err := os.ReadFile(cfg.RSAKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read RSA signing key %s: %w", cfg.RSAKeyPath, err)
	}
	if len(keyBytes) == 0 {
		return nil, fmt.Errorf("RSA signing key %s is empty", cfg.RSAKeyPath)
	}
	files = append(files, recoveryclient.File{Path: keyRelPath, Data: keyBytes, Mode: 0600})

	// The deployment key material. The database ships every TOTP secret and paired-system
	// token encrypted under the encryption key, so a capsule without it restores a directory
	// whose MFA state is permanently unreadable. The secret key: without it every session
	// and CSRF token minted before the restore is silently invalid. Taken from the loaded
	// config, so a deployment that supplies them by environment is backed up as faithfully.
	for _, k := range []struct {
		relPath  string
		material []byte
		name     string
	}{
		{encKeyRelPath, cfg.EncryptionKey, "encryption key"},
		{secretKeyRelPath, cfg.SecretKey, "secret key"},
	} {
		if len(k.material) != config.KeyLength {
			return nil, fmt.Errorf("backup requires a %d-byte %s; the loaded one is %d bytes",
				config.KeyLength, k.name, len(k.material))
		}
		files = append(files, recoveryclient.File{Path: k.relPath, Data: k.material, Mode: 0600})
	}

	// The suite recovery public key rides along when this instance is paired, so a restore
	// comes back paired rather than steering the operator into a re-pair.
	if pub, err := os.ReadFile(RecoveryKeyPath(cfg.DataDir)); err == nil {
		files = append(files, recoveryclient.File{Path: recoveryPubPath, Data: pub, Mode: 0600})
	}

	cfgJSON, err := json.MarshalIndent(map[string]any{
		"app_name":                cfg.AppName,
		"version":                 appVersion,
		"port":                    cfg.Port,
		"issuer_url":              cfg.IssuerURL,
		"data_dir":                cfg.DataDir,
		"allow_private_callbacks": cfg.AllowPrivateCallbacks,
		"secure_cookies":          cfg.SecureCookies,
		"session_ttl_sec":         int64(cfg.SessionTTL / time.Second),
		"session_idle_ttl_sec":    int64(cfg.SessionIdleTTL / time.Second),
	}, "", "  ")
	if err != nil {
		return nil, err
	}
	files = append(files, recoveryclient.File{Path: configRelPath, Data: cfgJSON, Mode: 0600})

	portNum, _ := strconv.Atoi(cfg.Port)
	if portNum == 0 {
		portNum = 5867
	}
	reqFiles := make([]string, 0, len(files))
	for _, f := range files {
		reqFiles = append(reqFiles, f.Path)
	}
	return &recoveryclient.Payload{
		ServiceName: cfg.AppName,
		AppVersion:  appVersion,
		Files:       files,
		Dependencies: map[string]any{
			"ports": []int{portNum},
			"env":   []string{"KYIDENTITY_PORT", "KYIDENTITY_ISSUER_URL"},
		},
		VerificationRecipe: map[string]any{
			"check_sqlite_integrity": true,
			"sqlite_paths":           []string{dbRelPath},
			"required_files":         reqFiles,
			// The drill asserts these tables exist and the admin directory is non-empty.
			// PRAGMA integrity_check only proves the file is not corrupt. A restore that
			// can authenticate but has lost policy, group membership, app linkage or the
			// remote identity mappings is not a restore of this directory.
			"required_tables": []string{
				"users", "oauth_clients", "mfa_methods", "paired_systems",
				"enrollment_policies", "directory_groups", "group_memberships",
				"app_registry", "app_user_assignments", "app_group_assignments", "app_roles",
				"admin_delegations", "access_requests",
				"scim_connectors", "scim_user_links", "sync_resource_state", "sync_reconcile_jobs",
				"audit_events", "alerts", "system_settings",
			},
			"require_any_admin": true,
			// Proving the restored bytes are also usable: the encrypted columns still read
			// and the service could issue a token.
			"encryption_key_file":     encKeyRelPath,
			"secret_key_file":         secretKeyRelPath,
			"rsa_key_file":            keyRelPath,
			"prove_secret_decryption": true,
			"prove_token_signing":     true,
			"expected_env":            []string{"KYIDENTITY_PORT", "KYIDENTITY_ISSUER_URL"},
			"expected_ports":          []int{portNum},
		},
	}, nil
}
