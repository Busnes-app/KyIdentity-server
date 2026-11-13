package backup

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Busnes-app/ky-primitives/capsule"
	"github.com/Busnes-app/ky-primitives/recoveryclient"
	"github.com/Busnes-app/kyidentity-server/internal/config"
	"github.com/Busnes-app/kyidentity-server/internal/mfa"
)

// Relative paths inside a capsule. The restore drill and the restore command both have to
// find the same files the collector wrote.
const (
	dbRelPath        = "data/kyidentity.db"
	keyRelPath       = "data/jwt_rs256.key"
	encKeyRelPath    = "data/encryption.key"
	secretKeyRelPath = "data/secret.key"
	recoveryPubPath  = "data/recovery.pub"
	vapidKeyRelPath  = "data/" + config.VAPIDKeyFile
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
	if _, err := os.Stat(cfg.VAPIDKeyPath); err == nil {
		m = append(m, vapidKeyRelPath)
	}
	keys, _ := relayKeys(cfg.DataDir)
	for _, k := range keys {
		m = append(m, "data/"+k)
	}
	for _, k := range envRelayKeys(cfg) {
		if !slices.Contains(m, k.Path) {
			m = append(m, k.Path)
		}
	}
	return append(m, configRelPath)
}

// envRelayKeys are the relay keys configured by environment, under the file name the
// relay sender reads when the variable is not set.
func envRelayKeys(cfg *config.Config) []recoveryclient.File {
	var out []recoveryclient.File
	for _, k := range []struct{ transport, url, key string }{
		{"fcm", cfg.PushRelayURL, cfg.PushRelayKey},
		{"apns", cfg.APNSRelayURL, cfg.APNSRelayKey},
	} {
		if k.url != "" && k.key != "" {
			name := filepath.Base(mfa.RelayKeyFile(cfg.DataDir, k.transport, k.url))
			out = append(out, recoveryclient.File{Path: "data/" + name, Data: []byte(k.key + "\n"), Mode: 0600})
		}
	}
	return out
}

// dbPartPrefix names the ordered members of a snapshot too large for one capsule member.
const dbPartPrefix = dbRelPath + ".part"

// dbMembers splits the snapshot into ordered members within capsule.MaxFileBytes. One that
// fits stays the single member every earlier capsule has.
func dbMembers(db []byte) []recoveryclient.File {
	if int64(len(db)) <= capsule.MaxFileBytes {
		return []recoveryclient.File{{Path: dbRelPath, Data: db, Mode: 0600}}
	}
	var out []recoveryclient.File
	for i := 0; len(db) > 0; i++ {
		n := min(int64(len(db)), capsule.MaxFileBytes)
		out = append(out, recoveryclient.File{Path: fmt.Sprintf("%s%03d", dbPartPrefix, i), Data: db[:n], Mode: 0600})
		db = db[n:]
	}
	return out
}

// JoinDatabaseParts rebuilds data/kyidentity.db from a split snapshot opened into dir (a
// restore target or a drill sandbox) and removes the parts. A capsule with the single
// member needs nothing.
func JoinDatabaseParts(dir string) (err error) {
	part := func(i int) string { return filepath.Join(dir, fmt.Sprintf("%s%03d", dbPartPrefix, i)) }
	if _, err := os.Stat(part(0)); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	out, err := os.OpenFile(filepath.Join(dir, dbRelPath), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("joining the database parts: %w", err)
	}
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
	}()
	for i := 0; ; i++ {
		data, err := os.ReadFile(part(i))
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			return err
		}
		if _, err := out.Write(data); err != nil {
			return err
		}
		if err := os.Remove(part(i)); err != nil {
			return err
		}
	}
	if left, _ := filepath.Glob(filepath.Join(dir, dbPartPrefix+"*")); len(left) > 0 {
		return fmt.Errorf("database parts are not consecutive: %s is left over", filepath.Base(left[0]))
	}
	return out.Sync()
}

// relayKeys names the self-registered push relay keys (mfa.RelayKeyFile) in dataDir. The
// relay binds each phone's push token to the key that first sent to it, so a restore on
// another host without them reaches no paired phone, and re-pairing keeps the same token.
// A server that never registered with a relay has none.
func relayKeys(dataDir string) ([]string, error) {
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if n := e.Name(); e.Type().IsRegular() && strings.HasPrefix(n, "push-relay-") && strings.HasSuffix(n, ".key") {
			names = append(names, n)
		}
	}
	return names, nil
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
	files = append(files, dbMembers(dbBytes)...)

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

	// The UnifiedPush VAPID key, so a restore keeps the server's push identity. Created at first
	// start; a capsule from before UnifiedPush has none and the restored server makes a new one.
	if vapid, err := os.ReadFile(cfg.VAPIDKeyPath); err == nil {
		files = append(files, recoveryclient.File{Path: vapidKeyRelPath, Data: vapid, Mode: 0600})
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("failed to read VAPID key: %w", err)
	}

	// The push relay keys, so a restore keeps the identity the relay bound every phone to.
	// A capsule from before them restores a server that registers afresh.
	keys, err := relayKeys(cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to list push relay keys: %w", err)
	}
	for _, k := range keys {
		key, err := os.ReadFile(filepath.Join(cfg.DataDir, k))
		if err != nil {
			return nil, fmt.Errorf("failed to read push relay key %s: %w", k, err)
		}
		files = append(files, recoveryclient.File{Path: "data/" + k, Data: key, Mode: 0600})
	}
	// A key supplied by PUSH_RELAY_KEY or APNS_RELAY_KEY is the one in use and never
	// reaches the disk; it goes where a restored server without that variable reads it.
	for _, k := range envRelayKeys(cfg) {
		replaced := false
		for i := range files {
			if files[i].Path == k.Path {
				files[i], replaced = k, true
			}
		}
		if !replaced {
			files = append(files, k)
		}
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
	total := 0
	for _, f := range files {
		total += len(f.Data)
		// A split database is joined back before the drill checks it.
		if strings.HasPrefix(f.Path, dbPartPrefix) {
			if f.Path != dbPartPrefix+"000" {
				continue
			}
			f.Path = dbRelPath
		}
		reqFiles = append(reqFiles, f.Path)
	}
	// The capsule holds a gzipped tar that may expand to capsule.MaxExpandedBytes; past it
	// every backup, export and drill fails. Say so while there is time to act.
	if int64(total) >= capsule.MaxExpandedBytes*4/5 {
		log.Printf("[BACKUP] WARNING: the backup payload is %d MiB, over 80%% of the %d MiB a capsule can hold; backups, exports and drills fail once it is full.",
			total>>20, capsule.MaxExpandedBytes>>20)
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
