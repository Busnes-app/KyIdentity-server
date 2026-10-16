package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/mail"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Busnes-app/ky-primitives/recoveryclient"

	"github.com/Busnes-app/kyidentity-server/internal/api"
	"github.com/Busnes-app/kyidentity-server/internal/appattest"
	"github.com/Busnes-app/kyidentity-server/internal/attest"
	"github.com/Busnes-app/kyidentity-server/internal/audit"
	"github.com/Busnes-app/kyidentity-server/internal/auth"
	"github.com/Busnes-app/kyidentity-server/internal/backup"
	"github.com/Busnes-app/kyidentity-server/internal/config"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/mfa"
	"github.com/Busnes-app/kyidentity-server/internal/netguard"
	"github.com/Busnes-app/kyidentity-server/internal/oauth"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/Busnes-app/kyidentity-server/internal/sync"
	"github.com/Busnes-app/kyidentity-server/web"
	"github.com/google/uuid"
)

// auditRetention bounds how long audit events are kept. On SQLite this is the table that
// grows fastest and never stops.
const auditRetention = 180 * 24 * time.Hour

const appVersion = "0.4.2"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "apply-setup":
			if err := runSetup(os.Args[2:], os.Stdout); err != nil {
				log.Fatal(err)
			}
			return
		case "bootstrap-admin":
			runBootstrap(os.Args[2:])
			return
		case "backup-drill":
			runBackupDrill()
			return
		case "export-capsule":
			exportCmd := flag.NewFlagSet("export-capsule", flag.ExitOnError)
			outPath := exportCmd.String("out", "", "output path (default <capsule-id>.kycap in the current directory)")
			_ = exportCmd.Parse(os.Args[2:])
			runExportCapsule(*outPath)
			return
		case "deposit":
			runDeposit()
			return
		case "restore":
			runRestore(os.Args[2:])
			return
		}
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	dbStore, err := store.New(cfg.DBPath)
	if err != nil {
		log.Fatalf("Failed to initialize database store: %v", err)
	}
	defer dbStore.Close()
	// Before anything reads a secret: the read path refuses legacy ciphertext.
	if err := dbStore.SealLegacySecrets(cfg.EncryptionKey); err != nil {
		log.Fatalf("Sealing legacy secrets failed, refusing to start: %v", err)
	}

	keyManager, err := crypto.LoadOrCreateRSAKey(cfg.RSAKeyPath)
	if err != nil {
		log.Fatalf("Failed to initialize RSA key manager: %v", err)
	}

	// Paired systems on a shared container network need private callbacks; on a public
	// deployment allowing them turns an attacker-chosen callback into an SSRF primitive.
	netguard.AllowPrivate = cfg.AllowPrivateCallbacks
	if cfg.BackupAllowPrivateRecovery {
		log.Printf("[BACKUP] KYIDENTITY_BACKUP_ALLOW_PRIVATE_RECOVERY is set: capsules may be deposited to a KyRecovery on a private address (HTTPS still required)")
	}
	if cfg.AllowPrivateCallbacks {
		log.Println("WARNING: KYIDENTITY_ALLOW_PRIVATE_CALLBACKS is on; paired systems may register internal callback URLs")
	}

	auditLogger := audit.NewLogger(dbStore)
	// A restored directory is applied before anything can authenticate against it or
	// deliver from it.
	if err := applyRestoreMarker(cfg.DataDir, dbStore, auditLogger); err != nil {
		log.Fatalf("Applying the restored state failed, refusing to start: %v", err)
	}
	syncEngine := sync.NewEngine(dbStore, cfg.EncryptionKey)
	mfaEngine := mfa.NewEngine(dbStore, cfg.EncryptionKey)
	relaySender, err := mfa.NewRelaySender(
		mfa.RelayConfig{
			URL:     cfg.PushRelayURL,
			Key:     cfg.PushRelayKey,
			KeyFile: filepath.Join(cfg.DataDir, "push-relay-fcm.key"),
			Label:   "kyidentity-" + cfg.IssuerURL,
		},
		mfa.RelayConfig{
			URL:     cfg.APNSRelayURL,
			Key:     cfg.APNSRelayKey,
			KeyFile: filepath.Join(cfg.DataDir, "push-relay-apns.key"),
			Label:   "kyidentity-" + cfg.IssuerURL,
		},
	)
	if err != nil {
		log.Fatalf("Failed to initialize push relay sender: %v", err)
	}
	if relaySender != nil { // a typed nil would reach SendPush
		mfaEngine.SetPushSender(relaySender)
	}
	embedded, err := attest.LoadEmbeddedRoots()
	if err != nil {
		log.Fatalf("Failed to load attestation roots: %v", err)
	}
	extra, err := attest.LoadExtraRoots(cfg.AttestationExtraRoots)
	if err != nil {
		log.Fatalf("Failed to load extra attestation roots: %v", err)
	}
	_, base := embedded.Pool()
	attestRoots := attest.NewRefreshingRoots(append(base, extra...), "https://android.googleapis.com/attestation/root", httpFetch, log.Printf)
	attestStatus := attest.NewStatusList(cfg.AttestationStatusURL, httpFetch)
	if cfg.AttestationStatusURL == "" {
		log.Print("attestation revocation check disabled: KYIDENTITY_ATTESTATION_STATUS_URL is empty")
	}
	digests := make([][]byte, 0, len(cfg.KyAuthCertSHA256))
	for _, d := range cfg.KyAuthCertSHA256 {
		b, _ := hex.DecodeString(d) // validated by config.Load
		digests = append(digests, b)
	}
	mfaEngine.SetAttestor(attest.NewVerifier(attestRoots, attestStatus, "org.kysecurity.authenticator", digests, requireLockedBootloader(dbStore.AttestationSettings, log.Printf)))
	if len(cfg.AppAttestAppIDs) == 0 {
		log.Print("iOS App Attest grading disabled: KYIDENTITY_APPATTEST_APP_IDS is empty")
	} else {
		appAttest, err := appattest.NewVerifier(cfg.AppAttestAppIDs, cfg.AppAttestAllowDevelopment)
		if err != nil {
			log.Fatalf("Failed to load the App Attest root: %v", err)
		}
		mfaEngine.SetAppAttestor(appAttest)
	}
	pushOrigin, err := mfa.IssuerOrigin(cfg.IssuerURL)
	if err != nil {
		log.Fatalf("Invalid issuer URL for push approvals: %v", err)
	}
	mfaEngine.SetIssuerOrigin(pushOrigin)
	unifiedPush, err := mfa.NewUnifiedPushSender(filepath.Join(cfg.DataDir, config.VAPIDKeyFile), pushOrigin)
	if err != nil {
		log.Fatalf("Failed to initialize UnifiedPush sender: %v", err)
	}
	mfaEngine.SetUnifiedPushSender(unifiedPush)
	mfaEngine.SetUbuntuPushSender(mfa.NewUbuntuPushSender(cfg.UbuntuPushURL, cfg.UbuntuPushAppID))
	oauthEngine := oauth.NewEngine(dbStore, keyManager, cfg.IssuerURL)

	if err := bootstrapOnStart(dbStore, cfg.BootstrapUser, cfg.BootstrapPass, cfg.DataDir); err != nil {
		log.Fatalf("Bootstrap failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start background account sync dispatcher worker
	go syncEngine.StartWorker(ctx)
	go oauthEngine.StartLogoutWorker(ctx)

	// Background housekeeping.
	go func() {
		var lastSweep time.Time
		housekeep := func() {
			purgeExpired(dbStore, time.Now().UTC())
			if err := clearFirstRunPasswordFile(dbStore, cfg.DataDir); err != nil {
				log.Printf("Housekeeping: %v", err)
			}
			lastSweep = runAttestationHousekeeping(time.Now(), lastSweep, attestStatus.Stale(), func() {
				if err := attestRoots.Refresh(); err != nil {
					log.Printf("attestation roots refresh failed: %v", err)
				}
				if err := attestStatus.Refresh(); err != nil {
					log.Printf("attestation status refresh failed: %v", err)
				}
			}, func() {
				n, err := mfaEngine.SweepAttestations(attestStatus, sweepRequireLocked(dbStore.AttestationSettings, log.Printf), func(id, uid, reason string) {
					// The downgrade stands even if its record is lost: rolling it back would keep
					// trusting a revoked key.
					auditLogger.Observe("device.attestation_downgraded", "", "", id, "device", "", "sweep", "success", map[string]any{"userId": uid, "reason": reason})
				})
				log.Printf("attestation sweep: %d downgraded", n)
				if err != nil {
					log.Printf("attestation sweep failed: %v", err)
				}
			})
		}
		housekeep()

		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				housekeep()
			}
		}
	}()

	staticFS, _ := web.FS()

	go backupLoop(ctx, cfg, dbStore, auditLogger)

	server := api.NewServer(
		cfg,
		dbStore,
		keyManager,
		syncEngine,
		mfaEngine,
		oauthEngine,
		auditLogger,
		staticFS,
	)

	go func() {
		log.Printf("KyIdentity Server listening on %s (Issuer: %s)", net.JoinHostPort(cfg.ListenHost, cfg.Port), cfg.IssuerURL)
		if err := server.Start(); err != nil && err.Error() != "http: Server closed" {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Graceful shutdown handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down KyIdentity Server gracefully...")
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("Shutdown error: %v", err)
	}
	log.Println("KyIdentity Server stopped.")
}

// bootstrapOnStart creates the first administrator when none exists, from
// BOOTSTRAP_ADMIN_PASS or a generated password written to first-run-password.txt.
func bootstrapOnStart(dbStore *store.Store, username, password, dataDir string) error {
	adminCount, err := dbStore.CountAdmins()
	if err != nil {
		return fmt.Errorf("failed to count administrators: %w", err)
	}
	if adminCount > 0 {
		if password != "" {
			log.Println("BOOTSTRAP_ADMIN_PASS is set but an administrator already exists; ignoring it. " +
				"Use the admin UI to change a password.")
		}
		return nil
	}
	generated := password == ""
	if generated {
		if password, err = crypto.GenerateRandomAlphanumeric(16); err != nil {
			return fmt.Errorf("failed to generate first-run admin password: %w", err)
		}
	}
	created, err := ensureBootstrapAdmin(dbStore, username, "", password, "kyidentity-startup")
	if err != nil || !created {
		return err
	}
	if !generated {
		log.Printf("Bootstrap administrator %q created from BOOTSTRAP_ADMIN_PASS.", username)
		return nil
	}
	passFile, err := writeFirstRunPassword(dataDir, username, password)
	if err != nil {
		return err
	}
	log.Printf("Bootstrap admin created. Credentials written to %s (removed automatically after first sign-in).", passFile)
	return nil
}

// writeFirstRunPassword hands a generated password over in a private file, never on
// stdout or in a log: container output is routinely collected.
func writeFirstRunPassword(dataDir, username, password string) (string, error) {
	passFile := filepath.Join(dataDir, "first-run-password.txt")
	if err := os.WriteFile(passFile, []byte(fmt.Sprintf("User: %s\nPassword: %s\n", username, password)), 0600); err != nil {
		return "", fmt.Errorf("created the bootstrap admin but could not write %s: %w", passFile, err)
	}
	return passFile, nil
}

type bootstrapRequest struct {
	username, email, password string
	generated                 bool
}

// parseBootstrap reads the bootstrap-admin flags and the password, which comes from the
// first line of stdin and never from argv: argv is world-readable and lands in shell history.
func parseBootstrap(args []string, stdin io.Reader, prompt bool) (bootstrapRequest, error) {
	fs := flag.NewFlagSet("bootstrap-admin", flag.ContinueOnError)
	username := fs.String("username", "admin", "Admin username")
	email := fs.String("email", "", "Admin email (default <username>@local.kysecurity)")
	argvPass := fs.String("password", "", "refused: the password is read from stdin")
	if err := fs.Parse(args); err != nil {
		return bootstrapRequest{}, err
	}
	if *argvPass != "" {
		return bootstrapRequest{}, errors.New("refusing -password: argv is world-readable and lands in shell history; pipe the password on stdin")
	}
	req := bootstrapRequest{username: strings.TrimSpace(*username), email: strings.TrimSpace(*email)}
	if req.username == "" {
		return bootstrapRequest{}, errors.New("-username must not be empty")
	}
	if req.email != "" {
		if a, err := mail.ParseAddress(req.email); err != nil || a.Address != req.email {
			return bootstrapRequest{}, fmt.Errorf("-email %q is not a bare email address", req.email)
		}
	}
	if prompt {
		fmt.Fprintln(os.Stderr, "Admin password (min 12 characters; empty generates one), then Enter:")
	}
	line, err := bufio.NewReader(io.LimitReader(stdin, 4<<10)).ReadString('\n')
	if err != nil && err != io.EOF {
		return bootstrapRequest{}, fmt.Errorf("reading the password from stdin: %w", err)
	}
	req.password = strings.TrimRight(line, "\r\n")
	if req.password == "" {
		if req.password, err = crypto.GenerateRandomAlphanumeric(16); err != nil {
			return bootstrapRequest{}, fmt.Errorf("failed to generate admin password: %w", err)
		}
		req.generated = true
	}
	return req, nil
}

func runBootstrap(args []string) {
	req, err := parseBootstrap(args, os.Stdin, stdinIsTerminal())
	if err != nil {
		log.Fatalf("bootstrap-admin: %v", err)
	}
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Config load error: %v", err)
	}
	dbStore, err := store.New(cfg.DBPath)
	if err != nil {
		log.Fatalf("Store error: %v", err)
	}
	defer dbStore.Close()

	created, err := ensureBootstrapAdmin(dbStore, req.username, req.email, req.password, "kyidentity-cli")
	if err != nil {
		log.Fatalf("Bootstrap failed: %v", err)
	}
	if !created {
		fmt.Printf("%q is already an active administrator; nothing changed.\n", req.username)
		return
	}
	if req.generated {
		passFile, err := writeFirstRunPassword(cfg.DataDir, req.username, req.password)
		if err != nil {
			log.Fatalf("Bootstrap failed: %v", err)
		}
		fmt.Printf("Generated admin password written to %s (removed automatically after first sign-in).\n", passFile)
	}
	fmt.Printf("Admin user '%s' bootstrapped successfully.\n", req.username)
}

// ensureBootstrapAdmin creates an administrator and its admin.user_created audit row in one
// transaction, and reports whether it did. It deliberately does NOT touch an existing
// account: BOOTSTRAP_ADMIN_PASS usually lives in an .env file that stays set, and
// re-applying it on every restart would silently revert any password rotation the admin
// performed. An existing account that is not an active administrator is an error, never a
// silent success: bootstrap neither promotes nor re-enables anyone.
func ensureBootstrapAdmin(dbStore *store.Store, username, email, password, via string) (bool, error) {
	existing, err := dbStore.GetUserByUsername(username)
	if err != nil {
		return false, fmt.Errorf("failed to check for an existing %q account: %w", username, err)
	}
	if existing != nil {
		if existing.Role == "admin" && existing.Status == "active" {
			return false, nil
		}
		return false, fmt.Errorf("account %q exists but is not an active administrator; bootstrap will not promote or re-enable it", username)
	}

	passHash, err := auth.HashPassword(password)
	if err != nil {
		return false, fmt.Errorf("bootstrap password rejected: %w", err)
	}
	if email == "" {
		email = username + "@local.kysecurity"
	}
	admin := &store.User{
		ID:           uuid.New().String(),
		Username:     username,
		DisplayName:  "Administrator",
		Email:        email,
		PasswordHash: passHash,
		Role:         "admin",
		Status:       "active",
	}
	event := audit.NewLogger(dbStore).Prepare("admin.user_created", "", "bootstrap", admin.ID, "user", "", via, "success",
		map[string]any{"username": admin.Username, "role": admin.Role, "pending": false})
	if err := dbStore.CreateUserWithSyncEvents(admin, event.Row); err != nil {
		return false, fmt.Errorf("failed to create the bootstrap administrator: %w", err)
	}
	event.Committed()
	return true, nil
}

func adminSessionExpiry() time.Time {
	return time.Now().UTC().Add(24 * time.Hour)
}

// clearFirstRunPasswordFile removes the generated credentials file once any session has
// existed, meaning someone has logged in and no longer needs a plaintext password on disk.
func clearFirstRunPasswordFile(dbStore *store.Store, dataDir string) error {
	path := filepath.Join(dataDir, "first-run-password.txt")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}

	loggedIn, err := dbStore.HasAnySession()
	if err != nil {
		return err
	}
	if !loggedIn {
		return nil
	}

	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove %s: %w", path, err)
	}
	log.Printf("Removed %s; the first administrator has signed in.", path)
	return nil
}

// openStoreForBackup opens the live database so backups can take a consistent snapshot
// through it rather than copying the file out from under WAL.
//
// It also materializes the RSA signing key the same way the server does. The key is created
// lazily on first server start, so backing up a freshly bootstrapped install would otherwise
// fail on a missing file — and a capsule without the signing key cannot restore a working
// service, which is why its absence is fatal rather than skipped.
func openStoreForBackup(cfg *config.Config) *store.Store {
	if _, err := crypto.LoadOrCreateRSAKey(cfg.RSAKeyPath); err != nil {
		log.Fatalf("Failed to load the RSA signing key at %s: %v", cfg.RSAKeyPath, err)
	}
	dbStore, err := store.New(cfg.DBPath)
	if err != nil {
		log.Fatalf("Failed to open the database at %s: %v", cfg.DBPath, err)
	}
	return dbStore
}

func runBackupDrill() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	dbStore := openStoreForBackup(cfg)
	defer dbStore.Close()

	payload, err := backup.CollectSealable(cfg, dbStore, appVersion)
	if err != nil {
		log.Fatalf("Failed to collect backup payload: %v", err)
	}
	pinned, err := backup.LoadRecoveryKey(cfg.DataDir, dbStore)
	if err != nil && !errors.Is(err, backup.ErrNotPaired) {
		log.Fatalf("Recovery key: %v", err)
	}
	result, err := backup.RunRestoreDrill(context.Background(), cfg.DataDir, payload.ServiceName, payload.AppVersion, payload.Files, payload.Dependencies, payload.VerificationRecipe, pinned)
	if err != nil {
		log.Fatalf("Drill execution failed: %v", err)
	}

	fmt.Printf("\n=== KyBackup Restore Drill Summary ===\n")
	statusStr := "PASSED (OK)"
	if !result.Passed {
		statusStr = "FAILED"
	}
	fmt.Printf("Status:   %s\n", statusStr)
	fmt.Printf("Duration: %d ms\n", result.DurationMs)
	for _, check := range result.Checks {
		status := "\u2713"
		if !check.Passed {
			status = "\u2717"
		}
		fmt.Printf("  [%s] %s: %s\n", status, check.Name, check.Message)
	}
	fmt.Println("==================================================")
	if !result.Passed {
		os.Exit(1)
	}
}

// runExportCapsule writes the capsule sealed to the suite recovery key. Only k custodian
// shares open it, so the file is safe anywhere; kyrecovery is where it belongs.
func runExportCapsule(outPath string) {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	dbStore := openStoreForBackup(cfg)
	defer dbStore.Close()

	key, err := backup.LoadRecoveryKey(cfg.DataDir, dbStore)
	if err != nil {
		log.Fatalf("Recovery key: %v", err)
	}
	payload, err := backup.CollectSealable(cfg, dbStore, appVersion)
	if err != nil {
		log.Fatalf("Failed to collect backup payload: %v", err)
	}
	raw, m, err := backup.Seal(payload.ServiceName, payload.AppVersion, payload.Files, payload.Dependencies, payload.VerificationRecipe, key)
	if err != nil {
		log.Fatalf("Seal: %v", err)
	}
	if outPath == "" {
		outPath = backup.FilenameSafe(m.CapsuleID) + ".kycap"
	}
	if err := os.WriteFile(outPath, raw, 0600); err != nil {
		log.Fatalf("Write: %v", err)
	}
	// The digest is what `restore -expect-digest` checks; record it away from the file.
	log.Printf("Capsule %s sealed to recovery key %s, written to %s (%d bytes); digest %s", m.CapsuleID, m.RecoveryKeyID, outPath, len(raw), sha256Hex(raw))
}

// runDeposit seals and deposits one capsule now, for cron or an operator at a shell.
func runDeposit() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	dbStore := openStoreForBackup(cfg)
	defer dbStore.Close()
	auditLogger := audit.NewLogger(dbStore)

	res, err := backup.RunBackup(context.Background(), cfg, dbStore, dbStore, backup.NewKyRecoveryClient(cfg.BackupAllowPrivateRecovery), appVersion)
	action, outcome, details := backup.Outcome(res, err)
	auditLogger.Observe(action, "", "cli", res.Manifest.CapsuleID, "backup", "", "kyidentity-cli", outcome, details)
	if err != nil {
		log.Fatalf("Backup: %v", err)
	}
	log.Print(describe(res))
}

// describe says where one run's capsule went.
func describe(res backup.Result) string {
	msg := fmt.Sprintf("capsule %s (%d bytes, sealed to recovery key %s)", res.Manifest.CapsuleID, res.SizeBytes, res.Manifest.RecoveryKeyID)
	if res.LocalPath != "" {
		msg += " written to " + res.LocalPath
	}
	if res.Receipt != nil {
		msg += fmt.Sprintf(" deposited with KyRecovery at %s; digest %s", res.Receipt.DepositedAt.Format(time.RFC3339), res.Receipt.Digest)
	}
	return msg
}

// backupLoop runs the schedule the admin set (or the KYIDENTITY_BACKUP_DEPOSIT_INTERVAL
// default). It checks once a minute whether a run is due, so a schedule changed in the UI
// takes effect without a restart and a restart never loses its place: the last attempt is in
// the database. The wait honours shutdown; the run itself does not, so a SIGTERM mid-upload
// cannot end the process between KyRecovery storing a capsule and the receipt being written.
func backupLoop(ctx context.Context, cfg *config.Config, dbStore *store.Store, auditLogger *audit.Logger) {
	client := backup.NewKyRecoveryClient(cfg.BackupAllowPrivateRecovery)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		next, on, err := backup.NextRun(cfg, dbStore)
		if err != nil {
			log.Printf("[BACKUP] schedule unreadable: %s", backup.AuditSafe(err.Error()))
			continue
		}
		if !on || time.Now().Before(next) {
			continue
		}
		res, err := backup.RunBackup(context.WithoutCancel(ctx), cfg, dbStore, dbStore, client, appVersion)
		if errors.Is(err, backup.ErrNotPaired) || errors.Is(err, backup.ErrNoDestination) {
			continue
		}
		action, outcome, details := backup.Outcome(res, err)
		auditLogger.Observe(action, "", "system", res.Manifest.CapsuleID, "backup", "", "kyidentity-scheduler", outcome, details)
		if err != nil {
			log.Printf("[BACKUP] scheduled backup: %s", backup.AuditSafe(err.Error()))
			continue
		}
		log.Printf("[BACKUP] scheduled %s", describe(res))
	}
}

func stdinIsTerminal() bool {
	st, err := os.Stdin.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// restoreMarkerName is dropped into the restored data directory by `kysignon restore`
// and read once by the next start. It is the seam between unpacking a capsule and
// putting it into service: the restore command cannot reach the running server, and the
// server cannot otherwise tell a restored directory from the one it wrote itself.
const restoreMarkerName = "restored.json"

type restoreMarker struct {
	Capsule string `json:"capsule"`
	Service string `json:"service"`
	// Digest is the deposit-record SHA-256 the capsule was checked against; empty when the
	// operator accepted it unauthenticated.
	Digest     string    `json:"digest,omitempty"`
	RestoredAt time.Time `json:"restoredAt"`
}

// writeRestoreMarker records that this directory came out of a capsule. It holds no
// secret: the capsule name, the service name, the verified digest and the time.
func writeRestoreMarker(targetDir, capsulePath, service, digest string) error {
	body, err := json.Marshal(restoreMarker{Capsule: filepath.Base(capsulePath), Service: service, Digest: digest, RestoredAt: time.Now().UTC()})
	if err != nil {
		return err
	}
	dataDir := filepath.Join(targetDir, "data")
	if _, err := os.Stat(dataDir); err != nil {
		// A capsule that unpacked no data directory is not something to paper over.
		return err
	}
	return os.WriteFile(filepath.Join(dataDir, restoreMarkerName), body, 0600)
}

// applyRestoreMarker invalidates the ephemeral credentials a restored snapshot carries
// and holds outbound provisioning until each connector has been reconciled. The marker
// is removed only after that has committed, so a crash midway repeats the work rather
// than skipping it.
func applyRestoreMarker(dataDir string, s *store.Store, auditLogger *audit.Logger) error {
	path := filepath.Join(dataDir, restoreMarkerName)
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var marker restoreMarker
	if err := json.Unmarshal(body, &marker); err != nil {
		// An unreadable marker still means a restore happened. Apply it.
		log.Printf("Restore marker at %s is unreadable (%v); applying the restore anyway", path, err)
	}
	event := auditLogger.Prepare("system.restored", "", "restore", "", "system", "", "", "success",
		map[string]any{"capsule": marker.Capsule, "restoredAt": marker.RestoredAt, "digest": marker.Digest, "authenticated": marker.Digest != ""})
	report, err := s.ApplyRestoredState(time.Now().UTC(), event.Row)
	if err != nil {
		return err
	}
	event.Committed()
	log.Printf("Restored directory applied: %d credential(s) invalidated, %d queued delivery/deliveries closed, %d back-channel logout(s) queued for the logins it ended, provisioning held on %v until each is reconciled; review their stored credentials for rotation",
		report.Credentials, report.QueuedDeliveries, report.LogoutsQueued, report.Connectors)
	return os.Remove(path)
}

// sha256Hex is a capsule's digest as KyRecovery records it at deposit.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// readAuthenticCapsule returns the capsule's bytes only when they hash to wantDigest. The
// suite recovery public key is not secret, so a capsule that opens proves nothing about who
// sealed it; the digest KyRecovery recorded when this server deposited it does.
func readAuthenticCapsule(path, wantDigest string) ([]byte, error) {
	want := strings.ToLower(strings.TrimSpace(wantDigest))
	if b, err := hex.DecodeString(want); err != nil || len(b) != sha256.Size {
		return nil, fmt.Errorf("-expect-digest must be the 64-hex-character SHA-256 from the deposit record, got %q", wantDigest)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if got := sha256Hex(raw); got != want {
		return nil, fmt.Errorf("capsule digest is %s, the deposit record says %s; refusing a capsule this server did not deposit", got, want)
	}
	return raw, nil
}

// restore is the one place in this server that combines custodian shares and opens a capsule
// sealed to the suite key; the decrypt guard test pins that. It opens a private copy of raw,
// so the file cannot change between its digest check and the open.
func restore(raw []byte, targetDir, expectService string, shares []string, stdout io.Writer) error {
	dir, err := os.MkdirTemp("", "kyidentity-restore-") // mode 0700
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "capsule.kycap")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		return err
	}
	return recoveryclient.Restore(path, targetDir, expectService, shares, stdout)
}

const restoreUsage = "Usage: kyidentity restore -capsule <file.kycap> -to <dir> -expect-digest <sha256> [-service <name>]\n\n" +
	"-expect-digest is the capsule's digest from KyRecovery's deposit record (or the one\n" +
	"export-capsule printed), checked before any share is read: anyone can seal a capsule to\n" +
	"the public recovery key. Custodian shares are read from stdin, one ky2-... share per\n" +
	"line, and never from the command line: argv is world-readable and lands in shell history.\n\n"

func restoreCommand(args []string, stdin io.Reader, stdout, stderr io.Writer, prompt bool) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	fs.SetOutput(stderr)
	capsulePath := fs.String("capsule", "", "path to the .kycap file")
	target := fs.String("to", "", "empty directory to restore into")
	service := fs.String("service", "", restoreServiceHelp())
	digest := fs.String("expect-digest", "", "SHA-256 of the capsule from KyRecovery's deposit record")
	unauthenticated := fs.Bool("accept-unauthenticated-capsule", false, "restore without -expect-digest: whoever could write the capsule file chooses the restored administrators and keys")
	fs.Usage = func() {
		fmt.Fprint(stderr, restoreUsage)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *capsulePath == "" || *target == "" {
		fs.Usage()
		return errors.New("-capsule and -to are required")
	}
	var raw []byte
	var err error
	switch {
	case *digest != "" && *unauthenticated:
		return errors.New("-expect-digest and -accept-unauthenticated-capsule contradict each other")
	case *digest != "":
		raw, err = readAuthenticCapsule(*capsulePath, *digest)
	case *unauthenticated:
		fmt.Fprintln(stderr, "WARNING: -accept-unauthenticated-capsule: this capsule's origin is unproven; anyone who could write it chose its administrators and keys.")
		raw, err = os.ReadFile(*capsulePath)
	default:
		fs.Usage()
		return errors.New("-expect-digest is required: take it from KyRecovery's deposit record for this capsule")
	}
	if err != nil {
		return err
	}
	if *service == "" {
		*service = os.Getenv("KYIDENTITY_APP_NAME")
	}
	if *service == "" {
		*service = config.DefaultAppName
	}
	if prompt {
		fmt.Fprintln(stderr, "Paste the custodian shares, one per line, then press Ctrl-D:")
	}
	shares, err := recoveryclient.ReadShares(stdin)
	if err != nil {
		return fmt.Errorf("reading shares: %w", err)
	}
	if len(shares) == 0 {
		return errors.New("no shares read from stdin")
	}
	if err := restore(raw, *target, *service, shares, stdout); err != nil {
		return err
	}
	if err := writeRestoreMarker(*target, *capsulePath, *service, strings.ToLower(strings.TrimSpace(*digest))); err != nil {
		return fmt.Errorf("restore unpacked but the restore marker could not be written (%v); the next start would treat the old sessions, tokens and queued deliveries as live", err)
	}
	fmt.Fprintln(stdout, "Restored. On first start the server invalidates the sessions, tokens and invitations this capsule contains and holds outbound provisioning until each connector is reconciled.")
	return nil
}

func runRestore(args []string) {
	if err := restoreCommand(args, os.Stdin, os.Stdout, os.Stderr, stdinIsTerminal()); err != nil {
		log.Fatalf("Restore: %v", err)
	}
}

func restoreServiceHelp() string {
	return "expected service name (default: $KYIDENTITY_APP_NAME or " + config.DefaultAppName + ")"
}

// runAttestationHousekeeping refreshes the attestation caches whenever the status list is stale
// or the daily sweep is due, so a failed fetch is retried next tick. It returns the sweep time.
// purgeExpired deletes rows past their use. Every table here is written by unauthenticated
// or per-request paths, so none may grow without bound; a failed purge is retried next tick.
func purgeExpired(s *store.Store, now time.Time) {
	purges := []struct {
		name string
		run  func() error
	}{
		{"sessions", s.CleanupExpiredSessions},
		{"MFA tokens", s.DeleteExpiredMFATokens},
		{"authorization codes", s.DeleteExpiredAuthorizationCodes},
		{"issued tokens", s.DeleteExpiredIssuedTokens},
		{"device pairing tokens", s.DeleteExpiredDevicePairingTokens},
		{"account tokens", s.DeleteExpiredAccountTokens},
		{"MFA challenges", s.DeleteExpiredMFAChallenges},
		{"WebAuthn challenges", s.DeleteExpiredWebAuthnChallenges},
		{"step-up tokens", s.DeleteExpiredStepUpTokens},
		{"delivered sync events", func() error { return s.DeleteDeliveredSyncEvents(now.Add(-7 * 24 * time.Hour)) }},
		{"logout deliveries", func() error { return s.DeleteLogoutDeliveriesOlderThan(now.Add(-7 * 24 * time.Hour)) }},
		{"audit events", func() error { return s.DeleteAuditEventsOlderThan(now.Add(-auditRetention)) }},
		{"alerts", func() error { return s.DeleteAlertsOlderThan(now.Add(-auditRetention)) }},
		{"orphaned launcher icons", func() error { _, err := s.DeleteOrphanedLauncherIcons(time.Hour); return err }},
	}
	for _, p := range purges {
		if err := p.run(); err != nil {
			log.Printf("Housekeeping: purge %s: %v", p.name, err)
		}
	}
}

func runAttestationHousekeeping(now, lastSweep time.Time, stale bool, refresh, sweep func()) time.Time {
	due := now.Sub(lastSweep) >= 24*time.Hour
	if stale || due {
		refresh()
	}
	if !due {
		return lastSweep
	}
	sweep()
	return now
}

// fetchClient refuses redirects: a 3xx fails as non-2xx instead of leaving the pinned host.
var fetchClient = &http.Client{
	Timeout:       10 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// httpFetch GETs url for the attestation caches; the body is capped at 4 MiB.
func httpFetch(url string) ([]byte, http.Header, error) {
	resp, err := fetchClient.Get(url)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, nil, err
	}
	return body, resp.Header, nil
}

// requireLockedBootloader reads the admin policy per grade. A failed read keeps the
// requirement on: an error may only downgrade a grade, never relax the policy.
func requireLockedBootloader(read func() (store.AttestationSettings, error), warn func(string, ...any)) func() bool {
	return func() bool {
		s, err := read()
		if err != nil {
			warn("attestation settings unreadable, requiring locked bootloader: %v", err)
			return true
		}
		return s.RequireLockedBootloader
	}
}

// sweepRequireLocked is the sweep's bootloader policy. Unlike registration it does not fail
// closed on a read error: a downgrade needs re-pairing to undo, so unknown state downgrades no one.
func sweepRequireLocked(read func() (store.AttestationSettings, error), warn func(string, ...any)) bool {
	s, err := read()
	if err != nil {
		warn("attestation sweep: settings unreadable, skipping bootloader check: %v", err)
		return false
	}
	return s.RequireLockedBootloader
}
