package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Busness-app/ky-primitives/recoveryclient"

	"github.com/Busness-app/kyidentity-server/internal/api"
	"github.com/Busness-app/kyidentity-server/internal/audit"
	"github.com/Busness-app/kyidentity-server/internal/auth"
	"github.com/Busness-app/kyidentity-server/internal/backup"
	"github.com/Busness-app/kyidentity-server/internal/config"
	"github.com/Busness-app/kyidentity-server/internal/crypto"
	"github.com/Busness-app/kyidentity-server/internal/mfa"
	"github.com/Busness-app/kyidentity-server/internal/netguard"
	"github.com/Busness-app/kyidentity-server/internal/oauth"
	"github.com/Busness-app/kyidentity-server/internal/store"
	"github.com/Busness-app/kyidentity-server/internal/sync"
	"github.com/Busness-app/kyidentity-server/web"
	"github.com/google/uuid"
)

// auditRetention bounds how long audit events are kept. On SQLite this is the table that
// grows fastest and never stops.
const auditRetention = 180 * 24 * time.Hour

const appVersion = "1.0.0"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "bootstrap-admin":
			bootstrapCmd := flag.NewFlagSet("bootstrap-admin", flag.ExitOnError)
			bootstrapUser := bootstrapCmd.String("username", "admin", "Admin username")
			bootstrapPass := bootstrapCmd.String("password", "", "Admin password (min 12 chars)")
			bootstrapEmail := bootstrapCmd.String("email", "admin@local.kysecurity", "Admin email")
			_ = bootstrapCmd.Parse(os.Args[2:])
			runBootstrap(*bootstrapUser, *bootstrapPass, *bootstrapEmail)
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
	mfaEngine.SetPushSender(relaySender)
	oauthEngine := oauth.NewEngine(dbStore, keyManager, cfg.IssuerURL)

	adminCount, err := dbStore.CountAdmins()
	if err != nil {
		log.Fatalf("Failed to count administrators: %v", err)
	}
	switch {
	case adminCount > 0:
		if cfg.BootstrapPass != "" {
			log.Println("BOOTSTRAP_ADMIN_PASS is set but an administrator already exists; ignoring it. " +
				"Use the admin UI to change a password.")
		}
	case cfg.BootstrapPass != "":
		if err := ensureBootstrapAdmin(dbStore, cfg.BootstrapUser, cfg.BootstrapPass); err != nil {
			log.Fatalf("Bootstrap failed: %v", err)
		}
		log.Printf("Bootstrap administrator %q created from BOOTSTRAP_ADMIN_PASS.", cfg.BootstrapUser)
	default:
		firstRunPass, err := crypto.GenerateRandomAlphanumeric(16)
		if err != nil {
			log.Fatalf("Failed to generate first-run admin password: %v", err)
		}
		if err := ensureBootstrapAdmin(dbStore, cfg.BootstrapUser, firstRunPass); err != nil {
			log.Fatalf("Bootstrap failed: %v", err)
		}
		passFile := filepath.Join(cfg.DataDir, "first-run-password.txt")
		if err := os.WriteFile(passFile, []byte(fmt.Sprintf("User: %s\nPassword: %s\n", cfg.BootstrapUser, firstRunPass)), 0600); err != nil {
			log.Fatalf("Created the bootstrap admin but could not write %s: %v", passFile, err)
		}
		log.Printf("Bootstrap admin created. Credentials written to %s (removed automatically after first sign-in).", passFile)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start background account sync dispatcher worker
	go syncEngine.StartWorker(ctx)

	// Background housekeeping. Every table below is written by unauthenticated or
	// per-request paths, so none of them may grow without bound.
	go func() {
		housekeep := func() {
			_ = dbStore.CleanupExpiredSessions()
			_ = dbStore.DeleteExpiredMFATokens()
			_ = dbStore.DeleteExpiredAuthorizationCodes()
			_ = dbStore.DeleteExpiredIssuedTokens()
			_ = dbStore.DeleteExpiredDevicePairingTokens()
			_ = dbStore.DeleteExpiredMFAChallenges()
			_ = dbStore.DeleteExpiredWebAuthnChallenges()
			_ = dbStore.DeleteDeliveredSyncEvents(time.Now().UTC().Add(-7 * 24 * time.Hour))
			_ = dbStore.DeleteAuditEventsOlderThan(time.Now().UTC().Add(-auditRetention))
			_, _ = dbStore.DeleteOrphanedLauncherIcons(time.Hour)
			if err := clearFirstRunPasswordFile(dbStore, cfg.DataDir); err != nil {
				log.Printf("Housekeeping: %v", err)
			}
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
		log.Printf("KyIdentity Server listening on :%s (Issuer: %s)", cfg.Port, cfg.IssuerURL)
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

func runBootstrap(username, password, email string) {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Config load error: %v", err)
	}

	dbStore, err := store.New(cfg.DBPath)
	if err != nil {
		log.Fatalf("Store error: %v", err)
	}
	defer dbStore.Close()

	if password == "" {
		password, err = crypto.GenerateRandomAlphanumeric(16)
		if err != nil {
			log.Fatalf("Failed to generate admin password: %v", err)
		}
		fmt.Printf("Generated admin password: %s\n", password)
	}

	if err := ensureBootstrapAdmin(dbStore, username, password); err != nil {
		log.Fatalf("Bootstrap failed: %v", err)
	}
	fmt.Printf("Admin user '%s' bootstrapped successfully.\n", username)
}

// ensureBootstrapAdmin creates the first administrator. It deliberately does NOT touch an
// existing account: BOOTSTRAP_ADMIN_PASS usually lives in an .env file that stays set, and
// re-applying it on every restart would silently revert any password rotation the admin
// performed, with nothing in the audit log to explain it.
func ensureBootstrapAdmin(dbStore *store.Store, username, password string) error {
	existing, err := dbStore.GetUserByUsername(username)
	if err != nil {
		return fmt.Errorf("failed to check for an existing %q account: %w", username, err)
	}
	if existing != nil {
		return nil
	}

	passHash, err := auth.HashPassword(password)
	if err != nil {
		return fmt.Errorf("bootstrap password rejected: %w", err)
	}

	admin := &store.User{
		ID:           uuid.New().String(),
		Username:     username,
		DisplayName:  "Administrator",
		Email:        username + "@local.kysecurity",
		PasswordHash: passHash,
		Role:         "admin",
		Status:       "active",
	}
	if err := dbStore.CreateUser(admin); err != nil {
		return fmt.Errorf("failed to create the bootstrap administrator: %w", err)
	}
	return nil
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
	log.Printf("Capsule %s sealed to recovery key %s, written to %s (%d bytes)", m.CapsuleID, m.RecoveryKeyID, outPath, len(raw))
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
	_ = auditLogger.Record(action, "", "cli", res.Manifest.CapsuleID, "backup", "", "kyidentity-cli", outcome, details)
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
		_ = auditLogger.Record(action, "", "system", res.Manifest.CapsuleID, "backup", "", "kyidentity-scheduler", outcome, details)
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

// restore is the one place in this server that combines custodian shares and opens a capsule
// sealed to the suite key; the decrypt guard test pins that.
func restore(capsulePath, targetDir, expectService string, shares []string, stdout io.Writer) error {
	return recoveryclient.Restore(capsulePath, targetDir, expectService, shares, stdout)
}

func runRestore(args []string) {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	capsulePath := fs.String("capsule", "", "path to the .kycap file")
	target := fs.String("to", "", "empty directory to restore into")
	service := fs.String("service", "", "expected service name (default: $KYIDENTITY_APP_NAME or KyIdentity)")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, "Usage: kyidentity restore -capsule <file.kycap> -to <dir> [-service <name>]\n\n"+
			"Custodian shares are read from stdin, one ky2-... share per line, and never from\n"+
			"the command line: argv is world-readable and lands in shell history.\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if *capsulePath == "" || *target == "" {
		fs.Usage()
		os.Exit(2)
	}
	if *service == "" {
		*service = os.Getenv("KYIDENTITY_APP_NAME")
	}
	if *service == "" {
		*service = config.DefaultAppName
	}
	if stdinIsTerminal() {
		fmt.Fprintln(os.Stderr, "Paste the custodian shares, one per line, then press Ctrl-D:")
	}
	shares, err := recoveryclient.ReadShares(os.Stdin)
	if err != nil {
		log.Fatalf("Reading shares: %v", err)
	}
	if len(shares) == 0 {
		log.Fatal("No shares read from stdin")
	}
	if err := restore(*capsulePath, *target, *service, shares, os.Stdout); err != nil {
		log.Fatalf("Restore: %v", err)
	}
}
