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
	"maps"
	"net"
	"net/http"
	"net/mail"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/Busnes-app/ky-primitives/recoveryclient"

	"github.com/Busnes-app/kyidentity-server/internal/api"
	"github.com/Busnes-app/kyidentity-server/internal/appattest"
	"github.com/Busnes-app/kyidentity-server/internal/appversion"
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
	"github.com/Busnes-app/kyidentity-server/internal/store/pgdialect"
	"github.com/Busnes-app/kyidentity-server/internal/sync"
	"github.com/Busnes-app/kyidentity-server/web"
	"github.com/google/uuid"
)

// auditRetention bounds how long audit events are kept. On SQLite this is the table that
// grows fastest and never stops.
const auditRetention = 180 * 24 * time.Hour

// attestationSweepInterval is how often revoked device attestations are swept for; the
// lease of that length is what makes it once across replicas and restarts.
const attestationSweepInterval = 24 * time.Hour

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "apply-setup":
			if err := runSetup(os.Args[2:], os.Stdout); err != nil {
				log.Fatal(err)
			}
			return
		case "disable-user":
			if err := runDisableUser(os.Args[2:], os.Stdout); err != nil {
				log.Fatal(err)
			}
			return
		case "resync-system":
			if err := runResyncSystem(os.Args[2:], os.Stdout); err != nil {
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
		case "migrate-to-postgres":
			if err := migrateToPostgres(os.Args[2:], os.Stdout, os.Stderr); err != nil {
				log.Fatal(err)
			}
			return
		}
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	dbStore, err := openStore(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize database store: %v", err)
	}
	defer dbStore.Close()
	// The environment seeds session limits until an administrator stores their own.
	if err := dbStore.LoadSessionLimits(store.SessionLimits{Absolute: int64(cfg.SessionTTL / time.Second), Idle: int64(cfg.SessionIdleTTL / time.Second)}); err != nil {
		log.Fatalf("Session limits: %v", err)
	}
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
	if strings.HasPrefix(cfg.IssuerURL, "https://") && len(cfg.TrustedProxyCIDRs) == 0 {
		// Plain HTTP here, https outside: a proxy is in front, and without its address every
		// caller is keyed as the proxy, so a stranger's wrong passwords lock the admin out.
		log.Println("WARNING: TRUSTED_PROXY_CIDRS is not set; behind a TLS proxy every client shares the proxy's address for sign-in lockout and rate limits. Set it to the proxy's peer address (INSTALL.md).")
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
			URL:      cfg.PushRelayURL,
			Key:      cfg.PushRelayKey,
			KeyFile:  mfa.RelayKeyFile(cfg.DataDir, "fcm", cfg.PushRelayURL),
			Keys:     dbStore,
			SealKey:  cfg.EncryptionKey,
			Label:    "kyidentity-" + cfg.IssuerURL,
			Optional: cfg.PushRelayURL == config.DefaultPushRelayURL,
		},
		mfa.RelayConfig{
			URL:      cfg.APNSRelayURL,
			Key:      cfg.APNSRelayKey,
			KeyFile:  mfa.RelayKeyFile(cfg.DataDir, "apns", cfg.APNSRelayURL),
			Keys:     dbStore,
			SealKey:  cfg.EncryptionKey,
			Label:    "kyidentity-" + cfg.IssuerURL,
			Optional: cfg.APNSRelayURL == config.DefaultAPNSRelayURL,
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
	unifiedPush, err := mfa.NewUnifiedPushSender(cfg.VAPIDKeyPath, pushOrigin, cfg.VAPIDKeyMounted)
	if err != nil {
		log.Fatalf("Failed to initialize UnifiedPush sender: %v", err)
	}
	mfaEngine.SetUnifiedPushSender(unifiedPush)
	mfaEngine.SetUbuntuPushSender(mfa.NewUbuntuPushSender(cfg.UbuntuPushURL, cfg.UbuntuPushAppID))
	oauthEngine := oauth.NewEngine(dbStore, keyManager, cfg.IssuerURL)

	if err := bootstrapOnStart(dbStore, cfg.BootstrapUser, cfg.BootstrapPass, cfg.DataDir, cfg.Replicated); err != nil {
		log.Fatalf("Bootstrap failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	waitSync := startSyncWorker(ctx, syncEngine)
	go oauthEngine.StartLogoutWorker(ctx)

	// Background housekeeping.
	go func() {
		housekeep := func() {
			purgeExpired(dbStore, time.Now().UTC())
			if err := clearFirstRunPasswordFile(dbStore, cfg.DataDir); err != nil {
				log.Printf("Housekeeping: %v", err)
			}
			var releaseSweep func()
			runAttestationHousekeeping(attestStatus.Stale(), func() bool {
				release, ok, err := dbStore.AcquireLease("attestation-sweep", attestationSweepInterval)
				if err != nil {
					log.Printf("attestation sweep: lease: %v", err)
				}
				releaseSweep = release
				return ok
			}, func() {
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
					releaseSweep() // so the next tick, on any replica, tries again
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
	if !waitSync(shutdownCtx) {
		log.Println("Sync worker still running at the shutdown deadline; an attempt it began stays fenced for operator recovery.")
	}
	log.Println("KyIdentity Server stopped.")
}

// startSyncWorker runs the sync dispatcher. The returned wait blocks until it has
// returned or done ends, so shutdown does not exit between a delivery's fence and
// its recorded outcome.
func startSyncWorker(ctx context.Context, e *sync.Engine) (wait func(context.Context) bool) {
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		e.StartWorker(ctx)
	}()
	return func(done context.Context) bool {
		select {
		case <-stopped:
			return true
		case <-done.Done():
			return false
		}
	}
}

// bootstrapOnStart creates the first administrator when none exists, from
// BOOTSTRAP_ADMIN_PASS or a generated password written to first-run-password.txt.
func bootstrapOnStart(dbStore *store.Store, username, password, dataDir string, replicated bool) error {
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
	if generated && replicated {
		// The file would land in one pod's own directory, where nobody looks for it.
		return errors.New("KYIDENTITY_REPLICATED is set, no administrator exists and BOOTSTRAP_ADMIN_PASS is empty: a generated password cannot be handed over from a replica; set BOOTSTRAP_ADMIN_PASS from a Secret or run bootstrap-admin")
	}
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
	dbStore, err := openStore(cfg)
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
		// A bootstrap password sits in a file, an .env or shell history: replace it first.
		PasswordChangeRequired: true,
	}
	event := audit.NewLogger(dbStore).Prepare("admin.user_created", "", "bootstrap", admin.ID, "user", "", via, "success",
		map[string]any{"username": admin.Username, "role": admin.Role, "pending": false, "passwordChangeRequired": true})
	if err := dbStore.CreateUserWithSyncEvents(admin, event.Row); err != nil {
		// Two first starts on one database both see no administrator; the name is unique,
		// so one insert fails, and its account is the one the other just created.
		if won, rerr := dbStore.GetUserByUsername(username); rerr == nil && won != nil && won.Role == "admin" && won.Status == "active" {
			return false, nil
		}
		return false, fmt.Errorf("failed to create the bootstrap administrator: %w", err)
	}
	event.Committed()
	return true, nil
}

func adminSessionExpiry() time.Time {
	return time.Now().UTC().Add(24 * time.Hour)
}

// clearFirstRunPasswordFile removes the generated credentials file once the account it names
// has signed in and no longer needs a plaintext password on disk. Other users' sessions say
// nothing about it: the emergency bootstrap-admin runbook writes the file while they exist.
func clearFirstRunPasswordFile(dbStore *store.Store, dataDir string) error {
	path := filepath.Join(dataDir, "first-run-password.txt")
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}

	userID := "" // a file that names no account falls back to any sign-in
	if first, _, _ := strings.Cut(string(raw), "\n"); strings.HasPrefix(first, "User: ") {
		u, err := dbStore.GetUserByUsername(strings.TrimPrefix(first, "User: "))
		if err != nil {
			return err
		}
		if u != nil {
			userID = u.ID
		}
	}
	loggedIn, err := dbStore.HasAnySession(userID)
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

// openStore opens the shared Postgres database when one is configured, else the SQLite file.
func openStore(cfg *config.Config) (*store.Store, error) {
	if cfg.DatabaseURL != "" {
		return store.NewPostgres(cfg.DatabaseURL)
	}
	return store.New(cfg.DBPath)
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
	dbStore, err := openStore(cfg)
	if err != nil {
		log.Fatalf("Failed to open the database: %v", err)
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

	release, ok, err := dbStore.AcquireLease(backup.DrillLease, backup.LeaseTTL)
	if err != nil || !ok {
		log.Fatalf("A restore drill is already running, or its lease is unreadable (%v)", err)
	}
	// log.Fatalf skips defers, and a lease left behind would refuse the next drill.
	result, err := func() (*backup.DrillResult, error) {
		defer release()
		payload, err := backup.CollectSealable(cfg, dbStore, appversion.String())
		if err != nil {
			return nil, fmt.Errorf("failed to collect backup payload: %w", err)
		}
		pinned, err := backup.LoadRecoveryKey(cfg.DataDir, dbStore)
		if err != nil && !errors.Is(err, backup.ErrNotPaired) {
			return nil, fmt.Errorf("recovery key: %w", err)
		}
		return backup.RunRestoreDrill(context.Background(), cfg.DataDir, payload.ServiceName, payload.AppVersion, payload.Files, payload.Dependencies, payload.VerificationRecipe, pinned)
	}()
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
	payload, err := backup.CollectSealable(cfg, dbStore, appversion.String())
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

	var res backup.Result
	release, ok, err := dbStore.AcquireLease(backup.Lease, backup.LeaseTTL)
	if err == nil && !ok {
		err = backup.ErrDepositInProgress
	}
	if err == nil {
		res, err = backup.RunBackup(context.Background(), cfg, dbStore, dbStore, backup.NewKyRecoveryClient(cfg.BackupAllowPrivateRecovery), appversion.String())
		release() // before log.Fatalf below, which skips defers
	}
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
		scheduledBackup(ctx, cfg, dbStore, client, auditLogger)
	}
}

// scheduledBackup runs one backup if the schedule says one is due. The schedule is read
// under the lease, and the run stamps its attempt before anything else: of two replicas
// that both tick while a run is due, the second finds the lease held or the run no longer due.
func scheduledBackup(ctx context.Context, cfg *config.Config, dbStore *store.Store, client backup.Depositor, auditLogger *audit.Logger) {
	release, ok, err := dbStore.AcquireLease(backup.Lease, backup.LeaseTTL)
	if err != nil {
		log.Printf("[BACKUP] lease: %v", err)
	}
	if !ok {
		return
	}
	defer release()
	next, on, err := backup.NextRun(cfg, dbStore)
	if err != nil {
		log.Printf("[BACKUP] schedule unreadable: %s", backup.AuditSafe(err.Error()))
		return
	}
	if !on || time.Now().Before(next) {
		return
	}
	res, err := backup.RunBackup(context.WithoutCancel(ctx), cfg, dbStore, dbStore, client, appversion.String())
	if errors.Is(err, backup.ErrNotPaired) || errors.Is(err, backup.ErrNoDestination) {
		return
	}
	action, outcome, details := backup.Outcome(res, err)
	auditLogger.Observe(action, "", "system", res.Manifest.CapsuleID, "backup", "", "kyidentity-scheduler", outcome, details)
	if err != nil {
		log.Printf("[BACKUP] scheduled backup: %s", backup.AuditSafe(err.Error()))
		return
	}
	log.Printf("[BACKUP] scheduled %s", describe(res))
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
	event := restoredEvent(auditLogger, marker)
	report, err := s.ApplyRestoredState(time.Now().UTC(), event.Row)
	if err != nil {
		return err
	}
	event.Committed()
	log.Print(describeRestore(report))
	log.Printf("Scheduled backup deposits are off; turn them back on (Disaster recovery, Schedule) once this server is the one in service")
	return os.Remove(path)
}

func restoredEvent(l *audit.Logger, marker restoreMarker) *audit.Pending {
	return l.Prepare("system.restored", "", "restore", "", "system", "", "", "success",
		map[string]any{"capsule": marker.Capsule, "restoredAt": marker.RestoredAt, "digest": marker.Digest, "authenticated": marker.Digest != ""})
}

func describeRestore(report store.RestoreReport) string {
	return fmt.Sprintf("Restored directory applied: %d credential(s) invalidated, %d queued delivery/deliveries closed, %d back-channel logout(s) queued for the logins it ended, provisioning held on %v until each is reconciled; review their stored credentials for rotation",
		report.Credentials, report.QueuedDeliveries, report.LogoutsQueued, report.Connectors)
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
	if err := recoveryclient.Restore(path, targetDir, expectService, shares, stdout); err != nil {
		return err
	}
	return backup.JoinDatabaseParts(targetDir)
}

const restoreUsage = "Usage: kyidentity restore -capsule <file.kycap> -to <dir> -expect-digest <sha256> [-service <name>] [-replace-database]\n\n" +
	"-expect-digest is the capsule's digest from KyRecovery's deposit record (or the one\n" +
	"export-capsule printed), checked before any share is read: anyone can seal a capsule to\n" +
	"the public recovery key. Custodian shares are read from stdin, one ky2-... share per\n" +
	"line, and never from the command line: argv is world-readable and lands in shell history.\n\n" +
	"With KYIDENTITY_DATABASE_URL[_FILE] set, the keys go to -to as always and the database is\n" +
	"loaded into Postgres, with the restored state applied in the same transaction. A Postgres\n" +
	"database that holds rows is refused unless -replace-database is given.\n\n"

func restoreCommand(args []string, stdin io.Reader, stdout, stderr io.Writer, prompt bool) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	fs.SetOutput(stderr)
	capsulePath := fs.String("capsule", "", "path to the .kycap file")
	target := fs.String("to", "", "empty directory to restore into")
	service := fs.String("service", "", restoreServiceHelp())
	digest := fs.String("expect-digest", "", "SHA-256 of the capsule from KyRecovery's deposit record")
	unauthenticated := fs.Bool("accept-unauthenticated-capsule", false, "restore without -expect-digest: whoever could write the capsule file chooses the restored administrators and keys")
	replace := fs.Bool("replace-database", false, "Postgres only: replace every row of a database that is not empty, in the restore's one transaction")
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
	databaseURL, err := config.LoadDatabaseURL()
	if err != nil {
		return err
	}
	if *replace && databaseURL == "" {
		return errors.New("-replace-database applies only to a restore into Postgres (KYIDENTITY_DATABASE_URL)")
	}
	var raw []byte
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
	if databaseURL != "" {
		return restoreIntoPostgres(databaseURL, *target, *capsulePath, strings.ToLower(strings.TrimSpace(*digest)), *replace, stdout)
	}
	fmt.Fprintln(stdout, "Restored. On first start the server invalidates the sessions, tokens and invitations this capsule contains, holds outbound provisioning until each connector is reconciled, and turns scheduled backup deposits off; turn them back on once this server is the one in service.")
	return nil
}

// restoreIntoPostgres loads the unpacked capsule's database into Postgres and applies the
// restored state with its audit row in the same transaction, so no replica ever sees the
// capsule's sessions. The SQLite file and the marker stay until that commits: a failure
// leaves Postgres unchanged and the directory as a SQLite restore would leave it.
func restoreIntoPostgres(databaseURL, target, capsulePath, digest string, replace bool, stdout io.Writer) error {
	dbPath := filepath.Join(target, "data", "kyidentity.db")
	event := restoredEvent(audit.NewLogger(nil), restoreMarker{Capsule: filepath.Base(capsulePath), Digest: digest, RestoredAt: time.Now().UTC()})
	res, err := store.ImportSQLite(databaseURL, dbPath, store.ImportOptions{Replace: replace, Restored: event.Row})
	if err != nil {
		return fmt.Errorf("loading the capsule's database into Postgres at %s failed; the database is unchanged: %w", pgdialect.Describe(databaseURL), err)
	}
	event.Committed()
	printCounts(stdout, res.Rows)
	fmt.Fprintln(stdout, describeRestore(res.Restore))
	for _, p := range []string{filepath.Join(target, "data", restoreMarkerName), dbPath} {
		if err := os.Remove(p); err != nil {
			return fmt.Errorf("the restore committed to Postgres, but %s could not be removed: %w; remove it before starting a server on this directory", p, err)
		}
	}
	fmt.Fprintf(stdout, "Restored into Postgres at %s; start the servers with -to's data directory for the keys. Scheduled backup deposits are off; turn them back on once this server is the one in service.\n", pgdialect.Describe(databaseURL))
	return nil
}

func printCounts(w io.Writer, rows map[string]int64) {
	for _, name := range slices.Sorted(maps.Keys(rows)) {
		fmt.Fprintf(w, "  %-36s %d\n", name, rows[name])
	}
}

const migrateUsage = "Usage: kyidentity migrate-to-postgres -from <kyidentity.db>\n\n" +
	"Copies a stopped server's SQLite database into the empty Postgres database named by\n" +
	"KYIDENTITY_DATABASE_URL or KYIDENTITY_DATABASE_URL_FILE, in one transaction. The file is\n" +
	"never modified. Going back is a restore of a capsule into SQLite.\n\n"

// migrateToPostgres is the one-way move of a SQLite install onto Postgres.
func migrateToPostgres(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("migrate-to-postgres", flag.ContinueOnError)
	fs.SetOutput(stderr)
	from := fs.String("from", "", "the SQLite database file (never modified)")
	fs.Usage = func() {
		fmt.Fprint(stderr, migrateUsage)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *from == "" {
		fs.Usage()
		return errors.New("-from is required")
	}
	databaseURL, err := config.LoadDatabaseURL()
	if err != nil {
		return err
	}
	if databaseURL == "" {
		return errors.New("set KYIDENTITY_DATABASE_URL or KYIDENTITY_DATABASE_URL_FILE to the Postgres database to migrate into")
	}
	where := pgdialect.Describe(databaseURL)
	res, err := store.ImportSQLite(databaseURL, *from, store.ImportOptions{})
	if err != nil {
		return fmt.Errorf("migration into %s failed; the database is unchanged: %w", where, err)
	}
	printCounts(stdout, res.Rows)
	got, err := store.PostgresRowCounts(databaseURL)
	if err != nil {
		return fmt.Errorf("the migration committed, but counting the rows in %s failed: %w", where, err)
	}
	var wrong []string
	for _, name := range slices.Sorted(maps.Keys(got)) {
		if want, ok := res.Rows[name]; !ok || want != got[name] {
			wrong = append(wrong, fmt.Sprintf("%s: file %d, Postgres %d", name, want, got[name]))
		}
	}
	if len(wrong) > 0 || len(got) != len(res.Rows) {
		return fmt.Errorf("the migration committed, but the row counts differ (%s); do not start a server on %s", strings.Join(wrong, "; "), where)
	}
	fmt.Fprintf(stdout, "Migrated %d tables into %s; every table's row count matches the file. Set KYIDENTITY_DATABASE_URL on the server and start it.\n", len(got), where)
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

// purgeExpired deletes rows past their use. Every table here is written by unauthenticated
// or per-request paths, so none may grow without bound; a failed purge is retried next tick.
func purgeExpired(s *store.Store, now time.Time) {
	purges := []struct {
		name string
		run  func() error
	}{
		{"sessions", s.CleanupExpiredSessions},
		{"MFA tokens", s.DeleteExpiredMFATokens},
		{"login failure counters", s.DeleteExpiredLoginFailures},
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

// runAttestationHousekeeping refreshes the attestation caches whenever the status list is
// stale or this replica claimed the daily sweep, then sweeps if it did. A sweep that fails
// gives its claim back, so the fetch and the sweep are retried next tick.
func runAttestationHousekeeping(stale bool, claimSweep func() bool, refresh, sweep func()) {
	due := claimSweep()
	if stale || due {
		refresh()
	}
	if due {
		sweep()
	}
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
