package main

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/Busnes-app/ky-primitives/capsule"
	"github.com/Busnes-app/ky-primitives/recoverykey"
	"github.com/Busnes-app/kyidentity-server/internal/audit"
	"github.com/Busnes-app/kyidentity-server/internal/auth"
	"github.com/Busnes-app/kyidentity-server/internal/backup"
	"github.com/Busnes-app/kyidentity-server/internal/config"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// commandEnv points config.Load at a fresh data directory and clears every variable that
// would change what the subcommands under test do.
func commandEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("KYIDENTITY_DATA_DIR", dir)
	for _, k := range []string{"KYIDENTITY_DB_PATH", "KYIDENTITY_RSA_KEY_PATH", "KYIDENTITY_ISSUER_URL", "KYIDENTITY_SECRET_KEY",
		"KYIDENTITY_ENCRYPTION_KEY", "KYIDENTITY_BACKUP_DIR", "KYIDENTITY_BACKUP_KEEP", "KYIDENTITY_APP_NAME",
		"BOOTSTRAP_ADMIN_USER", "BOOTSTRAP_ADMIN_PASS"} {
		t.Setenv(k, "")
	}
	return dir
}

// commandInstance is a loaded configuration with one active administrator in its database,
// optionally pinned to a suite recovery key.
func commandInstance(t *testing.T, pinned bool) (*config.Config, recoverykey.PrivateKey) {
	t.Helper()
	commandEnv(t)
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.New(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := ensureBootstrapAdmin(s, "admin", "", "a-good-first-password", "test"); err != nil {
		t.Fatal(err)
	}
	var priv recoverykey.PrivateKey
	if pinned {
		if priv, err = recoverykey.Generate(); err != nil {
			t.Fatal(err)
		}
		if err := backup.StoreRecoveryKey(cfg.DataDir, s, backup.RecoveryKey{Public: priv.Public(), Threshold: 2, TotalShares: 3}); err != nil {
			t.Fatal(err)
		}
	}
	return cfg, priv
}

// captureStdout runs fn with os.Stdout redirected to a file and returns what it printed.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = f
	defer func() { os.Stdout = old }()
	fn()
	_ = f.Close()
	out, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// captureLog runs fn with the standard logger writing to a buffer.
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	fn()
	return buf.String()
}

// withStdin runs fn with os.Stdin reading the given text from a regular file, which is
// also what a non-terminal stdin looks like to stdinIsTerminal.
func withStdin(t *testing.T, text string, fn func()) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stdin")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	old := os.Stdin
	os.Stdin = f
	defer func() { os.Stdin = old }()
	fn()
}

// A drill on a paired instance with an administrator must pass every check, including the
// signing key the command materializes itself on a never-started install, and say so.
func TestBackupDrillCommandPassesOnAPairedInstance(t *testing.T) {
	cfg, priv := commandInstance(t, true)
	if _, err := os.Stat(cfg.RSAKeyPath); !os.IsNotExist(err) {
		t.Fatal("fixture already has a signing key; the command must create it")
	}
	out := captureStdout(t, runBackupDrill)
	if !strings.Contains(out, "Status:   PASSED (OK)") {
		t.Fatalf("drill did not pass:\n%s", out)
	}
	if strings.Contains(out, "\u2717") {
		t.Fatalf("a passing drill listed a failed check:\n%s", out)
	}
	for _, check := range []string{"Recovery Key", "Token Signing", "MFA Secret Decryption", "Administrator Directory"} {
		if !strings.Contains(out, "[\u2713] "+check) {
			t.Errorf("summary lacks a passing %q check:\n%s", check, out)
		}
	}
	if id := priv.Public().ID(); !strings.Contains(out, id[:16]) {
		t.Errorf("summary does not name the pinned recovery key %s:\n%s", id[:16], out)
	}
	if info, err := os.Stat(cfg.RSAKeyPath); err != nil || info.Size() == 0 {
		t.Fatalf("the drill did not materialize the signing key: %v", err)
	}
}

// export-capsule writes a private file sealed to the pinned suite key, named after the
// capsule when no path is given, and logs the digest restore -expect-digest checks.
func TestExportCapsuleWritesAPrivateCapsuleSealedToThePin(t *testing.T) {
	cfg, priv := commandInstance(t, true)
	out := filepath.Join(t.TempDir(), "export.kycap")
	logged := captureLog(t, func() { runExportCapsule(out) })

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(out)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("capsule mode = %v, %v; want 0600", info.Mode().Perm(), err)
	}
	m, err := capsule.ReadUnverifiedManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.ServiceName != cfg.AppName || m.RecoveryKeyID != priv.Public().ID() {
		t.Fatalf("capsule names service %q key %q; want %q sealed to %q", m.ServiceName, m.RecoveryKeyID, cfg.AppName, priv.Public().ID())
	}
	if !strings.Contains(logged, "digest "+sha256Hex(raw)) {
		t.Fatalf("log does not carry the capsule digest %s: %s", sha256Hex(raw), logged)
	}

	// Without -out the capsule lands in the working directory under its own ID.
	cwd := t.TempDir()
	t.Chdir(cwd)
	captureLog(t, func() { runExportCapsule("") })
	entries, err := os.ReadDir(cwd)
	if err != nil || len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), ".kycap") {
		t.Fatalf("default export path: %v %v", entries, err)
	}
	raw, err = os.ReadFile(filepath.Join(cwd, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if m, err := capsule.ReadUnverifiedManifest(raw); err != nil || entries[0].Name() != backup.FilenameSafe(m.CapsuleID)+".kycap" {
		t.Fatalf("default file %s does not name capsule %+v: %v", entries[0].Name(), m, err)
	}
}

// deposit with only a local backup directory writes a capsule there, records the run in
// the audit log, and reports where the capsule went.
func TestDepositCommandWritesALocalCopyAndAudits(t *testing.T) {
	cfg, _ := commandInstance(t, true)
	backupDir := t.TempDir()
	t.Setenv("KYIDENTITY_BACKUP_DIR", backupDir)

	logged := captureLog(t, runDeposit)

	entries, err := os.ReadDir(backupDir)
	if err != nil || len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), ".kycap") {
		t.Fatalf("backup directory holds %v (%v); want one capsule", entries, err)
	}
	if !strings.Contains(logged, "written to "+filepath.Join(backupDir, entries[0].Name())) {
		t.Fatalf("log does not say where the capsule went: %s", logged)
	}
	if strings.Contains(logged, "deposited with KyRecovery") {
		t.Fatalf("an unpaired deposit claimed a KyRecovery receipt: %s", logged)
	}
	s, err := store.New(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	events, _, err := s.SearchAuditEvents(store.AuditFilter{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range events {
		if e.TargetType == "backup" && e.Outcome == "success" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no successful backup audit row: %+v", events)
	}
}

// describe names every destination one run reached, and only those.
func TestDescribeNamesEveryDestination(t *testing.T) {
	var res backup.Result
	res.Manifest.CapsuleID = "cap-1"
	res.Manifest.RecoveryKeyID = "rk-1"
	res.SizeBytes = 42
	if got := describe(res); !strings.Contains(got, "cap-1 (42 bytes, sealed to recovery key rk-1)") || strings.Contains(got, "written to") || strings.Contains(got, "KyRecovery") {
		t.Fatalf("bare result: %q", got)
	}
	at := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	res.LocalPath = "/backups/cap-1.kycap"
	res.Receipt = &backup.Receipt{DepositedAt: at, Digest: "abc123"}
	got := describe(res)
	if !strings.Contains(got, "written to /backups/cap-1.kycap") || !strings.Contains(got, "deposited with KyRecovery at 2026-10-23T12:00:00Z; digest abc123") {
		t.Fatalf("full result: %q", got)
	}
}

// The scheduler honours shutdown while it waits: a cancelled context ends the loop
// without running a backup.
func TestBackupLoopStopsOnShutdown(t *testing.T) {
	cfg, _ := commandInstance(t, true)
	s, err := store.New(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	backupLoop(ctx, cfg, s, audit.NewLogger(s))
	if _, err := s.GetSetting("backup_last_attempt"); err == nil {
		t.Fatal("a cancelled scheduler still attempted a backup")
	}
}

// bootstrap-admin creates the administrator from the stdin password, and is a no-op
// that says so when that administrator already exists.
func TestBootstrapCommandCreatesThenLeavesTheAdmin(t *testing.T) {
	dir := commandEnv(t)
	var out string
	withStdin(t, "a-good-first-password\n", func() {
		out = captureStdout(t, func() { runBootstrap([]string{"-username", "root", "-email", "root@example.test"}) })
	})
	if !strings.Contains(out, "Admin user 'root' bootstrapped successfully.") || strings.Contains(out, "a-good-first-password") {
		t.Fatalf("output: %q", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "first-run-password.txt")); !os.IsNotExist(err) {
		t.Fatal("a chosen password was written to disk:", err)
	}
	withStdin(t, "another-good-password\n", func() {
		out = captureStdout(t, func() { runBootstrap([]string{"-username", "root"}) })
	})
	if !strings.Contains(out, `"root" is already an active administrator; nothing changed.`) {
		t.Fatalf("second run output: %q", out)
	}
	s, err := store.New(filepath.Join(dir, "kyidentity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	u, err := s.GetUserByUsername("root")
	if err != nil || u == nil || u.Email != "root@example.test" {
		t.Fatalf("admin: %+v %v", u, err)
	}
	if ok, _ := auth.VerifyPassword("a-good-first-password", u.PasswordHash); !ok {
		t.Fatal("the second run changed the administrator's password")
	}
}

// With an empty stdin the command generates the password and hands it over only in a
// private file, never on stdout.
func TestBootstrapCommandGeneratedPasswordGoesToAPrivateFile(t *testing.T) {
	dir := commandEnv(t)
	var out string
	withStdin(t, "", func() { out = captureStdout(t, func() { runBootstrap(nil) }) })
	path := filepath.Join(dir, "first-run-password.txt")
	if !strings.Contains(out, "Generated admin password written to "+path) || !strings.Contains(out, "Admin user 'admin' bootstrapped successfully.") {
		t.Fatalf("output: %q", out)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("password file: %v %v", info, err)
	}
	body, _ := os.ReadFile(path)
	password := strings.TrimPrefix(strings.Split(string(body), "\n")[1], "Password: ")
	if len(password) < 16 || strings.Contains(out, password) {
		t.Fatalf("generated password %q too short or printed", password)
	}
	s, err := store.New(filepath.Join(dir, "kyidentity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	u, err := s.GetUserByUsername("admin")
	if err != nil || u == nil {
		t.Fatal(err)
	}
	if ok, _ := auth.VerifyPassword(password, u.PasswordHash); !ok {
		t.Fatal("the password in the file does not sign in")
	}
}

// Flag mistakes and unreadable stdin are refused before anything is created.
func TestParseBootstrapRefusesBadInput(t *testing.T) {
	cases := []struct {
		name string
		args []string
		in   *strings.Reader
		want string
	}{
		{"unknown flag", []string{"-nope"}, strings.NewReader("pw\n"), "not defined"},
		{"blank username", []string{"-username", "   "}, strings.NewReader("pw\n"), "-username must not be empty"},
	}
	for _, c := range cases {
		if _, err := parseBootstrap(c.args, c.in, false); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}
	if _, err := parseBootstrap(nil, iotest.ErrReader(os.ErrClosed), false); err == nil || !strings.Contains(err.Error(), "reading the password from stdin") {
		t.Fatalf("stdin read error: %v", err)
	}
	// The prompt goes to stderr; the password still comes from the first stdin line.
	req, err := parseBootstrap(nil, strings.NewReader("a-good-first-password\r\n"), true)
	if err != nil || req.password != "a-good-first-password" {
		t.Fatalf("prompted read: %+v %v", req, err)
	}
}

// First start: an existing administrator is left alone even with BOOTSTRAP_ADMIN_PASS set;
// with none, a configured password creates one without writing a file and a generated one
// is written privately.
func TestBootstrapOnStartPaths(t *testing.T) {
	t.Run("existing admin", func(t *testing.T) {
		db := testStore(t)
		if _, err := ensureBootstrapAdmin(db, "admin", "", "a-good-first-password", "test"); err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		if err := bootstrapOnStart(db, "second", "another-good-password", dir); err != nil {
			t.Fatal(err)
		}
		if u, _ := db.GetUserByUsername("second"); u != nil {
			t.Fatal("a second administrator was created over an existing one")
		}
	})
	t.Run("configured password", func(t *testing.T) {
		db := testStore(t)
		dir := t.TempDir()
		if err := bootstrapOnStart(db, "admin", "a-good-first-password", dir); err != nil {
			t.Fatal(err)
		}
		u, _ := db.GetUserByUsername("admin")
		if u == nil {
			t.Fatal("no administrator created")
		}
		if ok, _ := auth.VerifyPassword("a-good-first-password", u.PasswordHash); !ok {
			t.Fatal("the configured password does not sign in")
		}
		if _, err := os.Stat(filepath.Join(dir, "first-run-password.txt")); !os.IsNotExist(err) {
			t.Fatal("a configured password was copied to disk:", err)
		}
	})
	t.Run("generated password", func(t *testing.T) {
		db := testStore(t)
		dir := t.TempDir()
		if err := bootstrapOnStart(db, "admin", "", dir); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(filepath.Join(dir, "first-run-password.txt"))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("generated password file: %v %v", info, err)
		}
	})
	t.Run("unwritable data directory", func(t *testing.T) {
		db := testStore(t)
		err := bootstrapOnStart(db, "admin", "", filepath.Join(t.TempDir(), "missing"))
		if err == nil || !strings.Contains(err.Error(), "could not write") {
			t.Fatalf("lost generated password was not reported: %v", err)
		}
	})
	t.Run("unreadable database", func(t *testing.T) {
		db := testStore(t)
		_ = db.Close()
		if err := bootstrapOnStart(db, "admin", "", t.TempDir()); err == nil || !strings.Contains(err.Error(), "count administrators") {
			t.Fatalf("a failed admin count was not reported: %v", err)
		}
		if _, err := ensureBootstrapAdmin(db, "admin", "", "a-good-first-password", "test"); err == nil {
			t.Fatal("ensureBootstrapAdmin succeeded against a closed database")
		}
	})
}

// A database error while deciding whether to delete the first-run password is reported,
// and the file is kept: deleting it unasked could lock the operator out.
func TestFirstRunPasswordFileKeptWhenSessionsAreUnreadable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "first-run-password.txt")
	if err := os.WriteFile(path, []byte("User: admin\nPassword: x\n"), 0600); err != nil {
		t.Fatal(err)
	}
	db := testStore(t)
	_ = db.Close()
	if err := clearFirstRunPasswordFile(db, dir); err == nil {
		t.Fatal("a session lookup failure was swallowed")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("the password file was removed without proof of a login:", err)
	}
}

// An unreadable marker still means a restore happened, so it is applied; a marker that
// cannot be read at all, or a database that cannot take the restore, stops startup and
// keeps the marker for the next try.
func TestRestoreMarkerFailureModes(t *testing.T) {
	t.Run("garbled marker is applied", func(t *testing.T) {
		dir, s := restoredDataDir(t)
		marker := filepath.Join(dir, restoreMarkerName)
		if err := os.WriteFile(marker, []byte("{not json"), 0600); err != nil {
			t.Fatal(err)
		}
		captureLog(t, func() {
			if err := applyRestoreMarker(dir, s, audit.NewLogger(s)); err != nil {
				t.Fatal(err)
			}
		})
		if sess, err := s.GetSessionByTokenHash("token-from-the-capsule", time.Hour); err == nil && sess != nil {
			t.Fatal("a garbled marker left the capsule's logins live")
		}
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatal("the applied marker was kept:", err)
		}
	})
	t.Run("marker is a directory", func(t *testing.T) {
		dir, s := restoredDataDir(t)
		if err := os.Mkdir(filepath.Join(dir, restoreMarkerName), 0700); err != nil {
			t.Fatal(err)
		}
		if err := applyRestoreMarker(dir, s, audit.NewLogger(s)); err == nil {
			t.Fatal("an unreadable marker was treated as no restore")
		}
		if sess, err := s.GetSessionByTokenHash("token-from-the-capsule", time.Hour); err != nil || sess == nil {
			t.Fatal("sessions were touched although the marker could not be read:", err)
		}
	})
	t.Run("database refuses", func(t *testing.T) {
		dir, s := restoredDataDir(t)
		marker := filepath.Join(dir, restoreMarkerName)
		if err := os.WriteFile(marker, []byte(`{"capsule":"x.kycap"}`), 0600); err != nil {
			t.Fatal(err)
		}
		_ = s.Close()
		if err := applyRestoreMarker(dir, s, audit.NewLogger(s)); err == nil {
			t.Fatal("a failed restore application was swallowed")
		}
		if _, err := os.Stat(marker); err != nil {
			t.Fatal("the marker was removed although the restore was not applied:", err)
		}
	})
}

// restoreCase seals a capsule with the given member to a fresh key and returns the
// capsule path, its digest, and two valid custodian shares.
func restoreCase(t *testing.T, service, member string) (string, string, string) {
	t.Helper()
	priv, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	split, err := recoverykey.Split(priv, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := capsule.Seal(service, "1.0.0", []capsule.File{{Path: member, Content: []byte("db"), Mode: 0600}}, nil, nil, 2, 3, priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "c.kycap")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path, sha256Hex(raw), split[0].String() + "\n" + split[1].String() + "\n"
}

// Every way a restore can go wrong ends in an error before the target is written: a
// half-restored directory, or one carrying a restore marker, would start as if genuine.
func TestRestoreCommandRefusals(t *testing.T) {
	t.Setenv("KYIDENTITY_APP_NAME", "")
	capPath, digest, shares := restoreCase(t, config.DefaultAppName, "data/kyidentity.db")
	_, _, otherShares := restoreCase(t, config.DefaultAppName, "data/kyidentity.db")
	corrupt := filepath.Join(t.TempDir(), "corrupt.kycap")
	if err := os.WriteFile(corrupt, []byte("not a capsule"), 0600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		args  []string
		stdin string
		want  string
	}{
		{"unknown flag", []string{"-bogus"}, shares, "not defined"},
		{"missing capsule flag", []string{"-expect-digest", digest}, shares, "-capsule and -to are required"},
		{"wrong custodian shares", []string{"-capsule", capPath, "-expect-digest", digest}, otherShares, "sealed to a different recovery key"},
		{"no shares", []string{"-capsule", capPath, "-expect-digest", digest}, "\n\n", "no shares read from stdin"},
		{"oversized share line", []string{"-capsule", capPath, "-expect-digest", digest}, strings.Repeat("x", 2<<20), "reading shares"},
		{"malformed share", []string{"-capsule", capPath, "-expect-digest", digest}, "ky2-garbage\nky2-more\n", "share 1"},
		{"corrupt capsule", []string{"-capsule", corrupt, "-accept-unauthenticated-capsule"}, shares, "not a recognised capsule"},
		{"missing capsule file", []string{"-capsule", filepath.Join(t.TempDir(), "absent.kycap"), "-accept-unauthenticated-capsule"}, shares, "no such file"},
		{"missing capsule file with digest", []string{"-capsule", filepath.Join(t.TempDir(), "absent.kycap"), "-expect-digest", digest}, shares, "no such file"},
		{"wrong service", []string{"-capsule", capPath, "-expect-digest", digest, "-service", "KyOther"}, shares, `capsule is for service "KySignOn"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "restored")
			var stderr bytes.Buffer
			err := restoreCommand(append(c.args, "-to", target), strings.NewReader(c.stdin), &bytes.Buffer{}, &stderr, false)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want one containing %q", err, c.want)
			}
			if _, err := os.Stat(target); !os.IsNotExist(err) {
				t.Fatal("a failed restore wrote the target:", err)
			}
		})
	}
}

// The service defaults to $KYIDENTITY_APP_NAME, then the stable KySignOn identity; a
// terminal gets a prompt for the shares on stderr.
func TestRestoreCommandServiceDefaultsAndPrompt(t *testing.T) {
	capPath, digest, shares := restoreCase(t, config.DefaultAppName, "data/kyidentity.db")
	t.Setenv("KYIDENTITY_APP_NAME", "KyOther")
	target := filepath.Join(t.TempDir(), "restored")
	err := restoreCommand([]string{"-capsule", capPath, "-to", target, "-expect-digest", digest}, strings.NewReader(shares), &bytes.Buffer{}, &bytes.Buffer{}, false)
	if err == nil || !strings.Contains(err.Error(), `this instance is "KyOther"`) {
		t.Fatalf("KYIDENTITY_APP_NAME was not the default service: %v", err)
	}

	t.Setenv("KYIDENTITY_APP_NAME", "")
	var stdout, stderr bytes.Buffer
	if err := restoreCommand([]string{"-capsule", capPath, "-to", target, "-expect-digest", digest}, strings.NewReader(shares), &stdout, &stderr, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "Paste the custodian shares") {
		t.Fatalf("no prompt on a terminal: %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "Restored.") {
		t.Fatalf("stdout: %q", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(target, "data", restoreMarkerName)); err != nil {
		t.Fatal("successful restore has no marker:", err)
	}
}

// A capsule that unpacks no data directory restores its files but fails loudly: without a
// marker the next start would treat the capsule's sessions and tokens as live.
func TestRestoreCommandFailsWhenTheMarkerCannotBeWritten(t *testing.T) {
	capPath, digest, shares := restoreCase(t, config.DefaultAppName, "elsewhere/kyidentity.db")
	target := filepath.Join(t.TempDir(), "restored")
	err := restoreCommand([]string{"-capsule", capPath, "-to", target, "-expect-digest", digest}, strings.NewReader(shares), &bytes.Buffer{}, &bytes.Buffer{}, false)
	if err == nil || !strings.Contains(err.Error(), "restore marker could not be written") {
		t.Fatalf("missing marker was not reported: %v", err)
	}
}

// The private copy the restore opens is made in the temp directory; if that cannot be
// created, nothing is opened or written.
func TestRestoreRefusesWithoutAPrivateCopy(t *testing.T) {
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
	target := filepath.Join(t.TempDir(), "restored")
	if err := restore([]byte("raw"), target, config.DefaultAppName, []string{"s"}, &bytes.Buffer{}); err == nil {
		t.Fatal("restore went ahead without its private copy")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("restore wrote the target:", err)
	}
}

// A failed purge is logged by table name and the rest still run; housekeeping never stops.
func TestPurgeExpiredLogsEachFailedTable(t *testing.T) {
	db := testStore(t)
	_ = db.Close()
	logged := captureLog(t, func() { purgeExpired(db, time.Now().UTC()) })
	for _, name := range []string{"purge sessions", "purge audit events", "purge orphaned launcher icons"} {
		if !strings.Contains(logged, name) {
			t.Errorf("log lacks %q: %s", name, logged)
		}
	}
}

// A fetch that cannot connect returns an error and no body, so the attestation caches keep
// what they had.
func TestHTTPFetchReportsConnectionFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	url := srv.URL
	srv.Close()
	body, header, err := httpFetch(url)
	if err == nil || body != nil || header != nil {
		t.Fatalf("closed server: body=%q header=%v err=%v", body, header, err)
	}
}

// The maintenance commands act only on an initialized database: a missing path or a file
// that is not a KyIdentity database is refused without creating anything or printing.
func TestMaintenanceCommandsRefuseAnUninitializedDatabase(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KYIDENTITY_DATA_DIR", dir)
	t.Setenv("KYIDENTITY_DB_PATH", "")
	missing := filepath.Join(dir, "absent.db")
	garbage := filepath.Join(dir, "garbage.db")
	if err := os.WriteFile(garbage, bytes.Repeat([]byte("not sqlite "), 64), 0600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		run  func(db string, out *bytes.Buffer) error
		db   string
		want string
	}{
		{"disable-user missing", func(db string, out *bytes.Buffer) error {
			return runDisableUser([]string{"--username", "a", "--require-active-admin", "b", "--db", db}, out)
		}, missing, "requires an initialized KyIdentity database"},
		{"disable-user garbage", func(db string, out *bytes.Buffer) error {
			return runDisableUser([]string{"--username", "a", "--require-active-admin", "b", "--db", db}, out)
		}, garbage, "nothing was changed"},
		{"resync-system missing", func(db string, out *bytes.Buffer) error {
			return runResyncSystem([]string{"--client", "notes", "--db", db}, out)
		}, missing, "requires an initialized KyIdentity database"},
		{"resync-system garbage", func(db string, out *bytes.Buffer) error {
			return runResyncSystem([]string{"--client", "notes", "--db", db}, out)
		}, garbage, "nothing was queued"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := c.run(c.db, &out); err == nil || !strings.Contains(err.Error(), c.want) || out.Len() != 0 {
				t.Fatalf("err = %v (output %q), want %q", err, out.String(), c.want)
			}
		})
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("a maintenance command created a database:", err)
	}
}

// When the first-run password file cannot be read, disable-user says so instead of
// reporting success with a possibly live bootstrap password still on disk.
func TestDisableUserReportsAnUnreadableFirstRunPassword(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KYIDENTITY_DATA_DIR", dir)
	t.Setenv("KYIDENTITY_DB_PATH", "")
	s, err := store.New(filepath.Join(dir, "kyidentity.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"bootstrap", "owner", "third"} {
		if err := s.CreateUser(&store.User{ID: name, Username: name, DisplayName: name, Email: name + "@example.test", PasswordHash: "x", Role: "admin", Status: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()
	if err := os.Mkdir(filepath.Join(dir, "first-run-password.txt"), 0700); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = runDisableUser([]string{"--username", "bootstrap", "--require-active-admin", "owner"}, &out)
	if err == nil || !strings.Contains(err.Error(), "first-run password file could not be read") || out.Len() != 0 {
		t.Fatalf("err = %v, output %q", err, out.String())
	}
	s, err = store.New(filepath.Join(dir, "kyidentity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if u, _ := s.GetUserByUsername("bootstrap"); u == nil || u.Status != "disabled" {
		t.Fatalf("the account was not disabled: %+v", u)
	}
}
