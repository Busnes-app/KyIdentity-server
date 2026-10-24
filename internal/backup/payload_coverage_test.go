package backup_test

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/backup"
	"github.com/Busnes-app/kyidentity-server/internal/config"
)

// snapshotFunc adapts a function to backup.Snapshotter.
type snapshotFunc func(dest string) error

func (f snapshotFunc) SnapshotTo(dest string) error { return f(dest) }

// A capsule that could not restore the service is worse than none, so every missing or
// unusable member is a collection error naming what is wrong, never a smaller capsule.
func TestCollectSealableRefusesAnIncompleteInstance(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, cfg *config.Config) backup.Snapshotter
		want  string
	}{
		{"no database path", func(_ *testing.T, cfg *config.Config) backup.Snapshotter {
			cfg.DBPath = ""
			return nil
		}, "requires a database path"},
		{"no live handle", func(*testing.T, *config.Config) backup.Snapshotter { return nil }, "live database handle"},
		{"data directory gone", func(t *testing.T, cfg *config.Config) backup.Snapshotter {
			cfg.DataDir = filepath.Join(t.TempDir(), "missing")
			return snapshotFunc(func(string) error { return nil })
		}, "snapshot scratch directory"},
		{"snapshot fails", func(*testing.T, *config.Config) backup.Snapshotter {
			return snapshotFunc(func(string) error { return errors.New("disk full") })
		}, "disk full"},
		{"snapshot writes nothing", func(*testing.T, *config.Config) backup.Snapshotter {
			return snapshotFunc(func(string) error { return nil })
		}, "failed to read database snapshot"},
		{"empty snapshot", func(*testing.T, *config.Config) backup.Snapshotter {
			return snapshotFunc(func(dest string) error { return os.WriteFile(dest, nil, 0600) })
		}, "database snapshot is empty"},
		{"no signing key path", func(_ *testing.T, cfg *config.Config) backup.Snapshotter {
			cfg.RSAKeyPath = ""
			return fakeSnapshot()
		}, "RSA signing key path"},
		{"signing key missing", func(t *testing.T, cfg *config.Config) backup.Snapshotter {
			cfg.RSAKeyPath = filepath.Join(t.TempDir(), "absent.key")
			return fakeSnapshot()
		}, "failed to read RSA signing key"},
		{"signing key empty", func(t *testing.T, cfg *config.Config) backup.Snapshotter {
			cfg.RSAKeyPath = filepath.Join(t.TempDir(), "empty.key")
			if err := os.WriteFile(cfg.RSAKeyPath, nil, 0600); err != nil {
				t.Fatal(err)
			}
			return fakeSnapshot()
		}, "is empty"},
		{"short encryption key", func(_ *testing.T, cfg *config.Config) backup.Snapshotter {
			cfg.EncryptionKey = cfg.EncryptionKey[:16]
			return fakeSnapshot()
		}, "32-byte encryption key; the loaded one is 16 bytes"},
		{"missing secret key", func(_ *testing.T, cfg *config.Config) backup.Snapshotter {
			cfg.SecretKey = nil
			return fakeSnapshot()
		}, "32-byte secret key; the loaded one is 0 bytes"},
		{"unreadable VAPID key", func(t *testing.T, cfg *config.Config) backup.Snapshotter {
			if err := os.Mkdir(filepath.Join(cfg.DataDir, config.VAPIDKeyFile), 0700); err != nil {
				t.Fatal(err)
			}
			return fakeSnapshot()
		}, "failed to read VAPID key"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, _ := instance(t)
			snap := c.setup(t, cfg)
			p, err := backup.CollectSealable(cfg, snap, "1.0.0")
			if err == nil || p != nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("payload %v err = %v, want %q", p != nil, err, c.want)
			}
		})
	}
}

// fakeSnapshot writes a non-empty placeholder database.
func fakeSnapshot() backup.Snapshotter {
	return snapshotFunc(func(dest string) error { return os.WriteFile(dest, []byte("db"), 0600) })
}

// A paired instance carries recovery.pub so a restore comes back paired, Members says so
// before anything is sealed, and an unparseable port still yields the default in the recipe.
func TestCollectSealableCarriesThePinAndDefaultsThePort(t *testing.T) {
	cfg, st := instance(t)
	if slices.Contains(backup.Members(cfg), "data/recovery.pub") {
		t.Fatal("an unpaired instance lists recovery.pub")
	}
	pair(t, cfg, st)
	if !slices.Contains(backup.Members(cfg), "data/recovery.pub") {
		t.Fatalf("a paired instance does not list recovery.pub: %v", backup.Members(cfg))
	}
	cfg.Port = "not-a-port"
	p, err := backup.CollectSealable(cfg, st, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := os.ReadFile(backup.RecoveryKeyPath(cfg.DataDir))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(fileData(t, p.Files, "data/recovery.pub")); got != string(pub) {
		t.Fatalf("capsule recovery.pub = %q, want %q", got, pub)
	}
	if ports, _ := p.VerificationRecipe["expected_ports"].([]int); len(ports) != 1 || ports[0] != 5867 {
		t.Fatalf("expected_ports = %v, want [5867]", p.VerificationRecipe["expected_ports"])
	}
}

// Sealing to the pinned key yields a capsule that names this service and that key.
func TestSealNamesServiceAndPinnedKey(t *testing.T) {
	cfg, st := instance(t)
	priv := pair(t, cfg, st)
	key, err := backup.LoadRecoveryKey(cfg.DataDir, st)
	if err != nil {
		t.Fatal(err)
	}
	p, err := backup.CollectSealable(cfg, st, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	raw, m, err := backup.Seal(p.ServiceName, p.AppVersion, p.Files, p.Dependencies, p.VerificationRecipe, key)
	if err != nil || len(raw) == 0 {
		t.Fatal(err)
	}
	if m.ServiceName != cfg.AppName || m.RecoveryKeyID != priv.Public().ID() {
		t.Fatalf("manifest names %q/%q, want %q/%q", m.ServiceName, m.RecoveryKeyID, cfg.AppName, priv.Public().ID())
	}
	if _, _, err := backup.Seal(p.ServiceName, p.AppVersion, p.Files, nil, nil, backup.RecoveryKey{}); err == nil {
		t.Fatal("sealed to a zero recovery key")
	}
}

// A pasted pin must carry a usable key and a k-of-n topology.
func TestParsePinRequestRefusesBadInput(t *testing.T) {
	cfg, st := instance(t)
	pair(t, cfg, st)
	key, err := backup.LoadRecoveryKey(cfg.DataDir, st)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.StdEncoding.EncodeToString(key.Public.Bytes())
	if got, err := backup.ParsePinRequest(enc, 2, 3); err != nil || got.Public.ID() != key.Public.ID() || got.Threshold != 2 || got.TotalShares != 3 {
		t.Fatalf("valid pin: %+v %v", got, err)
	}
	for _, bad := range []struct {
		key  string
		k, n int
	}{{"not-a-key", 2, 3}, {enc, 4, 3}, {enc, 0, 0}} {
		if _, err := backup.ParsePinRequest(bad.key, bad.k, bad.n); err == nil {
			t.Errorf("pin %q %d-of-%d accepted", bad.key, bad.k, bad.n)
		}
	}
}

// The schedule: the environment default applies until an admin stores one, an invalid
// interval is refused, and zero turns the schedule off.
func TestScheduleIntervalAndNextRun(t *testing.T) {
	cfg, st := instance(t)
	cfg.BackupDepositInterval = 24 * time.Hour
	if d, err := backup.Interval(cfg, st); err != nil || d != 24*time.Hour {
		t.Fatalf("default interval: %v %v", d, err)
	}
	if next, on, err := backup.NextRun(cfg, st); err != nil || !on || time.Until(next) > time.Minute {
		t.Fatalf("never-run instance is not due now: %v %v %v", next, on, err)
	}
	if err := backup.SetInterval(st, 6*3600); err != nil {
		t.Fatal(err)
	}
	if d, err := backup.Interval(cfg, st); err != nil || d != 6*time.Hour {
		t.Fatalf("stored interval: %v %v", d, err)
	}
	if err := backup.SetInterval(st, 1); !errors.Is(err, backup.ErrBadInterval) {
		t.Fatalf("a one-second interval: %v", err)
	}
	if err := backup.SetInterval(st, 0); err != nil {
		t.Fatal(err)
	}
	if _, on, err := backup.NextRun(cfg, st); err != nil || on {
		t.Fatalf("a disabled schedule is still on: %v %v", on, err)
	}
}

// The real client never dials a loopback KyRecovery: the deposit is refused, no receipt is
// recorded, and the local copy written in the same run survives.
func TestRunBackupRefusesALoopbackRecoveryAndKeepsTheLocalCopy(t *testing.T) {
	cfg, st := instance(t)
	pair(t, cfg, st)
	if err := backup.StorePairing(st, cfg.EncryptionKey, "https://127.0.0.1:8443", "kyrec_live_t"); err != nil {
		t.Fatal(err)
	}
	cfg.BackupDir, cfg.BackupKeep = t.TempDir(), 3
	res, err := backup.RunBackup(context.Background(), cfg, st, st, backup.NewKyRecoveryClient(true), "1.0.0")
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("loopback deposit: %v", err)
	}
	if res.Receipt != nil {
		t.Fatal("a refused deposit produced a receipt")
	}
	if _, ok, _ := backup.LastDeposit(st); ok {
		t.Fatal("a refused deposit was recorded as the last deposit")
	}
	if res.LocalPath == "" {
		t.Fatal("the local copy was not written")
	}
	if _, err := os.Stat(res.LocalPath); err != nil {
		t.Fatal(err)
	}
	action, outcome, _ := backup.Outcome(res, err)
	if outcome == "success" {
		t.Fatalf("a refused deposit audits as %s/%s", action, outcome)
	}
}

// A collection failure stops the run before anything is sealed or written.
func TestRunBackupStopsOnCollectionFailure(t *testing.T) {
	cfg, st := instance(t)
	pair(t, cfg, st)
	cfg.BackupDir, cfg.BackupKeep = t.TempDir(), 3
	if err := os.Remove(cfg.RSAKeyPath); err != nil {
		t.Fatal(err)
	}
	remote := &fakeStore{}
	if _, err := backup.RunBackup(context.Background(), cfg, st, st, remote, "1.0.0"); err == nil || !strings.Contains(err.Error(), "RSA signing key") {
		t.Fatalf("run without a signing key: %v", err)
	}
	if remote.container != nil {
		t.Fatal("a capsule was deposited although collection failed")
	}
	if entries, _ := os.ReadDir(cfg.BackupDir); len(entries) != 0 {
		t.Fatalf("a local copy was written although collection failed: %v", entries)
	}
}

// Legacy local copies are migrated only when it is safe: a name collision or an unreadable
// backup directory stops the run instead of overwriting or skipping a capsule.
func TestLegacyMigrationRefusesUnsafeStates(t *testing.T) {
	cfg, st := instance(t)
	dir := t.TempDir()
	legacy := "KySignOn-cap-KySignOn-1700000000000000000.kycap"
	if err := os.WriteFile(filepath.Join(dir, legacy), []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.ListLocalCopies(dir, "KySignOn"); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() == legacy {
		t.Fatalf("legacy copy not migrated: %v", entries)
	}
	migrated := entries[0].Name()

	// The same legacy name again would land on the migrated file: refuse, keep both.
	if err := os.WriteFile(filepath.Join(dir, legacy), []byte("old again"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.ListLocalCopies(dir, "KySignOn"); err == nil || !strings.Contains(err.Error(), "destination already exists") {
		t.Fatalf("collision: %v", err)
	}
	cfg.BackupDir, cfg.BackupKeep = dir, 3
	pair(t, cfg, st)
	if _, err := backup.RunBackup(context.Background(), cfg, st, st, &fakeStore{}, "1.0.0"); err == nil || !strings.Contains(err.Error(), "destination already exists") {
		t.Fatalf("run over a collision: %v", err)
	}
	for _, name := range []string{legacy, migrated} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s lost: %v", name, err)
		}
	}

	// A backup directory that is a file is an error, not an empty list.
	notDir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notDir, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.ListLocalCopies(notDir, "KySignOn"); err == nil {
		t.Fatal("a file was listed as a backup directory")
	}
	// No directory configured, or one not yet created, is simply empty.
	if copies, err := backup.ListLocalCopies(filepath.Join(t.TempDir(), "absent"), "KySignOn"); err != nil || len(copies) != 0 {
		t.Fatalf("absent directory: %v %v", copies, err)
	}
}

// AuditSafe bounds remote text before it reaches the audit table, which rides in every capsule.
func TestAuditSafeBoundsRemoteText(t *testing.T) {
	got := backup.AuditSafe("line one\nline two\x00" + strings.Repeat("x", 500))
	if strings.ContainsAny(got, "\n\x00") || len(got) > 203 || !strings.HasSuffix(got, "...") || !strings.HasPrefix(got, "line one line two") {
		t.Fatalf("AuditSafe left %d bytes / control characters: %q", len(got), got)
	}
}
