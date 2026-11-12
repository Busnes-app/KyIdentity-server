package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Busnes-app/kyidentity-server/internal/audit"
	"github.com/Busnes-app/kyidentity-server/internal/auth"
	"github.com/Busnes-app/kyidentity-server/internal/backup"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// handles opens n stores on one database: n replicas as far as the database can tell.
func handles(t *testing.T, path string, n int) []*store.Store {
	t.Helper()
	out := make([]*store.Store, n)
	for i := range out {
		s, err := store.New(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		out[i] = s
	}
	return out
}

func allAtOnce(stores []*store.Store, fn func(i int, s *store.Store) error) []error {
	start := make(chan struct{})
	errs := make([]error, len(stores))
	var wg sync.WaitGroup
	for i, s := range stores {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = fn(i, s)
		}()
	}
	close(start)
	wg.Wait()
	return errs
}

// Two first starts on one database both find no administrator. Neither may die for it,
// one account results, and the password handed over is the one that signs in.
func TestConcurrentFirstStartsCreateOneAdministrator(t *testing.T) {
	for _, configured := range []string{"a-good-first-password", ""} {
		name := "configured password"
		if configured == "" {
			name = "generated password"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			stores := handles(t, filepath.Join(dir, "test.db"), 6)
			for i, err := range allAtOnce(stores, func(_ int, s *store.Store) error {
				return bootstrapOnStart(s, "admin", configured, dir, false)
			}) {
				if err != nil {
					t.Fatalf("start %d failed: %v", i, err)
				}
			}
			if n, err := stores[0].CountAdmins(); err != nil || n != 1 {
				t.Fatalf("administrators = %d (%v), want 1", n, err)
			}
			password := configured
			if configured == "" {
				raw, err := os.ReadFile(filepath.Join(dir, "first-run-password.txt"))
				if err != nil {
					t.Fatal(err)
				}
				_, password, _ = strings.Cut(strings.TrimSpace(string(raw)), "Password: ")
			}
			u, err := stores[0].GetUserByUsername("admin")
			if err != nil || u == nil {
				t.Fatal(u, err)
			}
			if ok, _ := auth.VerifyPassword(password, u.PasswordHash); !ok {
				t.Fatal("the password handed over does not sign in: a losing start overwrote the winner's file")
			}
		})
	}
}

// A replica cannot hand a generated password to anyone: it fails instead of writing one
// into its own pod.
func TestReplicaRefusesToGenerateTheFirstPassword(t *testing.T) {
	db, dir := testStore(t), t.TempDir()
	err := bootstrapOnStart(db, "admin", "", dir, true)
	if err == nil || !strings.Contains(err.Error(), "BOOTSTRAP_ADMIN_PASS") {
		t.Fatalf("err = %v", err)
	}
	if n, _ := db.CountAdmins(); n != 0 {
		t.Fatal("an administrator was created anyway")
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Fatalf("files written: %v", left)
	}
	if err := bootstrapOnStart(db, "admin", "a-good-first-password", dir, true); err != nil {
		t.Fatal("a configured password must still bootstrap a replica:", err)
	}
	if err := bootstrapOnStart(db, "admin", "", dir, true); err != nil {
		t.Fatal("an existing administrator must satisfy a replica:", err)
	}
}

// Every replica's scheduler sees the same backup come due. One runs it.
func TestScheduledBackupRunsOnOneReplica(t *testing.T) {
	cfg, _ := commandInstance(t, true)
	cfg.BackupDir = t.TempDir()
	if _, err := crypto.LoadOrCreateRSAKey(cfg.RSAKeyPath); err != nil {
		t.Fatal(err)
	}
	stores := handles(t, cfg.DBPath, 4)
	capsules := func() int {
		t.Helper()
		copies, err := backup.ListLocalCopies(cfg.BackupDir, cfg.AppName)
		if err != nil {
			t.Fatal(err)
		}
		return len(copies)
	}
	for range 3 {
		allAtOnce(stores, func(_ int, s *store.Store) error {
			scheduledBackup(context.Background(), cfg, s, nil, audit.NewLogger(s))
			return nil
		})
		if n := capsules(); n != 1 {
			t.Fatalf("%d capsules after the schedule came due once, want 1", n)
		}
	}
	// The lease is given back, so the next due run is not refused.
	if release, ok, err := stores[0].AcquireLease(backup.Lease, backup.LeaseTTL); err != nil || !ok {
		t.Fatal("the backup lease was left held:", ok, err)
	} else {
		release()
	}
	// While another replica is mid-backup, this one does not start a second.
	if err := stores[0].DeleteSetting("backup_last_attempt"); err != nil {
		t.Fatal(err)
	}
	release, _, _ := stores[1].AcquireLease(backup.Lease, backup.LeaseTTL)
	scheduledBackup(context.Background(), cfg, stores[0], nil, audit.NewLogger(stores[0]))
	if n := capsules(); n != 1 {
		t.Fatalf("a second backup ran while the lease was held: %d capsules", n)
	}
	release()
	scheduledBackup(context.Background(), cfg, stores[0], nil, audit.NewLogger(stores[0]))
	if n := capsules(); n != 2 {
		t.Fatalf("the due backup did not run once the lease was free: %d capsules", n)
	}
}

// A replica whose data directory holds no recovery.pub takes the pinned key from the
// database, once its configuration names that key, and runs the due backup. With no copy to take it from, the run is audited as
// a failure: it used to return without a word, and nothing was backed up.
func TestScheduledBackupOnAReplicaWithoutTheKeyFile(t *testing.T) {
	cfg, _ := commandInstance(t, true)
	cfg.BackupDir = t.TempDir()
	if _, err := crypto.LoadOrCreateRSAKey(cfg.RSAKeyPath); err != nil {
		t.Fatal(err)
	}
	s := handles(t, cfg.DBPath, 1)[0]
	replica := *cfg
	replica.DataDir = t.TempDir()
	var err error
	if replica.RecoveryKeyID, err = s.GetSetting("kyrecovery_key_id"); err != nil {
		t.Fatal(err)
	}
	failures := func() int {
		t.Helper()
		_, n, err := s.SearchAuditEvents(store.AuditFilter{Action: "admin.backup_run", Outcome: "failure", Limit: 1})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Not before its configuration names the key: the database alone does not choose it.
	unnamed := replica
	unnamed.RecoveryKeyID = ""
	for range 2 {
		scheduledBackup(context.Background(), &unnamed, s, nil, audit.NewLogger(s))
	}
	if copies, _ := backup.ListLocalCopies(cfg.BackupDir, cfg.AppName); len(copies) != 0 || failures() != 1 {
		t.Fatalf("replica with no key named: %d capsules, %d failures, want none and one", len(copies), failures())
	}
	if err := s.DeleteSetting("backup_last_attempt"); err != nil {
		t.Fatal(err)
	}

	scheduledBackup(context.Background(), &replica, s, nil, audit.NewLogger(s))
	copies, err := backup.ListLocalCopies(cfg.BackupDir, cfg.AppName)
	if err != nil || len(copies) != 1 || failures() != 1 {
		t.Fatalf("replica without recovery.pub: %d capsules, %d failures, %v", len(copies), failures(), err)
	}

	for _, key := range []string{"kyrecovery_public_key", "backup_last_attempt"} {
		if err := s.DeleteSetting(key); err != nil {
			t.Fatal(err)
		}
	}
	bare := *cfg
	bare.DataDir = t.TempDir()
	scheduledBackup(context.Background(), &bare, s, nil, audit.NewLogger(s))
	if failures() != 2 {
		t.Fatal("a pinned key this replica cannot load was skipped without an audit row")
	}
}
