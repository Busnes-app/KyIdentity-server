package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/capsule"
	"github.com/Busnes-app/kyidentity-server/internal/audit"
	"github.com/Busnes-app/kyidentity-server/internal/backup"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// shortLease shortens the backup lease for one test.
func shortLease(t *testing.T, ttl time.Duration) {
	t.Helper()
	prev := backup.LeaseTTL
	backup.LeaseTTL = ttl
	t.Cleanup(func() { backup.LeaseTTL = prev })
}

func localCopies(t *testing.T, dir, app string) []string {
	t.Helper()
	copies, err := backup.ListLocalCopies(dir, app)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range copies {
		names = append(names, c.Name)
	}
	slices.Sort(names)
	return names
}

// A holder that died with the backup lease delays another replica's due backup by at most
// the lease's ttl and one scheduler tick, not by the hours a fixed lease used to cost.
func TestADeadHolderDelaysTheScheduleByOneTTL(t *testing.T) {
	const ttl, tick = time.Second, 100 * time.Millisecond
	shortLease(t, ttl)
	cfg, _ := commandInstance(t, true)
	cfg.BackupDir, cfg.BackupKeep = t.TempDir(), 3
	if _, err := crypto.LoadOrCreateRSAKey(cfg.RSAKeyPath); err != nil {
		t.Fatal(err)
	}
	stores := handles(t, cfg.DBPath, 2)
	// The dead replica took the lease and will never renew or release it.
	if _, ok, err := stores[1].AcquireLease(backup.Lease, ttl); err != nil || !ok {
		t.Fatal(ok, err)
	}
	died := time.Now()
	sched, stop := context.WithCancel(context.Background())
	defer stop()
	done := make(chan struct{})
	go func() {
		defer close(done)
		backupLoop(sched, context.Background(), cfg, stores[0], nil, audit.NewLogger(stores[0]), tick)
	}()
	for len(localCopies(t, cfg.BackupDir, cfg.AppName)) == 0 {
		if time.Since(died) > ttl+tick+3*time.Second {
			t.Fatal("the due backup never ran after the dead holder's lease expired")
		}
		time.Sleep(20 * time.Millisecond)
	}
	waited := time.Since(died)
	stop()
	<-done
	// The run itself (snapshot, seal, write) takes well under a second here.
	if waited > ttl+tick+time.Second {
		t.Fatalf("the due backup waited %v behind a dead holder, want at most %v plus the run", waited, ttl+tick)
	}
	t.Logf("ran %v after the holder died (ttl %v, tick %v)", waited, ttl, tick)
}

// Taking the lease from a running deposit, by deleting or stealing its row, ends that
// deposit within one renewal interval: it records a failure, writes no receipt, and the
// replica the lease now belongs to can run.
func TestALostLeaseEndsTheRunningDeposit(t *testing.T) {
	for _, how := range []string{"deleted", "stolen"} {
		t.Run(how, func(t *testing.T) {
			const ttl = 800 * time.Millisecond
			shortLease(t, ttl)
			cfg, _ := commandInstance(t, true)
			if _, err := crypto.LoadOrCreateRSAKey(cfg.RSAKeyPath); err != nil {
				t.Fatal(err)
			}
			stores := handles(t, cfg.DBPath, 2)
			a, b := stores[0], stores[1]
			if err := backup.StorePairing(a, cfg.EncryptionKey, "https://recovery.example.test", "token"); err != nil {
				t.Fatal(err)
			}
			raw, err := store.OpenRawForTest(cfg.DBPath)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			dep := newBlocker()
			done := make(chan struct{})
			go func() { defer close(done); scheduledBackup(context.Background(), cfg, a, dep, audit.NewLogger(a)) }()
			dep.wait(t, "the deposit")
			q := `DELETE FROM leases WHERE name=?`
			if how == "stolen" {
				q = `UPDATE leases SET token='thief' WHERE name=?`
			}
			if _, err := raw.Exec(q, backup.Lease); err != nil {
				t.Fatal(err)
			}
			taken := time.Now()
			select {
			case <-done:
			case <-time.After(ttl/4 + 2*time.Second):
				t.Fatal("the deposit kept running after its lease was taken")
			}
			if took := time.Since(taken); took > ttl/4+time.Second {
				t.Fatalf("the deposit ended %v after the lease was taken, interval %v", took, ttl/4)
			}
			if failures(t, a, "admin.backup_run") != 1 {
				t.Fatal("the cancelled deposit recorded no failure")
			}
			if _, ok, _ := backup.LastDeposit(a); ok {
				t.Fatal("the cancelled deposit recorded a receipt")
			}
			if how == "stolen" {
				if _, err := raw.Exec(`DELETE FROM leases WHERE name=? AND token='thief'`, backup.Lease); err != nil {
					t.Fatal(err)
				}
			}
			// B's turn: the run is due again once its attempt stamp is cleared.
			if err := b.DeleteSetting("backup_last_attempt"); err != nil {
				t.Fatal(err)
			}
			scheduledBackup(context.Background(), cfg, b, &fakeDepositor{}, audit.NewLogger(b))
			if _, ok, err := backup.LastDeposit(b); err != nil || !ok {
				t.Fatalf("the replica holding the lease next did not deposit: %v %v", ok, err)
			}
		})
	}
}

// A schedule the scheduler cannot read is a failed run in the audit log, never a quiet skip.
func TestUnreadableSettingsAreAFailedScheduledRun(t *testing.T) {
	cfg, _ := commandInstance(t, true)
	s := handles(t, cfg.DBPath, 1)[0]
	raw, err := store.OpenRawForTest(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`ALTER TABLE system_settings RENAME TO system_settings_hidden`); err != nil {
		t.Fatal(err)
	}
	scheduledBackup(context.Background(), cfg, s, nil, audit.NewLogger(s))
	if _, err := raw.Exec(`ALTER TABLE system_settings_hidden RENAME TO system_settings`); err != nil {
		t.Fatal(err)
	}
	if failures(t, s, "admin.backup_run") != 1 {
		t.Fatal("an unreadable schedule was skipped without a failed admin.backup_run")
	}
}

// One backup directory shared by every replica: concurrent due runs from several handles
// write one capsule per due run, retention holds KEEP, and every handle lists the same
// copies. Per-replica directories hold only their own server's copies.
func TestLocalBackupDirectoryLayouts(t *testing.T) {
	t.Run("shared", func(t *testing.T) {
		cfg, _ := commandInstance(t, true)
		cfg.BackupDir, cfg.BackupKeep = t.TempDir(), 2
		if _, err := crypto.LoadOrCreateRSAKey(cfg.RSAKeyPath); err != nil {
			t.Fatal(err)
		}
		stores := handles(t, cfg.DBPath, 3)
		for round := 1; round <= 4; round++ {
			if err := stores[0].DeleteSetting("backup_last_attempt"); err != nil {
				t.Fatal(err)
			}
			allAtOnce(stores, func(_ int, s *store.Store) error {
				scheduledBackup(context.Background(), cfg, s, nil, audit.NewLogger(s))
				return nil
			})
			if n := len(localCopies(t, cfg.BackupDir, cfg.AppName)); n != min(round, cfg.BackupKeep) {
				t.Fatalf("round %d: %d capsules, want %d", round, n, min(round, cfg.BackupKeep))
			}
		}
		_, runs, err := stores[0].SearchAuditEvents(store.AuditFilter{Action: "admin.backup_run", Outcome: "success", Limit: 1})
		if err != nil || runs != 4 {
			t.Fatalf("%d successful runs for four due runs: %v", runs, err)
		}
		want := localCopies(t, cfg.BackupDir, cfg.AppName)
		for i := range stores {
			// Each replica lists the directory it is configured with: here, the same one.
			replica := *cfg
			replica.DataDir = filepath.Join(t.TempDir(), "replica")
			if got := localCopies(t, replica.BackupDir, replica.AppName); !slices.Equal(got, want) {
				t.Fatalf("handle %d lists %v, want %v", i, got, want)
			}
		}
	})
	t.Run("per replica", func(t *testing.T) {
		cfg, _ := commandInstance(t, true)
		if _, err := crypto.LoadOrCreateRSAKey(cfg.RSAKeyPath); err != nil {
			t.Fatal(err)
		}
		stores := handles(t, cfg.DBPath, 3)
		dirs := make([]string, len(stores))
		for i := range dirs {
			dirs[i] = t.TempDir()
		}
		total := 0
		for round := 1; round <= 3; round++ {
			if err := stores[0].DeleteSetting("backup_last_attempt"); err != nil {
				t.Fatal(err)
			}
			allAtOnce(stores, func(i int, s *store.Store) error {
				own := *cfg
				own.BackupDir, own.BackupKeep = dirs[i], 5
				scheduledBackup(context.Background(), &own, s, nil, audit.NewLogger(s))
				return nil
			})
			total = 0
			seen := map[string]int{}
			for i, dir := range dirs {
				names := localCopies(t, dir, cfg.AppName)
				total += len(names)
				entries, _ := os.ReadDir(dir)
				if len(entries) != len(names) {
					t.Fatalf("replica %d's directory holds files it does not list: %v", i, entries)
				}
				for _, n := range names {
					seen[n]++
				}
			}
			for name, n := range seen {
				if n != 1 {
					t.Fatalf("capsule %s is in %d replicas' directories", name, n)
				}
			}
			if total != round {
				t.Fatalf("round %d: %d capsules across the replicas, want %d", round, total, round)
			}
		}
	})
}

// fakeDepositor is KyRecovery accepting a deposit and answering with its receipt.
type fakeDepositor struct{}

func (fakeDepositor) Deposit(_ context.Context, _, _ string, raw []byte) (backup.Receipt, error) {
	m, err := capsule.ReadUnverifiedManifest(raw)
	if err != nil {
		return backup.Receipt{}, err
	}
	return backup.Receipt{CapsuleID: m.CapsuleID, Digest: sha256Hex(raw), SizeBytes: int64(len(raw)), DepositedAt: time.Now().UTC()}, nil
}
