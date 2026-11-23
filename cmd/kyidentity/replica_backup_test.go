package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/capsule"
	"github.com/Busnes-app/kyidentity-server/internal/audit"
	"github.com/Busnes-app/kyidentity-server/internal/backup"
	"github.com/Busnes-app/kyidentity-server/internal/config"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

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

// A dead replica never releases its lease. The next scheduler tick must refuse
// the live row, then take it as soon as the database says it has expired.
func TestADeadHolderDelaysTheScheduleByOneTTL(t *testing.T) {
	cfg, _ := commandInstance(t, true)
	cfg.BackupDir, cfg.BackupKeep = t.TempDir(), 3
	if _, err := crypto.LoadOrCreateRSAKey(cfg.RSAKeyPath); err != nil {
		t.Fatal(err)
	}
	stores := handles(t, cfg.DBPath, 2)
	raw, err := store.OpenRawForTest(cfg.DBPath + "?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, ok, err := stores[1].AcquireLease(backup.Lease, backup.LeaseTTL); err != nil || !ok {
		t.Fatal(ok, err)
	}
	tick := func() {
		scheduledBackup(context.Background(), cfg, stores[0], nil, audit.NewLogger(stores[0]))
	}
	tick()
	if n := len(localCopies(t, cfg.BackupDir, cfg.AppName)); n != 0 {
		t.Fatalf("scheduler ran with the dead holder's lease still live: %d copies", n)
	}
	res, err := raw.Exec(`UPDATE leases SET until_ms=0 WHERE name=?`, backup.Lease)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		t.Fatalf("expiring the dead holder's lease: %d rows, %v", n, err)
	}
	tick()
	if n := len(localCopies(t, cfg.BackupDir, cfg.AppName)); n != 1 {
		t.Fatalf("first scheduler tick after expiry wrote %d backups, want 1", n)
	}
}

// Taking the lease from a running deposit, by deleting or stealing its row, ends that
// deposit at its next renewal: it records a failure, writes no receipt, and the replica the
// lease now belongs to can run. The test sends that renewal itself, under the production
// ttl, so a starved process cannot lose the lease for time first; how soon renewals run is
// TestALostLeaseEndsTheHold's to prove.
func TestALostLeaseEndsTheRunningDeposit(t *testing.T) {
	for _, how := range []string{"deleted", "stolen"} {
		t.Run(how, func(t *testing.T) {
			renew := make(chan time.Time)
			store.LeaseTicksForTest(t, renew)
			cfg, _ := commandInstance(t, true)
			if _, err := crypto.LoadOrCreateRSAKey(cfg.RSAKeyPath); err != nil {
				t.Fatal(err)
			}
			stores := handles(t, cfg.DBPath, 2)
			a, b := stores[0], stores[1]
			if err := backup.StorePairing(a, cfg.EncryptionKey, "https://recovery.example.test", "token"); err != nil {
				t.Fatal(err)
			}
			raw, err := store.OpenRawForTest(cfg.DBPath + "?_pragma=busy_timeout(5000)")
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
			select {
			case <-done:
				t.Fatal("the deposit ended before its lease was taken")
			default:
			}
			if res, err := raw.Exec(q, backup.Lease); err != nil {
				t.Fatal(err)
			} else if n, _ := res.RowsAffected(); n != 1 {
				t.Fatal("the running deposit held no lease to take")
			}
			select {
			case renew <- time.Now():
			case <-time.After(30 * time.Second):
				t.Fatal("the deposit's lease holder stopped renewing")
			}
			select {
			case <-done:
			case <-time.After(30 * time.Second):
				t.Fatal("the deposit kept running after its lease was taken")
			}
			if cause := <-dep.ended; !errors.Is(cause, store.ErrLeaseLost) {
				t.Fatalf("the deposit ended with %v, not the lost lease", cause)
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
		_, runs, err := stores[0].DefaultOrg().SearchAuditEvents(store.AuditFilter{Action: "admin.backup_run", Outcome: "success", Limit: 1})
		if err != nil || runs != 4 {
			t.Fatalf("%d successful runs for four due runs: %v", runs, err)
		}
		// Each replica's own backup page, its own data directory and handle, lists the same copies.
		want := localCopies(t, cfg.BackupDir, cfg.AppName)
		cfgs := make([]*config.Config, len(stores))
		for i := range stores {
			own := *cfg
			own.DataDir = t.TempDir()
			cfgs[i] = &own
		}
		for i, got := range statusCopies(t, stores, cfgs) {
			if !slices.Equal(got, want) {
				t.Fatalf("replica %d's backup page lists %v, want %v", i, got, want)
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
		// Each replica's backup page lists its own directory and nothing from the others'.
		cfgs := make([]*config.Config, len(stores))
		for i := range stores {
			own := *cfg
			own.BackupDir, own.BackupKeep, own.DataDir = dirs[i], 5, t.TempDir()
			cfgs[i] = &own
		}
		for i, got := range statusCopies(t, stores, cfgs) {
			if want := localCopies(t, dirs[i], cfg.AppName); !slices.Equal(got, want) {
				t.Fatalf("replica %d's backup page lists %v, its directory holds %v", i, got, want)
			}
		}
	})
}

// statusCopies serves each store with its configuration and returns the local copies each
// server's GET /api/admin/backup/status lists, as an administrator signed in on the first.
func statusCopies(t *testing.T, stores []*store.Store, cfgs []*config.Config) [][]string {
	t.Helper()
	var admin *adminClient
	out := make([][]string, len(stores))
	for i, s := range stores {
		_, base := liveServer(t, cfgs[i], s)
		if admin == nil {
			admin = newAdminClient(t, s, base)
		}
		res := admin.at(base).do("GET", "/api/admin/backup/status")
		var body struct {
			LocalCopies []struct {
				Name string `json:"name"`
			} `json:"local_copies"`
		}
		if res.status != 200 || json.Unmarshal(res.body, &body) != nil {
			t.Fatalf("replica %d status: %d %s", i, res.status, res.body)
		}
		for _, c := range body.LocalCopies {
			out[i] = append(out[i], c.Name)
		}
		slices.Sort(out[i])
	}
	return out
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
