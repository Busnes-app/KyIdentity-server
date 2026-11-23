package backup_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/Busnes-app/ky-primitives/recoverykey"
	"github.com/Busnes-app/kyidentity-server/internal/backup"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// switchingReader commits a change on a second handle immediately after the
// reader takes its pairing snapshot, while the public operation is still running.
type switchingReader struct {
	*store.Store
	afterRead func()
}

func (r switchingReader) GetSettings(keys ...string) (map[string]string, error) {
	rows, err := r.Store.GetSettings(keys...)
	if err == nil {
		r.afterRead()
	}
	return rows, err
}

func TestPairingReadsAreCoherentUnderConcurrentRepairing(t *testing.T) {
	cfg, writer := instance(t)
	pair(t, cfg, writer)
	reader, err := store.NewTest(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	const firstURL, firstToken = "https://recovery.example.test", "kyrec_live_t"
	const nextURL, nextToken = "https://b.recovery.example", "token-b"
	// Exercise the real multi-row SELECT across commits, including a driver
	// regression that splits one GetSettings call into separate queries.
	setPair := func(url, token string) {
		t.Helper()
		if err := writer.EditSettings(nil, func(st store.Settings) error {
			return backup.StorePairing(st, cfg.EncryptionKey, url, token)
		}); err != nil {
			t.Fatal(err)
		}
	}
	var reads sync.WaitGroup
	reads.Go(func() {
		for range 400 {
			p, err := backup.LoadPairing(cfg, reader)
			if err != nil || !(p.URL == firstURL && p.Token == firstToken || p.URL == nextURL && p.Token == nextToken) {
				t.Errorf("concurrent load: (%q, %q), %v", p.URL, p.Token, err)
				return
			}
		}
	})
	defer reads.Wait()
	for range 20 {
		setPair(nextURL, nextToken)
		setPair(firstURL, firstToken)
	}
	reads.Wait()
	unpair := func() {
		t.Helper()
		if err := writer.EditSettings(nil, func(st store.Settings) error { return backup.ClearPairing(st) }); err != nil {
			t.Fatal(err)
		}
	}
	// Load starts paired to A. Unpair and re-pair to B after the read: the
	// in-flight operation must retain A's URL and token.
	load := switchingReader{reader, func() {
		unpair()
		setPair(nextURL, nextToken)
	}}
	p, err := backup.LoadPairing(cfg, load)
	if err != nil || p.URL != firstURL || p.Token != firstToken {
		t.Fatalf("load during re-pair: (%q, %q), %v", p.URL, p.Token, err)
	}
	// The next operation must see B even though the writer now unpairs while
	// the backup is in flight. Its attempt and receipt can write normally.
	run := switchingReader{reader, unpair}
	dep := &fakeStore{}
	if _, err := backup.RunBackup(t.Context(), cfg, run, reader, dep, "1.0.0"); err != nil {
		t.Fatal(err)
	}
	if dep.url != nextURL || dep.token != nextToken {
		t.Fatalf("deposit during unpair used (%q, %q)", dep.url, dep.token)
	}
	if _, err := backup.LoadPairing(cfg, reader); !errors.Is(err, backup.ErrNotPaired) {
		t.Fatalf("load after unpair: %v", err)
	}
}

// failingSettings fails every read, as a database that has gone away does.
type failingSettings struct{ backup.SettingsStore }

var errUnreadable = errors.New("settings unreadable")

func (failingSettings) GetSetting(string) (string, error) { return "", errUnreadable }

// A read that fails is an error, never "unpaired" or "not pinned".
func TestUnreadableSettingsAreNotUnpaired(t *testing.T) {
	cfg, st := instance(t)
	pair(t, cfg, st)
	bad := failingSettings{st}
	if pinned, err := backup.KeyPinned(bad); !errors.Is(err, errUnreadable) || pinned {
		t.Fatalf("KeyPinned: %v %v", pinned, err)
	}
	if paired, err := backup.HasPairing(bad); !errors.Is(err, errUnreadable) || paired {
		t.Fatalf("HasPairing: %v %v", paired, err)
	}
	cfg.BackupDir, cfg.BackupKeep = t.TempDir(), 1
	if _, err := backup.RunBackup(context.Background(), cfg, bad, st, &fakeStore{}, "1.0.0"); err == nil || errors.Is(err, backup.ErrNotPaired) || errors.Is(err, backup.ErrNoDestination) {
		t.Fatalf("a backup with unreadable settings: %v", err)
	}
	if _, err := backup.LoadRecoveryKey(cfg, bad); err == nil || errors.Is(err, backup.ErrNotPaired) {
		t.Fatalf("a key load with unreadable settings: %v", err)
	}
	// Truly unpaired still reads as unpaired.
	_, fresh := instance(t)
	if pinned, err := backup.KeyPinned(fresh); err != nil || pinned {
		t.Fatalf("fresh KeyPinned: %v %v", pinned, err)
	}
	if paired, err := backup.HasPairing(fresh); err != nil || paired {
		t.Fatalf("fresh HasPairing: %v %v", paired, err)
	}
}

// A pinned key's k-of-n is written once: the same key with another topology is refused and
// changes nothing; the same topology again is accepted.
func TestPinnedTopologyIsWriteOnce(t *testing.T) {
	cfg, st := instance(t)
	priv, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	key := backup.RecoveryKey{Public: priv.Public(), Threshold: 2, TotalShares: 3}
	if err := backup.StoreRecoveryKey(cfg, st, key); err != nil {
		t.Fatal(err)
	}
	sealed, err := st.GetSetting("kyrecovery_public_key")
	if err != nil {
		t.Fatal(err)
	}
	for _, other := range []backup.RecoveryKey{{Public: priv.Public(), Threshold: 3, TotalShares: 3}, {Public: priv.Public(), Threshold: 2, TotalShares: 5}} {
		err := st.EditSettings(nil, func(s store.Settings) error { return backup.StoreRecoveryKey(cfg, s, other) })
		if !errors.Is(err, backup.ErrTopologyChanged) {
			t.Fatalf("%d-of-%d over 2-of-3: %v", other.Threshold, other.TotalShares, err)
		}
	}
	got, err := backup.LoadRecoveryKey(cfg, st)
	if err != nil || got.Threshold != 2 || got.TotalShares != 3 {
		t.Fatalf("stored topology after refusals: %+v %v", got, err)
	}
	if after, _ := st.GetSetting("kyrecovery_public_key"); after != sealed {
		t.Fatal("a refused re-pin rewrote the sealed key copy")
	}
	if err := backup.StoreRecoveryKey(cfg, st, key); err != nil {
		t.Fatal("the same key and topology again:", err)
	}
}

// snapshotProbe records the scratch directory's mode while the snapshot is written.
type snapshotProbe struct {
	inner backup.Snapshotter
	dir   string
	mode  os.FileMode
}

func (p *snapshotProbe) SnapshotTo(dest string) error {
	p.dir = filepath.Dir(dest)
	if info, err := os.Stat(p.dir); err == nil {
		p.mode = info.Mode().Perm()
	}
	return p.inner.SnapshotTo(dest)
}

// The plaintext snapshot lives only in a private, locked directory that is gone afterwards.
// A directory a crash left behind is removed at start; one a live process holds, a symlink
// and anything else are left alone.
func TestSnapshotScratchIsPrivateLockedAndSwept(t *testing.T) {
	cfg, st := instance(t)
	probe := &snapshotProbe{inner: st}
	if _, err := backup.CollectSealable(cfg, probe, "1.0.0"); err != nil {
		t.Fatal(err)
	}
	if probe.mode != 0o700 || !strings.HasPrefix(filepath.Base(probe.dir), "snapshot-") {
		t.Fatalf("scratch %s had mode %v", probe.dir, probe.mode)
	}
	if _, err := os.Stat(probe.dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scratch left behind: %v", err)
	}

	dir := cfg.DataDir
	mk := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "kyidentity.db"), []byte("plaintext"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	crashed := mk("snapshot-123")
	held := mk("snapshot-456")
	unrelated := mk("snapshotted-notes")
	elsewhere := t.TempDir()
	if err := os.WriteFile(filepath.Join(elsewhere, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "snapshot-link")
	if err := os.Symlink(elsewhere, link); err != nil {
		t.Fatal(err)
	}
	// A CLI deposit sharing the data directory holds its scratch directory's lock.
	fd, err := syscall.Open(held, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}

	backup.SweepScratch(dir)
	if _, err := os.Stat(crashed); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a crash leftover survived the sweep: %v", err)
	}
	for _, kept := range []string{filepath.Join(held, "kyidentity.db"), filepath.Join(unrelated, "kyidentity.db"), filepath.Join(elsewhere, "keep")} {
		if _, err := os.Stat(kept); err != nil {
			t.Fatalf("the sweep removed %s: %v", kept, err)
		}
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the sweep touched the symlink: %v", err)
	}
}
