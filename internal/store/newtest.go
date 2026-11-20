package store

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// NewTest is New for test fixtures. On SQLite a path that does not exist yet starts as a
// copy of one database migrated once per test binary: migrating costs about a second
// under -race, paid by every test. Tests about migrations call New. Outside test
// binaries, on the Postgres test backend and for an existing path, it is New.
func NewTest(dbPath string) (*Store, error) {
	if !testing.Testing() || testDatabaseURL() != "" || dbPath == ":memory:" {
		return New(dbPath)
	}
	tmpl, err := sqliteTemplate()
	if err != nil {
		return nil, err
	}
	// Written aside and linked in, so a concurrent open never sees a partial copy and an
	// existing file is never replaced.
	f, err := os.CreateTemp(filepath.Dir(dbPath), ".template-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(tmpl)
	if err = errors.Join(err, f.Close()); err != nil {
		return nil, err
	}
	if err := os.Link(f.Name(), dbPath); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	return New(dbPath)
}

var sqliteTemplate = sync.OnceValues(func() ([]byte, error) {
	dir, err := os.MkdirTemp("", "kyidentity-template-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "template.db")
	s, err := New(path)
	if err != nil {
		return nil, err
	}
	if err := s.Close(); err != nil {
		return nil, err
	}
	// Closing the last connection checkpoints the WAL into the file; a leftover WAL
	// would mean the copy misses part of the schema.
	if _, err := os.Stat(path + "-wal"); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("template database left a WAL file behind")
	}
	return os.ReadFile(path)
})

// LeaseTicksForTest makes every lease holder renew on a receive from ticks instead of
// every ttl/4 until t ends, so a test, not the scheduler, decides when a renewal runs.
func LeaseTicksForTest(t testing.TB, ticks <-chan time.Time) {
	leaseTicks.Store(&ticks)
	t.Cleanup(func() { leaseTicks.Store(nil) })
}
