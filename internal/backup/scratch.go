package backup

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// scratchPrefix names the directories CollectSealable snapshots the database into. They hold
// the plaintext database: on a PostgreSQL replica, the only copy of it on that disk.
const scratchPrefix = "snapshot-"

// lockedScratch makes a 0700 scratch directory under dataDir and holds an exclusive flock on
// it until release, which also removes it. The lock is what tells SweepScratch that the
// directory is in use by a live process, a CLI deposit sharing the data directory included.
func lockedScratch(dataDir string) (dir string, release func(), err error) {
	dir, err = os.MkdirTemp(dataDir, scratchPrefix+"*") // mode 0700
	if err != nil {
		return "", nil, err
	}
	f, err := lockDir(dir, syscall.LOCK_EX)
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", nil, err
	}
	// A server starting in the moment between the mkdir and the lock may have swept the
	// directory: refuse to write plaintext into anything but the directory this lock holds.
	if !sameDir(f, dir) {
		_ = f.Close()
		return "", nil, fmt.Errorf("snapshot scratch %s was removed before it could be locked", dir)
	}
	return dir, func() {
		_ = os.RemoveAll(dir)
		_ = f.Close()
	}, nil
}

func lockDir(dir string, how int) (*os.File, error) {
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), dir)
	if err := syscall.Flock(fd, how); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// sameDir reports whether path still names the directory f has open.
func sameDir(f *os.File, path string) bool {
	held, err := f.Stat()
	if err != nil {
		return false
	}
	now, err := os.Lstat(path)
	return err == nil && os.SameFile(held, now)
}

// SweepScratch removes snapshot scratch directories a killed process left under dataDir. It
// takes each one's lock without waiting, so a directory a live process holds is skipped; it
// never follows a symlink, and removes only directories this user owns that the path still
// names once locked. One owned by another user is reported, not removed.
func SweepScratch(dataDir string) {
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		log.Printf("[BACKUP] scratch sweep: %v", err)
		return
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), scratchPrefix) || e.Type()&os.ModeType != os.ModeDir {
			continue
		}
		path := filepath.Join(dataDir, e.Name())
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() {
			continue
		}
		if st, ok := info.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Getuid() {
			// Another user's, such as a deposit run as root: it may hold a plaintext database,
			// and only its owner may remove it.
			owner := -1
			if ok {
				owner = int(st.Uid)
			}
			log.Printf("[BACKUP] %s is a database snapshot left by another user (uid %d); it may hold the plaintext database: remove it as that user", path, owner)
			continue
		}
		f, err := lockDir(path, syscall.LOCK_EX|syscall.LOCK_NB)
		if errors.Is(err, syscall.EWOULDBLOCK) {
			continue // in use
		}
		if err != nil {
			log.Printf("[BACKUP] scratch sweep: %s: %v", e.Name(), err)
			continue
		}
		if sameDir(f, path) {
			if err := os.RemoveAll(path); err != nil {
				log.Printf("[BACKUP] scratch sweep: %s: %v", e.Name(), err)
			} else {
				log.Printf("[BACKUP] removed %s, a database snapshot an interrupted backup left behind", e.Name())
			}
		}
		_ = f.Close()
	}
}
