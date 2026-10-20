package crypto

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// The server and a CLI subcommand starting together on a fresh data directory must agree on
// one signing key. Before, each wrote its own and the last write won, so tokens one process
// had already signed stopped verifying.
func TestLoadOrCreateRSAKeyConcurrentFirstStartAgrees(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jwt_rs256.key")
	const n = 8
	ids := make([]string, n)
	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			km, err := LoadOrCreateRSAKey(path)
			if errs[i] = err; err == nil {
				ids[i] = km.KeyID
			}
		}()
	}
	close(start)
	wg.Wait()
	onDisk, err := LoadOrCreateRSAKey(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if errs[i] != nil || ids[i] != onDisk.KeyID {
			t.Fatalf("caller %d: key %s, err %v; the file holds %s", i, ids[i], errs[i], onDisk.KeyID)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("temp files left behind: %v %v", entries, err)
	}
}

func TestCreateKeyFileNeverReplaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k")
	if err := CreateKeyFile(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := CreateKeyFile(path, []byte("second")); !os.IsExist(err) {
		t.Fatalf("second create: %v", err)
	}
	got, err := os.ReadFile(path)
	fi, _ := os.Stat(path)
	if err != nil || string(got) != "first" || fi.Mode().Perm() != 0600 {
		t.Fatalf("key file = %q mode %v, %v", got, fi.Mode().Perm(), err)
	}
}

func TestRSAKeyRefusesSharedAndSymlinkFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rsa")
	if _, err := LoadOrCreateRSAKey(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateRSAKey(path); err == nil {
		t.Fatal("read shared signing key")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, path+".link"); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateRSAKey(path + ".link"); err == nil {
		t.Fatal("read symlink signing key")
	}
}
