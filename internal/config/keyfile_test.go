package config

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// Concurrent first starts (server plus bootstrap-admin, deposit or export-capsule) must all
// end up with the one key on disk, never each with their own.
func TestKeyFileConcurrentFirstStartAgrees(t *testing.T) {
	path := filepath.Join(t.TempDir(), "encryption.key")
	const n = 16
	keys := make([][]byte, n)
	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			keys[i], errs[i] = loadOrGenerateKeyFile(path)
		}()
	}
	close(start)
	wg.Wait()
	onDisk, err := loadOrGenerateKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if errs[i] != nil || !bytes.Equal(keys[i], onDisk) {
			t.Fatalf("caller %d got a key other than the one on disk (err %v)", i, errs[i])
		}
	}
}

func TestKeyFileRefusesUnsafeRetainedFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, make([]byte, KeyLength), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrGenerateKeyFile(path); err == nil {
		t.Fatal("read shared key")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrGenerateKeyFile(link); err == nil {
		t.Fatal("read symlink key")
	}
	if _, err := loadOrGenerateKeyFile(path); err != nil {
		t.Fatal(err)
	}
}
