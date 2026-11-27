package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadMLDSAKeyDefaultsToWritableDataDir verifies that mounting an RSA key
// from a read-only directory (such as a Kubernetes Secret) does not cause the
// default ML-DSA-65 key path to point into that read-only mount.
func TestLoadMLDSAKeyDefaultsToWritableDataDir(t *testing.T) {
	dataDir := t.TempDir()
	roDir := t.TempDir()
	rsaPath := filepath.Join(roDir, "jwt_rs256.key")
	if err := os.WriteFile(rsaPath, []byte("placeholder"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(roDir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(roDir, 0700) })

	t.Setenv("KYIDENTITY_DATA_DIR", dataDir)
	t.Setenv("KYIDENTITY_RSA_KEY_PATH", rsaPath)
	t.Setenv("KYIDENTITY_MLDSA_KEY_PATH", "")
	t.Setenv("KYIDENTITY_REPLICATED", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("config.Load failed: %v", err)
	}
	want := filepath.Join(dataDir, MLDSAKeyFile)
	if cfg.MLDSAKeyPath != want {
		t.Fatalf("MLDSAKeyPath = %q, want %q (writable DataDir)", cfg.MLDSAKeyPath, want)
	}
}
