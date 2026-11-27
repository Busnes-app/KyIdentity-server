package main

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/Busnes-app/kyidentity-server/internal/backup"
	"github.com/Busnes-app/kyidentity-server/internal/config"
)

func TestLoadSigningKeysClearsMissingMLDSAPathOnReplica(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		DataDir:      dir,
		RSAKeyPath:   filepath.Join(dir, "oidc-signing.pem"),
		MLDSAKeyPath: filepath.Join(dir, "oidc-mldsa65.pem"),
		Replicated:   true,
	}

	km, err := loadSigningKeys(cfg)
	if err != nil {
		t.Fatalf("loadSigningKeys(replica without ML-DSA key): %v", err)
	}
	if km.MLDSAPublicKey != nil {
		t.Fatal("expected RSA-only key manager on replica without pre-provisioned ML-DSA key")
	}
	if cfg.MLDSAKeyPath != "" {
		t.Fatalf("cfg.MLDSAKeyPath = %q, want empty string so backup collection stays RSA-only", cfg.MLDSAKeyPath)
	}
	if slices.Contains(backup.Members(cfg), "oidc-mldsa65.pem") {
		t.Fatalf("backup.Members(cfg) unexpectedly listed oidc-mldsa65.pem for RSA-only replica: %v", backup.Members(cfg))
	}
}
