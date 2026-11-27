package backup_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Busnes-app/kyidentity-server/internal/backup"
	"github.com/Busnes-app/kyidentity-server/internal/config"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
)

func TestBackupAndDrillCarriesAndVerifiesMLDSAKey(t *testing.T) {
	cfg, st := instance(t)
	cfg.MLDSAKeyPath = filepath.Join(cfg.DataDir, config.MLDSAKeyFile)
	if _, _, _, err := crypto.LoadOrCreateMLDSAKey(cfg.MLDSAKeyPath); err != nil {
		t.Fatalf("LoadOrCreateMLDSAKey: %v", err)
	}
	origBytes, err := os.ReadFile(cfg.MLDSAKeyPath)
	if err != nil {
		t.Fatalf("read mldsa key: %v", err)
	}

	if m := backup.Members(cfg); !slices.Contains(m, "data/"+config.MLDSAKeyFile) {
		t.Fatalf("Members %v omitted data/%s", m, config.MLDSAKeyFile)
	}

	payload, err := backup.CollectSealable(cfg, st, "1.0.0")
	if err != nil {
		t.Fatalf("CollectSealable: %v", err)
	}
	if got := payload.VerificationRecipe["mldsa_key_file"]; got != "data/"+config.MLDSAKeyFile {
		t.Fatalf("VerificationRecipe[mldsa_key_file] = %q, want data/%s", got, config.MLDSAKeyFile)
	}

	var foundMLDSA bool
	for _, f := range payload.Files {
		if f.Path == "data/"+config.MLDSAKeyFile {
			foundMLDSA = true
			if f.Mode != 0600 {
				t.Fatalf("mldsa key mode = %o, want 0600", f.Mode)
			}
			if !bytes.Equal(f.Data, origBytes) {
				t.Fatal("mldsa key bytes were altered during collection")
			}
		}
	}
	if !foundMLDSA {
		t.Fatal("CollectSealable omitted data/jwt_mldsa65.key")
	}

	checkPassed := func(res *backup.DrillResult, name string) bool {
		for _, c := range res.Checks {
			if c.Name == name {
				return c.Passed
			}
		}
		return false
	}

	res, err := backup.RunRestoreDrill(context.Background(), cfg.DataDir, payload.ServiceName, payload.AppVersion, payload.Files, payload.Dependencies, payload.VerificationRecipe, backup.RecoveryKey{})
	if err != nil {
		t.Fatalf("RunRestoreDrill with valid ML-DSA-65 key: %v", err)
	}
	if !checkPassed(res, "Token Signing") {
		t.Fatalf("expected Token Signing check to pass, got %+v", res.Checks)
	}

	// Corrupting the backed-up ML-DSA-65 key must fail the Token Signing drill check.
	corrupted := slices.Clone(payload.Files)
	for i := range corrupted {
		if corrupted[i].Path == "data/"+config.MLDSAKeyFile {
			corrupted[i].Data = []byte("not-a-valid-mldsa-pem")
		}
	}
	badRes, err := backup.RunRestoreDrill(context.Background(), cfg.DataDir, payload.ServiceName, payload.AppVersion, corrupted, payload.Dependencies, payload.VerificationRecipe, backup.RecoveryKey{})
	if err == nil && checkPassed(badRes, "Token Signing") {
		t.Fatalf("RunRestoreDrill must fail Token Signing check when jwt_mldsa65.key is corrupted: %+v", badRes.Checks)
	}
}
