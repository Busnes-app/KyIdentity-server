package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/mfa"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

func TestOfflineKeyRotationPreservesPreparedSetupAndRecoveryCodes(t *testing.T) {
	b, file, db := stageFixture(t)
	t.Setenv("KYIDENTITY_DB_PATH", db)
	if _, err := stageCommand(t, b, file, db, false); err != nil {
		t.Fatal(err)
	}
	if err := runSetup([]string{"--file", file, "--db", db}, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	data := os.Getenv("KYIDENTITY_DATA_DIR")
	if err := os.Chmod(data, 0700); err != nil {
		t.Fatal(err)
	}
	oldKey, err := os.ReadFile(filepath.Join(data, "encryption.key"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.New(db)
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.GetUserByUsername(b.Everyday.Username)
	if err != nil {
		t.Fatal(err)
	}
	codes, err := mfa.NewEngine(s, oldKey).GenerateRecoveryCodes(u.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := crypto.Seal(oldKey, store.SealTOTP, u.ID, []byte("test-totp-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SetMFAMethod(&store.MFAMethod{ID: "totp", UserID: u.ID, MethodType: "totp", EncryptedSecret: sealed}, nil); err != nil {
		t.Fatal(err)
	}
	token, err := crypto.EncryptAESGCM(crypto.DeriveKey(oldKey, "kysignon:setting:kyrecovery_token"), []byte("keep-recovery-token"))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SetSetting("kyrecovery_token_enc", token); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 2; round++ {
		out := filepath.Join(t.TempDir(), "rotated")
		var report bytes.Buffer
		if err = runKeyRotation([]string{"--confirm-stopped", "--out", out}, &report); err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(report.Bytes(), []byte(`"verified":true`)) {
			t.Fatal("unverified rotation")
		}
		retained, _ := os.ReadFile(filepath.Join(data, "encryption.key"))
		if !bytes.Equal(retained, oldKey) {
			t.Fatal("source key changed")
		}
		newKey, err := os.ReadFile(filepath.Join(out, "encryption.key"))
		if err != nil || bytes.Equal(newKey, oldKey) {
			t.Fatal("no new key", err)
		}
		// Activate at the original path, exactly as the operator runbook requires.
		previous := data + "-previous"
		if err = os.Rename(data, previous); err != nil {
			t.Fatal(err)
		}
		if err = os.Rename(out, data); err != nil {
			t.Fatal(err)
		}
		if err = runSetup([]string{"--file", file, "--db", db, "--check"}, new(bytes.Buffer)); err != nil {
			t.Fatal("rotated setup cannot resume", err)
		}
		s, err = store.New(db)
		if err != nil {
			t.Fatal(err)
		}
		methods, err := s.ListUserMFAMethods(u.ID)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := crypto.Open(newKey, store.SealTOTP, u.ID, methods[0].EncryptedSecret)
		if err != nil || string(plain) != "test-totp-secret" {
			t.Fatal("TOTP lost", err)
		}
		sealedToken, err := s.GetSetting("kyrecovery_token_enc")
		if err != nil {
			t.Fatal(err)
		}
		plain, err = crypto.DecryptAESGCM(crypto.DeriveKey(newKey, "kysignon:setting:kyrecovery_token"), sealedToken)
		if err != nil || string(plain) != "keep-recovery-token" {
			t.Fatal("recovery token lost", err)
		}
		ok, err := mfa.NewEngine(s, newKey).VerifyAndConsumeRecoveryCode(u.ID, codes[round], nil)
		if err != nil || !ok {
			t.Fatal("recovery code lost", err)
		}
		s.Close()
		if err = os.RemoveAll(previous); err != nil {
			t.Fatal(err)
		}
		oldKey = newKey
	}
}

func TestOfflineKeyRotationRefusesLiveServerAndChangedReceipt(t *testing.T) {
	b, file, db := stageFixture(t)
	t.Setenv("KYIDENTITY_DB_PATH", db)
	if _, err := stageCommand(t, b, file, db, false); err != nil {
		t.Fatal(err)
	}
	data := os.Getenv("KYIDENTITY_DATA_DIR")
	if err := os.Chmod(data, 0700); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "output")
	lock, err := rotationLock(data, false)
	if err != nil {
		t.Fatal(err)
	}
	if err = runKeyRotation([]string{"--confirm-stopped", "--out", out}, new(bytes.Buffer)); err == nil {
		t.Fatal("rotated running server")
	}
	lock.Close()
	if err = os.WriteFile(filepath.Join(filepath.Dir(file), "credentials.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err = runKeyRotation([]string{"--confirm-stopped", "--out", out}, new(bytes.Buffer)); err == nil {
		t.Fatal("accepted corrupt receipt")
	}
	if _, err = os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("published failed rotation")
	}
}
