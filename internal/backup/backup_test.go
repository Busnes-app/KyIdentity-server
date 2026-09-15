package backup_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/kyidentity-server/internal/backup"
	"github.com/Busness-app/kyidentity-server/internal/config"
	"github.com/Busness-app/kyidentity-server/internal/crypto"
	"github.com/Busness-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// instance is a live kyidentity data directory: a store with one active admin, a signing key,
// and 32-byte deployment keys, which is what the collector needs to produce a capsule.
func instance(t *testing.T) (*config.Config, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		Port:          "5867",
		IssuerURL:     "https://sso.example.test",
		DBPath:        filepath.Join(dir, "kyidentity.db"),
		DataDir:       dir,
		RSAKeyPath:    filepath.Join(dir, "jwt_rs256.key"),
		SecretKey:     make([]byte, config.KeyLength),
		EncryptionKey: make([]byte, config.KeyLength),
		AppName:       config.DefaultAppName,
		SessionTTL:    time.Hour,
	}
	if _, err := rand.Read(cfg.EncryptionKey); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(cfg.SecretKey); err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.LoadOrCreateRSAKey(cfg.RSAKeyPath); err != nil {
		t.Fatal(err)
	}
	st, err := store.New(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.CreateUser(&store.User{ID: uuid.NewString(), Username: "admin", DisplayName: "Admin", Email: "admin@example.test",
		PasswordHash: "x", Role: "admin", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	return cfg, st
}

func pair(t *testing.T, cfg *config.Config, st *store.Store) recoverykey.PrivateKey {
	t.Helper()
	priv, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := backup.StoreRecoveryKey(cfg.DataDir, st, backup.RecoveryKey{Public: priv.Public(), Threshold: 2, TotalShares: 3}); err != nil {
		t.Fatal(err)
	}
	if err := backup.StorePairing(st, cfg.EncryptionKey, "https://recovery.example.test", "kyrec_live_t"); err != nil {
		t.Fatal(err)
	}
	return priv
}

// fakeStore is kyrecovery's side of a deposit: it answers with the receipt the real server
// would for the bytes it received.
type fakeStore struct {
	url, token string
	container  []byte
	err        error
}

func (f *fakeStore) Deposit(_ context.Context, serverURL, apiToken string, container []byte) (backup.Receipt, error) {
	f.url, f.token, f.container = serverURL, apiToken, container
	if f.err != nil {
		return backup.Receipt{}, f.err
	}
	m, err := capsule.ReadUnverifiedManifest(container)
	if err != nil {
		return backup.Receipt{}, err
	}
	sum := sha256.Sum256(container)
	return backup.Receipt{CapsuleID: m.CapsuleID, Digest: hex.EncodeToString(sum[:]), SizeBytes: int64(len(container)), DepositedAt: time.Now().UTC()}, nil
}

// The capsule must carry everything a restore needs, and the database inside it must be a
// consistent snapshot: the store runs in WAL mode, and a row committed moments ago lives only
// in the -wal until a checkpoint.
func TestCollectSealableCarriesEverythingARestoreNeeds(t *testing.T) {
	cfg, st := instance(t)
	if err := st.SetSetting("canary", "still-in-the-wal"); err != nil {
		t.Fatal(err)
	}
	payload, err := backup.CollectSealable(cfg, st, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]byte{}
	for _, f := range payload.Files {
		got[f.Path] = f.Data
		if f.Mode != 0600 {
			t.Errorf("%s mode %o", f.Path, f.Mode)
		}
	}
	for _, want := range []string{"data/kyidentity.db", "data/jwt_rs256.key", "data/encryption.key", "data/secret.key", "config/kyidentity.json"} {
		if len(got[want]) == 0 {
			t.Errorf("missing %s", want)
		}
	}
	if string(got["data/encryption.key"]) != string(cfg.EncryptionKey) {
		t.Error("encryption key is not the loaded one byte for byte")
	}
	restored := filepath.Join(t.TempDir(), "restored.db")
	if err := os.WriteFile(restored, got["data/kyidentity.db"], 0600); err != nil {
		t.Fatal(err)
	}
	copyStore, err := store.New(restored)
	if err != nil {
		t.Fatalf("snapshot does not open: %v", err)
	}
	defer copyStore.Close()
	if v, err := copyStore.GetSetting("canary"); err != nil || v != "still-in-the-wal" {
		t.Fatalf("snapshot lacks the uncheckpointed row: %q %v", v, err)
	}
	if entries, _ := os.ReadDir(cfg.DataDir); len(entries) > 0 {
		for _, e := range entries {
			if e.IsDir() && strings.HasPrefix(e.Name(), "snapshot-") {
				t.Error("snapshot scratch directory left behind")
			}
		}
	}
	if payload.ServiceName != "KyIdentity" {
		t.Errorf("service name %q", payload.ServiceName)
	}
}

func TestDrillProvesARestoreIsUsable(t *testing.T) {
	cfg, st := instance(t)
	payload, err := backup.CollectSealable(cfg, st, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	result, err := backup.RunRestoreDrill(context.Background(), cfg.DataDir, payload.ServiceName, payload.AppVersion, payload.Files, payload.Dependencies, payload.VerificationRecipe, backup.RecoveryKey{})
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, c := range result.Checks {
		names[c.Name] = c.Passed
	}
	// Unpaired: the only failing check is the recovery key; everything about the bytes passes.
	if names["Recovery Key"] {
		t.Error("unpaired drill claimed a recovery key")
	}
	for _, want := range []string{"Directory Unpack", "Required Files", "Token Signing", "Session Secret Restored"} {
		if !names[want] {
			t.Errorf("check %q did not pass: %+v", want, result.Checks)
		}
	}
	if result.Passed {
		t.Error("an unpaired drill passed")
	}

	priv := pair(t, cfg, st)
	pinned, err := backup.LoadRecoveryKey(cfg.DataDir, st)
	if err != nil {
		t.Fatal(err)
	}
	result, err = backup.RunRestoreDrill(context.Background(), cfg.DataDir, payload.ServiceName, payload.AppVersion, payload.Files, payload.Dependencies, payload.VerificationRecipe, pinned)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Passed {
		t.Fatalf("paired drill failed: %+v", result.Checks)
	}
	_ = priv
}

func TestDepositSealsToThePinnedKeyAndRecordsTheReceipt(t *testing.T) {
	cfg, st := instance(t)
	priv := pair(t, cfg, st)
	fake := &fakeStore{}
	res, err := backup.RunBackup(context.Background(), cfg, st, st, fake, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if fake.url != "https://recovery.example.test" || fake.token != "kyrec_live_t" {
		t.Errorf("sent to %s with %s", fake.url, fake.token)
	}
	m, rcpt := res.Manifest, res.Receipt
	if rcpt == nil || m.ServiceName != "KyIdentity" || m.RecoveryKeyID != priv.Public().ID() || rcpt.CapsuleID != m.CapsuleID || res.LocalPath != "" {
		t.Fatalf("result %+v", res)
	}
	if _, files, err := capsule.Open(fake.container, priv, t.TempDir()); err != nil || len(files) < 5 {
		t.Fatalf("what the store holds does not open with the suite key: %v (%d files)", err, len(files))
	}
	last, ok, err := backup.LastDeposit(st)
	if err != nil || !ok || last.CapsuleID != rcpt.CapsuleID {
		t.Errorf("last deposit %+v %v %v", last, ok, err)
	}
}

func TestLocalCopiesWithoutKyRecovery(t *testing.T) {
	cfg, st := instance(t)
	cfg.BackupDir = filepath.Join(t.TempDir(), "capsules")
	cfg.BackupKeep = 2
	priv, _ := recoverykey.Generate()
	if err := backup.StoreRecoveryKey(cfg.DataDir, st, backup.RecoveryKey{Public: priv.Public(), Threshold: 2, TotalShares: 3}); err != nil {
		t.Fatal(err)
	}
	fake := &fakeStore{}
	var last backup.Result
	for i := 0; i < 3; i++ {
		res, err := backup.RunBackup(context.Background(), cfg, st, st, fake, "1.0.0")
		if err != nil {
			t.Fatal(err)
		}
		if res.Receipt != nil || res.LocalPath == "" {
			t.Fatalf("unpaired run: %+v", res)
		}
		last = res
		time.Sleep(20 * time.Millisecond)
	}
	if fake.container != nil {
		t.Error("bytes were sent without a pairing")
	}
	copies, err := backup.ListLocalCopies(cfg.BackupDir, cfg.AppName)
	if err != nil || len(copies) != 2 || copies[0].Name != filepath.Base(last.LocalPath) {
		t.Fatalf("copies %+v %v", copies, err)
	}
	raw, err := os.ReadFile(last.LocalPath)
	if err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(last.LocalPath); info.Mode().Perm() != 0600 {
		t.Errorf("mode %v", info.Mode())
	}
	if _, files, err := capsule.Open(raw, priv, t.TempDir()); err != nil || len(files) < 5 {
		t.Fatalf("local copy does not open with the suite key: %v", err)
	}
}

func TestLegacyLocalCopyIsMigratedWithoutTouchingForeignFiles(t *testing.T) {
	dir := t.TempDir()
	legacy := "KyIdentity-cap-KyIdentity-123456789.kycap"
	foreign := "KyIdentity-operator-export.kycap"
	if err := os.WriteFile(filepath.Join(dir, legacy), []byte("sealed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, foreign), []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	copies, err := backup.ListLocalCopies(dir, "KyIdentity")
	if err != nil {
		t.Fatal(err)
	}
	if len(copies) != 1 || copies[0].Name != "KyIdentity.cap-KyIdentity-123456789.kycap" {
		t.Fatalf("migrated copies = %+v", copies)
	}
	if _, err := os.Stat(filepath.Join(dir, legacy)); !os.IsNotExist(err) {
		t.Fatalf("legacy filename still exists: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(dir, foreign)); err != nil || string(got) != "foreign" {
		t.Fatalf("foreign file changed: %q, %v", got, err)
	}
}

// The directory may already hold capsules the operator put there: another service's, an
// export, a restore staged. Pruning touches only what this instance wrote.
func TestRecoveryTokenIsNeverStoredInTheClear(t *testing.T) {
	cfg, st := instance(t)
	pair(t, cfg, st)
	for _, key := range []string{"kyrecovery_token_enc", "kyrecovery_url", "kyrecovery_token"} {
		v, err := st.GetSetting(key)
		if err == nil && strings.Contains(v, "kyrec_live_t") {
			t.Errorf("%s holds the token in the clear", key)
		}
	}
	p, err := backup.LoadPairing(cfg.DataDir, st, cfg.EncryptionKey)
	if err != nil || p.Token != "kyrec_live_t" {
		t.Fatalf("load: %+v %v", p, err)
	}
	other := make([]byte, config.KeyLength)
	if _, err := backup.LoadPairing(cfg.DataDir, st, other); err == nil {
		t.Error("the token decrypted under a different deployment key")
	}
}

func TestALostKeyPinIsNotSilentlyUnpaired(t *testing.T) {
	cfg, st := instance(t)
	pair(t, cfg, st)
	if err := os.Remove(backup.RecoveryKeyPath(cfg.DataDir)); err != nil {
		t.Fatal(err)
	}
	_, err := backup.RunBackup(context.Background(), cfg, st, st, &fakeStore{}, "1.0.0")
	if !errors.Is(err, backup.ErrKeyPinMissing) {
		t.Fatalf("got %v, want ErrKeyPinMissing", err)
	}
	if errors.Is(err, backup.ErrNotPaired) {
		t.Error("a broken pairing reads as never paired, which the scheduler skips silently")
	}
	_, outcome, details := backup.Outcome(backup.Result{}, err)
	if outcome != "failure" || !strings.Contains(fmt.Sprint(details["error"]), "missing") {
		t.Errorf("outcome %s %v", outcome, details)
	}
}

// ClearPairing removes rows; it does not claim more. A half-cleared pairing is still
// clearable, and the key pin survives.
func TestClearPairingRemovesRowsAndKeepsThePin(t *testing.T) {
	cfg, st := instance(t)
	priv := pair(t, cfg, st)
	if err := backup.ClearPairing(st); err != nil {
		t.Fatal(err)
	}
	if backup.HasPairing(st) {
		t.Error("still paired")
	}
	if _, err := st.GetSetting("kyrecovery_token_enc"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("token row: %v", err)
	}
	if k, err := backup.LoadRecoveryKey(cfg.DataDir, st); err != nil || k.Public.ID() != priv.Public().ID() {
		t.Errorf("key pin lost: %v", err)
	}
	if err := backup.ClearPairing(st); !errors.Is(err, backup.ErrNotPaired) {
		t.Errorf("second clear: %v", err)
	}
	// Only the URL survived an earlier failure: still clearable.
	if err := st.SetSetting("kyrecovery_url", "https://recovery.example.test"); err != nil {
		t.Fatal(err)
	}
	if err := backup.ClearPairing(st); err != nil {
		t.Errorf("half-cleared: %v", err)
	}
	if _, err := st.GetSetting("kyrecovery_url"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("url row: %v", err)
	}
}

// A token sealed by the pre-lib code path, with the same label, must open through the adapter:
// this is what keeps the live pairing working across the swap.
func TestAPairingSealedBeforeTheLibStillOpens(t *testing.T) {
	cfg, st := instance(t)
	priv, _ := recoverykey.Generate()
	if err := backup.StoreRecoveryKey(cfg.DataDir, st, backup.RecoveryKey{Public: priv.Public(), Threshold: 2, TotalShares: 3}); err != nil {
		t.Fatal(err)
	}
	sealed, err := crypto.EncryptAESGCM(crypto.DeriveKey(cfg.EncryptionKey, "kysignon:setting:kyrecovery_token"), []byte("kyrec_live_old"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting("kyrecovery_url", "https://recovery.example.test"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting("kyrecovery_token_enc", sealed); err != nil {
		t.Fatal(err)
	}
	p, err := backup.LoadPairing(cfg.DataDir, st, cfg.EncryptionKey)
	if err != nil || p.Token != "kyrec_live_old" {
		t.Fatalf("%v %+v", err, p)
	}
}

// The store's not-found must read as the lib's, or a never-paired instance would look broken.
func TestSettingsAdapterMapsNotFound(t *testing.T) {
	cfg, st := instance(t)
	if _, err := backup.LoadRecoveryKey(cfg.DataDir, st); !errors.Is(err, backup.ErrNotPaired) {
		t.Fatalf("fresh store: %v", err)
	}
	if backup.HasPairing(st) {
		t.Fatal("fresh store paired")
	}
	if err := backup.ClearPairing(st); !errors.Is(err, backup.ErrNotPaired) {
		t.Fatalf("clear on fresh store: %v", err)
	}
}

func TestPrivateDestinationRefusalNamesTheSwitch(t *testing.T) {
	err := backup.ValidateRecoveryURL("https://192.168.1.91", false)
	if err == nil || !strings.Contains(err.Error(), "KYIDENTITY_BACKUP_ALLOW_PRIVATE_RECOVERY") {
		t.Fatalf("%v", err)
	}
	if err := backup.ValidateRecoveryURL("https://192.168.1.91", true); err != nil {
		t.Fatalf("with the switch: %v", err)
	}
}
