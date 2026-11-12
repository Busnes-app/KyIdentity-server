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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/capsule"
	"github.com/Busnes-app/ky-primitives/recoverykey"
	"github.com/Busnes-app/kyidentity-server/internal/backup"
	"github.com/Busnes-app/kyidentity-server/internal/config"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
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
		VAPIDKeyPath:  filepath.Join(dir, config.VAPIDKeyFile),
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
	if err := backup.StoreRecoveryKey(cfg, st, backup.RecoveryKey{Public: priv.Public(), Threshold: 2, TotalShares: 3}); err != nil {
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
	vapid := []byte("vapid-private-key-fixture\n")
	if err := os.WriteFile(filepath.Join(cfg.DataDir, config.VAPIDKeyFile), vapid, 0600); err != nil {
		t.Fatal(err)
	}
	relayKey := []byte("relay-api-key-fixture\n")
	if err := os.WriteFile(filepath.Join(cfg.DataDir, "push-relay-fcm-relay.example.key"), relayKey, 0600); err != nil {
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
	if string(got["data/"+config.VAPIDKeyFile]) != string(vapid) {
		t.Error("VAPID key is not carried byte for byte")
	}
	if m := backup.Members(cfg); !slices.Contains(m, "data/"+config.VAPIDKeyFile) {
		t.Errorf("members %v omit the VAPID key", m)
	}
	// The relay binds every phone's push token to this key; a restore elsewhere needs it.
	if string(got["data/push-relay-fcm-relay.example.key"]) != string(relayKey) {
		t.Error("push relay key is not carried byte for byte")
	}
	if m := backup.Members(cfg); !slices.Contains(m, "data/push-relay-fcm-relay.example.key") {
		t.Errorf("members %v omit the push relay key", m)
	}
	if string(got["data/encryption.key"]) != string(cfg.EncryptionKey) {
		t.Error("encryption key is not the loaded one byte for byte")
	}
	restored := filepath.Join(t.TempDir(), "restored.db")
	if err := os.WriteFile(restored, got["data/kyidentity.db"], 0600); err != nil {
		t.Fatal(err)
	}
	// The capsule's database is a SQLite file on either backend.
	t.Setenv("KYIDENTITY_TEST_DATABASE_URL", "")
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
	if payload.ServiceName != "KySignOn" {
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
	pinned, err := backup.LoadRecoveryKey(cfg, st)
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
	if rcpt == nil || m.ServiceName != "KySignOn" || m.RecoveryKeyID != priv.Public().ID() || rcpt.CapsuleID != m.CapsuleID || res.LocalPath != "" {
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
	if err := backup.StoreRecoveryKey(cfg, st, backup.RecoveryKey{Public: priv.Public(), Threshold: 2, TotalShares: 3}); err != nil {
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
	legacy := "KySignOn-cap-KySignOn-123456789.kycap"
	foreign := "KySignOn-operator-export.kycap"
	if err := os.WriteFile(filepath.Join(dir, legacy), []byte("sealed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, foreign), []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	copies, err := backup.ListLocalCopies(dir, "KySignOn")
	if err != nil {
		t.Fatal(err)
	}
	if len(copies) != 1 || copies[0].Name != "KySignOn.cap-KySignOn-123456789.kycap" {
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
	p, err := backup.LoadPairing(cfg, st)
	if err != nil || p.Token != "kyrec_live_t" {
		t.Fatalf("load: %+v %v", p, err)
	}
	other := *cfg
	other.EncryptionKey = make([]byte, config.KeyLength)
	if _, err := backup.LoadPairing(&other, st); err == nil {
		t.Error("the token decrypted under a different deployment key")
	}
}

func TestALostKeyPinIsNotSilentlyUnpaired(t *testing.T) {
	cfg, st := instance(t)
	pair(t, cfg, st)
	if err := os.Remove(backup.RecoveryKeyPath(cfg.DataDir)); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteSetting("kyrecovery_public_key"); err != nil {
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
	if k, err := backup.LoadRecoveryKey(cfg, st); err != nil || k.Public.ID() != priv.Public().ID() {
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
	if err := backup.StoreRecoveryKey(cfg, st, backup.RecoveryKey{Public: priv.Public(), Threshold: 2, TotalShares: 3}); err != nil {
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
	p, err := backup.LoadPairing(cfg, st)
	if err != nil || p.Token != "kyrec_live_old" {
		t.Fatalf("%v %+v", err, p)
	}
}

// The store's not-found must read as the lib's, or a never-paired instance would look broken.
func TestSettingsAdapterMapsNotFound(t *testing.T) {
	cfg, st := instance(t)
	if _, err := backup.LoadRecoveryKey(cfg, st); !errors.Is(err, backup.ErrNotPaired) {
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

// replica is a second server on the same database with its own, empty data directory,
// configured for the recovery key keyID.
func replica(t *testing.T, cfg *config.Config, keyID string) *config.Config {
	t.Helper()
	r := *cfg
	r.DataDir = t.TempDir()
	r.RecoveryKeyID = keyID
	return &r
}

// A replica that did not do the pairing has no recovery.pub. It takes the key its
// configuration names from the settings, so whichever replica the scheduler picks can seal
// the backup.
func TestEveryReplicaLoadsThePinnedKey(t *testing.T) {
	cfg, st := instance(t)
	priv := pair(t, cfg, st)
	other := replica(t, cfg, priv.Public().ID())
	k, err := backup.LoadRecoveryKey(other, st)
	if err != nil || k.Public.ID() != priv.Public().ID() || k.Threshold != 2 || k.TotalShares != 3 {
		t.Fatalf("replica load: %+v %v", k, err)
	}
	third := replica(t, cfg, priv.Public().ID())
	third.BackupDir, third.BackupKeep = t.TempDir(), 1
	if _, err := backup.RunBackup(context.Background(), third, st, st, &fakeStore{}, "1.0.0"); err != nil {
		t.Fatal("a replica with an empty data directory could not back up:", err)
	}
	// The key never sits in the settings in the clear.
	v, err := st.GetSetting("kyrecovery_public_key")
	if err != nil || strings.Contains(v, hex.EncodeToString(priv.Public().Bytes()[:16])) {
		t.Fatalf("settings copy: %v", err)
	}
}

// An install paired before the settings copy existed gains one the first time the server
// that holds recovery.pub loads the key.
func TestAnEarlierPairingIsSharedOnFirstLoad(t *testing.T) {
	cfg, st := instance(t)
	priv := pair(t, cfg, st)
	if err := st.DeleteSetting("kyrecovery_public_key"); err != nil {
		t.Fatal(err)
	}
	other := replica(t, cfg, priv.Public().ID())
	if _, err := backup.LoadRecoveryKey(other, st); !errors.Is(err, backup.ErrNotPaired) {
		t.Fatalf("a replica loaded a key nobody shared: %v", err)
	}
	if _, err := backup.LoadRecoveryKey(cfg, st); err != nil {
		t.Fatal(err)
	}
	if k, err := backup.LoadRecoveryKey(other, st); err != nil || k.Public.ID() != priv.Public().ID() {
		t.Fatalf("replica load after the holder shared it: %v", err)
	}
}

// noBackup fails the test if cfg can load a key, seal a capsule or gain a recovery.pub it
// did not start with.
func noBackup(t *testing.T, cfg *config.Config, st *store.Store) {
	t.Helper()
	_, statErr := os.Stat(backup.RecoveryKeyPath(cfg.DataDir))
	cfg.BackupDir, cfg.BackupKeep = t.TempDir(), 1
	if k, err := backup.LoadRecoveryKey(cfg, st); err == nil {
		t.Fatalf("loaded key %s", k.Public.ID())
	}
	if _, err := backup.LoadPairing(cfg, st); err == nil {
		t.Fatal("loaded the pairing")
	}
	if _, err := backup.RunBackup(context.Background(), cfg, st, st, &fakeStore{}, "1.0.0"); err == nil {
		t.Fatal("a backup was sealed")
	}
	if left, _ := os.ReadDir(cfg.BackupDir); len(left) != 0 {
		t.Fatalf("capsules written: %v", left)
	}
	if _, err := os.Stat(backup.RecoveryKeyPath(cfg.DataDir)); err == nil && statErr != nil {
		t.Fatal("recovery.pub was written")
	}
}

// Whoever can write the database, and nothing else, must not choose the key capsules are
// sealed to. Every forged or relocated copy leaves the replica without a key.
func TestADatabaseWriterCannotChooseTheRecoveryKey(t *testing.T) {
	attacker, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	foreign := make([]byte, config.KeyLength)
	foreign[0] = 1
	sealedUnder := func(key []byte, label string) string {
		t.Helper()
		v, err := crypto.EncryptAESGCM(crypto.DeriveKey(key, label), attacker.Public().Bytes())
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	cfg, st := instance(t)
	priv := pair(t, cfg, st)
	token, err := st.GetSetting("kyrecovery_token_enc")
	if err != nil {
		t.Fatal(err)
	}
	for name, forged := range map[string]string{
		"in the clear":                 hex.EncodeToString(attacker.Public().Bytes()),
		"sealed under another key":     sealedUnder(foreign, "kyidentity:setting:kyrecovery_public_key"),
		"sealed for another setting":   sealedUnder(cfg.EncryptionKey, "kysignon:setting:kyrecovery_token"),
		"another sealed setting moved": token,
	} {
		t.Run(name, func(t *testing.T) {
			if err := st.SetSetting("kyrecovery_public_key", forged); err != nil {
				t.Fatal(err)
			}
			if err := st.SetSetting("kyrecovery_key_id", attacker.Public().ID()); err != nil {
				t.Fatal(err)
			}
			noBackup(t, replica(t, cfg, priv.Public().ID()), st)
			noBackup(t, replica(t, cfg, attacker.Public().ID()), st)
		})
	}
}

// After a rotation the database still has, or can be given back, the old key's sealed copy
// and its ID: both are genuine, so only the configuration tells them from the current key.
// No server may go back to the old key, whether it has no recovery.pub or an old one.
func TestADatabaseWriterCannotPutBackAnEarlierKey(t *testing.T) {
	cfg, st := instance(t)
	old := pair(t, cfg, st)
	stale := replica(t, cfg, old.Public().ID())
	if _, err := backup.LoadRecoveryKey(stale, st); err != nil {
		t.Fatal(err) // stale now holds the old recovery.pub, as a replica with a volume would
	}
	oldCopy, err := st.GetSetting("kyrecovery_public_key")
	if err != nil {
		t.Fatal(err)
	}

	// Rotate: clear the pin, then pin the new key.
	for _, k := range []string{"kyrecovery_key_id", "kyrecovery_threshold", "kyrecovery_total_shares", "kyrecovery_public_key"} {
		if err := st.DeleteSetting(k); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(backup.RecoveryKeyPath(cfg.DataDir)); err != nil {
		t.Fatal(err)
	}
	current := pair(t, cfg, st)
	cfg.RecoveryKeyID = current.Public().ID()
	stale.RecoveryKeyID = current.Public().ID()

	// The rollback.
	if err := st.SetSetting("kyrecovery_public_key", oldCopy); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting("kyrecovery_key_id", old.Public().ID()); err != nil {
		t.Fatal(err)
	}

	t.Run("no recovery.pub", func(t *testing.T) { noBackup(t, replica(t, cfg, current.Public().ID()), st) })
	t.Run("no recovery.pub, nothing configured", func(t *testing.T) { noBackup(t, replica(t, cfg, ""), st) })
	t.Run("the old recovery.pub", func(t *testing.T) {
		noBackup(t, stale, st)
		if _, err := backup.LoadRecoveryKey(stale, st); !errors.Is(err, backup.ErrKeyRefused) {
			t.Fatalf("want the key refused, got %v", err)
		}
	})
	t.Run("the old recovery.pub, replica with nothing configured", func(t *testing.T) {
		unset := *stale
		unset.RecoveryKeyID, unset.Replicated = "", true
		noBackup(t, &unset, st)
		_, err := backup.LoadRecoveryKey(&unset, st)
		if !errors.Is(err, backup.ErrKeyRefused) || !strings.Contains(backup.AuditSafe(err.Error()), old.Public().ID()+", check it against KyRecovery") {
			t.Fatalf("want a refusal that names the variable and the key held, got %v", err)
		}
	})
	t.Run("the pinning server", func(t *testing.T) { noBackup(t, cfg, st) })
}

// A server configured for one key does not pin another, through the API or a pairing.
func TestOnlyTheConfiguredKeyIsPinned(t *testing.T) {
	cfg, st := instance(t)
	wanted, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	other, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	cfg.RecoveryKeyID = wanted.Public().ID()
	err = backup.StoreRecoveryKey(cfg, st, backup.RecoveryKey{Public: other.Public(), Threshold: 2, TotalShares: 3})
	if !errors.Is(err, backup.ErrKeyRefused) || backup.KeyPinned(st) {
		t.Fatalf("pinned a key the configuration does not name: %v", err)
	}
	if _, err := os.Stat(backup.RecoveryKeyPath(cfg.DataDir)); err == nil {
		t.Fatal("recovery.pub written for a refused key")
	}
	if err := backup.StoreRecoveryKey(cfg, st, backup.RecoveryKey{Public: wanted.Public(), Threshold: 2, TotalShares: 3}); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.LoadRecoveryKey(cfg, st); err != nil {
		t.Fatal(err)
	}
}

// A copy of a key that is no longer the pinned one is never written out.
func TestAStaleCopyIsNotWritten(t *testing.T) {
	cfg, st := instance(t)
	priv := pair(t, cfg, st)
	attacker, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting("kyrecovery_key_id", attacker.Public().ID()); err != nil {
		t.Fatal(err)
	}
	noBackup(t, replica(t, cfg, priv.Public().ID()), st)
}
