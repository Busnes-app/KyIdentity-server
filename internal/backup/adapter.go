package backup

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Busnes-app/ky-primitives/capsule"
	"github.com/Busnes-app/ky-primitives/keyfile"
	"github.com/Busnes-app/ky-primitives/recoveryclient"
	"github.com/Busnes-app/ky-primitives/recoverykey"
	"github.com/Busnes-app/kyidentity-server/internal/config"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// This package is KyIdentity's adapter over ky-primitives/recoveryclient: what to seal
// (payload.go), the drill's application checks (drill.go), and the glue below that maps the
// store, the deployment key and the config onto the lib's interfaces. Behaviour lives in the
// lib; nothing here decides anything about keys, destinations or schedules.

// Aliases so handlers and the CLI read the lib's types under the names they already use.
type (
	RecoveryKey   = recoveryclient.RecoveryKey
	Receipt       = recoveryclient.Receipt
	Result        = recoveryclient.Result
	PairingResult = recoveryclient.PairingResult
	Depositor     = recoveryclient.Depositor
	Payload       = recoveryclient.Payload
	File          = recoveryclient.File
	LocalCopy     = recoveryclient.LocalCopy
	DrillResult   = recoveryclient.DrillResult
	CheckItem     = recoveryclient.Check
	Client        = recoveryclient.Client
)

var (
	ErrNotPaired           = recoveryclient.ErrNotPaired
	ErrRecoveryKeyMismatch = recoveryclient.ErrKeyMismatch
	ErrKeyPinMissing       = recoveryclient.ErrKeyPinMissing
	ErrNoDestination       = recoveryclient.ErrNoDestination
	ErrDepositInProgress   = recoveryclient.ErrInProgress
	ErrReceiptUnrecorded   = recoveryclient.ErrReceiptUnrecorded
	ErrRemote              = recoveryclient.ErrRemote
	ErrBadInterval         = recoveryclient.ErrBadInterval
	TooLargeMessage        = recoveryclient.TooLargeMessage
)

// Sanitisers are wrapped as functions, not re-exported as variables, so nothing in the
// package can reassign them.
func AuditSafe(s string) string             { return recoveryclient.AuditSafe(s) }
func FilenameSafe(s string) string          { return recoveryclient.FilenameSafe(s) }
func RecoveryKeyPath(dataDir string) string { return recoveryclient.RecoveryKeyPath(dataDir) }

// privateSwitch names the deployment's own switch in refusals the lib phrases generically,
// so the operator reads what to flip.
func privateSwitch(err error) error {
	if err != nil && strings.Contains(err.Error(), "private-destination option") {
		return fmt.Errorf("%w (set KYIDENTITY_BACKUP_ALLOW_PRIVATE_RECOVERY=true for a KyRecovery on your own network)", err)
	}
	return err
}

// recoveryTokenLabel is the domain-separation label the sealed KyRecovery token has always
// been encrypted under. Changing it would orphan every live pairing.
const recoveryTokenLabel = "kysignon:setting:kyrecovery_token"

// Lease names the database lease one backup run holds, so replicas never run two at once;
// DrillLease does the same for the restore drill. LeaseTTL has no renewal behind it, so it
// is far longer than either takes; a holder that dies delays the next run by it.
const (
	Lease      = "backup"
	DrillLease = "restore-drill"
	LeaseTTL   = 2 * time.Hour
)

// SettingsStore is the slice of the store this adapter needs; *store.Store satisfies it.
type SettingsStore interface {
	GetSetting(key string) (string, error)
	SetSetting(key, value string) error
	DeleteSetting(key string) error
}

// settings maps the store onto recoveryclient.Settings, translating not-found.
type settings struct{ s SettingsStore }

func (a settings) Get(k string) (string, error) {
	v, err := a.s.GetSetting(k)
	if errors.Is(err, store.ErrNotFound) {
		return "", recoveryclient.ErrNotFound
	}
	return v, err
}
func (a settings) Set(k, v string) error { return a.s.SetSetting(k, v) }
func (a settings) Delete(k string) error { return a.s.DeleteSetting(k) }

// sealer wraps the deployment-key AEAD this server has always sealed the token with, so a
// pairing stored before the lib existed keeps opening.
type sealer struct{ key []byte }

func newSealer(encryptionKey []byte) sealer {
	return sealer{key: crypto.DeriveKey(encryptionKey, recoveryTokenLabel)}
}
func (s sealer) Seal(plain []byte) (string, error)  { return crypto.EncryptAESGCM(s.key, plain) }
func (s sealer) Open(sealed string) ([]byte, error) { return crypto.DecryptAESGCM(s.key, sealed) }

// ValidateRecoveryURL is the URL rule for where this server sends a capsule.
func ValidateRecoveryURL(raw string, allowPrivate bool) error {
	return privateSwitch(recoveryclient.ValidateURL(raw, allowPrivate))
}

// NewKyRecoveryClient builds the client with this deployment's private-destination choice.
func NewKyRecoveryClient(allowPrivate bool) *Client {
	return recoveryclient.NewClient(recoveryclient.Options{AllowPrivate: allowPrivate})
}

// The recovery public key also lives in the settings, sealed under the encryption key, so
// a replica that did not do the pairing has it. Sealed, because whoever can only write the
// database must not be able to choose the key capsules are sealed to.
const (
	settingRecoveryPublicKey = "kyrecovery_public_key"
	recoveryPublicKeyLabel   = "kyidentity:setting:kyrecovery_public_key"
)

func StoreRecoveryKey(cfg *config.Config, s SettingsStore, k RecoveryKey) error {
	if err := recoveryclient.StoreRecoveryKey(cfg.DataDir, settings{s}, k); err != nil {
		return err
	}
	return sealRecoveryKey(cfg, s, k)
}

func sealRecoveryKey(cfg *config.Config, s SettingsStore, k RecoveryKey) error {
	sealed, err := crypto.EncryptAESGCM(crypto.DeriveKey(cfg.EncryptionKey, recoveryPublicKeyLabel), k.Public.Bytes())
	if err != nil {
		return err
	}
	return s.SetSetting(settingRecoveryPublicKey, sealed)
}

// LoadRecoveryKey returns the pinned key. When recovery.pub is absent it is first written
// from the settings copy, if that copy is the pinned key; an install paired before the
// copy existed gains one here. The file is still what the pin is checked against.
func LoadRecoveryKey(cfg *config.Config, s SettingsStore) (RecoveryKey, error) {
	if err := shareRecoveryKey(cfg, s); err != nil {
		return RecoveryKey{}, err
	}
	return recoveryclient.LoadRecoveryKey(cfg.DataDir, settings{s})
}

func shareRecoveryKey(cfg *config.Config, s SettingsStore) error {
	path := RecoveryKeyPath(cfg.DataDir)
	sealed, err := s.GetSetting(settingRecoveryPublicKey)
	if errors.Is(err, store.ErrNotFound) {
		k, err := recoveryclient.LoadRecoveryKey(cfg.DataDir, settings{s})
		if err != nil {
			return nil // not paired, or a file the pin rejects: the caller's load reports it
		}
		return sealRecoveryKey(cfg, s, k)
	}
	if err != nil {
		return err
	}
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	raw, err := crypto.DecryptAESGCM(crypto.DeriveKey(cfg.EncryptionKey, recoveryPublicKeyLabel), sealed)
	if err != nil {
		return errors.New("the stored recovery public key does not open under this encryption key")
	}
	pub, err := recoverykey.ParsePublicKey(raw)
	if err != nil {
		return err
	}
	if pinned, err := s.GetSetting("kyrecovery_key_id"); err != nil || pinned != pub.ID() {
		return nil // a copy of a key that is no longer pinned
	}
	if err := keyfile.Store(path, raw, keyfile.Raw); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return nil
}

// ParsePinRequest turns the pasted public key and its k-of-n into a RecoveryKey.
func ParsePinRequest(publicKeyB64 string, threshold, total int) (RecoveryKey, error) {
	return recoveryclient.ParsePinRequest(publicKeyB64, threshold, total)
}

func StorePairing(s SettingsStore, encryptionKey []byte, serverURL, token string) error {
	return recoveryclient.StorePairing(settings{s}, newSealer(encryptionKey), serverURL, token)
}

func LoadPairing(cfg *config.Config, s SettingsStore) (recoveryclient.Pairing, error) {
	if err := shareRecoveryKey(cfg, s); err != nil {
		return recoveryclient.Pairing{}, err
	}
	return recoveryclient.LoadPairing(cfg.DataDir, settings{s}, newSealer(cfg.EncryptionKey))
}

// KeyPinned reports whether the settings pin a recovery key, whether or not this server
// holds its recovery.pub.
func KeyPinned(s SettingsStore) bool {
	_, err := s.GetSetting("kyrecovery_key_id")
	return err == nil
}

func HasPairing(s SettingsStore) bool    { return recoveryclient.HasPairing(settings{s}) }
func ClearPairing(s SettingsStore) error { return recoveryclient.ClearPairing(settings{s}) }
func LastDeposit(s SettingsStore) (Receipt, bool, error) {
	return recoveryclient.LastDeposit(settings{s})
}

// Seal writes a capsule for the given payload members, sealed to key.
func Seal(serviceName, appVersion string, files []File, deps, recipe map[string]any, key RecoveryKey) ([]byte, capsule.Manifest, error) {
	return recoveryclient.Seal(Payload{ServiceName: serviceName, AppVersion: appVersion, Files: files, Dependencies: deps, VerificationRecipe: recipe}, key)
}

func ListLocalCopies(dir, appName string) ([]LocalCopy, error) {
	if err := migrateLegacyLocalCopies(dir, appName); err != nil {
		return nil, err
	}
	return recoveryclient.ListLocalCopies(dir, appName)
}

func migrateLegacyLocalCopies(dir, appName string) error {
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	legacyPrefix := FilenameSafe(appName) + "-"
	legacyName := regexp.MustCompile(`^` + regexp.QuoteMeta(legacyPrefix+"cap-"+appName+"-") + `[0-9]+\.kycap$`)
	for _, entry := range entries {
		if entry.IsDir() || !legacyName.MatchString(entry.Name()) {
			continue
		}
		oldPath := filepath.Join(dir, entry.Name())
		newPath := filepath.Join(dir, recoveryclient.LocalPrefix(appName)+entry.Name()[len(legacyPrefix):])
		if _, err := os.Stat(newPath); err == nil {
			return fmt.Errorf("migrate legacy local copy %s: destination already exists", entry.Name())
		} else if !os.IsNotExist(err) {
			return err
		}
		if err := os.Rename(oldPath, newPath); err != nil {
			return fmt.Errorf("migrate legacy local copy %s: %w", entry.Name(), err)
		}
	}
	return nil
}

func Interval(cfg *config.Config, s SettingsStore) (time.Duration, error) {
	return recoveryclient.Interval(cfg.BackupDepositInterval, settings{s})
}

func SetInterval(s SettingsStore, sec int64) error {
	return recoveryclient.SetInterval(settings{s}, sec)
}

func NextRun(cfg *config.Config, s SettingsStore) (time.Time, bool, error) {
	return recoveryclient.NextRun(cfg.BackupDepositInterval, settings{s})
}

// RunBackup seals the instance once and delivers to every configured destination.
func RunBackup(ctx context.Context, cfg *config.Config, s SettingsStore, snap Snapshotter, client Depositor, appVersion string) (Result, error) {
	if err := migrateLegacyLocalCopies(cfg.BackupDir, cfg.AppName); err != nil {
		return Result{}, err
	}
	if err := shareRecoveryKey(cfg, s); err != nil {
		return Result{}, err
	}
	return recoveryclient.Run(ctx, recoveryclient.RunConfig{
		DataDir: cfg.DataDir, AppName: cfg.AppName, AppVersion: appVersion,
		BackupDir: cfg.BackupDir, Keep: cfg.BackupKeep, Sealer: newSealer(cfg.EncryptionKey),
	}, settings{s}, func() (Payload, error) {
		p, err := CollectSealable(cfg, snap, appVersion)
		if err != nil {
			return Payload{}, err
		}
		return *p, nil
	}, client)
}

// Outcome classifies a run for the audit log.
func Outcome(res Result, err error) (action, outcome string, details map[string]any) {
	return recoveryclient.Outcome(res, err)
}
