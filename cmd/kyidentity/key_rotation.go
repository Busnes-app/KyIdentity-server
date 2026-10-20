package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Busnes-app/ky-primitives/keyfile"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"golang.org/x/sys/unix"
)

// rotationLock excludes a running new server. Operators must stop older binaries
// and all administrative commands too; --confirm-stopped acknowledges that boundary.
func rotationLock(data string, exclusive bool) (*os.File, error) {
	p := filepath.Join(data, ".encryption-rotation.lock")
	fd, err := syscall.Open(p, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, errors.New("cannot open encryption rotation lock")
	}
	f := os.NewFile(uintptr(fd), p)
	if _, err = crypto.ReadKeyFile(p, 1); err != nil {
		f.Close()
		return nil, errors.New("unsafe encryption rotation lock")
	}
	mode := syscall.LOCK_SH
	if exclusive {
		mode = syscall.LOCK_EX
	}
	if err = syscall.Flock(fd, mode|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("stop KyIdentity before rotating its encryption key")
	}
	return f, nil
}

func keyDigest(key []byte) string { sum := sha256.Sum256(key); return hex.EncodeToString(sum[:]) }

func runKeyRotation(args []string, out io.Writer) error {
	f := flag.NewFlagSet("rotate-encryption-key", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	destination := f.String("out", "", "new private replacement data directory")
	stopped := f.Bool("confirm-stopped", false, "all server and administrative processes are stopped")
	if f.Parse(args) != nil || f.NArg() != 0 || !*stopped || !filepath.IsAbs(*destination) || filepath.Clean(*destination) != *destination {
		return errors.New("rotate-encryption-key requires --confirm-stopped --out ABSOLUTE-NEW-DIRECTORY")
	}
	if os.Getenv("KYIDENTITY_ENCRYPTION_KEY") != "" {
		return errors.New("offline rotation requires a file-backed encryption key; remove the environment override only after preserving the matching key securely")
	}
	source, err := setupDataDirectory()
	if err != nil {
		return err
	}
	if source == *destination || strings.HasPrefix(*destination, source+string(os.PathSeparator)) || strings.HasPrefix(source, *destination+string(os.PathSeparator)) {
		return errors.New("rotation source and output must be separate directories")
	}
	if err = keyfile.RequireTrustedAncestry(source); err != nil {
		return err
	}
	if err = keyfile.RequirePrivateDirectory(source); err != nil {
		return err
	}
	if err = keyfile.RequireTrustedAncestry(filepath.Dir(*destination)); err != nil {
		return err
	}
	if _, err = os.Lstat(*destination); !errors.Is(err, os.ErrNotExist) {
		return errors.New("rotation output already exists or cannot be inspected")
	}
	dbPath, err := filepath.Abs(setupDatabasePath(""))
	if err != nil {
		return err
	}
	if filepath.Dir(dbPath) != source {
		return errors.New("rotation requires the database inside the product data directory")
	}
	if path := os.Getenv("KYIDENTITY_RSA_KEY_PATH"); path != "" {
		absolute, err := filepath.Abs(path)
		if err != nil || !strings.HasPrefix(absolute, source+string(os.PathSeparator)) {
			return errors.New("rotation requires the signing key inside the product data directory")
		}
	}
	oldKey, err := crypto.ReadKeyFile(filepath.Join(source, "encryption.key"), 32)
	if err != nil || len(oldKey) != 32 {
		return errors.New("rotation requires the existing private 32-byte encryption.key")
	}
	lock, err := rotationLock(source, true)
	if err != nil {
		return err
	}
	defer lock.Close()
	stage, err := os.MkdirTemp(filepath.Dir(*destination), ".kyidentity-rotation-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err = copyRotationTree(source, stage, filepath.Base(dbPath)); err != nil {
		return err
	}
	s, err := store.OpenInstallerStore(dbPath, true)
	if err != nil {
		return err
	}
	err = s.SnapshotTo(filepath.Join(stage, filepath.Base(dbPath)))
	closeErr := s.Close()
	if err = errors.Join(err, closeErr); err != nil {
		return err
	}
	newKey := make([]byte, 32)
	if _, err = rand.Read(newKey); err != nil {
		return err
	}
	receipts, err := rotatePreparationReceipts(source, stage, oldKey, newKey)
	if err != nil {
		return err
	}
	rotated, err := store.New(filepath.Join(stage, filepath.Base(dbPath)))
	if err != nil {
		return err
	}
	err = rotated.SealLegacySecrets(oldKey)
	if err == nil {
		err = rotated.RotateEncryptionKey(oldKey, newKey, receipts)
	}
	if err == nil {
		err = rotated.CheckIntegrity()
	}
	if err = errors.Join(err, rotated.Close()); err != nil {
		return err
	}
	// Only the private unpublished copy is changed; never replace the source key.
	if err = os.WriteFile(filepath.Join(stage, "encryption.key"), newKey, 0600); err != nil {
		return err
	}
	if err = syncRotationTree(stage); err != nil {
		return err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, stage, unix.AT_FDCWD, *destination, unix.RENAME_NOREPLACE); err != nil {
		return errors.New("cannot publish rotation output without replacing an existing path")
	}
	parent, err := os.Open(filepath.Dir(*destination))
	if err != nil {
		return err
	}
	err = parent.Sync()
	parent.Close()
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(map[string]any{"schema": "kyidentity.key-rotation/1", "verified": true, "output": *destination, "oldKeyFingerprint": keyDigest(oldKey), "newKeyFingerprint": keyDigest(newKey), "activateAt": source})
}

func copyRotationTree(source, stage, db string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if rel == ".encryption-rotation.lock" || rel == db || rel == db+"-wal" || rel == db+"-shm" {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSocket != 0 {
			return errors.New("rotation found a socket; stop the server and remove only its stale socket first")
		}
		if info.IsDir() {
			if err := keyfile.RequireTrustedAncestry(path); err != nil {
				return err
			}
			return os.Mkdir(filepath.Join(stage, rel), 0700)
		}
		if !info.Mode().IsRegular() {
			return errors.New("rotation refuses symlinks and special files")
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(filepath.Join(stage, rel), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, in)
		return errors.Join(err, out.Close())
	})
}

func rotatePreparationReceipts(source, stage string, oldKey, newKey []byte) (map[string][2]string, error) {
	result := map[string][2]string{}
	entries, err := os.ReadDir(filepath.Join(stage, "installer"))
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			return nil, errors.New("rotation refuses unexpected installer files")
		}
		id := entry.Name()
		scope := filepath.Join(stage, "installer", id)
		raw, err := keyfile.ReadPrivate(filepath.Join(source, "installer", id, "credentials.json"), setupBundleLimit)
		if err != nil {
			return nil, errors.New("rotation requires complete protected preparation receipts")
		}
		var receipt struct {
			Schema       string            `json:"schema"`
			BundleDigest string            `json:"bundleDigest"`
			Credentials  map[string]string `json:"credentials"`
		}
		if err := json.Unmarshal(raw, &receipt); err != nil || receipt.Schema != "kyidentity.prepared-credentials/1" || receipt.Credentials == nil {
			return nil, errors.New("invalid preparation receipt")
		}
		intent, err := keyfile.ReadPrivate(filepath.Join(source, "installer", id, "intent.json"), setupBundleLimit)
		if err != nil || keyDigest(intent) != receipt.BundleDigest {
			return nil, errors.New("rotation refused changed preparation intent")
		}
		bundle, err := keyfile.ReadPrivate(filepath.Join(source, "installer", id, "setup.json"), setupBundleLimit)
		if err != nil || !bytes.Equal(bundle, intent) {
			return nil, errors.New("rotation refused missing or changed prepared bundle")
		}
		for path, digest := range receipt.Credentials {
			if path == "product-encryption-key" {
				if digest != keyDigest(oldKey) {
					return nil, errors.New("preparation encryption key differs")
				}
				continue
			}
			if !strings.HasPrefix(path, source+string(os.PathSeparator)) {
				return nil, errors.New("rotation requires preparation credentials inside the data directory")
			}
			value, err := keyfile.ReadPrivate(path, 8193)
			if err != nil || keyDigest(value) != digest {
				return nil, errors.New("rotation refused a changed preparation credential")
			}
		}
		if _, ok := receipt.Credentials["product-encryption-key"]; ok {
			receipt.Credentials["product-encryption-key"] = keyDigest(newKey)
		}
		updated, err := json.Marshal(receipt)
		if err != nil {
			return nil, err
		}
		if err = os.WriteFile(filepath.Join(scope, "credentials.json"), updated, 0600); err != nil {
			return nil, err
		}
		result[id] = [2]string{keyDigest(raw), keyDigest(updated)}
	}
	return result, nil
}

func syncRotationTree(root string) error {
	return filepath.WalkDir(root, func(path string, _ fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		return errors.Join(f.Sync(), f.Close())
	})
}
