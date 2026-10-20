package crypto

import (
	"github.com/Busnes-app/ky-primitives/keyfile"
	"os"
	"path/filepath"
)

// CreateKeyFile writes data to path at mode 0600 unless path exists. It goes through an
// fsynced temp file and a hard link, so a crash never leaves a short key and two first
// starts never overwrite each other: the loser gets an error satisfying
// errors.Is(err, fs.ErrExist) and must read the winner's key instead of using its own.
func CreateKeyFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".key-*") // mode 0600
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Link(tmp.Name(), path); err != nil {
		return err
	}
	// The link is durable only once the directory entry is.
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// ReadKeyFile preserves not-found for first-start creation while refusing unsafe
// retained files through the shared descriptor-verified reader.
func ReadKeyFile(path string, limit int64) ([]byte, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	path = absolute
	if _, err := os.Lstat(path); err != nil {
		return nil, err
	}
	return keyfile.ReadPrivate(path, limit)
}
