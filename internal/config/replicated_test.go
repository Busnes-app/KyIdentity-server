package config

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A replica that cannot load a key must stop, not mint its own: a second identity behind
// the same load balancer rejects the first one's tokens, cookies and sealed secrets.
func TestReplicatedRefusesToGenerateKeys(t *testing.T) {
	key := strings.Repeat("ab", KeyLength)
	keyFile := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyFile, []byte(key+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	present := filepath.Join(t.TempDir(), "present.key")
	if err := os.WriteFile(present, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	absent := filepath.Join(t.TempDir(), "absent.key")
	all := map[string]string{
		"KYIDENTITY_REPLICATED":          "true",
		"KYIDENTITY_DATABASE_URL":        "postgres:///kyidentity",
		"KYIDENTITY_SECRET_KEY_FILE":     keyFile,
		"KYIDENTITY_ENCRYPTION_KEY_FILE": keyFile,
		"KYIDENTITY_RSA_KEY_PATH":        present,
		"KYIDENTITY_VAPID_KEY_PATH":      present,
	}
	for _, c := range []struct{ name, unset, set, want string }{
		{"secret key", "KYIDENTITY_SECRET_KEY_FILE", "", "set KYIDENTITY_SECRET_KEY_FILE"},
		{"encryption key", "KYIDENTITY_ENCRYPTION_KEY_FILE", "", "set KYIDENTITY_ENCRYPTION_KEY_FILE"},
		{"signing key", "KYIDENTITY_RSA_KEY_PATH", absent, "set KYIDENTITY_RSA_KEY_PATH"},
		{"signing key in the data directory", "KYIDENTITY_RSA_KEY_PATH", "", "set KYIDENTITY_RSA_KEY_PATH"},
		{"VAPID key", "KYIDENTITY_VAPID_KEY_PATH", absent, "set KYIDENTITY_VAPID_KEY_PATH"},
		{"VAPID key in the data directory", "KYIDENTITY_VAPID_KEY_PATH", "", "set KYIDENTITY_VAPID_KEY_PATH"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dataDir := t.TempDir()
			t.Setenv("KYIDENTITY_DATA_DIR", dataDir)
			withEnv(t, all)
			t.Setenv(c.unset, c.set)
			if cfg, err := Load(); err == nil || cfg != nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			if left, _ := os.ReadDir(dataDir); len(left) != 0 {
				t.Fatalf("a refused replica wrote %v into its data directory", left)
			}
			if _, err := os.Stat(absent); !os.IsNotExist(err) {
				t.Fatal("a refused replica created the missing key")
			}
		})
	}

	t.Run("every key supplied", func(t *testing.T) {
		dataDir := t.TempDir()
		t.Setenv("KYIDENTITY_DATA_DIR", dataDir)
		withEnv(t, all)
		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		want, _ := hex.DecodeString(key)
		if !cfg.Replicated || !cfg.VAPIDKeyMounted || cfg.VAPIDKeyPath != present || !bytes.Equal(cfg.SecretKey, want) || !bytes.Equal(cfg.EncryptionKey, want) {
			t.Fatalf("loaded %+v", cfg)
		}
		if left, _ := os.ReadDir(dataDir); len(left) != 0 {
			t.Fatalf("a replica with mounted keys wrote %v into its data directory", left)
		}
	})

	t.Run("keys shared through the data directory", func(t *testing.T) {
		dataDir := t.TempDir()
		for _, name := range []string{"secret.key", "encryption.key"} {
			if err := os.WriteFile(filepath.Join(dataDir, name), bytes.Repeat([]byte{7}, KeyLength), 0600); err != nil {
				t.Fatal(err)
			}
		}
		t.Setenv("KYIDENTITY_DATA_DIR", dataDir)
		withEnv(t, map[string]string{"KYIDENTITY_REPLICATED": "true", "KYIDENTITY_DATABASE_URL": "postgres:///kyidentity", "KYIDENTITY_RSA_KEY_PATH": present, "KYIDENTITY_VAPID_KEY_PATH": present})
		if _, err := Load(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestKeyFileVariable(t *testing.T) {
	raw := bytes.Repeat([]byte{0x5a}, KeyLength)
	write := func(data []byte) string {
		path := filepath.Join(t.TempDir(), "key")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for _, c := range []struct {
		name string
		data []byte
	}{
		{"raw bytes", raw},
		{"hex", []byte(hex.EncodeToString(raw))},
		{"hex with newline", []byte(hex.EncodeToString(raw) + "\n")},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("KYIDENTITY_DATA_DIR", t.TempDir())
			t.Setenv("KYIDENTITY_ENCRYPTION_KEY_FILE", write(c.data))
			cfg, err := Load()
			if err != nil || !bytes.Equal(cfg.EncryptionKey, raw) {
				t.Fatalf("key %x err %v", cfg.EncryptionKey, err)
			}
		})
	}
	for _, c := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"short", map[string]string{"KYIDENTITY_SECRET_KEY_FILE": write([]byte("abcd"))}, "KYIDENTITY_SECRET_KEY must be exactly 64 hex characters"},
		{"raw with newline", map[string]string{"KYIDENTITY_SECRET_KEY_FILE": write(append(bytes.Clone(raw), '\n'))}, "KYIDENTITY_SECRET_KEY must be exactly 64 hex characters"},
		{"missing", map[string]string{"KYIDENTITY_SECRET_KEY_FILE": filepath.Join(t.TempDir(), "none")}, "KYIDENTITY_SECRET_KEY_FILE"},
		{"both sources", map[string]string{"KYIDENTITY_SECRET_KEY_FILE": write(raw), "KYIDENTITY_SECRET_KEY": hex.EncodeToString(raw)}, "both set"},
		{"replicated not boolean", map[string]string{"KYIDENTITY_REPLICATED": "2"}, "KYIDENTITY_REPLICATED"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dataDir := t.TempDir()
			t.Setenv("KYIDENTITY_DATA_DIR", dataDir)
			withEnv(t, c.env)
			if cfg, err := Load(); err == nil || cfg != nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			if _, err := os.Stat(filepath.Join(dataDir, "secret.key")); !os.IsNotExist(err) {
				t.Fatal("a refused key file fell back to a generated key")
			}
		})
	}
}
