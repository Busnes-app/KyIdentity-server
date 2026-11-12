package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDatabaseURL(t *testing.T) {
	const secret = "postgres://ky:hunter2@/ky"
	file := filepath.Join(t.TempDir(), "url")
	if err := os.WriteFile(file, []byte(secret+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		env  map[string]string
		want string // error substring; "" means it loads
		url  string
	}{
		{"unset means SQLite", nil, "", ""},
		{"variable", map[string]string{"KYIDENTITY_DATABASE_URL": secret}, "", secret},
		{"file", map[string]string{"KYIDENTITY_DATABASE_URL_FILE": file}, "", secret},
		{"both", map[string]string{"KYIDENTITY_DATABASE_URL": secret, "KYIDENTITY_DATABASE_URL_FILE": file}, "both set", ""},
		{"not postgres", map[string]string{"KYIDENTITY_DATABASE_URL": "mysql://ky:hunter2@/ky"}, "postgres:// URL", ""},
		{"unparsable", map[string]string{"KYIDENTITY_DATABASE_URL": "postgres://ky:hunter2@:port/ky"}, "postgres:// URL", ""},
		{"missing file", map[string]string{"KYIDENTITY_DATABASE_URL_FILE": file + ".none"}, "KYIDENTITY_DATABASE_URL_FILE", ""},
		{"replicated SQLite", map[string]string{"KYIDENTITY_REPLICATED": "true", "KYIDENTITY_SECRET_KEY": strings.Repeat("ab", KeyLength), "KYIDENTITY_ENCRYPTION_KEY": strings.Repeat("ab", KeyLength), "KYIDENTITY_RSA_KEY_PATH": file, "KYIDENTITY_VAPID_KEY_PATH": file}, "replicas must share one database", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("KYIDENTITY_DATA_DIR", t.TempDir())
			t.Setenv("KYIDENTITY_DATABASE_URL", "")
			t.Setenv("KYIDENTITY_DATABASE_URL_FILE", "")
			withEnv(t, c.env)
			cfg, err := Load()
			if c.want == "" {
				if err != nil || cfg.DatabaseURL != c.url {
					t.Fatalf("url %q err %v", cfg.DatabaseURL, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			if strings.Contains(err.Error(), "hunter2") {
				t.Fatalf("the error repeats the password: %v", err)
			}
		})
	}
}
