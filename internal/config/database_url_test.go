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
		{"multi-tenant on one server", map[string]string{"KYIDENTITY_TENANCY": "multi", "KYIDENTITY_DATABASE_URL": secret}, "requires KYIDENTITY_REPLICATED=true", ""},
		// Replicated configuration passes this check; the release gate still refuses multi.
		{"multi-tenant replicated", map[string]string{"KYIDENTITY_TENANCY": "multi", "KYIDENTITY_DATABASE_URL": secret, "KYIDENTITY_REPLICATED": "true", "KYIDENTITY_SECRET_KEY": strings.Repeat("ab", KeyLength), "KYIDENTITY_ENCRYPTION_KEY": strings.Repeat("ab", KeyLength), "KYIDENTITY_RSA_KEY_PATH": file, "KYIDENTITY_VAPID_KEY_PATH": file}, "is not available in this release", ""},
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

// KYIDENTITY_PLATFORM_LISTEN: an IP literal and port of its own, multi-tenant only.
func TestPlatformListen(t *testing.T) {
	for _, c := range []struct{ value, want string }{
		{"10.0.0.5:5868", "multi-tenant mode only"}, // single-tenant
		{"localhost:5868", "IP literal and port"},
		{"10.0.0.5", "IP literal and port"},
		{"10.0.0.5:0", "IP literal and port"},
		{"10.0.0.5:99999", "IP literal and port"},
	} {
		t.Run(c.value, func(t *testing.T) {
			t.Setenv("KYIDENTITY_DATA_DIR", t.TempDir())
			t.Setenv("KYIDENTITY_PLATFORM_LISTEN", c.value)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
	t.Setenv("KYIDENTITY_PLATFORM_LISTEN", "")
	for _, c := range []struct{ value, want string }{
		{"https://billing.example.test/events", "multi-tenant mode only"}, // single-tenant
		{"http://billing.example.test/events", "https URL"},
		{"http://8.8.8.8/events", "https URL"},
		{"https://user:pw@billing.example.test/events", "https URL"},
		{"ftp://10.0.0.1/x", "https URL"},
		{"::", "https URL"},
		{"http://10.0.0.7:8080/events", "multi-tenant mode only"},
	} {
		t.Run(c.value, func(t *testing.T) {
			t.Setenv("KYIDENTITY_DATA_DIR", t.TempDir())
			t.Setenv("KYIDENTITY_PLATFORM_EVENTS_URL", c.value)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
	t.Setenv("KYIDENTITY_DATA_DIR", t.TempDir())
	t.Setenv("KYIDENTITY_PLATFORM_EVENTS_URL", "")
	if cfg, err := Load(); err != nil || cfg.PlatformListen != "" {
		t.Fatalf("unset: %v %v", cfg, err)
	}
}
