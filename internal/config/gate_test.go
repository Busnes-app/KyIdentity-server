package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// multiEnv is a complete multi-tenant configuration on an issuer a test build accepts.
func multiEnv(t *testing.T) map[string]string {
	file := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		"KYIDENTITY_DATA_DIR":       t.TempDir(),
		"KYIDENTITY_ISSUER_URL":     "https://id.e2e.test",
		"KYIDENTITY_TENANCY":        "multi",
		"KYIDENTITY_REPLICATED":     "true",
		"KYIDENTITY_DATABASE_URL":   "postgres://ky@db/ky",
		"KYIDENTITY_SECRET_KEY":     strings.Repeat("ab", KeyLength),
		"KYIDENTITY_ENCRYPTION_KEY": strings.Repeat("cd", KeyLength),
		"KYIDENTITY_RSA_KEY_PATH":   file,
		"KYIDENTITY_VAPID_KEY_PATH": file,
	}
}

// loadIssuers loads a single-tenant configuration on each issuer outside .test.
func loadIssuers(t *testing.T, check func(t *testing.T, err error)) {
	for _, issuer := range []string{"https://id.example.com", "https://id.test.example.com", "https://test", "http://localhost:5867"} {
		t.Run(issuer, func(t *testing.T) {
			env := multiEnv(t)
			env["KYIDENTITY_TENANCY"] = "single"
			env["KYIDENTITY_ISSUER_URL"] = issuer
			withEnv(t, env)
			_, err := Load()
			check(t, err)
		})
	}
}
