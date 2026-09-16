package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func withEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		t.Setenv(k, v)
	}
}

// A key that is too short, or not hex, must stop the server. Silently padding it to 32
// bytes gives an operator who tried to configure security less of it than one who did nothing.
func TestWeakEncryptionKeyIsRejected(t *testing.T) {
	for _, bad := range []string{"changeme", "a", "deadbeef", strings.Repeat("z", 64)} {
		t.Run(bad[:min(len(bad), 12)], func(t *testing.T) {
			withEnv(t, map[string]string{
				"KYIDENTITY_DATA_DIR":       t.TempDir(),
				"KYIDENTITY_ENCRYPTION_KEY": bad,
				"BOOTSTRAP_ADMIN_PASS":      "",
			})
			if _, err := Load(); err == nil {
				t.Errorf("KYIDENTITY_ENCRYPTION_KEY=%q was accepted; it must be rejected", bad)
			}
		})
	}
}

func TestLegacyEnvironmentIsRejected(t *testing.T) {
	t.Setenv("KYSIGNON_ISSUER_URL", "https://auth.example.test")
	t.Setenv("KYIDENTITY_DATA_DIR", t.TempDir())

	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "KYSIGNON_ISSUER_URL") || !strings.Contains(err.Error(), "KYIDENTITY_ISSUER_URL") {
		t.Fatalf("Load did not reject the legacy environment: %v", err)
	}
}

func TestEmptyLegacyEnvironmentIsIgnored(t *testing.T) {
	t.Setenv("KYSIGNON_ISSUER_URL", "")
	t.Setenv("KYIDENTITY_DATA_DIR", t.TempDir())
	if _, err := Load(); err != nil {
		t.Fatalf("empty legacy environment placeholder was rejected: %v", err)
	}
}

func TestLegacyDatabasePathIsReused(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "kysignon.db")
	if err := os.WriteFile(legacy, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KYIDENTITY_DATA_DIR", dir)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DBPath != legacy {
		t.Fatalf("DBPath = %q, want existing legacy database %q", cfg.DBPath, legacy)
	}
	if _, err := os.Stat(filepath.Join(dir, "kyidentity.db")); !os.IsNotExist(err) {
		t.Fatalf("new database path was created or already exists: %v", err)
	}
}

func TestWeakSecretKeyIsRejected(t *testing.T) {
	withEnv(t, map[string]string{
		"KYIDENTITY_DATA_DIR":   t.TempDir(),
		"KYIDENTITY_SECRET_KEY": "hunter2",
	})
	if _, err := Load(); err == nil {
		t.Error("a 7-byte KYIDENTITY_SECRET_KEY was accepted")
	}
}

func TestValidHexKeysAreAccepted(t *testing.T) {
	key := strings.Repeat("ab", 32) // 64 hex chars = 32 bytes
	withEnv(t, map[string]string{
		"KYIDENTITY_DATA_DIR":       t.TempDir(),
		"KYIDENTITY_ENCRYPTION_KEY": key,
		"KYIDENTITY_SECRET_KEY":     key,
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("valid 32-byte hex keys were rejected: %v", err)
	}
	if len(cfg.EncryptionKey) != 32 || len(cfg.SecretKey) != 32 {
		t.Errorf("key lengths = %d/%d, want 32/32", len(cfg.EncryptionKey), len(cfg.SecretKey))
	}
}

// Generated key files must survive a restart. Overwriting a short or unreadable file
// silently invalidates every session and every TOTP secret on disk.
func TestExistingShortKeyFileIsNotSilentlyReplaced(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "encryption.key")
	if err := os.WriteFile(keyFile, []byte("truncated"), 0600); err != nil {
		t.Fatal(err)
	}
	withEnv(t, map[string]string{"KYIDENTITY_DATA_DIR": dir})

	if _, err := Load(); err == nil {
		t.Error("a truncated encryption.key was silently regenerated instead of reported")
	}

	after, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != "truncated" {
		t.Error("the existing key file was overwritten; every TOTP secret on disk just became undecryptable")
	}
}

func TestGeneratedKeysPersistAcrossLoads(t *testing.T) {
	dir := t.TempDir()
	withEnv(t, map[string]string{"KYIDENTITY_DATA_DIR": dir})

	first, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	second, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if string(first.EncryptionKey) != string(second.EncryptionKey) {
		t.Error("encryption key changed between loads; TOTP secrets would not decrypt after a restart")
	}
	if string(first.SecretKey) != string(second.SecretKey) {
		t.Error("secret key changed between loads")
	}
}

// The shipped default must not believe forwarding headers from the whole RFC1918 space.
func TestNoProxiesAreTrustedByDefault(t *testing.T) {
	withEnv(t, map[string]string{"KYIDENTITY_DATA_DIR": t.TempDir()})
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.TrustedProxyCIDRs) != 0 {
		t.Errorf("TrustedProxyCIDRs defaults to %v; it must default to empty", cfg.TrustedProxyCIDRs)
	}
}

func TestPublicHTTPIssuerIsRejectedAndHTTPSForcesSecureCookies(t *testing.T) {
	withEnv(t, map[string]string{
		"KYIDENTITY_DATA_DIR":   t.TempDir(),
		"KYIDENTITY_ISSUER_URL": "http://auth.example.test",
	})
	if _, err := Load(); err == nil {
		t.Fatal("a public HTTP issuer was accepted")
	}

	withEnv(t, map[string]string{
		"KYIDENTITY_DATA_DIR":       t.TempDir(),
		"KYIDENTITY_ISSUER_URL":     "https://auth.example.test",
		"KYIDENTITY_SECURE_COOKIES": "false",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SecureCookies {
		t.Fatal("HTTPS issuer did not force Secure cookies")
	}
}

func TestRelayURLsRequireHTTPS(t *testing.T) {
	withEnv(t, map[string]string{
		"KYIDENTITY_DATA_DIR": t.TempDir(),
		"PUSH_RELAY_URL":      "http://relay.example.test",
	})
	if _, err := Load(); err == nil {
		t.Fatal("public HTTP PUSH_RELAY_URL was accepted")
	}

	withEnv(t, map[string]string{
		"KYIDENTITY_DATA_DIR": t.TempDir(),
		"PUSH_RELAY_URL":      "https://fcm.example.test/",
		"APNS_RELAY_URL":      "https://apns.example.test/",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PushRelayURL != "https://fcm.example.test" || cfg.APNSRelayURL != "https://apns.example.test" {
		t.Fatalf("relay URLs were not normalized: %q / %q", cfg.PushRelayURL, cfg.APNSRelayURL)
	}
}

// A CIDR that does not parse must be reported, not skipped, or an operator's typo
// silently drops their proxy out of the trusted set.
func TestMalformedTrustedProxyCIDRIsRejected(t *testing.T) {
	withEnv(t, map[string]string{
		"KYIDENTITY_DATA_DIR": t.TempDir(),
		"TRUSTED_PROXY_CIDRS": "10.89.0.1/32,not-a-cidr",
	})
	if _, err := Load(); err == nil {
		t.Error("a malformed entry in TRUSTED_PROXY_CIDRS was silently ignored")
	}
}

func TestSessionTimeoutConfiguration(t *testing.T) {
	withEnv(t, map[string]string{
		"KYIDENTITY_DATA_DIR":         t.TempDir(),
		"KYIDENTITY_SESSION_TTL":      "8h",
		"KYIDENTITY_SESSION_IDLE_TTL": "20m",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SessionTTL != 8*time.Hour || cfg.SessionIdleTTL != 20*time.Minute {
		t.Fatalf("session timeouts = %v / %v", cfg.SessionTTL, cfg.SessionIdleTTL)
	}

	withEnv(t, map[string]string{
		"KYIDENTITY_DATA_DIR":         t.TempDir(),
		"KYIDENTITY_SESSION_TTL":      "30m",
		"KYIDENTITY_SESSION_IDLE_TTL": "1h",
	})
	if _, err := Load(); err == nil {
		t.Fatal("idle timeout longer than absolute timeout was accepted")
	}
}

func TestLoadDerivesWebAuthnRelyingParty(t *testing.T) {
	t.Setenv("KYIDENTITY_ISSUER_URL", "https://auth.example.com/")
	t.Setenv("KYIDENTITY_DATA_DIR", t.TempDir())

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.RPID != "auth.example.com" || cfg.Origin != "https://auth.example.com" {
		t.Fatalf("RPID=%q Origin=%q", cfg.RPID, cfg.Origin)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
