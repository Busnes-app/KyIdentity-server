package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Every malformed value fails Load with a message naming the variable; none is replaced by
// a default, because a server running on a setting the operator did not choose is worse
// than one that will not start.
func TestLoadFailsClosedOnMalformedValues(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"forwarded header with colon", map[string]string{"KYIDENTITY_FORWARDED_HEADER": "X-Real-IP:"}, "KYIDENTITY_FORWARDED_HEADER"},
		{"forwarded header list", map[string]string{"KYIDENTITY_FORWARDED_HEADER": "X-Forwarded-For, X-Real-IP"}, "KYIDENTITY_FORWARDED_HEADER"},
		{"session ttl not a duration", map[string]string{"KYIDENTITY_SESSION_TTL": "a day"}, "KYIDENTITY_SESSION_TTL must be a positive Go duration"},
		{"session ttl negative", map[string]string{"KYIDENTITY_SESSION_TTL": "-1h"}, "KYIDENTITY_SESSION_TTL must be a positive Go duration"},
		{"idle ttl zero", map[string]string{"KYIDENTITY_SESSION_IDLE_TTL": "0s"}, "KYIDENTITY_SESSION_IDLE_TTL must be a positive Go duration"},
		{"apns relay http", map[string]string{"APNS_RELAY_URL": "http://apns.example.test"}, "APNS_RELAY_URL must be an https URL"},
		{"apns relay without host", map[string]string{"APNS_RELAY_URL": "https://"}, "APNS_RELAY_URL must be an https URL"},
		{"deposit interval garbage", map[string]string{"KYIDENTITY_BACKUP_DEPOSIT_INTERVAL": "daily"}, "non-negative Go duration"},
		{"deposit interval negative", map[string]string{"KYIDENTITY_BACKUP_DEPOSIT_INTERVAL": "-24h"}, "non-negative Go duration"},
		{"deposit interval too short", map[string]string{"KYIDENTITY_BACKUP_DEPOSIT_INTERVAL": "5m"}, "below the 15m0s minimum"},
		{"relative backup dir", map[string]string{"KYIDENTITY_BACKUP_DIR": "backups"}, "KYIDENTITY_BACKUP_DIR must be an absolute path"},
		{"backup keep zero", map[string]string{"KYIDENTITY_BACKUP_KEEP": "0"}, "KYIDENTITY_BACKUP_KEEP must be a positive integer"},
		{"backup keep word", map[string]string{"KYIDENTITY_BACKUP_KEEP": "seven"}, "KYIDENTITY_BACKUP_KEEP must be a positive integer"},
		{"proxy not an ip", map[string]string{"TRUSTED_PROXY_CIDRS": "proxy.local"}, "is not a valid IP or CIDR"},
		{"proxy bad prefix", map[string]string{"TRUSTED_PROXY_CIDRS": "10.0.0.0/33"}, "is not a valid CIDR"},
		{"short secret key", map[string]string{"KYIDENTITY_SECRET_KEY": "abcd"}, "KYIDENTITY_SECRET_KEY must be exactly 64 hex characters"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("KYIDENTITY_DATA_DIR", t.TempDir())
			withEnv(t, c.env)
			cfg, err := Load()
			if err == nil || cfg != nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("cfg %v err = %v, want %q", cfg != nil, err, c.want)
			}
		})
	}
}

// The backup and proxy settings that do parse are normalised the way the rest of the
// server expects: an absolute backup dir is cleaned, 0 disables the schedule, bare proxy
// addresses become single-host ranges, and the forwarded header is canonicalised.
func TestLoadNormalisesBackupAndProxySettings(t *testing.T) {
	backupDir := t.TempDir()
	withEnv(t, map[string]string{
		"KYIDENTITY_DATA_DIR":                t.TempDir(),
		"KYIDENTITY_BACKUP_DIR":              backupDir + "/./",
		"KYIDENTITY_BACKUP_KEEP":             "3",
		"KYIDENTITY_BACKUP_DEPOSIT_INTERVAL": "0",
		"TRUSTED_PROXY_CIDRS":                " 10.0.0.1 , ,fd00::1, 192.168.0.0/16",
		"KYIDENTITY_FORWARDED_HEADER":        "cf-connecting-ip",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BackupDir != backupDir || cfg.BackupKeep != 3 || cfg.BackupDepositInterval != 0 {
		t.Fatalf("backup settings: dir=%q keep=%d interval=%v", cfg.BackupDir, cfg.BackupKeep, cfg.BackupDepositInterval)
	}
	want := []string{"10.0.0.1/32", "fd00::1/128", "192.168.0.0/16"}
	if strings.Join(cfg.TrustedProxyCIDRs, ",") != strings.Join(want, ",") {
		t.Fatalf("TrustedProxyCIDRs = %v, want %v", cfg.TrustedProxyCIDRs, want)
	}
	if cfg.ForwardedHeader != "Cf-Connecting-Ip" {
		t.Fatalf("ForwardedHeader = %q", cfg.ForwardedHeader)
	}

	// The defaults: a daily schedule, seven local copies, no backup dir.
	withEnv(t, map[string]string{"KYIDENTITY_DATA_DIR": t.TempDir(), "KYIDENTITY_BACKUP_DIR": "", "KYIDENTITY_BACKUP_KEEP": "",
		"KYIDENTITY_BACKUP_DEPOSIT_INTERVAL": "", "KYIDENTITY_FORWARDED_HEADER": ""})
	if cfg, err = Load(); err != nil {
		t.Fatal(err)
	}
	if cfg.BackupDir != "" || cfg.BackupKeep != DefaultBackupKeep || cfg.BackupDepositInterval != 24*time.Hour || cfg.ForwardedHeader != DefaultForwardedHeader {
		t.Fatalf("defaults: dir=%q keep=%d interval=%v header=%q", cfg.BackupDir, cfg.BackupKeep, cfg.BackupDepositInterval, cfg.ForwardedHeader)
	}
}

// A data directory or key file that cannot be read stops startup and is not replaced:
// generating a fresh key over an unreadable one orphans everything encrypted under it.
func TestLoadFailsClosedOnUnusableDataDirectory(t *testing.T) {
	parent := t.TempDir()
	file := filepath.Join(parent, "file")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	withEnv(t, map[string]string{"KYIDENTITY_DATA_DIR": filepath.Join(file, "data"), "KYIDENTITY_SECRET_KEY": "", "KYIDENTITY_ENCRYPTION_KEY": ""})
	if cfg, err := Load(); err == nil || cfg != nil {
		t.Fatal("a data directory under a regular file was accepted")
	}

	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "encryption.key"), 0700); err != nil {
		t.Fatal(err)
	}
	withEnv(t, map[string]string{"KYIDENTITY_DATA_DIR": dir})
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "failed to read key file") {
		t.Fatalf("unreadable encryption key file: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(dir, "encryption.key")); err != nil || !fi.IsDir() {
		t.Fatal("the unreadable key path was replaced")
	}

	// A data directory that cannot take a new key file is an error, not an ephemeral key.
	ro := t.TempDir()
	if err := os.Chmod(ro, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0700) })
	if _, err := loadOrGenerateKeyFile(filepath.Join(ro, "secret.key")); err == nil || !strings.Contains(err.Error(), "failed to persist generated key") {
		if os.Geteuid() == 0 {
			t.Skip("root ignores directory permissions")
		}
		t.Fatalf("unwritable key directory: %v", err)
	}
}

// KYIDENTITY_DB_PATH overrides the database location outright.
func TestExplicitDatabasePathWins(t *testing.T) {
	withEnv(t, map[string]string{"KYIDENTITY_DATA_DIR": t.TempDir(), "KYIDENTITY_DB_PATH": " /srv/identity/custom.db "})
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DBPath != "/srv/identity/custom.db" {
		t.Fatalf("DBPath = %q", cfg.DBPath)
	}
}
