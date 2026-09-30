package config

import (
	"os"
	"strings"
	"testing"
)

func attestEnv(t *testing.T) {
	t.Setenv("KYIDENTITY_DATA_DIR", t.TempDir())
}

func TestAttestationDefaults(t *testing.T) {
	attestEnv(t)
	for _, k := range []string{"KYIDENTITY_ATTESTATION_STATUS_URL", "KYIDENTITY_KYAUTH_CERT_SHA256", "KYIDENTITY_ATTESTATION_EXTRA_ROOTS"} {
		t.Setenv(k, "") // registers restore on cleanup
		os.Unsetenv(k)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AttestationStatusURL != "https://android.googleapis.com/attestation/status" || len(cfg.KyAuthCertSHA256) != 1 || cfg.AttestationExtraRoots != "" {
		t.Fatalf("%+v", cfg)
	}
}

func TestAttestationStatusURLEmptyDisablesAndHTTPIsRejected(t *testing.T) {
	attestEnv(t)
	t.Setenv("KYIDENTITY_ATTESTATION_STATUS_URL", "")
	cfg, err := Load()
	if err != nil || cfg.AttestationStatusURL != "" {
		t.Fatalf("%v %q", err, cfg.AttestationStatusURL)
	}
	t.Setenv("KYIDENTITY_ATTESTATION_STATUS_URL", "http://example.test/status")
	if _, err := Load(); err == nil {
		t.Fatal("http status URL accepted")
	}
}

func TestKyAuthCertDigestsValidated(t *testing.T) {
	attestEnv(t)
	good := strings.Repeat("ab", 32)
	t.Setenv("KYIDENTITY_KYAUTH_CERT_SHA256", strings.ToUpper(good)+", "+strings.Repeat("cd", 32))
	cfg, err := Load()
	if err != nil || len(cfg.KyAuthCertSHA256) != 2 || cfg.KyAuthCertSHA256[0] != good {
		t.Fatalf("%v %+v", err, cfg)
	}
	t.Setenv("KYIDENTITY_KYAUTH_CERT_SHA256", "abc")
	if _, err := Load(); err == nil {
		t.Fatal("short digest accepted")
	}
}
