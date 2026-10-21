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
	if cfg.AttestationStatusURL != "https://android.googleapis.com/attestation/status" || len(cfg.KyAuthCertSHA256) != len(DefaultKyAuthCertSHA256) || cfg.AttestationExtraRoots != "" {
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

func TestAppAttestConfig(t *testing.T) {
	attestEnv(t)
	for _, k := range []string{"KYIDENTITY_APPATTEST_APP_IDS", "KYIDENTITY_APPATTEST_ALLOW_DEVELOPMENT"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	cfg, err := Load()
	if err != nil || len(cfg.AppAttestAppIDs) != 1 || cfg.AppAttestAppIDs[0] != "TATYN4X57D.org.kysecurity.authenticator" || cfg.AppAttestAllowDevelopment {
		t.Fatalf("defaults: %v %+v", err, cfg)
	}
	t.Setenv("KYIDENTITY_APPATTEST_APP_IDS", " ")
	cfg, err = Load()
	if err != nil || len(cfg.AppAttestAppIDs) != 0 {
		t.Fatalf("set empty should disable: %v %+v", err, cfg)
	}
	t.Setenv("KYIDENTITY_APPATTEST_APP_IDS", "TATYN4X57D.org.kysecurity.authenticator, ABCDE12345.com.example.app-beta")
	t.Setenv("KYIDENTITY_APPATTEST_ALLOW_DEVELOPMENT", "TRUE")
	cfg, err = Load()
	if err != nil || len(cfg.AppAttestAppIDs) != 2 || cfg.AppAttestAppIDs[0] != "TATYN4X57D.org.kysecurity.authenticator" || !cfg.AppAttestAllowDevelopment {
		t.Fatalf("set: %v %+v", err, cfg)
	}
	t.Setenv("KYIDENTITY_APPATTEST_ALLOW_DEVELOPMENT", "")
	for _, bad := range []string{"org.kysecurity.authenticator", "tatyn4x57d.org.kysecurity.authenticator", "TATYN4X57D.", "TATYN4X57D.org..app", "TATYN4X57D.org.app,", "TATYN4X57.org.app", "TATYN4X57D.org/app"} {
		t.Setenv("KYIDENTITY_APPATTEST_APP_IDS", bad)
		if _, err := Load(); err == nil {
			t.Fatalf("app id %q accepted", bad)
		}
	}
	t.Setenv("KYIDENTITY_APPATTEST_APP_IDS", "")
	t.Setenv("KYIDENTITY_APPATTEST_ALLOW_DEVELOPMENT", "yes")
	if _, err := Load(); err == nil {
		t.Fatal("non-boolean development flag accepted")
	}
}

func TestDefaultKyAuthCertDigestsAreValid(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range DefaultKyAuthCertSHA256 {
		if !certDigestRE.MatchString(d) || seen[d] {
			t.Fatalf("bad or duplicate default digest %q", d)
		}
		seen[d] = true
	}
}
