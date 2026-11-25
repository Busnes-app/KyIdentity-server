//go:build kye2e

package config

import (
	"strings"
	"testing"
)

// The test build opens multi-tenant startup; every other requirement still holds.
func TestMultiTenantGate(t *testing.T) {
	withEnv(t, multiEnv(t))
	if cfg, err := Load(); err != nil || cfg.Tenancy != "multi" {
		t.Fatalf("cfg %v, err %v", cfg, err)
	}
	t.Setenv("KYIDENTITY_REPLICATED", "false")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "requires KYIDENTITY_REPLICATED=true") {
		t.Fatalf("err = %v, want the replicated requirement", err)
	}
}

// The test build refuses any issuer outside .test, in either mode.
func TestMultiTenantGateIssuer(t *testing.T) {
	loadIssuers(t, func(t *testing.T, err error) {
		if err == nil || !strings.Contains(err.Error(), "must be a host under .test") {
			t.Fatalf("err = %v, want the .test refusal", err)
		}
	})
}

// In the test build multi-tenant mode reaches the platform listener's own checks: an IP
// literal and port, never the public port.
func TestMultiTenantGatePlatformListen(t *testing.T) {
	for value, want := range map[string]string{
		"10.0.0.5:5868":  "",
		"10.0.0.5:5867":  "on its own port",
		"0.0.0.0:5867":   "on its own port",
		"localhost:5868": "IP literal and port",
	} {
		t.Run(value, func(t *testing.T) {
			env := multiEnv(t)
			env["KYIDENTITY_PORT"] = "5867"
			env["KYIDENTITY_PLATFORM_LISTEN"] = value
			withEnv(t, env)
			cfg, err := Load()
			if want == "" {
				if err != nil || cfg.PlatformListen != value {
					t.Fatalf("cfg %v, err %v", cfg, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("err = %v, want %q", err, want)
			}
		})
	}
}

// In the test build multi-tenant mode reaches the events URL's own checks.
func TestMultiTenantGatePlatformEventsURL(t *testing.T) {
	for value, want := range map[string]string{
		"https://billing.e2e.test/events": "",
		"http://10.0.0.7:8080/events":     "",
		"http://billing.e2e.test/events":  "https URL",
		"http://8.8.8.8/events":           "https URL",
	} {
		t.Run(value, func(t *testing.T) {
			env := multiEnv(t)
			env["KYIDENTITY_PLATFORM_EVENTS_URL"] = value
			withEnv(t, env)
			cfg, err := Load()
			if want == "" {
				if err != nil || cfg.PlatformEventsURL != value {
					t.Fatalf("cfg %v, err %v", cfg, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("err = %v, want %q", err, want)
			}
		})
	}
}
