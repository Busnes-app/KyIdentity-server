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
