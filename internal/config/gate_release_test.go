//go:build !kye2e

package config

import (
	"strings"
	"testing"
)

// A release build refuses multi-tenant startup even with every requirement met.
func TestMultiTenantGate(t *testing.T) {
	withEnv(t, multiEnv(t))
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "KYIDENTITY_TENANCY=multi is not available in this release") {
		t.Fatalf("err = %v, want the release refusal", err)
	}
}

// A release build takes any issuer; only the test build restricts it.
func TestMultiTenantGateIssuer(t *testing.T) {
	loadIssuers(t, func(t *testing.T, err error) {
		if err != nil {
			t.Fatal(err)
		}
	})
}
