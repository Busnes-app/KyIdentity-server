//go:build !kye2e

package config

// multiTenantBuild is false in every shipped binary: KYIDENTITY_TENANCY=multi is refused.
// Only the cross-app test harness builds with the other value (gate_kye2e.go).
const multiTenantBuild = false
