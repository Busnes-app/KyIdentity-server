//go:build kye2e

package config

// multiTenantBuild opens multi-tenant startup for the cross-app end-to-end harness only.
// scripts/check-test-gate.sh keeps this tag out of every release build.
const multiTenantBuild = true
