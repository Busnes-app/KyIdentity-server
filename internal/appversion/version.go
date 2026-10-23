// Package appversion is the one answer to "which version is this?".
//
// VERSION holds the release line, X.Y.Z, and is the only file a human bumps.
// Automated dependency releases add a fourth number (X.Y.Z.N) without a commit:
// release-image.yml passes the release tag's version to the build, which sets
// release through -ldflags. Source and CI builds report the release line.
package appversion

import (
	_ "embed"
	"strings"
)

//go:embed VERSION
var line string

// release is set at image build time with
// -ldflags "-X github.com/Busnes-app/kyidentity-server/internal/appversion.release=X.Y.Z[.N]".
var release string

// String is the version reported in capsule manifests and status responses.
func String() string {
	if release != "" {
		return release
	}
	return strings.TrimSpace(line)
}
