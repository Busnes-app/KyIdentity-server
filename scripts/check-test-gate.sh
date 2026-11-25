#!/usr/bin/env bash
# The kye2e build tag opens multi-tenant startup for the cross-app end-to-end harness
# (internal/config/gate_kye2e.go). It must never reach a release build, so:
#   - the tag is named only in the gate files, this check, check-release-image.sh, e2e/ and docs;
#   - no Dockerfile, Makefile, compose file or workflow passes -tags or GOFLAGS to a build;
#   - the gate opens in a tagged test build and stays shut in an untagged one.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
fail=0

bad=$(git grep -il 'kye2e' -- . \
	':!internal/config/gate_*.go' ':!scripts/check-test-gate.sh' ':!scripts/check-release-image.sh' \
	':!e2e/' ':!*.md' || true)
if [ -n "$bad" ]; then
	echo "kye2e named outside the gate files and its checks:"; echo "$bad"; fail=1
fi

bad=$(git grep -nE -- '-tags|GOFLAGS' -- 'Dockerfile*' '*/Dockerfile*' 'Makefile' '*/Makefile' \
	'docker-compose*.yml' '.github/workflows/*.yml' '.github/workflows/*.yaml' || true)
if [ -n "$bad" ]; then
	echo "build tags or GOFLAGS in a build or workflow file:"; echo "$bad"; fail=1
fi
[ "$fail" = 0 ] || exit 1

go test -count=1 -run '^TestMultiTenantGate' ./internal/config
go test -count=1 -tags kye2e -run '^TestMultiTenantGate' ./internal/config
echo "kye2e: source clean, gate shut untagged and open only when tagged"
