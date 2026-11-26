#!/usr/bin/env bash
# Keep Go's default hybrid post-quantum TLS key exchange (X25519MLKEM768) intact:
#   - no CurvePreferences overrides in non-test Go code;
#   - no tlsmlkem GODEBUG overrides in non-test Go code, workflows, Dockerfiles or Compose files;
#   - PQ TLS handshake tests pass normally and under GODEBUG=fips140=on.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
fail=0

bad=$(git grep -n 'CurvePreferences' -- '*.go' ':!*_test.go' || true)
if [ -n "$bad" ]; then
	echo "CurvePreferences override in non-test Go code:" >&2
	echo "$bad" >&2
	fail=1
fi

bad=$(git grep -ni 'tlsmlkem' -- '*.go' ':!*_test.go' \
	'Dockerfile*' '*/Dockerfile*' '*.Dockerfile' \
	'docker-compose*.yml' '.github/workflows/*.yml' '.github/workflows/*.yaml' || true)
if [ -n "$bad" ]; then
	echo "tlsmlkem override in source, workflow, Dockerfile or Compose file:" >&2
	echo "$bad" >&2
	fail=1
fi
[ "$fail" = 0 ] || exit 1

go test -count=1 -run 'HybridPQ' ./internal/netguard ./internal/sync ./cmd/kyidentity-dc-agent
GODEBUG=fips140=on go test -count=1 -run 'HybridPQ' ./internal/netguard ./internal/sync ./cmd/kyidentity-dc-agent
echo "pqc-tls: source clean; hybrid PQ TLS handshakes pass (default and fips140=on)"
