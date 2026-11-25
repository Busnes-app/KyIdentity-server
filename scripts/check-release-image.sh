#!/usr/bin/env bash
# Usage: check-release-image.sh IMAGE
# Fails unless IMAGE's binary is a release build: no kye2e build tag in its build info, and a
# complete multi-tenant configuration ends in the release refusal (internal/config/gate_*.go).
set -euo pipefail
image=${1:?usage: check-release-image.sh IMAGE}
work=$(mktemp -d)
cid=$(docker create "$image")
trap 'docker rm -f "$cid" >/dev/null; rm -rf "$work"' EXIT

docker cp -q "$cid:/usr/local/bin/kyidentity" "$work/kyidentity"
info=$(go version -m "$work/kyidentity")
grep -qE '^[[:space:]]+path[[:space:]]' <<<"$info" || { echo "no build info in the binary:"; echo "$info"; exit 1; }
if grep -E '^[[:space:]]+build[[:space:]]+-tags=' <<<"$info" | grep -q kye2e; then
	echo "the release binary was built with the kye2e tag:"; echo "$info"; exit 1
fi

# Key files are only checked for presence before the gate; the database is never reached.
mkdir "$work/keys"
for f in rsa vapid; do printf x > "$work/keys/$f"; done
chmod -R a+rX "$work/keys"
set +e
out=$(timeout 60 docker run --rm --network none -v "$work/keys:/keys:ro" \
	-e KYIDENTITY_ISSUER_URL=https://id.e2e.test \
	-e KYIDENTITY_TENANCY=multi \
	-e KYIDENTITY_REPLICATED=true \
	-e KYIDENTITY_DATABASE_URL=postgres://ky@db/ky \
	-e KYIDENTITY_SECRET_KEY="$(printf 'ab%.0s' {1..32})" \
	-e KYIDENTITY_ENCRYPTION_KEY="$(printf 'cd%.0s' {1..32})" \
	-e KYIDENTITY_RSA_KEY_PATH=/keys/rsa \
	-e KYIDENTITY_VAPID_KEY_PATH=/keys/vapid \
	-e PUSH_RELAY_URL= -e APNS_RELAY_URL= \
	"$image" 2>&1)
code=$?
set -e
if [ "$code" = 0 ] || ! grep -qF 'KYIDENTITY_TENANCY=multi is not available in this release' <<<"$out"; then
	echo "a complete multi-tenant configuration was not refused (exit $code):"; echo "$out"; exit 1
fi
echo "$image: release build, multi-tenant startup refused"
