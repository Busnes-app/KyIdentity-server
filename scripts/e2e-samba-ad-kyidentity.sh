#!/usr/bin/env bash
# End-to-end proof of Active Directory sync: a throwaway Samba AD DC (kyws-windows-dc),
# this branch's KyIdentity HTTP server (in-process, real listener) and the built
# kyidentity-dc-agent. Assertions use kinit, smbclient (NTLM) and ldapsearch in the DC.
#   scripts/e2e-samba-ad-kyidentity.sh
# Needs docker. Every docker object is kyws-windows-*; it is removed on exit.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

E2E_SOURCE_ONLY=1 source scripts/e2e-samba-ad.sh
trap dc_down EXIT
dc_up
go build -o "$E2E_DC_WORKDIR/kyidentity-dc-agent" ./cmd/kyidentity-dc-agent
PUSH_RELAY_URL='' APNS_RELAY_URL='' \
	KYIDENTITY_E2E_DC_ENV="$E2E_DC_WORKDIR/dc.env" \
	KYIDENTITY_E2E_AGENT="$E2E_DC_WORKDIR/kyidentity-dc-agent" \
	KYIDENTITY_E2E_SCRIPT="$PWD/scripts/e2e-samba-ad.sh" \
	go test ./internal/api -run '^TestSambaADEndToEnd$' -count=1 -v
