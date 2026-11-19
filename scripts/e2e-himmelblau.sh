#!/usr/bin/env bash
# End-to-end proof of workstation login: a throwaway KyIdentity from this checkout, behind a
# throwaway TLS terminator, and Himmelblau (Community Nightly, Debian 13) in a container,
# doing real PAM authentications with pamtester. Manual check, not in CI: it needs docker,
# network access for the image and about four minutes. See docs/WORKSTATION-LOGIN.md.
#
#   scripts/e2e-himmelblau.sh            # run every case, print a report
#   KEEP=1 scripts/e2e-himmelblau.sh     # leave the server and container up afterwards
#
# Relays are empty and nothing is sent anywhere but 127.0.0.1.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
NAME=${E2E_NAME:-kyws-e2e-$$}
PORT=${E2E_PORT:-53944}
TLS_PORT=${E2E_TLS_PORT:-53943}
HOST=ky-e2e.test
ISSUER="https://$HOST:$TLS_PORT"
IMAGE=${E2E_IMAGE:-$NAME-himmelblau:e2e}
WORK=$(mktemp -d "/tmp/$NAME.XXXXXX")
PASS_ADMIN="adm-$(openssl rand -hex 12)"
PIN=246813
PIDS=()

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
fail() { log "FAIL: $*"; exit 1; }

cleanup() {
	[ "${KEEP:-}" = 1 ] && { log "KEEP=1: server pids ${PIDS[*]}, container $NAME, work $WORK"; return; }
	docker rm -f "$NAME" >/dev/null 2>&1 || true
	for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
	rm -rf "$WORK"
}
trap cleanup EXIT

# --- TLS: a throwaway CA and a leaf for $HOST -----------------------------------------
tls() {
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj "/CN=$NAME CA" \
		-keyout "$WORK/ca.key" -out "$WORK/ca.pem" 2>/dev/null
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$HOST" \
		-keyout "$WORK/leaf.key" -out "$WORK/leaf.csr" 2>/dev/null
	printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$HOST" >"$WORK/ext"
	openssl x509 -req -in "$WORK/leaf.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" -CAcreateserial -days 1 \
		-extfile "$WORK/ext" -out "$WORK/leaf.pem" 2>/dev/null
}

# --- KyIdentity from this checkout ------------------------------------------------------
server() {
	(cd "$ROOT" && go build -o "$WORK/kyidentity" ./cmd/kyidentity)
	mkdir -p "$WORK/data"
	(cd "$WORK" && exec env -i PATH="$PATH" HOME="$WORK" KYIDENTITY_ISSUER_URL="$ISSUER" KYIDENTITY_PORT="$PORT" \
		KYIDENTITY_LISTEN_HOST=127.0.0.1 KYIDENTITY_DATA_DIR="$WORK/data" BOOTSTRAP_ADMIN_USER=admin \
		BOOTSTRAP_ADMIN_PASS="$PASS_ADMIN" PUSH_RELAY_URL= APNS_RELAY_URL= ./kyidentity >"$WORK/server.log" 2>&1) &
	PIDS+=($!)
	socat "openssl-listen:$TLS_PORT,bind=127.0.0.1,reuseaddr,fork,cert=$WORK/leaf.pem,key=$WORK/leaf.key,verify=0" \
		"tcp:127.0.0.1:$PORT" 2>"$WORK/socat.log" &
	PIDS+=($!)
	for _ in $(seq 60); do
		curl -sf --cacert "$WORK/ca.pem" --resolve "$HOST:$TLS_PORT:127.0.0.1" "$ISSUER/readyz" >/dev/null 2>&1 && return
		sleep 0.5
	done
	tail -20 "$WORK/server.log" >&2
	fail "server did not start"
}

# --- HTTP helpers: one cookie jar per person -------------------------------------------
# api JAR METHOD PATH [BODY] [STEPUP]
api() {
	local jar=$1 method=$2 path=$3 body=${4:-} step=${5:-} csrf
	csrf=$(curl -s --cacert "$WORK/ca.pem" --resolve "$HOST:$TLS_PORT:127.0.0.1" -b "$jar" -c "$jar" "$ISSUER/api/auth/csrf" | jq -r .csrfToken)
	curl -s --cacert "$WORK/ca.pem" --resolve "$HOST:$TLS_PORT:127.0.0.1" -b "$jar" -c "$jar" -X "$method" \
		-H "Content-Type: application/json" -H "X-CSRF-Token: $csrf" ${step:+-H "X-KyIdentity-StepUp: $step"} \
		${body:+--data "$body"} "$ISSUER$path"
}
stepup() { # JAR PASSWORD OPERATION -> grant; waits out the per-address step-up limit
	local grant
	for _ in $(seq 20); do
		grant=$(api "$1" POST /api/auth/step-up "$(jq -nc --arg p "$2" --arg o "$3" '{password:$p,code:"",method:"",operation:$o}')" | jq -r '.stepUpToken // empty')
		[ -n "$grant" ] && { echo "$grant"; return; }
		sleep 5
	done
	fail "step-up for $3"
}
admin() { # METHOD PATH [BODY]: an admin call with a fresh step-up grant
	api "$WORK/admin.jar" "$1" "$2" "${3:-}" "$(stepup "$WORK/admin.jar" "$PASS_ADMIN" "$1 ${2%%\?*}")"
}
signin() { # JAR USER PASSWORD; changes a required password to PASSWORD-2 and prints the password in use
	local jar=$1 user=$2 pass=$3 me
	rm -f "$jar"
	until api "$jar" POST /api/auth/login "$(jq -nc --arg u "$user" --arg p "$pass" '{username:$u,password:$p}')" | grep -qv rate_limit; do sleep 5; done
	me=$(api "$jar" GET /api/auth/me)
	if [ "$(jq -r .passwordChangeRequired <<<"$me")" = true ]; then
		api "$jar" POST /api/user/password "$(jq -nc --arg p "$pass-2" '{newPassword:$p}')" \
			"$(stepup "$jar" "$pass" "POST /api/user/password")" >/dev/null
		pass="$pass-2"
		rm -f "$jar"
		api "$jar" POST /api/auth/login "$(jq -nc --arg u "$user" --arg p "$pass" '{username:$u,password:$p}')" >/dev/null
	fi
	[ "$(api "$jar" GET /api/auth/me | jq -r .username)" = "$user" ] || fail "sign-in as $user"
	echo "$pass"
}

seed() {
	PASS_ADMIN=$(signin "$WORK/admin.jar" admin "$PASS_ADMIN")
	APP=$(admin POST /api/admin/workstation-apps '{"clientName":"Linux desktops"}')
	CLIENT=$(jq -r .clientId <<<"$APP")
	APP_ID=$(jq -r .appId <<<"$APP")
	[ -n "$CLIENT" ] && [ "$CLIENT" != null ] || fail "create workstation app: $APP"
	admin PUT "/api/admin/workstation-apps/$CLIENT" '{"deviceGrantEnabled":true,"deviceCodeTtl":300,"offlineWindow":604800}' >/dev/null
	GROUP=$(admin POST /api/admin/groups '{"name":"linux-users"}' | jq -r '.id // .group.id')
	admin PUT "/api/admin/app-registry/$APP_ID/assignments/groups/$GROUP" '{}' >/dev/null
	for u in alice bob carol; do
		local id
		id=$(admin POST /api/admin/users "$(jq -nc --arg u "$u" '{username:$u,displayName:$u,email:($u+"@e2e.test"),password:"initial-\($u)-passphrase",role:"user",status:"active"}')" | jq -r '.id // .user.id')
		[ -n "$id" ] && [ "$id" != null ] || fail "create $u"
		declare -g "ID_$u=$id"
		[ "$u" = bob ] || admin PUT "/api/admin/groups/$GROUP/members/$id" '{}' >/dev/null
		declare -g "PASS_$u=$(signin "$WORK/$u.jar" "$u" "initial-$u-passphrase")"
	done
	log "seeded: client $CLIENT, group linux-users (alice, carol), bob unassigned"
}

case "${1:-all}" in
seed-only)
	tls; server; seed
	log "issuer $ISSUER client $CLIENT"
	;;
esac
