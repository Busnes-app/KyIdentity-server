#!/usr/bin/env bash
# End-to-end proof of workstation login: a throwaway KyIdentity from this checkout, behind a
# throwaway TLS terminator, and Himmelblau (Community Nightly, Debian 13) in a container,
# doing real PAM authentications with pamtester. Manual check, not in CI: it needs podman,
# socat, openssl, jq, network access for the image and about ten minutes (two device codes
# are left to expire). See docs/WORKSTATION-LOGIN.md.
#
#   scripts/e2e-himmelblau.sh            # run every case; prints PASS/FAIL per case
#   KEEP=1 scripts/e2e-himmelblau.sh     # leave the server and container up afterwards
#
# Relays are empty and nothing is sent anywhere but 127.0.0.1. Uses ports 53943-53945.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
NAME=${E2E_NAME:-kyws-e2e-$$}
PORT=${E2E_PORT:-53944}
TLS_PORT=${E2E_TLS_PORT:-53943}
HOST=ky-e2e.test
ISSUER="https://$HOST:$TLS_PORT"
IMAGE=${E2E_IMAGE:-kyws-e2e-himmelblau:latest}
WORK=$(mktemp -d "/tmp/$NAME.XXXXXX")
PASS_ADMIN="adm-$(openssl rand -hex 12)"
PIN=246813
PIDS=()

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
fail() { log "FAIL: $*"; exit 1; }

cleanup() {
	[ "${KEEP:-}" = 1 ] && { log "KEEP=1: server pids ${PIDS[*]}, container $NAME, work $WORK"; return; }
	podman rm -f "$NAME" >/dev/null 2>&1 || true
	tls_down
	for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
	rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 143' TERM INT

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
	tls_up
	for _ in $(seq 60); do
		curl -sf "http://127.0.0.1:$PORT/readyz" >/dev/null 2>&1 && return
		sleep 0.5
	done
	tail -20 "$WORK/server.log" >&2
	fail "server did not start"
}

# The desktop's way in. Stopping it takes KyIdentity "offline" for Himmelblau; the admin
# keeps a second listener on TLS_PORT+2 (cookies are per host, not per port).
TLS_PIDS=()
tls_up() { # [PORT...]; default both
	local port
	for port in "${@:-$TLS_PORT $((TLS_PORT + 2))}"; do
		for port in $port; do
			socat "openssl-listen:$port,bind=127.0.0.1,reuseaddr,fork,cert=$WORK/leaf.pem,key=$WORK/leaf.key,verify=0" \
				"tcp:127.0.0.1:$PORT" 2>>"$WORK/socat.log" &
			TLS_PIDS+=($!)
		done
	done
}
tls_down() {
	local p
	for p in "${TLS_PIDS[@]}"; do kill $(pgrep -P "$p") "$p" 2>/dev/null || true; done
	TLS_PIDS=()
}

# --- HTTP helpers: one cookie jar per person -------------------------------------------
ADMIN_URL="https://$HOST:$((TLS_PORT + 2))"
# api JAR METHOD PATH [BODY] [STEPUP]
api() {
	local jar=$1 method=$2 path=$3 body=${4:-} step=${5:-} csrf
	local r=(--cacert "$WORK/ca.pem" --resolve "$HOST:$((TLS_PORT + 2)):127.0.0.1" -b "$jar" -c "$jar")
	csrf=$(curl -s "${r[@]}" "$ADMIN_URL/api/auth/csrf" | jq -r .csrfToken)
	curl -s "${r[@]}" -X "$method" -H "Content-Type: application/json" -H "X-CSRF-Token: $csrf" \
		${step:+-H "X-KyIdentity-StepUp: $step"} ${body:+--data "$body"} "$ADMIN_URL$path"
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
	# Two-minute codes, so the cases that wait for an unapproved code to expire stay short.
	admin PUT "/api/admin/workstation-apps/$CLIENT" '{"deviceGrantEnabled":true,"deviceCodeTtl":120,"offlineWindow":604800}' >/dev/null
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

# --- Himmelblau --------------------------------------------------------------------------
image() {
	podman image exists "$IMAGE" && return
	log "building $IMAGE (once)"
	podman build -q -t "$IMAGE" "$ROOT/scripts/e2e-himmelblau" >/dev/null
}
hb() { podman exec "$NAME" bash -c "$1"; }
desktop() {
	printf '[global]\noidc_issuer_url = %s\napp_id = %s\npam_allow_groups = linux-users\n' "$ISSUER" "$CLIENT" >"$WORK/himmelblau.conf"
	podman run -d --init --name "$NAME" --network host --add-host "$HOST:127.0.0.1" \
		-v "$WORK/ca.pem:/usr/local/share/ca-certificates/kyws-e2e.crt:ro,Z" \
		-v "$WORK/himmelblau.conf:/etc/himmelblau/himmelblau.conf:Z" "$IMAGE" >/dev/null
	hb 'update-ca-certificates >/dev/null 2>&1
		mkdir -p /run/himmelblaud /var/lib/himmelblaud /var/cache/himmelblaud
		[ -f /var/lib/himmelblaud/hsm-pin ] || openssl rand -hex 24 | tr -d "\n" >/var/lib/himmelblaud/hsm-pin
		chmod 700 /var/cache/himmelblaud; chmod 600 /var/lib/himmelblaud/hsm-pin
		chown -R himmelblaud /run/himmelblaud /var/lib/himmelblaud /var/cache/himmelblaud'
	daemon_start
}
# himmelblaud refuses root; systemd units need namespaces a rootless container lacks.
daemon_start() {
	hb 'su -s /bin/sh himmelblaud -c "HIMMELBLAU_HSM_PIN_PATH=/var/lib/himmelblaud/hsm-pin nohup /usr/sbin/himmelblaud >>/tmp/himmelblaud.log 2>&1 &"
		for i in $(seq 120); do [ -S /run/himmelblaud/socket ] && exit 0; sleep 1; done; exit 1' || fail "himmelblaud did not start"
}
daemon_restart() {
	hb 'kill $(pgrep -x himmelblaud); while pgrep -x himmelblaud >/dev/null; do sleep 0.2; done; rm -f /run/himmelblaud/*'
	daemon_start
}

# PAM conversation: pamtester reads answers from a fifo, so each prompt is answered as it appears.
pam_start() {
	hb 'p=$(pgrep -x pamtester) && kill $p; rm -f /tmp/in /tmp/pt.out; mkfifo /tmp/in; (sleep 900 >/tmp/in &)
		nohup sh -c "stdbuf -o0 -e0 pamtester -v kyws-e2e '"$1"' authenticate acct_mgmt </tmp/in >/tmp/pt.out 2>&1; echo exit=\$? >>/tmp/pt.out" >/dev/null 2>&1 &'
}
pam_out() { hb 'cat /tmp/pt.out 2>/dev/null' | grep -vE '█|▀|▄|^ *$' || true; }
pam_wait() { # REGEX [SECONDS]
	for _ in $(seq "${2:-30}"); do pam_out | grep -qE "$1" && return 0; sleep 1; done
	pam_out | tail -5 >&2
	return 1
}
pam_send() { hb "printf '%s\n' '$1' >/tmp/in"; }
pam_code() { pam_out | grep -oE '^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$' | tail -1; }
pam_result() { pam_wait '^exit=' "${1:-30}" && pam_out | grep -oE '^exit=[0-9]+' | tail -1; }
decide() { # USER CODE true|false -> HTTP body
	api "$WORK/$1.jar" POST /api/device/decision "$(jq -nc --arg c "$2" --argjson a "$3" '{userCode:$c,approve:$a}')"
}
refreshes() { grep -c '"action":"oauth.token_refresh"' "$WORK/server.log" || true; }
audit() { grep -c "\"action\":\"$1\"" "$WORK/server.log" || true; }

# A first sign-in: device code, approval, PIN enrolment.
enrol() { # USER
	pam_start "$1"
	pam_wait 'enter the code' || fail "$1: no device code shown"
	[ "$(decide "$1" "$(pam_code)" true | jq -r .approved)" = true ] || fail "$1: approval refused"
	pam_wait 'New PIN' 40 || fail "$1: no PIN set-up prompt"
	pam_send "$PIN"
	pam_wait 'Confirm PIN' || fail "$1: no PIN confirmation"
	pam_send "$PIN"
	[ "$(pam_result 60)" = exit=0 ] || fail "$1: enrolment did not authenticate"
}
pin_login() { # USER -> pamtester exit line, or "device-flow" when Himmelblau asks for a new code
	pam_start "$1"
	pam_wait 'PIN:' || fail "$1: no PIN prompt"
	pam_send "$PIN"
	for _ in $(seq 40); do
		pam_out | grep -q 'enter the code' && { echo device-flow; return; }
		pam_out | grep -qE '^exit=' && { pam_out | grep -oE '^exit=[0-9]+' | tail -1; return; }
		sleep 1
	done
	echo timeout
}

RESULTS=()
OBSERVED=()
known() { # NAME HOPED ACTUAL: a Himmelblau-side limit, reported but not failed
	if [ "$2" = "$3" ]; then RESULTS+=("PASS  $1"); else RESULTS+=("KNOWN $1 (hoped $2, got $3; needs a Himmelblau change, docs/WORKSTATION-LOGIN.md)"); fi
	log "${RESULTS[-1]}"
}
check() { # NAME EXPECTED ACTUAL
	if [ "$2" = "$3" ]; then RESULTS+=("PASS  $1"); else RESULTS+=("FAIL  $1 (expected $2, got $3)"); fi
	log "${RESULTS[-1]}"
}

cases() {
	local before out
	# 1. An assigned user signs in with a device code, then with the PIN.
	enrol alice
	check "assigned user: device code + PIN enrolment authenticates (pam auth + acct_mgmt)" ok ok
	before=$(refreshes)
	check "assigned user: online PIN sign-in authenticates" exit=0 "$(pin_login alice)"
	check "online PIN sign-in contacts KyIdentity (refreshes per sign-in)" 1 "$(($(refreshes) - before))"

	# 2. Unassigned: KyIdentity refuses the approval, so PAM never succeeds. A denial ends
	# the desktop's attempt at once; an expired code is only observed (see the report).
	pam_start bob
	pam_wait 'enter the code' || fail "bob: no device code shown"
	check "unassigned user: KyIdentity refuses the approval" no_access "$(decide bob "$(pam_code)" true | jq -r .error)"
	# The two-minute code expires unapproved.
	# Himmelblau reports the failure and starts a new code rather than ending PAM.
	pam_wait 'expired' 200 && out=reported || out=$(pam_out | grep -oE '^exit=[0-9]+' | tail -1 || true)
	check "unassigned user: the expired code is reported and PAM does not succeed" reported "$out"
	pam_start bob
	pam_wait 'enter the code' || fail "bob: no device code shown"
	decide bob "$(pam_code)" false >/dev/null
	pam_wait 'User denied authorization' 30 && ! pam_out | grep -q '^exit=0' && out=reported || out=missing
	check "denied code: the denial is reported and PAM does not succeed" reported "$out"

	# 3. A user KyIdentity lets in but who is outside pam_allow_groups: Himmelblau's own gate.
	admin PUT "/api/admin/app-registry/$APP_ID/assignments/users/$ID_bob" '{}' >/dev/null
	pam_start bob
	pam_wait 'enter the code' || fail "bob: no device code shown"
	decide bob "$(pam_code)" true >/dev/null
	pam_wait 'New PIN' 40 && { pam_send "$PIN"; pam_wait 'Confirm PIN' && pam_send "$PIN"; }
	out=$(pam_result 120 || true)
	check "user outside pam_allow_groups: account management refuses" true "$([ -n "$out" ] && [ "$out" != exit=0 ] && pam_out | grep -q 'acct_mgmt' && echo true || echo false)"
	admin DELETE "/api/admin/app-registry/$APP_ID/assignments/users/$ID_bob" >/dev/null

	# 4. Disabled after enrolment: the next online PIN sign-in is refused.
	enrol carol
	admin PUT "/api/admin/users/$ID_carol" '{"status":"disabled"}' >/dev/null
	check "disabled user: next online PIN sign-in is refused" device-flow "$(pin_login carol)"
	hb 'p=$(pgrep -x pamtester) && kill $p' || true

	# 5. Session revocation, online.
	admin POST "/api/admin/users/$ID_alice/revoke-sessions" >/dev/null
	check "revoked sessions: next online PIN sign-in is refused" device-flow "$(pin_login alice)"
	hb 'p=$(pgrep -x pamtester) && kill $p' || true
	PASS_alice=$(signin "$WORK/alice.jar" alice "$PASS_alice")
	enrol alice

	# 6. Offline: the cached PIN works, and a revocation made while offline is not seen.
	tls_down; tls_up "$((TLS_PORT + 2))" # the desktop loses KyIdentity; the admin keeps it
	sleep 1
	check "offline: cached PIN sign-in authenticates" exit=0 "$(pin_login alice)"
	admin POST "/api/admin/users/$ID_alice/revoke-sessions" >/dev/null
	check "offline: PIN still works after a revocation KyIdentity cannot deliver" exit=0 "$(pin_login alice)"
	tls_down; tls_up
	sleep 20 # Himmelblau re-probes an offline provider after 15 s
	check "back online: the revocation applies at the next PIN sign-in" device-flow "$(pin_login alice)"
	hb 'p=$(pgrep -x pamtester) && kill $p' || true

	# 7. Single-use rotation against Himmelblau's two token copies (in memory, sealed to the
	# PIN key). A short cache_timeout makes a user lookup refresh in the background.
	echo 'cache_timeout = 5' >>"$WORK/himmelblau.conf"
	daemon_restart
	PASS_alice=$(signin "$WORK/alice.jar" alice "$PASS_alice")
	enrol alice
	before=$(audit oauth.refresh_reuse)
	sleep 7; hb 'id alice >/dev/null 2>&1' || true
	check "after a background refresh: PIN sign-in authenticates" exit=0 "$(pin_login alice)"
	sleep 7; hb 'id alice >/dev/null 2>&1' || true
	daemon_restart
	known "background refresh, then daemon restart: PIN sign-in authenticates" exit=0 "$(pin_login alice)"
	known "no refresh-token reuse was detected" 0 "$(($(audit oauth.refresh_reuse) - before))"
}

case "${1:-all}" in
deny-probe) # what the desktop shows after a denial
	tls; server; seed; image; desktop
	pam_start alice; pam_wait 'enter the code'; decide alice "$(pam_code)" false; sleep 45; pam_out
	hb 'ps -o pid,stat,args -C pamtester; tail -5 /tmp/himmelblaud.log'
	;;
all)
	tls; server; seed; image; desktop; cases
	printf '%s\n' "${RESULTS[@]}" "${OBSERVED[@]/#/NOTE  }"
	hb 'dpkg-query -W -f="himmelblau \${Version}\n" himmelblau'
	! printf '%s\n' "${RESULTS[@]}" | grep -q '^FAIL'
	;;
seed-only)
	tls; server; seed
	log "issuer $ISSUER client $CLIENT"
	;;
esac
