#!/usr/bin/env bash
# Runs the docs/FORWARD-AUTH.md nginx configuration in a real nginx against a throwaway
# KyIdentity and checks header stripping, bypass, the sign-in redirect and internal check.
# Usage: check.sh <kyidentity binary>   (needs docker; host networking on loopback)
set -euo pipefail
bin=$(realpath "$1"); here=$(cd "$(dirname "$0")" && pwd)
KYID_PORT=${KYID_PORT:-5872} EDGE_PORT=${EDGE_PORT:-5873} APP_PORT=${APP_PORT:-5874}
work=$(mktemp -d); name="fwdauth-nginx-check-$$"
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; [ -n "${pid:-}" ] && kill "$pid" 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT
export KYIDENTITY_DATA_DIR=$work/data KYIDENTITY_LISTEN_HOST=127.0.0.1 KYIDENTITY_PORT=$KYID_PORT \
  KYIDENTITY_ISSUER_URL=http://127.0.0.1:$KYID_PORT KYIDENTITY_SECRET_KEY=$(openssl rand -hex 32) \
  KYIDENTITY_ENCRYPTION_KEY=$(openssl rand -hex 32) PUSH_RELAY_URL= APNS_RELAY_URL=
cd "$work"
openssl rand -hex 16 | "$bin" bootstrap-admin -username admin >/dev/null
"$bin" >"$work/server.log" 2>&1 & pid=$!
for _ in $(seq 60); do curl -fsS "http://127.0.0.1:$KYID_PORT/livez" >/dev/null 2>&1 && break; sleep 1; done
out=$("$bin" proxy-app --owner e2e --host app.e2e.test --name E2E --login-header X-WEBAUTH-USER --bypass /public)
secret=$(printf '%s' "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["edgeSecret"])')
cookie=$(openssl rand -hex 32)
# Seed what a completed sign-in leaves: an assigned user and a live forward session.
python3 -I - "$work/data/kyidentity.db" "$cookie" <<'PY'
import hashlib, sqlite3, sys, time
db = sqlite3.connect(sys.argv[1]); now = int(time.time())
uid = db.execute("SELECT id FROM users WHERE username='admin'").fetchone()[0]
card = db.execute("SELECT application_id FROM proxy_apps WHERE host='app.e2e.test'").fetchone()[0]
app = db.execute("SELECT id FROM app_registry WHERE launcher_id=?", (card,)).fetchone()[0]
# The bootstrap administrator must change its password first, which KyIdentity enforces here too.
db.execute("UPDATE users SET password_change_required=0 WHERE id=?", (uid,))
db.execute("INSERT INTO app_user_assignments(app_id,user_id) VALUES(?,?)", (app, uid))
db.execute("INSERT INTO forward_sessions(hash,application_id,host,user_id,session_id,primary_at,factor_at,factor_method,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
  (hashlib.sha256(sys.argv[2].encode()).hexdigest(), card, 'app.e2e.test', uid, 'seeded', now, now, 'totp', now, now + 3600))
db.commit()
PY
for f in nginx.conf ky-edge.conf; do
  sed -e "s/KYID_PORT/$KYID_PORT/g; s/EDGE_PORT/$EDGE_PORT/g; s/APP_PORT/$APP_PORT/g; s/EDGE_SECRET/$secret/g" "$here/$f" >"$work/$f"
done
chmod 0644 "$work/nginx.conf" "$work/ky-edge.conf"
docker run -d --name "$name" --network host -v "$work/nginx.conf:/etc/nginx/nginx.conf:ro" -v "$work/ky-edge.conf:/etc/nginx/ky-edge.conf:ro" nginx:stable >/dev/null
for _ in $(seq 30); do curl -s -o /dev/null "http://127.0.0.1:$EDGE_PORT/public" -H 'Host: app.e2e.test' && break; sleep 1; done
edge() { curl -sS -H 'Host: app.e2e.test' "$@"; }
spoof=(-H 'X-Ky-User: mallory' -H 'X-WEBAUTH-USER: mallory' -H 'X-Ky-Email: m@evil.test' -H 'X-Ky-Groups: admins' -H 'X-Ky-Edge-Secret: guess' -H 'X_WEBAUTH_USER: mallory')
fail=0
expect() { if [[ "$2" == *"$3"* ]]; then echo "ok   $1"; else echo "FAIL $1: got [$2], want [$3]"; fail=1; fi; }
expect "bypass strips client identity" "$(edge "${spoof[@]}" "http://127.0.0.1:$EDGE_PORT/public/x")" "user= webauth= underscore= email= groups= secret="
expect "signed-in request gets the check's identity, not the client's" \
  "$(edge "${spoof[@]}" -b "__Host-ky_fwd=$cookie" "http://127.0.0.1:$EDGE_PORT/dash")" "user=admin webauth=admin underscore= email="
expect "signed-in request carries no edge secret" "$(edge -b "__Host-ky_fwd=$cookie" "http://127.0.0.1:$EDGE_PORT/dash")" "secret=
"
loc=$(edge "${spoof[@]}" -o /dev/null -w '%{http_code} %{redirect_url}' "http://127.0.0.1:$EDGE_PORT/dash?a=1&b=2")
expect "no cookie redirects to KyIdentity start with the original URI" "$loc" "302 http://127.0.0.1:$KYID_PORT/forward/start?n="
expect "start keeps the full original URI" "$loc" "rd=https%3A%2F%2Fapp.e2e.test%2Fdash%3Fa%3D1%26b%3D2"
expect "wrong cookie is refused" "$(edge -b "__Host-ky_fwd=$(openssl rand -hex 32)" -o /dev/null -w '%{http_code}' "http://127.0.0.1:$EDGE_PORT/dash")" "302"
expect "the check is internal" "$(edge -o /dev/null -w '%{http_code}' "http://127.0.0.1:$EDGE_PORT/.ky/check")" "404"
expect "callback without nonce is refused" "$(edge -o /dev/null -w '%{http_code}' "http://127.0.0.1:$EDGE_PORT/.ky/callback?code=$(openssl rand -hex 32)")" "400"
expect "logout ends the session" "$(edge -b "__Host-ky_fwd=$cookie" -o /dev/null -w '%{http_code}' "http://127.0.0.1:$EDGE_PORT/.ky/logout")" "302"
expect "after logout the cookie no longer opens the app" "$(edge -b "__Host-ky_fwd=$cookie" -o /dev/null -w '%{http_code}' "http://127.0.0.1:$EDGE_PORT/dash")" "302"
if grep -q -- "$secret" "$work/server.log"; then echo "FAIL the edge secret is in the server log"; fail=1; else echo "ok   the edge secret is not in the server log"; fi
exit $fail
