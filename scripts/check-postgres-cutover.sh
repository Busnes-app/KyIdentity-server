#!/usr/bin/env bash
# Proves the documented SQLite -> PostgreSQL cutover with the real image: a SQLite install on
# a named /data volume is stopped with `docker stop` at its default timeout, copied with the
# image's migrate-to-postgres into an empty PostgreSQL 18 (C locale, pinned by digest) on a
# private network, and started on PostgreSQL. Everything runs on an --internal network with
# the push relays empty, so nothing can reach a production service. Every container, the
# network and the volume this run made are removed on exit.
#
# Usage: scripts/check-postgres-cutover.sh [image]   (default kyidentity-ci)
set -euo pipefail

image=${1:-kyidentity-ci}
pg_image=postgres:18.7-trixie@sha256:c699303802144847d238196173655dbbecf7a96aeca1565f2b02eb671a1f0b6b
run_id=$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')
name=kyidentity-cutover-$run_id
net=$name volume=$name-data pg=$name-pg sqlite_app=$name-sqlite pg_app=$name-postgres

cleanup() {
  docker rm -f -v "$sqlite_app" "$pg_app" "$pg" >/dev/null 2>&1 || true
  docker volume rm -f "$volume" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() {
  echo "cutover check failed: $*" >&2
  for c in "$sqlite_app" "$pg_app" "$pg"; do
    docker logs --tail 40 "$c" 2>/dev/null | sed "s/^/[$c] /" >&2 || true
  done
  exit 1
}

# An unset relay variable means the production relay; empty means none.
offline=(-e PUSH_RELAY_URL= -e APNS_RELAY_URL= -e KYIDENTITY_ATTESTATION_STATUS_URL=)

ready() { # container
  for _ in $(seq 1 60); do
    if docker exec "$1" wget -q -O /dev/null http://localhost:5867/readyz 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# Runs the image with the volume read-only, for inspecting the SQLite file.
inspect() { docker run --rm --network none -v "$volume:/data:ro" --entrypoint sh "$image" -c "$1"; }

docker network create --internal "$net" >/dev/null
docker volume create "$volume" >/dev/null

echo "1. SQLite install on a named /data volume, with a bootstrap administrator"
docker run -d --name "$sqlite_app" --network "$net" -v "$volume:/data" "${offline[@]}" \
  -e BOOTSTRAP_ADMIN_PASS=cutover-first-password "$image" >/dev/null
ready "$sqlite_app" || fail "the SQLite server never became ready"

echo "2. docker stop at its default timeout"
docker stop "$sqlite_app" >/dev/null
code=$(docker inspect -f '{{.State.ExitCode}}' "$sqlite_app")
[ "$code" = 0 ] || fail "the server exited $code on docker stop"
inspect 'test ! -e /data/kyidentity.db-wal' || fail "the stopped server left kyidentity.db-wal behind"
before=$(inspect 'sha256sum /data/kyidentity.db' | cut -d' ' -f1)

echo "3. PostgreSQL 18, C locale, on the private network"
password=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
docker run -d --name "$pg" --network "$net" -e POSTGRES_PASSWORD="$password" \
  -e POSTGRES_INITDB_ARGS='--locale=C --encoding=UTF8' "$pg_image" >/dev/null
for _ in $(seq 1 60); do
  # The image initialises on a socket-only server first; TCP means the real one is up.
  if docker exec "$pg" pg_isready -q -h 127.0.0.1 -U postgres; then break; fi
  sleep 1
done
docker exec "$pg" pg_isready -q -h 127.0.0.1 -U postgres || fail "PostgreSQL never became ready"
# The URL holds the password: it reaches the containers through the environment, never argv.
export KYIDENTITY_DATABASE_URL="postgres://postgres:$password@$pg:5432/postgres?sslmode=disable"

echo "4. migrate-to-postgres from the stopped volume, mounted read-only"
out=$(docker run --rm --network "$net" -v "$volume:/data:ro" -e KYIDENTITY_DATABASE_URL "${offline[@]}" \
  "$image" migrate-to-postgres -from /data/kyidentity.db 2>&1) || fail "the migration failed: $out"
case $out in *"every table's row count matches"*) ;; *) fail "unexpected migration output: $out" ;; esac
case $out in *"$password"*) fail "the migration printed the database password" ;; esac
after=$(inspect 'sha256sum /data/kyidentity.db' | cut -d' ' -f1)
[ "$before" = "$after" ] || fail "the migration changed the SQLite file"

echo "5. a repeat migration into the populated database is refused"
if again=$(docker run --rm --network "$net" -v "$volume:/data:ro" -e KYIDENTITY_DATABASE_URL "${offline[@]}" \
  "$image" migrate-to-postgres -from /data/kyidentity.db 2>&1); then
  fail "a second migration into the populated database succeeded"
fi
case $again in *"not empty"*) ;; *) fail "the repeat was refused for another reason: $again" ;; esac

echo "6. the image starts on PostgreSQL"
docker run -d --name "$pg_app" --network "$net" -v "$volume:/data" -e KYIDENTITY_DATABASE_URL "${offline[@]}" \
  "$image" >/dev/null
ready "$pg_app" || fail "the server never became ready on PostgreSQL"
admins=$(docker exec -u postgres "$pg" psql -qAtX -d postgres -c "SELECT count(*) FROM users WHERE username='admin' AND role='admin' AND status='active'")
[ "$admins" = 1 ] || fail "the bootstrap administrator is not in PostgreSQL ($admins rows)"
docker logs "$pg_app" 2>&1 | grep -qF "$password" && fail "the server logged the database password"

echo "cutover check passed: source digest $before unchanged, administrator present, /readyz 200 on PostgreSQL"
