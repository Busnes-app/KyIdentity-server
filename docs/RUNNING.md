# Running

[Product overview](../README.md) · [Standalone installation](../INSTALL.md)

Commands and unlinked file paths below are relative to the repository root.

## Quickstart with Docker Compose

### 1. Configure Environment
Clone the repository and copy the sample configuration:
```bash
[ -e .env ] || (umask 077; cp .env.example .env); chmod 600 .env   # an existing .env is kept; it holds secrets
```

Review and adjust variables in `.env`:
```ini
# Host interface for port 5867. KyIdentity serves plain HTTP only, so browsers reach it
# through a TLS proxy whatever you bind here.
KYIDENTITY_BIND=127.0.0.1

# Static container IP on shared kypost-net network
KYIDENTITY_IP=10.89.0.2

# Public URL used in issued tokens. Must be https unless the host is localhost or a
# loopback IP; startup refuses anything else.
KYIDENTITY_ISSUER_URL=https://auth.yourdomain.com

# Your TLS proxy's address as KyIdentity sees it, and nothing wider (see SECURITY.md).
TRUSTED_PROXY_CIDRS=<proxy-ip>/32
# Startup refuses wider-than-private ranges with X-Forwarded-For / Forwarded.
# A Cloudflare-only tunnel may use CF-Connecting-IP with proxy-only port access.

# Optional: Pre-seed administrator credentials
BOOTSTRAP_ADMIN_USER=admin
# BOOTSTRAP_ADMIN_PASS=<a privately generated unique password; never use this placeholder>

# Optional: native-push relays for KyAuth on Android (FCM) and iOS (APNs). Unset uses
# the Busnes.app relays below; an empty value turns one off, and then push MFA on that
# platform does not work (TOTP, passkeys and UnifiedPush still do). Without a
# *_RELAY_KEY the server self-registers, keeps the key sealed in its database, and
# re-registers once if the relay reports it superseded or unknown.
# PUSH_RELAY_URL=https://fcm.relay.kyauth.busnes.app
# APNS_RELAY_URL=https://apn.relay.kyauth.busnes.app

# Optional: Ubuntu Touch push (defaults shown; HTTPS only)
# KYIDENTITY_UBUNTU_PUSH_URL=https://push.ubports.com/notify
# KYIDENTITY_UBUNTU_PUSH_APPID=kyauth.busnes_kyauth
```

### 2. Start the Server
The compose file joins the external Docker network `kypost-net` (`KYPOST_NETWORK`) at the
fixed address `KYIDENTITY_IP` and does not create it; `up` fails until it exists. KyPost's
compose file creates it, so on a host that runs KyPost, start KyPost first. Otherwise create
it once:

```bash
docker network create --subnet 10.89.0.0/24 --ip-range 10.89.0.128/25 kypost-net
```

`--ip-range` keeps dynamically assigned addresses off the low, pinned ones such as
`10.89.0.2`. A KyPost added later finds a network its compose did not create and needs an
override marking `kypost-net` as `external: true`.

Published image:

```bash
docker compose up -d
```

Source install (never paste this into a published-image install: the build overlay wins over a
`KYIDENTITY_IMAGE` digest pin, and a source install must set this line before its first `up -d` on a
new checkout):

```bash
(umask 077; t=$(mktemp ./.env.XXXXXX) && touch .env \
  && cf=$({ grep '^COMPOSE_FILE=' .env || [ $? -eq 1 ]; } | tail -n1 | cut -d= -f2-) && cf=${cf:-docker-compose.yml} \
  && case ":$cf:" in *:docker-compose.build.yml:*) ;; *) cf="$cf:docker-compose.build.yml";; esac \
  && { grep -v -e '^COMPOSE_FILE=' .env || [ $? -eq 1 ]; } > "$t" \
  && printf 'COMPOSE_FILE=%s\n' "$cf" >> "$t" && mv "$t" .env)
docker compose up -d
```

Update a published-image install on the rolling tag:

```bash
docker compose pull && docker compose up -d
```

A digest-pinned install (`KYIDENTITY_IMAGE` in `.env`) gets nothing from `pull`: re-run the pin recipe in
`docker-compose.yml` with the commit sha you want first, or delete that line to follow `:latest` again.

### 3. Retrieve Credentials & Log In
If you did not define `BOOTSTRAP_ADMIN_PASS` in `.env`, KyIdentity generates a one-time bootstrap password on first start:

```bash
docker compose exec kyidentity-server cat /data/first-run-password.txt
```

Open your `KYIDENTITY_ISSUER_URL` (for example `https://<id.example.com>`) through your TLS
proxy and sign in with `admin` and the retrieved password. You'll be asked to choose a new
password before anything else opens, the same when `BOOTSTRAP_ADMIN_PASS` set it. With the default
`KYIDENTITY_BIND`, port 5867 is published on `127.0.0.1` only: for a proxy on the same host
and the health checks below, not for browsers on other machines.

### 4. Private certificate authority (LAN installs)
KyIdentity verifies every outbound TLS connection (KyRecovery, SCIM and suite connectors,
back-channel logout, mail, push relays) against the container's trust store. To add a
private CA, put its PEM certificate in a directory and point Go's standard `SSL_CERT_DIR` at
it with an overlay file, for example `docker-compose.ca.yml`:

```yaml
services:
  kyidentity-server:
    environment:
      SSL_CERT_DIR: /etc/kyidentity/ca
    volumes:
      - ./ca:/etc/kyidentity/ca:ro
```

Append it to the `COMPOSE_FILE` chain in `.env` (for example
`COMPOSE_FILE=docker-compose.yml:docker-compose.ca.yml`), then `docker compose up -d`.
`SSL_CERT_DIR` adds the directory's certificates to the image's bundle, so public roots
(push relays, UnifiedPush endpoints) stay trusted. Use a colon to list several directories.
The files must be readable by the container's non-root user (`kyidentity`).

---

## Running more than one replica

Replicas share one Postgres database. An install on SQLite moves there with
`migrate-to-postgres` (below); backup, the restore drill and `restore` work on both.

### The shared database

Replicas cannot share a SQLite file, so `KYIDENTITY_REPLICATED=true` is refused at startup
unless the database is Postgres. Set one of:

| Variable | Contents |
|---|---|
| `KYIDENTITY_DATABASE_URL` | a `postgres://` URL |
| `KYIDENTITY_DATABASE_URL_FILE` | the path of a file (a mounted Secret) holding that URL |

Setting both is refused. Unset means the SQLite file, exactly as before. The URL carries
the password: the server logs only the host and the database name, and never repeats the
URL in an error.

The server must be Postgres 16 or newer. The database must be UTF8 with the C locale, so
that names compare exactly as on SQLite (case-insensitive for ASCII letters only). Create
it with:

```sql
CREATE DATABASE kyidentity ENCODING 'UTF8' LOCALE 'C' TEMPLATE template0;
```

At startup the server checks this and refuses to start, before writing anything, when the
check fails. It creates the `citext` extension, a trusted extension since Postgres 13, so
the database owner needs no superuser for it. The first replica to start creates the schema
while the others wait.

Every connection requires a writable primary (`target_session_attrs=read-write` unless the
URL sets another value), connects within 5 s and is replaced after 5 min, so the pool
follows a failover. `/readyz` fails while the database is unreachable or read-only and
recovers without a restart. Statements wait at most 5 s for a lock, and a transaction left
idle for 30 s is ended by the server.

All writes are serialised: every write transaction takes one advisory lock, as SQLite lets
one writer in at a time. Write throughput is therefore that of one connection, however many
replicas run; reads are not affected.

`apply-setup`, `disable-user`, `resync-system`, `backup-drill`, `export-capsule`,
`deposit` and `restore` act on the Postgres database when the variable is set.

### Backups on Postgres

A backup copies the database out of one consistent Postgres snapshot into a SQLite file, so
it takes no write lock and a capsule made on Postgres has the same members as one made on
SQLite. Scheduled backups, Back up now and the drill work unchanged, and either kind of
capsule restores onto either backend.

### Moving an install from SQLite to Postgres

1. Stop the server. The copy refuses a file with a `-wal` beside it, which a server that
   is still running (or did not stop cleanly) leaves; start and stop it once if so.
2. Create the database as above. Nothing else may have written to it.
3. Copy the data:

   ```bash
   KYIDENTITY_DATABASE_URL_FILE=/run/secrets/db-url kyidentity migrate-to-postgres -from /data/kyidentity.db
   ```

   It copies every table in one transaction and prints each table's row count, then
   counts again after the commit and fails if any table differs. It refuses a database
   that holds any row, and a file at a schema version this release does not know (a file
   from before schema versions is brought up to date on a private copy first). The file
   is never modified. If the copy fails, the database is left as it was.
4. Set the variable on the server and start it. The keys stay where they are; for
   replicas, move them into a Secret as described under Keys.

There is no command back. To return to SQLite, take a capsule on Postgres (Back up now or
`export-capsule`) and restore it with the variable unset ([RESTORE.md](RESTORE.md)).

### Restoring into Postgres

Stop every replica, then run `restore` with the variable set. The keys and configuration go
to `-to` as always. The capsule's database is loaded into Postgres in one transaction, which
also ends the capsule's sessions and tokens, holds outbound provisioning, turns scheduled
deposits off and writes the `system.restored` audit row, so no replica ever serves the
capsule's logins. `kyidentity.db` and the restore marker are then removed from `-to`; start
the servers with its `data` directory (or its keys in the Secret).

A database that holds any row is refused. `-replace-database` empties every table first,
inside the same transaction: if the load fails, the old rows are still there.

### Keys

Several replicas behind one load balancer must be one identity: the same four keys in each.
A replica that generated its own would reject the others' tokens, cookies and sealed secrets.

Set `KYIDENTITY_REPLICATED=true` on every replica. It then never generates a key and stops
at startup, naming the variable, when one is missing. Supply the keys from a mounted Secret:

| Key | Variable | Contents |
|---|---|---|
| Cookie and CSRF secret | `KYIDENTITY_SECRET_KEY_FILE` | 32 raw bytes, or 64 hex characters (`openssl rand -hex 32`) |
| Encryption key | `KYIDENTITY_ENCRYPTION_KEY_FILE` | the same format |
| RSA signing key | `KYIDENTITY_RSA_KEY_PATH` | PEM, PKCS#1 or PKCS#8, 2048 bits or more |
| UnifiedPush VAPID key | `KYIDENTITY_VAPID_KEY_PATH` | the base64url P-256 private scalar on one line |

- An existing install already has all four in its data directory (`secret.key`,
  `encryption.key`, `jwt_rs256.key`, `push-vapid-private.key`). Copy those files into the
  Secret unchanged; new keys would end every session and orphan every sealed secret.
- `KYIDENTITY_SECRET_KEY` and `KYIDENTITY_ENCRYPTION_KEY` (hex in the environment) still
  work; setting one together with its `_FILE` variable is refused.
- Mount the Secret with `defaultMode: 0440`. The VAPID key is refused when others can read
  it; group read is allowed at a path you name because the kubelet grants it to the pod's
  `fsGroup`.
- Without the flag nothing changes: a single instance generates and keeps its keys in the
  data directory as before.

With the flag set the server also:

- keeps rate-limit buckets in the database as well as in memory, so a limit of five an hour
  is five an hour across all replicas, not five per replica. A limiter that cannot reach
  the database refuses the request;
- refuses to start when no administrator exists and `BOOTSTRAP_ADMIN_PASS` is empty. A
  generated password would be written inside one pod, where nobody looks for it. Supply
  `BOOTSTRAP_ADMIN_PASS` from a Secret or run `bootstrap-admin`.

These hold with or without the flag, because they cost a single instance nothing:

- Work that must happen once takes a lease in the database first: the scheduled backup,
  Back up now, the restore drill, the daily device-attestation sweep and push relay
  registration. Alert mail is claimed row by row before it is sent.
- The push relay keys live in the database, sealed under the encryption key, so every
  replica presents the same key and one of them renews it.
- Session limits changed on one replica reach the others within five seconds.
- Two servers starting at once on one database migrate it one after the other, and the
  first administrator is created once.

Still one per replica, and not shared: `recovery.pub` (the pinned backup key, written at
KyRecovery pairing), local backup copies in `KYIDENTITY_BACKUP_DIR`, and the files
`apply-setup` writes under `<data>/installer/`.

## Health & Status Verification

You can verify the status of the server at any time:

* **Suite health** (public `ky.health/1`): `/healthz` checks the database, signing key,
  encryption key, and audit persistence. Results are cached for five seconds. It returns
  `200` for `ok` or `degraded` and `503` for `down`. The JSON contains fixed check names,
  states, and a fixed audit degradation reason; it does not expose internal errors, paths,
  hostnames, versions, or uptime. This endpoint previously returned only `{"status":"alive"}`.
  ```bash
  curl http://localhost:5867/healthz
  # Response includes "schema":"ky.health/1", "service":"kyidentity", "status":"ok", and checks.
  ```
* **Liveness** (is the process running, independent of dependencies):
  ```bash
  curl http://localhost:5867/livez
  # Response: {"status":"alive"}
  ```
* **Readiness** (can this instance actually authenticate someone). Point your load balancer
  at this one. It runs a bounded database read and confirms the signing and encryption keys
  are loaded, and returns `503` when they are not. Unlike `/healthz`, it evaluates each
  request immediately and keeps its existing response shape.
  ```bash
  curl http://localhost:5867/readyz
  # Response: {"status":"ready","checks":{"audit":"ok","database":"ok",...}}
  ```
* **Proxy and scheme check** (public, the suite installer status endpoint that
  `kyquickstart verify-edge` reads): reports the client address and scheme as KyIdentity
  resolved them, and whether the immediate peer is in `TRUSTED_PROXY_CIDRS` so its forwarding
  headers were believed. Through your public route it should show your own address,
  `"proxyHeadersTrusted":true` and `"scheme":"https"`.
  ```bash
  curl https://id.example.com/api/installer/network
  # Response: {"clientIp":"203.0.113.6","proxyHeadersTrusted":true,"scheme":"https"}
  ```
* **OpenID Connect Discovery**:
  ```bash
  curl http://localhost:5867/.well-known/openid-configuration
  ```
* **Docker Container Health**:
  ```bash
  docker compose ps
  # Look for "Up (healthy)"
  ```

---

## Command Line Utilities

Create the first admin account directly within the running container. The password is the
first line of stdin, never an argument (argv is world-readable and lands in shell history);
`-password` is refused. An empty line generates one and prints it once.
```bash
docker compose exec kyidentity-server /usr/local/bin/kyidentity bootstrap-admin -username admin -email admin@example.com
```

`bootstrap-admin` only creates a missing account, as an active administrator, and records
`admin.user_created` in the audit log in the same transaction. `-email` defaults to
`<username>@local.kysecurity`. If the name already belongs to an active administrator it
changes nothing; if it belongs to anyone else (an ordinary or disabled account) it fails
rather than promote or re-enable them. Change existing passwords from the admin UI, so the
action is audited. To retire a bootstrap administrator once another exists, use
`kyidentity disable-user --username admin --require-active-admin <other admin>`
([docs/INSTALLER-SETUP.md](INSTALLER-SETUP.md#retiring-the-bootstrap-administrator)).

Restoring from a `.kycap` backup is `kyidentity restore`, with the capsule's digest from
KyRecovery's deposit record as `-expect-digest` and k custodian shares typed on stdin. The full procedure, including putting the result back into service and proving it,
is [docs/RESTORE.md](RESTORE.md).

---
