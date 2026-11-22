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

# Optional: office networks that skip the per-address sign-in limit (SECURITY.md).
# RATE_LIMIT_EXEMPT_CIDRS=203.0.113.0/24

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

Application replicas are not database high availability. PostgreSQL standby, failover and
fencing are yours to run (below), and so is the load balancer in front. The replica tests
prove correctness, not capacity: no user count or request rate is claimed.

### Load balancer

- **Health check.** Probe `/readyz` actively, every second. It answers 503 while this
  replica cannot reach a writable database or is stopping. `/livez` only says the process
  runs; use it for restarts, never for routing.
- **Retries.** Retry a request on another replica only when it is idempotent (GET, HEAD)
  and its connection failed before anything was sent. Never retry after a timeout: the
  first replica may still be doing the work.
- **Timeouts.** Give the upstream at least 30 s. An ordinary request is answered within
  25 s (the request deadline, below). The few routes outside the deadline (mail sends, the
  KyRecovery pairing claim, the audit export) put their own timeouts on their outbound
  calls, but nothing bounds their database calls: on a frozen database they wait with it,
  so the proxy's timeout is what ends them. The listener's 30 s write timeout stops the
  answer being written, not the handler. Only the three backup routes need 16 minutes:
  `POST /api/admin/backup/deposit`, `POST /api/admin/backup/drill` and
  `GET /api/admin/backup/export-capsule`.
- **nginx and Nginx Proxy Manager** (described from their documentation, not run here).
  Open-source nginx, which Nginx Proxy Manager is built on, has passive checks only
  (`max_fails`, `fail_timeout`): it notices a replica after requests to it fail, and never
  reads `/readyz`, so a stopping replica stays in rotation until its listener closes.
  Active `health_check` is an NGINX Plus feature. `proxy_next_upstream error;` retries on
  another replica when the connection failed, but also when sending the request or
  reading the response header failed, so an idempotent request that reached the first
  replica may be sent again; nginx never resends POST, PATCH or LOCK unless
  `non_idempotent` is set, so leave it off, and leave `timeout` out of the list. Nginx Proxy
  Manager's proxy host forwards to one host: for several replicas, give it a host name
  that resolves to every replica, or define an `upstream` in its custom configuration
  (`/data/nginx/custom/http_top.conf`) and point the proxy host at it. A replica that
  drains still serves for its five seconds, so passive checks lose nothing during a stop;
  they do route new requests to a replica whose database is down until those requests
  fail.

### Stopping a replica

On SIGTERM a replica (`KYIDENTITY_REPLICATED=true`):

1. turns `/readyz` to 503 (`checks.server = "draining"`), stops starting scheduled
   backups and other background work, and answers new Back up now and drill requests 503;
2. keeps serving for 5 s, five one-second probes, so the load balancer takes it out;
3. closes its listener and lets requests in flight finish, for up to 5 s;
4. cancels any backup or drill still running;
5. waits up to 10 s for those and the sync worker to record their outcome and give back
   their leases.

That is 20 s at most. **Give replicas a 30 s grace period** (Compose
`stop_grace_period: 30s`; Kubernetes' default `terminationGracePeriodSeconds` is 30). A
single server has no drain step: 5 s for requests, then 3 s for backup work, 8 s in all,
inside Docker's default 10 s, so `docker-compose.yml` needs nothing. On a single server the
listener closes at once, so a new Back up now or drill request gets no answer at all
rather than the 503.

A Kubernetes sketch, **not executed by CI**:

```yaml
spec:
  terminationGracePeriodSeconds: 30
  containers:
    - name: kyidentity
      readinessProbe:
        httpGet: { path: /readyz, port: 5867 }
        periodSeconds: 1
        timeoutSeconds: 3      # /readyz allows its database read 2 s; the default is 1 s
        failureThreshold: 2    # two failed probes still fit inside the 5 s drain
      livenessProbe:
        httpGet: { path: /livez, port: 5867 }
        periodSeconds: 10
        failureThreshold: 6
```

### Request deadline

Store calls have no client-side deadline, so a database that freezes (a paused VM, a storage
hang) would hold requests open. Every request therefore has 25 s; one that has not been
answered by then gets `503 {"error":"request_timeout"}`. **A 503 after the deadline does not
prove the request had no effect**: the work may finish once the database answers, so check
before repeating a change. The routes that keep budgets of their own are the three backup
routes above and those that wait on another server: `POST /api/admin/backup/pair-remote`,
`GET /api/admin/audit-events/export`, `POST /api/admin/mail/test`,
`POST /api/admin/users/{id}/activation-link` and `reset-link`, and
`POST /api/admin/access-requests/{id}/approve` and `deny`. A sign-in or step-up that sends a
push waits at most 10 s for the push relays, so a relay key being renewed cannot take it
past the deadline. Sends continue in the background while the process remains running;
retry or use another factor if the replica stops before delivery. A session the database cannot look up is
answered `503 temporarily_unavailable`, never 401, and the web app then offers to retry
rather than showing the sign-in page. Browser navigations to `/oauth/authorize`,
`/oauth/logout` and `/forward/start` get that answer as JSON: without the database neither the
client nor its redirect can be checked, so there is nowhere safe to send the browser.

### Shared configuration

On Postgres, the first server to start records a fingerprint of the settings every replica
must share, in the database, and every later start compares its own. **This applies to a
single server on Postgres too**: after changing one of these settings it refuses to start
until the change is accepted. A server that differs refuses to start and names the
settings, never their values:

```
Refusing to start: this server's configuration differs from the one recorded in the database by an earlier start: KYIDENTITY_ISSUER_URL. Use the same values on every server. After a deliberate change: stop every server, run `kyidentity accept-replica-config` once with the new values, then start them
```

Shared: `KYIDENTITY_ISSUER_URL`, the secret and encryption keys, the RSA signing and VAPID
**public** keys (the paths may differ), `KYIDENTITY_REPLICATED`,
`KYIDENTITY_SECURE_COOKIES`, `KYIDENTITY_SESSION_TTL`, `KYIDENTITY_SESSION_IDLE_TTL`,
`RATE_LIMIT_EXEMPT_CIDRS`, `KYIDENTITY_ALLOW_PRIVATE_CALLBACKS`, `PUSH_RELAY_URL`/`_KEY`,
`APNS_RELAY_URL`/`_KEY`, `KYIDENTITY_UBUNTU_PUSH_URL`/`_APPID`, `KYIDENTITY_APP_NAME`,
`KYIDENTITY_BACKUP_DEPOSIT_INTERVAL`, `KYIDENTITY_BACKUP_ALLOW_PRIVATE_RECOVERY`,
`KYIDENTITY_ATTESTATION_STATUS_URL`, the content of `KYIDENTITY_ATTESTATION_EXTRA_ROOTS`,
`KYIDENTITY_KYAUTH_CERT_SHA256`, `KYIDENTITY_APPATTEST_APP_IDS` and `_ALLOW_DEVELOPMENT`,
`KYIDENTITY_TENANCY`.

Per host, free to differ: port and listen host, data directory and SQLite path, the
database URL (host lists may differ), key file paths, `TRUSTED_PROXY_CIDRS`,
`KYIDENTITY_FORWARDED_HEADER`, `KYIDENTITY_BACKUP_DIR`/`_KEEP`, `BOOTSTRAP_ADMIN_*` and
`KYIDENTITY_RECOVERY_KEY_ID`, so the rolling recovery-key replacement under Keys still works.

Each value is an HMAC under a subkey of the encryption key, so someone who can read the
database cannot test guesses for an issuer, a network list or a relay URL. A different
encryption key is reported alone, since every other value depends on it. SQLite records
nothing, and no command other than the server start compares.

To change a shared setting deliberately:

1. Stop every server.
2. Change the setting everywhere.
3. Run `kyidentity accept-replica-config` once, with the new configuration. It rewrites
   the record and writes an `admin.replica_config_accepted` audit row naming the changed
   settings; it never prints a value. `-h` prints its usage and changes nothing; it takes
   no other argument.
4. Start the servers.

Run it **with the servers' own, complete environment**: the same variables, key files and
Secrets. It records what that process sees, so a bare shell or a container missing some of
it records the defaults (an unset `PUSH_RELAY_URL` is the production relay, for one), and
every server then refuses; run it again with the right environment. With Compose, the
servers stopped, this runs the service's own configuration once without its ports
(checked with throwaway containers on a Postgres override of `docker-compose.yml`):

```bash
docker compose run --rm --no-deps kyidentity-server accept-replica-config
```

On Kubernetes (not executed here), scale the Deployment to zero, then use a one-off **Job**
with the Deployment's image, `env`, `envFrom`, volumes, Secret mounts and `securityContext`
(including `fsGroup`). Set `args: ["accept-replica-config"]`, `restartPolicy: Never` in the
pod spec and `backoffLimit: 0` in the Job spec; omit probes and use labels that match neither
the Deployment's selector nor the Service's. Wait for successful completion, then scale
the Deployment back up. Also allow the Job through any NetworkPolicy required to reach
Postgres. Copying the whole Deployment template unchanged is not valid.

**Never use it for the encryption key**: it refuses, because every sealed secret opens only
under the key the servers already use.

Upgrading a Postgres install to this release: stop every server, start one (it records the
configuration), then start the rest. A restore removes the record, and the first start
afterwards records the restored environment's. Turning on `KYIDENTITY_REPLICATED` on an
install that already started on Postgres is a change to a shared setting: stop the server,
run `accept-replica-config` with the replicas' environment, then start the replicas. When
moving keys into a Secret, copy them unchanged; if a key differs, fix the copy rather than
accepting the change. A different encryption key is always refused.

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

For a primary with a standby, name both in the URL (`postgres://user:pw@db1:5432,db2:5432/kyidentity`)
or use one address that always reaches the primary. Two rules keep a failover safe:

- **Replicate synchronously** (`synchronous_standby_names` on the primary). A standby that
  lags is missing the last writes when it is promoted, and here those writes include
  sign-outs, password changes, disabled accounts and spent authorization codes: a session
  that was ended would work again.
- **A failed primary must not come back writable.** The server takes the first writable
  host in the URL, so an old primary that restarts on its own would be used again, with
  stale data. Whatever promotes the standby must also fence or rebuild the old primary.

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

1. Stop the server (`docker stop` at its default timeout is enough), and any commands such
   as `deposit` that share the live file. The copy refuses a file with a `-wal` beside it,
   which a running server (or one that stopped uncleanly) leaves; start and stop it once
   if so. For replicas, set `KYIDENTITY_REPLICATED=true` before the first Postgres start
   (copy the keys unchanged, as under Keys), or accept that flag change later as under
   Shared configuration.
2. Create the database as above. Nothing else may have written to it.
3. Copy the data:

   ```bash
   KYIDENTITY_DATABASE_URL_FILE=/run/secrets/db-url kyidentity migrate-to-postgres -from /data/kyidentity.db
   ```

   It copies every table in one transaction and prints each table's row count, then
   counts again after the commit and fails if any table differs. It refuses a database
   that holds any row, and a file from a newer release than this one (a file from an older
   release is brought up to date on a private copy first). It also refuses a file that
   fails SQLite's `integrity_check` or `foreign_key_check`, and one that changes while it is
   copied (a different size, time or SHA-256, or a `-wal` that appears): it rolls back and
   leaves the database empty. The file is never modified, so it can be mounted read-only.
   `-from` may be relative. If the copy fails, the database is left as it was.
4. Set the variable on the server and start it. The keys stay where they are; for
   replicas, move them into a Secret as described under Keys.

`scripts/check-postgres-cutover.sh` runs these steps with the real image, offline, and CI
runs it on every change.

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

- checks each cached forward-auth answer against its session row, so a forward-auth logout
  or revocation on one replica holds on all of them at once (`docs/FORWARD-AUTH.md`);
- keeps rate-limit buckets in the database as well as in memory, so a limit of five an hour
  is five an hour across all replicas, not five per replica. A limiter that cannot reach
  the database refuses the request;
- refuses to start when no administrator exists and `BOOTSTRAP_ADMIN_PASS` is empty. A
  generated password would be written inside one pod, where nobody looks for it. Supply
  `BOOTSTRAP_ADMIN_PASS` from a Secret or run `bootstrap-admin`.

These hold with or without the flag, because they cost a single instance nothing:

- Work that must happen once takes a lease in the database first: the scheduled backup,
  Back up now, the restore drill, the daily device-attestation sweep and push relay
  registration. Alert mail is claimed row by row before it is sent. Lease time is the
  database's clock, so a replica whose clock is off neither takes a live lease nor keeps a
  dead one. The backup and drill leases last 2 minutes and are renewed every 30 s while the
  work runs, so a replica that crashes mid-backup delays the next one by at most 2 minutes
  and a tick. A run that loses its lease (renewal finds another holder, or keeps failing
  until the lease is nearly out) stops its upload and records a failure. A lease is single
  ownership of scheduling, not exactly-once: a deposit is idempotent per capsule, and sync,
  logout, HR and reconciliation keep their own fences.
- The push relay keys live in the database, sealed under the encryption key, so every
  replica presents the same key and one of them renews it.
- Session limits changed on one replica reach the others within five seconds.
- The other housekeeping runs on every replica with no lease: the 15-minute purge of
  expired rows and the minute's expiry, provisioning reconcile, reconcile scheduling,
  directory-password expiry and erasure passes. Each re-checks its rows inside a write
  transaction, and writes are serialised across replicas, so passes that overlap apply
  each change once.
- Two servers starting at once on one database migrate it one after the other, and the
  first administrator is created once.
- The pinned backup key is kept in the database as well as in `recovery.pub`, sealed under
  the encryption key. A replica whose data directory has no `recovery.pub` writes it from
  that copy, so whichever replica the schedule falls to can seal the backup, and a pod
  that restarts with an empty data directory keeps backing up. An install paired before
  this copy existed gains it the first time a server that holds `recovery.pub` starts.
- **Set `KYIDENTITY_RECOVERY_KEY_ID` on every replica** to the recovery key's ID, 64 hex
  characters. A backup carries the server's keys, so the database must not be able to
  choose who can open one, and the database still holds, or can be given back, the copy
  and ID of a key you replaced. A replica therefore pins, loads and seals to the key this
  variable names and no other, and without it backs up to nothing: the backup page and
  the audit log say so and name the variable. To set it up:
  1. Pair with KyRecovery, or pin the key, as on a single instance.
  2. Take the key ID from KyRecovery. The backup page shows the ID it pinned; the two
     must be equal. Do not copy it from the server alone.
  3. Add the variable to the deployment and roll it out. It is not a secret.
- Replacing the recovery key means clearing the pin by hand; no screen does it. The
  replicas can keep serving:
  1. Set the variable to the new ID on every replica and roll them. A replica that names
     the new ID backs up to nothing until step 3; one not yet rolled still seals to the
     old key.
  2. Clear the old pin in the database:
     ```sql
     DELETE FROM system_settings WHERE key IN
       ('kyrecovery_key_id', 'kyrecovery_threshold', 'kyrecovery_total_shares', 'kyrecovery_public_key');
     ```
  3. Remove `recovery.pub` from every replica's data directory that has one, then pin the
     new key. A replica still holding the old `recovery.pub` refuses to pin and to back up
     until that file is removed; it never seals to the old key.
- A pinned key's custodian split (k of n) is written once: pinning or pairing the same key
  with another split is refused with 409, naming the split it is pinned with. If that
  pinned split is wrong (a typo when pinning by hand), correct it the way a key is replaced:
  clear the pin with the `DELETE` above, remove `recovery.pub` from every data directory
  that has one, and pin it again with the right split. A refused pairing has already spent
  its pairing code: ask the KyRecovery administrator to revoke the token KyRecovery issued
  for it.
  For a **single-server SQLite install**, keep the same suite public key and
  `KYIDENTITY_RECOVERY_KEY_ID` if set, and confirm the correct split against the ceremony
  record. From the install's Compose directory, stop the server and repair its
  `kysignon_data` volume with this disposable helper (the server image has no SQLite shell;
  `apk` installs it only in the helper, which needs access to the Alpine package mirror):

  ```bash
  docker compose stop kyidentity-server
  docker compose run --rm --no-deps -T --user 0 --entrypoint /bin/sh kyidentity-server -es <<'REPAIR'
  apk add --no-cache sqlite
  db=${KYIDENTITY_DB_PATH:-/data/kyidentity.db}
  if [ -z "${KYIDENTITY_DB_PATH:-}" ] && [ ! -f "$db" ]; then db=/data/kysignon.db; fi
  test -f "$db" || { echo "No SQLite database at $db; check the data volume and KYIDENTITY_DB_PATH" >&2; exit 1; }
  echo "Clearing the recovery-key pin in $db"
  sqlite3 -bail "$db" <<'SQL'
  BEGIN IMMEDIATE;
  DELETE FROM system_settings WHERE key IN
    ('kyrecovery_key_id', 'kyrecovery_threshold', 'kyrecovery_total_shares', 'kyrecovery_public_key');
  COMMIT;
  SQL
  rm -f /data/recovery.pub
  REPAIR
  docker compose up -d --wait kyidentity-server
  ```

  This preserves pairing credentials, receipts and existing capsules. Pin the same key
  again with the correct split, or pair again with a fresh code. Never delete the database
  or its encryption/signing keys to repair a split. For a host install, stop it and run the
  same SQL with the host's `sqlite3` on its data file, then remove only `recovery.pub`.
- A scheduled backup that finds a pinned key it cannot load is recorded as a failed
  `admin.backup_run`; it is never skipped quietly.

`KYIDENTITY_BACKUP_DIR` takes either layout:

- **One per replica** (the default): each replica keeps the copies it made in its own
  directory, under the same names as on a single server, and lists only those. The backup
  page shows the directory of whichever replica answered it, so behind a load balancer its
  count and newest copy can change from one refresh to the next.
- **One directory shared by every replica**, on a filesystem you provide (NFS, a shared
  volume): KyIdentity implements no shared storage. Copies are written (to a temporary
  file, then renamed) and pruned to `KYIDENTITY_BACKUP_KEEP` only inside a backup run,
  which holds the backup lease, so one replica writes at a time; the backup page only reads
  the directory, so every replica lists the same copies. Set the same
  `KYIDENTITY_BACKUP_KEEP` on every replica that shares a directory: it is per host, so
  otherwise how many copies stay depends on which replica ran last. One limit remains: a
  run whose lease is lost while it is sealing a large capsule (after its snapshot) still
  writes and prunes its copy before it notices, because the sealing step belongs to the
  backup library and does not yet check for that; the copies stay complete files (written
  to a temporary name, then renamed), but for that moment two replicas may write at once.

The plaintext database snapshot a backup seals is written to a private, locked
`snapshot-*` directory under the data directory and removed as soon as the capsule is
sealed. One left by a killed process is removed when the server next starts; one in use by
a running command is left alone.

The files `apply-setup` writes under `<data>/installer/` stay per replica.

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
  are loaded, and returns `503` when they are not, or while the server is stopping
  (`"server":"draining"`). Unlike `/healthz`, it evaluates each request immediately. Both
  `/readyz` and `/livez` are sent with `Cache-Control: no-store`.
  ```bash
  curl http://localhost:5867/readyz
  # Response: {"status":"ready","checks":{"audit":"ok","database":"ok",...,"server":"ok"}}
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

On PostgreSQL replicas, `kyidentity accept-replica-config` records a deliberate change to a
shared setting once every replica has it; see
[Shared configuration](#shared-configuration).

---
