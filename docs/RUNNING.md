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

# Optional: Pre-seed administrator credentials
BOOTSTRAP_ADMIN_USER=admin
# BOOTSTRAP_ADMIN_PASS=<a privately generated unique password; never use this placeholder>

# Optional: Cloudflare Worker native-push relays. Without a *_RELAY_KEY the server
# self-registers, keeps the key under the data directory, and re-registers once if
# the relay reports it superseded.
PUSH_RELAY_URL=https://kysecurity-mobile-push-fcm.<account>.workers.dev
APNS_RELAY_URL=https://kysecurity-mobile-push-apns.<account>.workers.dev

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
proxy and sign in with `admin` and the retrieved password. With the default
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
