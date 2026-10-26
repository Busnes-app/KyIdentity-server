# KyIdentity standalone installation

## Before you start

These steps are for a **new, independent installation** from this repository. Use the
README’s upgrade/restore procedure for an existing instance. Keep its volumes, keys,
configuration and Compose overlays; do not replace its environment files with examples.

Use Linux with Docker Engine and Docker Compose 2.24 or newer, Git, and permission to use Docker.
Choose a release/revision and use its matching Compose files and documentation. Image tags
can move: follow the README/Compose attestation and digest-pinning procedure before relying
on a published image. Source builds use the separate build overlay where provided.

Clone this repository, enter its directory, then run the product steps below:

```sh
git clone https://github.com/Busnes-app/KyIdentity-server.git
cd KyIdentity-server
```

Each service needs its own directory and persistent storage. Several products use host
port 8080 by default; install them on separate hosts or configure distinct host ports and
matching public origins. For remote users, provide a TLS reverse proxy and a hostname you
control. Trust only the proxy’s actual peer address, and forward the original scheme/client
address according to the product’s proxy guide.

## Key strength and TLS

Read [the key-strength configuration](docs/STRONG-CRYPTO.md) before upgrading
existing credentials or enabling the optional process TLS overlay. Preserve the
original data volume, keys, issuer and Compose chain; verify the external TLS
proxy separately. The guide identifies independent Worker/platform limits.

## Install the identity provider

No other Ky product is required. An SMTP service is needed for account email, and push
MFA needs a paired KyAuth device and its delivery transport. Ordinary TOTP MFA does not.

```sh
[ -e .env ] || (umask 077; cp .env.example .env)
chmod 600 .env
```

Set `KYIDENTITY_ISSUER_URL` in `.env` to the exact browser-facing origin, such as
`https://identity.example.com`. For a same-host trial, `http://localhost:5867` is accepted.
Set `KYIDENTITY_BIND=127.0.0.1` for a proxy on the host. For HTTPS, set
`TRUSTED_PROXY_CIDRS` to the proxy’s exact peer IP/CIDR.

Compose uses the external network `kypost-net` with static IP `10.89.0.2`. If it does not
exist, create it once (first check `docker network inspect kypost-net`):

```sh
docker network create --subnet 10.89.0.0/24 --ip-range 10.89.0.128/25 kypost-net
docker compose config --quiet
docker compose pull
docker compose up -d
docker compose exec kyidentity-server cat /data/first-run-password.txt
```

Choose a different unused subnet and compatible `KYIDENTITY_IP` if that range conflicts;
do not delete or recreate an existing shared network. The network name is historical and
does not require KyPost to be installed.

Open the issuer URL and sign in as `admin` with that password. You'll be asked to choose a
new password before anything else opens. Then enable MFA and store recovery codes privately. Keep a separate everyday user. Configure the email sender
in the administrator settings, send a real verification email, follow its link as the
user, and verify the user’s email status. A successful SMTP connection alone does not prove
inbox delivery or a verified address.

Check `/readyz`, `/healthz` and `/.well-known/openid-configuration` at the issuer origin.
Discovery’s issuer must match exactly. Register downstream OIDC clients and directory
connectors only when adding those products; SSO does not automatically configure mail,
provision every product or verify offboarding.

The named `kysignon_data` volume contains accounts, keys and configuration; keep the name
on upgrades. For a source install, retain `docker-compose.build.yml` in `COMPOSE_FILE` as
described in the [README](README.md). Recovery: [restore runbook](docs/RESTORE.md).

## Keep it recoverable

If reusing an RSA token-signing key, it must be at least 2048 bits (PKCS#1 or
PKCS#8). Startup refuses a smaller key and preserves its file. Follow the
[signing-key upgrade guidance](docs/UPGRADES-AND-RECOVERY.md#rsa-signing-key-minimum)
before replacing one; a signing-key change affects previously issued tokens.

Preserve the database **and deployment keys**, not just the image. Configure recovery using
the linked restore runbook, retain an independent copy, and complete a scratch restore with
custodian cards before treating recovery as verified. A synthetic drill uses a throwaway
key and does not prove that the real cards are available or correct.

For upgrades, back up first, read the chosen release’s migration notes, and reuse the same
Compose project, volume mounts and overlay selection for every command. `docker compose
pull` followed by `docker compose up -d` updates a published-image installation; a digest pin
must be deliberately changed after verification. A source install must keep its build
overlay and rebuild. `docker compose down -v` deletes managed volumes: it is not an upgrade.

## What verification means

The startup checks above prove only the checks they perform. Use the README’s development
section and the repository CI workflow for source/build tests; a passing health response or
screenshot is not a substitute. Record the revision, commands, environment and skips when
reporting results. Design plans and dated evidence remain records of their stated scope.
