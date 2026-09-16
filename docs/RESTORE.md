# Restoring KyIdentity from a capsule

This is the procedure for bringing a KyIdentity back from a `.kycap` backup after the original
is gone. It needs three things, held by three different parties by design:

| Thing | Who has it |
|---|---|
| The capsule (`.kycap`) | KyRecovery, or the local backup directory, or a downloaded copy |
| k custodian cards | The custodians from the suite ceremony (k is usually 2 of 3) |
| A machine to restore on | You |

Nobody can do this alone. KyRecovery cannot open a capsule. One custodian cannot. The server
that made the backup never could. That is the point, and it is also why you should run this
procedure once as a drill before you ever need it.

The `docker compose` commands below use the base file alone, which runs the published
image. Source install: confirm the `COMPOSE_FILE` line in `.env` contains `docker-compose.build.yml`
before the first command; extra overlays beside it, such as `docker-compose.lan-dns.yml`, are
fine (the "Start the Server" step in `README.md` adds it). Check: `grep '^COMPOSE_FILE=' .env | grep -q
docker-compose.build.yml && echo ok`. Otherwise a restore silently pulls a different binary than
the one you built and are running.
Published install: never restore onto a floating `:latest`; the step before the restore
command pins and verifies a digest.

## What a capsule holds

Everything a fresh KyIdentity needs to be the old one:

| Path in the capsule | What it is |
|---|---|
| `data/kyidentity.db` | The whole directory: users, sessions, OAuth clients, MFA state, audit log, settings |
| `data/jwt_rs256.key` | The RSA signing key. Without it every issued token and every OIDC client breaks |
| `data/encryption.key` | 32 bytes. Every TOTP secret and paired-system token in the database is encrypted under it |
| `data/secret.key` | 32 bytes. Signs sessions and CSRF tokens |
| `data/recovery.pub` | The suite recovery public key, so the restored server comes back pinned (present when the backup was paired) |
| `config/kyidentity.json` | Issuer URL, port, TTLs, app name. For your reference when re-deploying; nothing reads it |

The restored directory is the live directory in the clear. Treat it like the running server's
`/data`.

Capsules created before this release contain `data/kysignon.db` and `config/kysignon.json`; the
server still picks up those legacy filenames through the fallback in `internal/config/config.go`.

## Before you start

- **Pick the capsule.** In the KyRecovery dashboard, open Capsules, find the newest one for
  service `KySignOn` that is not flagged corrupt, and note its `capsule_id`, `created_at` and
  `digest`. You will compare these after the restore. Download it with an operator session
  (`GET /api/capsules/{id}/download`). From a local backup directory, the file is
  `<APP_NAME>-<capsule-id>.kycap`; the newest is the one to use unless you have a reason.
- **Gather k custodians.** Each card carries one share, a single line beginning `ky2-`. They
  type or paste it themselves; do not collect the shares in a file, a chat, or an email. Two
  shares in one place is the suite key in one place.
- **Prepare an empty directory** on a machine you trust, ideally the one that will run the
  restored server. The restore refuses a directory that is not empty.

## Step 1: open the capsule

With the binary (from a release, or `go build ./cmd/kyidentity`):

```bash
kyidentity restore -capsule cap-KySignOn-XXXXXXXX.kycap -to ./restored
```

For a published-image install, and always on a fresh recovery machine, pin the commit you
intend to run (normally the one that made the backup, or the current tip) to a digest you have
verified before it reads a single share (`gh` must be logged in). Name the commit yourself.
Tags are movable, `:<commit sha>` included, so the chain also checks that the attestation records
your commit as its source: the guarantee is the commit you named, not whatever the tag points at. The
chain stops at the first failure and renames a same-directory staging file over `.env` only
if the filtered copy was written in full, so your secrets are never truncated. The pin persists
in `.env` after the drill: see the README's upgrade note for moving off it. Commits built before 2026-09-16 were attested under the previous organisation name, so verify those with the exact `--repo` and `--cert-identity` strings that were in effect when they were built (owner `Busness-app`); keep the exact match rather than switching to `--cert-identity-regex`.

```bash
sha=<full commit sha you intend to run, e.g. $(git rev-parse origin/master)>
d=$(docker buildx imagetools inspect ghcr.io/busnes-app/kyidentity-server:$sha --format '{{.Manifest.Digest}}') \
  && gh attestation verify "oci://ghcr.io/busnes-app/kyidentity-server@$d" --repo Busnes-app/KyIdentity-server \
       --cert-identity https://github.com/Busnes-app/KyIdentity-server/.github/workflows/ci.yml@refs/heads/master \
  && [ "$(gh attestation verify "oci://ghcr.io/busnes-app/kyidentity-server@$d" --repo Busnes-app/KyIdentity-server \
       --cert-identity https://github.com/Busnes-app/KyIdentity-server/.github/workflows/ci.yml@refs/heads/master \
       --format json --jq '.[0].verificationResult.statement.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit')" = "$sha" ] \
  && (umask 077; t=$(mktemp ./.env.XXXXXX) && touch .env && { grep -v '^KYIDENTITY_IMAGE=' .env || [ $? -eq 1 ]; } > "$t" \
      && echo "KYIDENTITY_IMAGE=ghcr.io/busnes-app/kyidentity-server@$d" >> "$t" && mv "$t" .env) \
  && grep -qxF "KYIDENTITY_IMAGE=ghcr.io/busnes-app/kyidentity-server@$d" .env
```

Then, in the same shell (the check compares against `$d`), refuse to go on unless the image in
effect is exactly that digest. A source install passes on its `kyidentity-server:local` build instead,
since `docker-compose.build.yml` wins over the pin, which is what a source install wants. The
two refusal messages are distinct on purpose: a broken invocation is not an unpinned image.

```bash
imgs=$(docker compose config --images) || { echo 'refusing: compose could not resolve the image'; false; }
printf '%s\n' "$imgs" | grep -qxF "ghcr.io/busnes-app/kyidentity-server@$d" || printf '%s\n' "$imgs" | grep -qxF 'kyidentity-server:local' \
  || { echo "refusing: image in effect is '$imgs', not the digest verified above"; false; }
```

With Docker Compose, from the repository directory, mount the capsule and an empty target
directory into a one-off container. Create the target yourself at mode 700 and run the
container as your own user, so the extraction can write into it and what comes out is owned
by you, not by root and not by the image's user. The image's entrypoint is the binary, so the
subcommand goes straight after the service name; `--no-deps` keeps the real server down:

```bash
mkdir -m 700 restored
docker compose run --rm --no-deps --user "$(id -u):$(id -g)" \
  -v "$PWD/cap-KySignOn-XXXXXXXX.kycap:/in.kycap:ro" \
  -v "$PWD/restored:/restored" \
  kyidentity-server restore -capsule /in.kycap -to /restored
```

The bare binary needs none of this: it creates a missing target itself at mode 700.

The command prompts:

```
Paste the custodian shares, one per line, then press Ctrl-D:
```

Each custodian enters their share on its own line. After the k-th, press Ctrl-D. Shares are
read from stdin only, never from the command line, because argv is world-readable and lands
in shell history.

Only for a rehearsal with synthetic test shares, never with real cards, stdin can be a file.
Delete it afterwards; a file holding k shares is the suite key in a file.

```bash
kyidentity restore -capsule cap-KySignOn-XXXXXXXX.kycap -to ./restored < test-shares.txt
```

On success it prints the authenticated manifest:

```
Restored 5 files from capsule cap-KySignOn-1788564568139109864
  service:      KySignOn (v1.0.0)
  created:      2026-09-04T23:29:28Z
  recovery key: 886ff52c...
  payload hash: 8a053985...
```

**Check it against KyRecovery's record.** The capsule ID and `created` must match the
deposit record you noted. `capsule.Open` has already proved the bytes are intact and were
sealed to the suite key; matching the ID and time against the blind store's record is what
proves this is the capsule you meant, not an older one someone substituted.

Failures you may see, and what they mean:

| Message | Meaning |
|---|---|
| `capsule is for service "KySignOn", this instance is "X"` | You passed `-service` or set `KYIDENTITY_APP_NAME` to something else. Only override `-service` if the backup was made under a different app name |
| `shamir: fewer shares than the threshold requires` | Fewer than k valid lines were read. Check for a missed line or a truncated paste |
| `restore target directory is not empty` | Use an empty directory. The restore never overwrites |
| a decrypt or integrity error | Wrong shares (from a different ceremony), a share mistyped, or a damaged file. Re-download and retry with the custodians |

## Step 2: check what came out

```bash
find restored -type f -printf '%m %p\n'
```

Expect five or six files, all mode `600`, under `restored/data` and `restored/config`.
`cat restored/config/kyidentity.json` shows the issuer URL and port the old server ran with.

## Step 3: put it in service

The server reads keys from `/data` files unless the same keys are given by environment.
Choose one form and be consistent.

**Docker Compose (the normal deployment).** The data volume must be empty before the copy,
for the same reason Step 1 demands an empty directory. A capsule carries `kyidentity.db` but
never its `-wal` and `-shm` sidecars; a write-ahead log left over from the old database
would be replayed into the restored one at first open, mixing two databases. Any other
leftover file the capsule does not overwrite would survive too.

```bash
docker compose down
docker compose run --rm --no-deps --entrypoint sh kyidentity-server -c 'ls -A /data | wc -l'
```

That must print `0`. If it does not, the old volume still holds data, and you keep a copy
of it before anything else: it holds every change made after the capsule was sealed, and it
is the only record Step 5 can walk. Create the destination yourself, mode 700, so the daemon
does not create it world-readable; run the copy as root, as the copy-in below does, because
the image's user cannot write a directory it does not own:

```bash
mkdir -m 700 old-data
docker compose run --rm --no-deps --user root -v "$PWD/old-data:/out" --entrypoint sh kyidentity-server \
  -c 'cp -a /data/. /out/ && ls -A /out | wc -l'
```

The count it prints must equal the count from the `/data` check above, and the command must
exit 0. `old-data/` is now the old live directory in the clear, with the same keys the
capsule holds; it is removed in "Afterwards", not before Step 5 is done.

Only with the copy confirmed, remove the volume. This is irreversible:

```bash
docker compose down -v
docker compose run --rm --no-deps --entrypoint sh kyidentity-server -c 'ls -A /data | wc -l'
```

With `0` confirmed, copy the restored files in and start:

```bash
docker compose run --rm --no-deps --user root --entrypoint sh \
  -v "$PWD/restored/data:/from:ro" kyidentity-server \
  -c 'cp -a /from/. /data/ && chown -R kyidentity:kyidentity /data && chmod 600 /data/*'
docker compose up -d
```

The one-off container mounts the same `kysignon_data` volume the service uses, so the copy
lands where the server will read it, owned by the image's `kyidentity` user. Keep
`KYIDENTITY_ISSUER_URL` identical to the old deployment, from `config/kyidentity.json`: the RSA
key, every OIDC client and every passkey are bound to it.

The restored `encryption.key` and `secret.key` files are the keys; the file form is the one
to use. If the old deployment supplied `KYIDENTITY_SECRET_KEY` or `KYIDENTITY_ENCRYPTION_KEY` by
environment instead, the environment wins when both are present, so either remove those
variables so the files are read, or keep supplying the same values from wherever the old
deployment kept them. Never print a key to a terminal or type one on a command line: it lands
in scrollback, session recordings and shell history. If you must produce the hex form, write
it straight into the compose project's `.env` with `umask 077` and nothing else on stdout.

**Bare binary.** Point `KYIDENTITY_DATA_DIR` at `restored/data`, set `KYIDENTITY_ISSUER_URL` as
before, and start.

## Step 4: prove it

1. Open the issuer URL and sign in with an existing admin account and its second factor.
   TOTP working proves `encryption.key` is right. A passkey working proves the issuer URL is
   right.
2. Open Disaster recovery. If the backup was paired, the recovery key shows as pinned with
   the same key ID as before. The pairing token is in the database, so the restored server can
   deposit again without re-pairing; click Back up now to prove it. If the screen says the
   key is missing, `data/recovery.pub` did not come across; re-pair, which is refused unless
   KyRecovery hands back the same key.
3. Have one downstream application sign in through KyIdentity. That proves the RSA key.
4. Check the audit log: the last events before the restore are there, followed by your
   sign-in.

## Step 5: decide what to trust

The restore proves the service works. It does not make the restored state current or safe.
Everything comes back as of the capsule's `created_at`: users, passwords, MFA enrolments,
OAuth clients, paired systems, sessions, and `secret.key`. Anything you revoked or changed
after that moment is undone, and a session cookie minted before the capsule still validates
against the restored server.

1. Revoke sessions. The admin UI's control is per account: the row action on each user in
   Users, repeated for every user in the list. After hardware loss that is enough. After a
   suspected compromise it is not; rotating `secret.key` (step 3) is what invalidates every
   session and CSRF token at once, including any the list does not show you.
2. Walk the old audit log in `old-data/kyidentity.db` from `created_at` to the moment the old
   server was lost (the restored server's log stops at `created_at`), and re-apply
   what happened after the capsule: disabled accounts, rotated passwords, deleted or rotated
   OAuth clients, removed paired systems, reset MFA.
3. If the reason for the restore was a suspected compromise rather than hardware loss, treat
   the restored keys as exposed and rotate the two that can be rotated. A restore from before
   a compromise brings the attacker's access back with the service unless you do this.

   **Never rotate `encryption.key`.** Every TOTP secret, every paired-system token and the
   KyRecovery pairing token are encrypted under it. Remove it and every user's second factor
   and the pairing are gone for good, on a server you just recovered. It sits beside the two
   files below; leave it there.

   File form (the default). Stop the service, remove the signing key and the secret key, and
   start; both are regenerated on start when missing:

   ```bash
   docker compose down
   docker compose run --rm --no-deps --user root --entrypoint sh kyidentity-server \
     -c 'rm /data/jwt_rs256.key /data/secret.key && ls -A /data'
   docker compose up -d
   docker compose logs kyidentity-server | head -20
   ```

   The listing must still show `encryption.key` and `kyidentity.db`. Environment form: if
   `KYIDENTITY_SECRET_KEY` is set, replace its value with `openssl rand -hex 32` written
   straight into `.env`, not echoed, then `docker compose up -d`; the RSA key is always a file.

   What this does: every session and CSRF token is invalid, so everyone signs in again;
   every access and ID token ever issued is invalid; OIDC clients pick up the new signing key
   from the JWKS endpoint on their next fetch, and any that cache it will reject tokens until
   they do. TOTP keeps working, passkeys keep working, and Disaster recovery still shows the
   key pinned. Then re-issue each OAuth client's secret from OAuth clients, and have every
   admin re-enrol their factors. Confirm with a Back up now so the recovered server has a
   capsule that reflects the rotation.

## Afterwards

- Delete the `restored/` directory once the server runs from its own copy, and `old-data/`
  once Step 5 is done. Both are the live directory in the clear, keys included. Files in
  `old-data/` are root-owned after the copy, so `sudo rm -rf old-data`.
- The custodians' cards are unchanged; a restore does not consume them. If a card was
  exposed during the restore (read aloud, photographed, pasted anywhere shared), that is a
  key compromise for the whole suite, not for one server: run a new ceremony.
- Make a backup from the restored server so the newest capsule reflects the recovery.

## Drill it

Run Steps 1 and 2 against the latest capsule on a scratch machine once a quarter, with the
real custodians and their real cards, and then delete the output. The in-app drill proves the
capsule format restores; only this proves the cards do.
