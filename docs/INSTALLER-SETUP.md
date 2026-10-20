# Container-local installer setup

`kyidentity apply-setup` configures an initialized KyIdentity database through the
product binary. It requires container access and exposes no HTTP setup endpoint.
The server must first have run this version's database migrations.

This initial interface supports dedicated administrator and everyday accounts,
confidential OIDC clients, assigned-only access, explicit per-app role/group assignments,
owned directory groups and generic SCIM or signed suite connectors attached to those clients' app identities.
It does not yet implement complete downstream group lifecycle, administrator verification,
existing account migration, or suite-wide enforcement of administrator separation.
These capabilities remain necessary before KyQuickStart can declare the suite ready.

## Native preparation

`apply-setup --stage --file /data/installer/<setup UUID>/setup.json` reads at most 128 KiB
of secret-free `kyidentity.setup/1` JSON from stdin. Use the schema below but omit
`admin.passwordFile`, `everyday.passwordFile`, each client's `secretFile` and each suite
connector's `signingSecretFile`. The product derives them in that UUID-owned directory;
explicit values must match those exact derived paths. The data directory follows the
running container's `KYIDENTITY_DATA_DIR` (default `./data`). The database must already
be initialized; preparation creates no account and runs no migration. `--check` opens
it read-only; apply records preparation ownership and its success audit.

It generates separate 32-byte random values encoded as 43-character base64url files:
`admin.password`, `everyday.password`, `client-<id>.secret` and, for signed suite connectors,
`client-<id>.webhook`. Preparation returns no credentials. Credentials never enter
arguments or workstation state; only the explicit private export below carries them on stdout.
Generic SCIM `tokenFile` must reference a destination-issued protected file outside every
preparation directory; stage and apply refuse any setup credential file, the encryption key
and the database, because the worker sends the token to the connector. Preparation validates that token and requires the existing product
encryption key before any writes when a connector is selected; neither is invented.

The container-owned product data directory must exclude other writers. Its `installer`
child and UUID directory must be private. Existing unsafe/shared directories and nonempty
unclaimed UUID directories are refused and retained. Private, fsynced no-clobber files
publish immutable `intent.json`, generated credentials, `credentials.json` (bundle and
credential digests), then commit the receipt digest to native installer ownership with
a success audit, and publish `setup.json` last. The native receipt survives filesystem
marker loss before account creation. An interrupted initial publication can resume its
retained files; before `intent.json` exists, only leftover `.keyfile-*.tmp` files are
cleared, and any other file still refuses. Once the credential receipt exists, a missing or changed credential is
an error. Native preparation/application ownership prevents replacement even after
all filesystem completion markers are removed. Different intent is refused; planned changes need deliberate
native administration rather than deleting preparation files. Keep these files in backup.

`--stage --check` compares retained intent, files and both receipts without writing
preparation files, accounts or audit rows.
Preparation returns only `kyidentity.setup-preparation/1` and status `created` or `present`.
Clients added after setup use an amendment (see Adding clients later).
Ordinary apply/check at this reserved UUID path also verifies the preparation receipt;
staging success alone does not imply configured accounts, downstream access or backups.
Capabilities include `bundle-preparation`, `target-credentials` and `protected-setup-files`.
KyQuickStart can pass its typed `identity` settings directly over native CLI stdin.
The private export below supports KyQuickStart's explicit Notes transfer selection. Actual
cross-target acceptance, interactive graph composition and printable owner handover remain unfinished. Existing manually supplied bundles outside the reserved path
continue to use the ordinary interface.

## Bundle and credentials

Keep the bundle and credential files inside the container's persistent storage,
owned by the container user, regular files with permissions `0600`. Credential
paths must be clean and absolute. Symlinks in every path component, unsafe parent ownership,
shared files and oversized inputs are refused. Parents belong to root or the container user
and exclude other writers; sticky ancestors are allowed.
Create credentials on the target; do not put them in workstation installation state.
Passwords require 12 to 1024 bytes; client secrets require at least 32 bytes. An optional
single trailing newline is accepted. Credentials are never returned in JSON reports.

## Private client credential export

`apply-setup --file /data/installer/<setup UUID>/setup.json --export-client <exact client ID>`
requires completed native preparation and applied account/client/role/connector ownership.
It inspects SQLite read-only, makes no configuration or audit changes, and refuses any
preparation or native drift. It cannot combine with stage, check or capabilities.
The command inherits the running container's explicit HTTPS `KYIDENTITY_ISSUER_URL`.

Its stdout is a private, at-most-64-KiB `kyidentity.client-credentials/1` JSON frame.
Fields are `setupId`, `issuerUrl`, `clientId`, `redirectUris`, `clientSecret`, optional
`directoryUrl`/`directorySecret`, and `administrator` with the native `subject`, `username`
and exact declared client `role`. The administrator is the account the setup's ownership
row recorded, by ID; export refuses if it no longer has the bundle's username or is not an
active administrator, so a username moved to another account is never exported.
Only the selected client is exported. Account passwords,
other clients' credentials, SCIM tokens, encryption keys and recovery material are excluded.
An administrator binding without an app role grants no downstream administrator authority.

Only a protected installer transport may consume this stdout in memory. Do not run it in
an ordinary terminal, redirect it into workstation state or retain it in logs. Normal
setup reports and preparation responses remain credential-free. The local tests verify
native export scope and read-only behavior. KyQuickStart implements an explicit Notes
transfer selection. Its disposable SSH fixture qualifies private transfer and native TLS
setup; Kubernetes transfer and downstream sign-on acceptance remain unfinished.

Example bundle (replace the identifiers, addresses, URLs and file paths):

```json
{
  "schema": "kyidentity.setup/1",
  "setupId": "271333e2-c221-4601-b249-563b3d828530",
  "admin": {
    "username": "owner-admin",
    "email": "owner-admin@example.com",
    "passwordFile": "/data/installer/owner-admin.password"
  },
  "everyday": {
    "username": "owner",
    "email": "owner@example.com",
    "passwordFile": "/data/installer/owner.password"
  },
  "clients": [{
    "id": "kydrive",
    "name": "KyDrive",
    "secretFile": "/data/installer/kydrive.secret",
    "redirectUris": ["https://drive.example.com/REPLACE-WITH-PRODUCT-CALLBACK"],
    "postLogoutUris": [],
    "administratorRole": "admin",
    "everydayRole": "user"
  }]
}
```

Use the product's actual documented callback path. Redirect and post-logout URIs must be
HTTPS; credentials and fragments are refused. Custom app schemes (`myapp://callback`) are
refused here and by native client registration, so a mobile app needs its HTTPS redirect.
Preserve `setupId` on reruns.

Clients default to `"clientType":"confidential"` for compatibility. Set
`"clientType":"public"` for a public PKCE client and omit `secretFile`; staging
creates no OAuth secret and private credential export is refused for that client.
S256 PKCE remains required for every client. Optional `backchannelLogoutUri` is an
exact HTTPS endpoint without credentials or fragments. Both values participate in
ownership and read-only drift checks; changing an already-owned client requires
native management, never silent installer replacement.

Role fields name the exact roles the product understands; they do not use the directory's
global administrator role. Native OIDC issues only this app's `roles` claim.

| Administrator role | Everyday role | Initial access |
|---|---|---|
| omitted | omitted | Everyday only, no app role; preserves the initial ordinary-client contract |
| omitted | specified | Everyday only with that role |
| specified | omitted | Administrator only with that role; everyday issuance is denied |
| specified | specified | Each identity has its own distinct role and assignment |

Names use the native app-role grammar, at most 64 characters; owner and everyday roles
must differ ignoring case. Validate the product's administrator grant and ordinary-workflow
separation before treating a dual-role client as ready. A claim alone is not that proof.
Changing an existing client's declared roles requires a deliberate migration; reruns refuse
changed intent, foreign roles, extra role holders or altered access policies.

The optional top-level `groups` creates at most 32 owned initial groups. Each group has
`name` (1-64 ASCII letters/digits, spaces, underscores, dots or hyphens; starts alphanumeric),
optional `description` (at most 1024 bytes) and `members` (empty, or the exact owned everyday
username). Names are unique ignoring case. Dedicated administrators and foreign accounts
cannot be initial ordinary members. For example:

```json
"groups": [{"name":"Suite users","members":["owner"]}]
```

A client's optional `groups:["Suite users"]` assigns those exact bundle-owned groups and
enables its app-scoped `groups` claim. Management-only clients cannot grant these groups.
Membership and assignment creation use native policy/revocation/provisioning hooks, with
atomic ownership and audits. Foreign groups, changed definitions, extra/missing/expiring
memberships and altered app group grants are refused on inspection/resume; setup never
overwrites these later administrator changes. Native group MFA policy changes are preserved.
Group/member lifecycle after initial setup belongs to native administration; deliberate
changes require reconciling the retained setup intent before rerunning it.

An optional per-client `scim` object adds its generic provisioning connection:

```json
{"url":"https://bridge.example.com/scim/v2/bookstack","tokenFile":"/data/installer/bookstack-scim.token"}
```

The URL is the receiver's actual SCIM base, verified HTTPS with no credentials, query or
fragment. The token file follows the protected credential boundary; its token contains
32 to 8192 visible ASCII bytes without spaces, with one optional trailing newline.
The existing `KYIDENTITY_ENCRYPTION_KEY` or protected `encryption.key` under
`KYIDENTITY_DATA_DIR` encrypts it at rest, bound to its connector ID. Setup and inspection
never generate that key, and do not re-encrypt legacy secrets: after an upgrade, start the
server once before rerunning setup over an existing connector.
Container commands must inherit the running product's key/data configuration; `--db`
does not select an alternative encryption key.

Connector ownership binds the stable app identity, endpoint and credential digest. The new
connector joins the app's existing roles and assignments in the creation transaction; the
ordinary administrator linking rules for unrelated existing apps remain unchanged.
It can be added on a later setup pass with the same setup UUID and client intent, after
the product account bindings and SCIM receiver are ready. Omitting `scim` leaves a retained
connector untouched; removal, token rotation and endpoint changes require deliberate native
administration. No foreign connector is adopted. SCIM `groups:true` explicitly enables
native group delivery and requires assigned bundle groups; omitted/false keeps it off.
Qualify the receiver's Groups support before enabling it: revocation-only bridges do not
implement group provisioning. Scheduled reconciliation remains off. A restored provisioning
hold is refused, never cleared.

The native worker reads committed connectors without restarting. Its existing desired-state,
retry and uncertain-delivery protections apply; initial work covers only users with effective
access to the linked app and carries its app-specific roles. Assignment loss or expiry,
account disablement, account end date and deletion send deactivation while preserving
downstream data. This interface
configures delivery; it does not deploy a receiver or prove that receiver revokes access.

## Signed suite directory connectors

A client can declare `suiteWebhook` instead of `scim`. It uses the suite's signed, bare
SCIM user-body protocol, not a Bearer-token SCIM server. Require capability
`suite-webhook-connectors`; use the exact endpoint in the product's setup runbook:

```json
"suiteWebhook": {
  "url": "https://notes.example.com/api/v1/sync/events",
  "signingSecretFile": "/data/installer/notes.directory-secret"
}
```

Generate a random signing secret once on the target. The file must be private and owned
by the container user; final symlinks and shared files are refused. Use 32–1024 visible
ASCII bytes without spaces, with an optional trailing newline; 32 random bytes encoded
as hex is suitable. Deliver the same bytes into the product's protected target-local
directory secret file and reference it through that product's native setup bundle. Keep
these credentials out of workstation state. Setup encrypts the source credential with
the existing product key and never returns it in a report or creates a replacement key.

Each client has at most one connector. Signed suite connectors use native type
`suite_webhook`, carry only that OIDC app's assigned users and roles, and do not deliver
groups. Their receipt binds app identity, protocol, endpoint and secret digest. Add one
on a later pass with the same setup ID and client intent. Omission preserves it; protocol
switches, endpoint/secret changes, foreign connections and restored holds require
deliberate native administration. Check/resume refuses them without repairs. HTTPS URLs
have no credentials, query or fragment; ordinary worker network/redirect protections apply.
Creation/link audits and initial desired-state work share the account/client transaction.
Existing generic SCIM receipts and bundle behavior remain compatible.

The opt-in real KyNotes worker fixture now qualifies this setup-owned app/connector
linkage, exact-role delivery and downstream native session/device revocation on disposable
state (KyNotes `docs/SSO.md`). It does not prove full OAuth issuance or installer secret
transfer between separate targets. Those remain full-stack acceptance gates.

## Adding clients later

Setup intent is immutable, so a product installed after the first setup comes in an
amendment: a new bundle with its own `setupId` and `"extends": "<parent setupId>"`. Require
capability `setup-amendments`. An amendment has no `admin`, `everyday` or top-level `groups`
block and at least one client. A client's `groups` names groups the parent owns, exactly.

```json
{
  "schema": "kyidentity.setup/1",
  "setupId": "9b0c6d1e-5f43-4c1a-8f0e-2d7a6b3c4e51",
  "extends": "271333e2-c221-4601-b249-563b3d828530",
  "clients": [{
    "id": "kyrecovery",
    "name": "KyRecovery",
    "redirectUris": ["https://recovery.example.com/REPLACE-WITH-PRODUCT-CALLBACK"],
    "administratorRole": "admin",
    "suiteWebhook": {"url": "https://recovery.example.com/REPLACE-WITH-SYNC-ENDPOINT"}
  }]
}
```

Prepare it like any bundle, at `/data/installer/<amendment setupId>/setup.json`. Preparation
refuses a parent with no native ownership and generates only `client-<id>.secret` and
`client-<id>.webhook`; intent and credential receipt are immutable as before.

Apply reads the parent's owned administrator and everyday accounts (and the named groups)
from native ownership and runs the parent's account and group inspection first: present,
active, unchanged, no end date or delegation. Any drift refuses the whole amendment.
Assignments and roles bind to those accounts, as in the parent. An amendment never creates
or changes an account or group. Any client ID already in the database is refused, whether
foreign or owned by another setup; rerunning the same amendment is a no-op. Clients, roles
and connectors are owned by the amendment ID and each client receipt records the parent ID.
Everything commits in one transaction with the usual audits, which also carry `extends`.

`--check` on the amendment inspects the parent's accounts and its own clients, roles and
connectors. The parent's `--check` is unchanged and does not look at amendments.
`--export-client` at the amendment's path exports only that amendment's clients, bound to
the parent's administrator. Amendments do not chain: the parent must be an initial setup.
Changing or removing a client added this way still needs native administration.

## Run and verify

```sh
kyidentity apply-setup --capabilities
kyidentity apply-setup --file /data/installer/bundle.json
kyidentity apply-setup --file /data/installer/bundle.json --check
```

With the stock compose file, run these inside the running container from the compose
directory. `-T` keeps stdin a plain pipe, which `--stage` reads:

```sh
docker compose exec -T kyidentity-server /usr/local/bin/kyidentity apply-setup \
  --stage --file /data/installer/<setup UUID>/setup.json < setup.json
docker compose exec -T kyidentity-server /usr/local/bin/kyidentity apply-setup \
  --file /data/installer/<setup UUID>/setup.json
docker compose exec -T kyidentity-server /usr/local/bin/kyidentity apply-setup \
  --file /data/installer/<setup UUID>/setup.json --check
```

The database path follows `KYIDENTITY_DB_PATH`, otherwise `KYIDENTITY_DATA_DIR`
(default `./data`), preferring the existing legacy `kysignon.db` when appropriate.
`--db` is available for local fixtures and explicit container layouts. A missing
database is refused rather than creating an unrelated empty identity service.

Creation, installer ownership and success audits commit in one transaction. Each
account, group, membership, client, role, initial assignment and connector creation/link has an audit event.
Connector creation uses the native credential-change event/alert with its actual protocol. Failure rolls back the
whole bundle. Existing objects without this setup's ownership are refused. A
changed owned object is refused rather than repaired. Password changes on owned
accounts are preserved; OIDC client-secret changes require a separate deliberate
migration. Deleting an owned object does not permit automatic recreation or adoption.

`--check` opens SQLite in read-only mode, performs no migrations or reconciliation,
and checks ownership, account state, group definitions/memberships, client configuration, exact role mappings, assignments
and declared connector linkage/configuration/decryptable credential. It does not probe a target.
Ordinary-only clients refuse administrator access; management-only clients refuse everyday
access. Inspection never repairs changed role mappings or claims.
It verifies stored configuration; it does not prove a downstream application's
administrator authorization, browser sign-on or offboarding behavior.

## Retiring the bootstrap administrator

An installer that started KyIdentity with `BOOTSTRAP_ADMIN_USER` is left with that account
after setup creates the owner's administrator. Retire it from inside the container, without
a step-up grant, once `--check` has passed (requires the `disable-user` capability):

```sh
kyidentity disable-user --username kyq-bootstrap --require-active-admin <owner admin>
```

It disables only that account, through the same transaction as an administrator's disable:
sessions, tokens and app access are revoked, connectors receive the inactive state, and an
`admin.user_updated` audit row (actor `kyidentity-cli`, `via: cli`) commits with it. Role and
password are untouched. It refuses unless `--require-active-admin` names a different active
administrator with no end date. An already-disabled account answers `unchanged` and writes
nothing, but only when nothing could revive it: an upstream (SCIM) account needs its local
override set, and a pending invitation must have no live activation link. Otherwise the
override is recorded or the link expired, with the same revocation and audit. `<data>/first-run-password.txt` is removed when it names the disabled account. The
only output is `{"schema":"kyidentity.disable-user/1","username":"…","status":"disabled|unchanged"}`;
refusals exit non-zero with nothing on stdout. It works while the server runs.

## Resyncing after a downstream restore

When an app restores its own backup, it may again hold accounts that KyIdentity has since
disabled, unassigned or deleted. Replay the current directory state to it from inside the
container, without a step-up grant (requires the `resync-system` capability):

```sh
kyidentity resync-system --client <client id> [--wait <duration, max 24h>]
```

It resyncs the connector that shares an app with that OAuth client, the same as **Resync**
in the admin UI: held accounts are re-sent, and every account the connector ever held that
is now removed is deactivated again (never deleted). An `admin.system_resynced` audit row
(actor `kyidentity-cli`, `via: cli`) commits with the queued work. Repeating it is safe.
The running server delivers; without `--wait` the command returns once the work is queued.
With `--wait` it returns when the connector's outbox is empty, or earlier on a failure.

The only output is one line:
`{"schema":"kyidentity.resync-system/1","clientId":"…","systemId":"…","status":"…","pending":N,"failed":N,"blocked":"…"}`.

| status | exit | meaning |
|---|---|---|
| `queued` | 0 | no `--wait`; `pending` is the connector's queued work |
| `delivered` | 0 | every queued event for the connector was acknowledged |
| `failed` | 1 | `failed` events exhausted their retries or have an uncertain remote write; an operator must resolve them under the connector's delivery attempts |
| `blocked` | 1 | the worker will not deliver: `blocked` is `disabled`, `held` (restore hold) or `unsupported` (connector type needs review) |
| `timeout` | 1 | `pending` work remained at the deadline; it stays queued |

`pending` and `failed` count every outbox event for the connector, not only this resync's.
A client without a connector, or bad arguments, exits 1 with nothing on stdout.
