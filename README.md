# KySignOn Server

KySignOn Server is the single-organization Single Sign-On (SSO) identity provider and central user directory for the **KySecurity Suite** (KyPost, KyPasswords, KyBookmarks, KyNotes).

Built in Go with a focus on simplicity, minimal external dependencies, and native platform standards, KySignOn serves as the authoritative source of truth for accounts, OpenID Connect authentication, and mutual system replication.

---

## Core Capabilities

1. **Authoritative User Directory & Real-Time Sync**: Create, manage, and deactivate accounts from a unified portal. Changes automatically propagate to paired KySecurity downstream products via HMAC-SHA256 signed sync webhooks.
2. **OpenID Connect & OAuth 2.0 Provider**: RFC-compliant authorization code flow with PKCE (`S256`), dynamic JWKS key discovery (`/.well-known/jwks.json`), and RS256 token signing.
3. **Multi-Factor Authentication (MFA)**:
   - **TOTP Authenticator Apps**: Standard RFC 6238 time-based one-time passwords with encrypted secrets at rest (AES-256-GCM).
   - **Push Authentication with Number Matching**: 2-digit verification challenges with decoy numbers for mobile pairing.
   - **Passkeys (WebAuthn)**: ES256 platform and roaming authenticators as a second factor, verified with the standard library alone. Works with KyAuth's Android credential provider, and with iCloud Keychain, Windows Hello and hardware keys.
   - **Emergency Recovery Codes**: Cryptographically hashed single-use recovery codes.
4. **90-Second Ephemeral Pairing**: Frictionless UI-based pairing with QR codes and short PINs for native mobile devices and downstream server applications.
5. **KySecurity Suite Application Launcher**: Single-pane dashboard themed in KySecurity Patina (dark `#0d0f14`, cyan `#4deeea`, Space Grotesk, IBM Plex Mono) embedding the full React frontend into the standalone binary.

---

## Architecture & Standard Library Philosophy

Following the **Ponytail** engineering philosophy (*use the smallest correct change, prefer native platform APIs, minimize external bloat*), **over 95% of the Go backend is built exclusively using the Go Standard Library (`stdlib`)**.

```
                           ┌───────────────────────────────┐
                           │      React Web Frontend       │
                           │  (Embedded via Go embed/fs)   │
                           └───────────────┬───────────────┘
                                           │
                                           ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             KySignOn Server (Go)                                 │
├──────────────────┬───────────────────┬─────────────────────┬─────────────────────┤
│   HTTP Routing   │   OIDC / OAuth    │     MFA & TOTP      │    Sync Engine      │
│  (net/http 1.22) │ (crypto/rsa, jwks)│ (crypto/hmac, sha1) │ (net/http, sha256)  │
├──────────────────┴───────────────────┴─────────────────────┴─────────────────────┤
│                          SQLite Database Engine                                  │
│             (database/sql abstraction + modernc.org/sqlite)                      │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### Standard Library Implementations

| Subsystem | Standard Library Components Used | Avoided External Dependencies |
| :--- | :--- | :--- |
| **HTTP Routing & API** | `net/http` (Go 1.22+ pattern routing), `context`, `net` | *No Gin, Fiber, Chi, or Gorilla Mux* |
| **OIDC, OAuth 2.0 & JWT** | `crypto/rsa`, `crypto/sha256`, `encoding/base64`, `encoding/json` | *No `golang-jwt`, `go-jose`, or `ory`* |
| **TOTP / 2FA Engine** | `crypto/hmac`, `crypto/sha1`, `encoding/base32`, `encoding/binary` | *No third-party TOTP libraries* |
| **At-Rest Encryption** | `crypto/aes` + `crypto/cipher` (AES-256-GCM) | *No third-party encryption packages* |
| **Sync Webhooks** | `net/http` client + `crypto/hmac` + `crypto/sha256` | *No webhook frameworks* |
| **Embedded Frontend** | `embed` + `io/fs` (React SPA served from binary memory) | *No packr or go-bindata* |
| **Database Access** | `database/sql` | *No GORM, Ent, or ORM frameworks* |

### Direct Dependencies

KySignOn relies on only **3 direct external packages**:
- **`modernc.org/sqlite`**: Pure-Go SQLite engine allowing zero-CGO static compilation (`CGO_ENABLED=0`) on Alpine Linux.
- **`golang.org/x/crypto`**: Official Go extended crypto library for secure `bcrypt` password hashing.
- **`github.com/google/uuid`**: RFC 4122 UUID generator.

---

## Quickstart with Docker Compose

### 1. Configure Environment
Clone the repository and copy the sample configuration:
```bash
[ -e .env ] || (umask 077; cp .env.example .env); chmod 600 .env   # an existing .env is kept; it holds secrets
```

Review and adjust variables in `.env`:
```ini
# Interface binding (127.0.0.1 for local/proxy only, or 0.0.0.0 if not using proxy)
KYSIGNON_BIND=127.0.0.1

# Static container IP on shared kypost-net network
KYSIGNON_IP=10.89.0.2

# Public URL used in issued tokens (use your public HTTPS domain in production)
KYSIGNON_ISSUER_URL=https://auth.yourdomain.com

# Optional: Pre-seed administrator credentials
BOOTSTRAP_ADMIN_USER=admin
BOOTSTRAP_ADMIN_PASS=YourSecurePassword123!

# Optional: Cloudflare Worker native-push relays
PUSH_RELAY_URL=https://kysecurity-mobile-push-fcm.<account>.workers.dev
APNS_RELAY_URL=https://kysecurity-mobile-push-apns.<account>.workers.dev
```

### 2. Start the Server
Published image:

```bash
docker compose up -d
```

Source install (never paste this into a published-image install: the build overlay wins over a
`KYSIGNON_IMAGE` digest pin, and a source install must set this line before its first `up -d` on a
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

A digest-pinned install (`KYSIGNON_IMAGE` in `.env`) gets nothing from `pull`: re-run the pin recipe in
`docker-compose.yml` with the commit sha you want first, or delete that line to follow `:latest` again.

### 3. Retrieve Credentials & Log In
If you did not define `BOOTSTRAP_ADMIN_PASS` in `.env`, KySignOn generates a one-time bootstrap password on first start:

```bash
docker compose exec kysignon cat /data/first-run-password.txt
```

Open your browser and navigate to:
```text
http://<YOUR_SERVER_IP>:5867
```
Sign in with `admin` and the retrieved password.

---

## Health & Status Verification

You can verify the status of the server at any time:

* **Liveness** (is the process running):
  ```bash
  curl http://localhost:5867/healthz
  # Response: {"status":"alive"}
  ```
* **Readiness** (can this instance actually authenticate someone). Point your load balancer
  at this one. It runs a bounded database read and confirms the signing and encryption keys
  are loaded, and returns `503` when they are not. `/healthz` deliberately proves none of
  that; a process that can encode JSON while its database is gone is still down.
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

Create the first admin account directly within the running container:
```bash
docker compose exec kysignon /usr/local/bin/kysignon bootstrap-admin --username admin --password "NewPassword123!"
```

`bootstrap-admin` only creates a missing account. It will not overwrite the password of an
account that already exists — change those from the admin UI, so the action is audited.

Restoring from a `.kycap` backup is `kysignon restore`, with k custodian shares typed on
stdin. The full procedure, including putting the result back into service and proving it,
is [docs/RESTORE.md](docs/RESTORE.md).

---

## Onboarding and passwords

**Inviting.** Creating a user without a password invites them: the account is pending
and disabled, holds no credential at all, and cannot sign in, be provisioned or hold app
access until an activation link sets a password. Users → the link button issues the
link (step-up required); it is shown once for hand-over, or mailed when mail delivery is
configured. Activation links last 24 hours, reset links 30 minutes, and a new link of
the same kind retires the previous one. Only the token's hash is stored, and the raw
link never appears in the audit log. A link is only redeemable while the account is
still in the state it was issued for, and every link dies when access is revoked: to
cancel an invitation, use the account's Revoke Sessions action (or delete it); setting a
password on a pending account also retires its activation link. Opening a link only shows the form; submitting it
spends the token and sets the password in one transaction, so a mail scanner that
follows the link changes nothing. Activation makes the account active and, when the link
was mailed, records the address as verified; the first sign-in then goes through any
required factor enrollment before app access. An administrator setting a password on a
pending account is the manual activation; flipping its status alone is refused.

**Passwords.** Security and devices → Password changes your own password after a
step-up; every other session, token and app grant ends, this browser stays signed in.
"Forgot your password?" on the sign-in page always answers the same way whether or not
the account exists or mail is configured, is limited per address and per account, and
mails a 30-minute reset link when it can. Redeeming a reset link signs the account out
everywhere and clears the lockout counter; it never removes a second factor. Losing a
factor is a recovery-code sign-in or an administrator MFA reset, not a password reset.

**Email verification.** `email_verified` in ID tokens and userinfo is true only after a
link mailed to the address was redeemed; existing addresses start unverified. Changing
an address clears verification and retires every outstanding link.

**Mail delivery.** Administration → Mail delivery holds one SMTP relay (host, port,
STARTTLS or implicit TLS, sender, optional credentials). The password is stored
encrypted with the deployment key and is never returned; a blank password keeps the
stored one only while host, port, username and transport are unchanged, so the stored
credential can never be pointed at a different relay, and a blank host turns delivery
off. "Send test to me" mails the signed-in
administrator and audits the outcome. Cleartext SMTP is not offered: a relay without
STARTTLS is refused before any credential is sent. Without mail delivery every link is
handed over by an administrator and self-service reset is unavailable.

## Directory groups

Administrators can create, rename and delete groups under **Groups**, manage each group's
members, or open membership controls from a row in **Users**. Names are trimmed and unique
under the directory's SQLite `NOCASE` collation; renaming preserves the group's stable ID.
Membership does not change the user's global role. Group assignments grant app access;
SCIM Groups delivery is available per generic SCIM connector; see Outbound provisioning.

Group and membership mutations require a single-use step-up grant for their exact method
and path and commit with their audit event. Repeated add/remove requests are idempotent;
each accepted request is audited. Deleting a group or user removes its membership rows.

| Method and path | Purpose |
| --- | --- |
| `GET /api/admin/groups` | List groups; optional `userId` annotates each group's `member` flag for that user. |
| `POST /api/admin/groups` | Create a group from `name` and `description`. |
| `PUT /api/admin/groups/{id}` | Replace the name and description. |
| `DELETE /api/admin/groups/{id}` | Delete the group and its memberships. |
| `GET /api/admin/groups/{id}/members` | List members; `includeNonMembers=true` includes candidates to add. |
| `PUT /api/admin/groups/{id}/members/{userId}` | Ensure the user is a member. |
| `DELETE /api/admin/groups/{id}/members/{userId}` | Ensure the user is not a member. |

Both list endpoints accept `limit` (1–100, default 25), `offset` (0–1,000,000, default 0),
and `q` (up to 200 characters). Group search matches names; member search matches username,
display name or email. Responses include `total`, `limit`, and `offset`, with results under
`groups` or `users`. Counts and results share a database snapshot. Membership and deletion
audits retain the group name and, for membership changes, the username captured in the
mutation transaction. Names allow 1–128 characters, rejecting control/format marks,
private-use characters, and whitespace other than ordinary spaces. Descriptions allow up
to 2048 characters without Unicode format marks. All routes require an active administrator;
member lists expose only public directory fields.

## App connections

Administrators can use **App connections** to associate an OAuth client, launcher card,
and provisioning system that belong to the same application. Review the connection names
and IDs, then confirm the link with step-up authentication. **Unlink** separates one
connection again. Each app has at most one connection of each type; overlapping types and
stale selections are rejected. Linking/unlinking commits with its audit record. Linking requires matching access and authentication settings
and no assignments on either app; unlinking copies both policies and assignments.

Existing connections initially receive separate stable app IDs, even when their names or
URLs match. Linking retains the selected app ID and all original connection IDs, client
secrets, callback URLs, launcher cards and sync settings. New connections automatically
receive their own app ID. Deleting a connection removes its reference; the app ID survives
while another connection remains. Connection settings stay in their existing admin views.

Use **Manage access** to assign users or groups and preview effective access. Existing
apps migrate to explicit **All active users** access. New apps default to **Assigned users
only**, with no grants. Direct and group assignments combine by union; removing one grant
preserves access while another applies. Administrators need assignments too. Disabled
users, disabled apps, and disabled linked OAuth clients cannot sign in. Use **Manage
launcher cards** to edit cards independently of your own app entitlements.

Policy changes show how many users would lose access across the directory, even when the
list is filtered. The preview reflects current membership; edits use app revisions to
reject stale settings. Mutations require operation-bound step-up and atomic audit records.
Launcher-only access controls visibility, not authorization at the destination website.
Provisioning follows effective access; see Outbound provisioning, Provisioning scope.

OAuth authorization and token exchange both enforce current access. Losing effective
access revokes online tokens and invalidates authorization codes in the same transaction.
Token registration rechecks access and the originating code atomically, including during
membership-removal races. Re-granting access cannot revive invalidated codes or tokens.
Offline JWT consumers may accept old access tokens for up to 15 minutes, and an app's own
session lasts until it asks KySignOn to sign out or receives the back-channel logout
described below; an app with no back-channel receiver is never told.

Admin API: `GET /api/admin/app-registry` accepts the same pagination bounds as group lists
and searches connection names and IDs. `POST /api/admin/app-registry/{id}/link` accepts
`sourceId`, `targetRevision`, and `sourceRevision`; the target app ID is retained.
`POST /api/admin/app-registry/{id}/unlink` accepts `kind` (`client`, `launcher`, or `system`)
and `revision`, returning the new app ID. Both mutations require operation-bound step-up.
A `409` means the selection is stale or its access settings/assignments prevent linking.
Reload before choosing again.

Access API: `GET /api/admin/app-registry/{id}/access-users` returns paginated users,
current/preview access, the current app revision and an unfiltered `losingAccess` count.
Optional `mode` (`assigned_only` or `all_active_users`) and `enabled` preview policy changes.
`GET /api/admin/app-registry/{id}/access-groups` lists groups and assignment state.
Both accept the same pagination bounds as group lists. `PUT .../{id}/access-policy`
requires `mode`, `enabled`, and `revision`. `PUT`/`DELETE
/api/admin/app-registry/{id}/assignments/{kind}/{principal}` adds/removes an individual
assignment (`kind` is `users` or `groups`). Duplicate assignments are idempotent.

## App roles and token claims

**Roles.** App connections → Roles defines the fixed role names an app understands
(letters, digits, `_`, `.`, `:`, `-`) and maps groups or users to them. A token for the
app carries exactly the roles the user holds there, sorted, under the `roles` claim,
and nothing about any other app; an app with no roles gets an empty list. Unassigned
apps issue no token at all, so they receive no claims. Any role, mapping or claim
setting change revokes the affected users' live tokens and pending codes for that app,
bumps the app's role revision so a code issued before the change cannot be exchanged
after it, and re-sends the users' profiles to the app's provisioning connection with
the new roles (a connection whose app defines roles receives those instead of the
global directory role).

**Claims by scope.** `profile` grants `preferred_username`, `username` and `name`;
`email` grants `email` and `email_verified`; `openid` always grants `sub`, `sid`, the
authentication claims and `roles`. The ID token and UserInfo apply the same rules to the
same granted scope, so neither can widen the other. Allowed scopes on a client are drawn
from `openid`, `profile` and `email`; an unknown scope is refused at registration, not
silently accepted. If the roles and groups mapped for a user do not fit in a token
(4 KiB of identity claims), the token request fails with `invalid_request` naming the
counts rather than truncating a permission set.

**Upgrade note.** Before this release every ID token and UserInfo answer carried the
name and email claims regardless of scope. A relying party that requests only `openid`
must now also request `profile` and `email` to keep receiving them; there is no switch
for this, because emitting claims a client did not ask for is the defect being fixed.
Group membership changes, including deletion of a mapped group and changes arriving
over inbound SCIM, count as role changes for every app that maps the group, and a
provisioned account whose roles are revoked receives an explicit empty `roles` list. An
app's first role, and its last one going, re-send every account provisioned through its
connection, since the whole role set changes shape at that point.

**Per-app switches.** *Legacy global role claim* keeps the directory-wide `role`
(`user` or `admin`) in the app's tokens; apps that existed before app roles keep it on,
new apps start with it off, and it should be turned off for each app once that app reads
`roles`. *Groups claim* adds a `groups` claim listing the app's assigned or role-mapped
groups the user belongs to, never the user's other groups. Both are per app; flipping
either revokes every live grant for the app so the token shape changes cleanly.

## Delegated administration

Global administrators (`role: admin`) hold every permission and are the only ones who
can delegate. Users → the delegation button on a user sets fixed, narrow permissions
for an ordinary account; each is read on every request, so removing one takes effect
on that user's next call without waiting for their session to end.

| Delegation | May | May not |
|---|---|---|
| Helpdesk | List users and groups; view a user's sessions and offboarding status; reset MFA, revoke sessions and app grants, retry logouts, issue activation and reset links, for ordinary users | Touch an administrator's or another delegate's account in any of those ways; create, edit or delete users; assign privileges |
| Auditor | Read every administration page: users, groups, app connections, provisioning, connectors, clients, policies, mail settings, backup status, audit log | Change anything, including step-up protected writes and the recovery capsule export |
| App owner (per app) | List users and groups to pick principals; see the owned app's access, roles and access explanations; assign users and groups to the app; create and delete its roles and map principals to them; decide access requests for the app | See or touch any other app; change the app's access mode, authentication policy, claim switches, links, OAuth credentials or provisioning connection |

Everyone holding a delegation falls under the *administrators* MFA enrollment policy
from the moment it is granted: a required policy restricts their session until they
enrol, and a user who cannot satisfy it cannot be delegated to. Nobody but a global
administrator can change delegations, global MFA policy, connector secrets, mail
settings, recovery material or OAuth credentials. Writes keep their step-up
requirement and audit row (`admin.delegations_updated` records each change). Ownership
names an app record; unlinking a connection into a new record ends ownership of it, so
re-delegate after an unlink. The `GET /api/auth/me` answer carries an `access` block
the SPA uses to show the pages a delegate can use; the server enforces every route.

## Expiring access and account end dates

A direct user assignment on an app connection and a membership in a group can each
carry an expiry instant; an account can carry an end date. The operator enters a
wall-clock time in their own zone and the page shows the exact UTC instant beside it,
so a DST edge or a wrong zone is visible before it bites. Instants must lie in the
future; repeating the grant moves or clears its instant.

Expiry is decided where access is decided: the access views exclude an expired grant
and an ended account on every authorize, token exchange, UserInfo and provisioning
decision, so it holds even with no background work running. Access is a union, so an
expired grant changes nothing while another live grant remains, and a token issued on
bounded access ends with that access (`expires_in` and the ID token `exp` stop at the
latest live grant, capped by the account end date).

The expiry follow-up runs at start and once a minute: it removes expired assignments and
memberships (roles mapped through the group end, MFA policy requirements lift), revokes
the tokens and codes that depended on them, sends back-channel logout to the apps that
saw those logins, deactivates the downstream accounts, and ends accounts past their end
date (disabled, not deleted; sessions and grants revoked; profile deprovisioned). Every
removal writes an audit row with actor `expiry`. Each item commits on its own: one row
the follow-up cannot process is audited as a `*_failed` row with outcome `failure`,
returned to the log, and retried next minute, while everything else due still lands.
The rows themselves are the persisted due work, so a restart drains overdue expiries
first and an instant extended before the follow-up runs is simply not due. The last
active administrator, counted as an administrator whose end date has not passed, can
neither be scheduled to end nor ended by the follow-up: the schedule is refused with
`cannot_remove_last_admin`, and an end date that would remove the last administrator is
cleared and audited as `account.end_refused`. Over the API, omitting `endsAt` keeps the
current schedule; an empty string clears it.

## Access requests and approvals

An administrator opens an assigned-only app to requests with *Users may request access*
on its access page. A user who lacks access then sees the app under *Request access* on
their dashboard, states a reason and picks a duration (none, 1, 7, 30 or 90 days);
apps that are not open to requests are never named, whether by listing or by guessed
ID. One pending request per app, at most five pending per user, ten filings per
minute, and a request nobody answers expires after fourteen days.

Owners of the app and global administrators see the request in *Access requests*; a
delegate's inbox holds only their apps. Approving or denying spends a step-up grant and
writes an audit row. An approval is an ordinary direct assignment with the requested
expiry, written through the same path a manual grant takes, so there is no second way
to hold access and everything in "Expiring access" applies to it. The decision re-reads
the approver's current authority, the app's policy and the request's state under the
write lock: a requester cannot approve their own request, a request is decided once,
an owner whose delegation was withdrawn cannot approve from a stale form, an app closed
to requests in the meantime cannot be approved, and a request withdrawn or expired
before the click grants nothing. The requester is told by mail when delivery is
configured.

## Explaining access decisions

*Explain* on a user's row of an app's access page shows why that user can or cannot
open the app, read from the same rows that decide it: the verdict and reason, every
direct and group grant with its expiry and whether it is still live (an upstream-managed
membership is marked), the app roles held and through which group, when access ends,
the account's status and end date, the app's authentication policy, and the access,
authentication and role revisions. The reason words are the ones the listing uses
(`user_disabled`, `account_ended`, `app_disabled`, `client_disabled`,
`all_active_users`, `direct_assignment`, `group_assignment`, `not_assigned`,
`grants_expired`), so the two never disagree. The access page's policy preview still
shows who would lose or gain access under a proposed policy without changing it.

Explanations follow viewer permissions: administrators and auditors may explain any app,
an app owner only their apps, and the answer names only groups assigned to that app,
which the same viewers already see. A user can ask `GET
/api/user/access-explanation?clientId=…` about themselves, ten times a minute, and gets
the verdict and whether the app is requestable; every denial reads the same
(`no_access`) whatever its cause, a client that does not exist reads like a denial,
and the app is named only when they have access or may request it, so the answer
discloses nothing an authorize attempt would not. A denied
authorization is audited with the reason and the access, authentication and role
revisions of that moment, so an old denial is never explained with today's policy, and
the redirect tells a user of a requestable app to ask from their dashboard.

## Audit search and export

The audit log page filters by actor (id or username), target id, action prefix (for
example `oauth.` covers every OAuth event), outcome and a time range entered in the
operator's zone. Filters are bounded, indexed, and paged in a total order (time, then
id), so paging never repeats or skips a row under tied timestamps. *Export CSV* and
*Export JSONL* carry the same filter as the page, over `GET
/api/admin/audit-events/export?format=csv|jsonl&…`, at most 50,000 rows and 30 seconds
per export (response headers `X-KySignOn-Export-Total`, `-Limit` and `-Truncated` say
when a filter exceeded the bound), with a burst of five exports refilling at about six a
minute per address and sixty listing calls a minute. An export that stopped short of the
filtered set, whether by the row bound, the deadline or a failed write, ends with an
in-band marker (`_export: incomplete` with the reason and row counts) so a downloaded
file is never mistaken for a complete one. Each export is recorded before the first
byte leaves (`admin.audit_export_started`; if that row cannot be written the export is
refused) and again when it ends (`admin.audit_exported` with the outcome and row count). Details whose keys look like
credential material (`secret`, `token`, `password`, `hash`, `credential`, `private`) are
redacted at any depth, CSV cells that start with `=`, `+`, `-`, `@`, tab or carriage
return are prefixed with a quote so no spreadsheet treats them as formulas, and the
recorded rows carry the filter and row count. Administrators
and auditors may search and export; nobody else. Retention is unchanged: rows older
than the configured cutoff are trimmed by the existing housekeeping, and any change to
that period is a separate decision, not part of search or export. For external log
collection use the structured process log; there is no second audit delivery path.

## Alerts

The alerts page turns the audit trail and connector state into a short list an
administrator or auditor can act on: privilege changes (an account made or unmade an
administrator, delegations changed), recovery use (a recovery code consumed, a second
factor reset by an administrator, a password reset link redeemed), connector credential
changes (inbound SCIM tokens issued or revoked, an outbound connector created or its
bearer token rotated, the mail relay changed), repeated login failures for one account
or, when the name matches no account, from one address (threshold and window
configurable, default ten in ten minutes; a submitted name never becomes an alert of
its own, past ten live login alerts further sources share a single "many sources"
alert, a login alert whose source has been quiet for a whole window resolves itself
without mail, and login-failure mail is one mailing per four hours however many
sources appear, so an attacker cycling names or addresses cannot flood the inbox, the
mail or the table),
failed or refused scheduled access removal, and outages (a connector whose deliveries are failing
or given up, a client whose back-channel logouts were given up). Every audit insert
queues its id through a trigger, the evaluator writes alerts and drains the queue in one
transaction, and a worker goroutine of its own runs it every few seconds with a bounded
pass, so a crash can repeat work but never skip a trigger, a stuck relay never delays
provisioning or expiry follow-up, and history recorded before this version is not
re-alerted.
Repeats fold into one open alert per rule and subject with a count; an acknowledged
alert reopens on the next occurrence rather than hiding it; an outage stays one alert
for its whole duration, resolves itself when deliveries succeed again, and a later
failure opens a fresh one. Alert text names the account, connector or app and nothing
else: the audit details behind it, and any recovery code or credential, never reach the
alert, the mail or the page. Recipients (`PUT /api/admin/alerts/settings`, administrators
with step-up, usernames on the wire) must be administrators or auditors when configured
and are checked again before each message; anyone who has since lost that access is
skipped and the skip is shown. Mail goes through the existing relay when one is
configured, with growing retry delays and a visible failure after eight attempts, so a
broken relay or a missing configuration shows on the alert rather than silently
dropping it. Administrators and auditors read the inbox (`GET /api/admin/alerts`), only
administrators acknowledge (`POST /api/admin/alerts/{id}/acknowledge`), and both
settings changes and acknowledgements are audited. Resolved alerts and finished
deliveries are trimmed with the audit retention period; live alerts are kept whatever
their age. There is no second alert transport and no per-rule switch; the process log
remains the place for external collection.

## Upgrades and restores

Upgrading is starting the new image on the existing data directory: migrations run at
startup, identifiers are stable, and an app that existed before per-app access modes is
marked `all_active_users` rather than quietly locked down, because that is what the old
server did. Running the migrations again changes nothing, which is checked by comparing
the schema of a twice-upgraded database with a fresh one.

Restoring is two commands and one deliberate consequence. `kysignon restore -capsule
<file> -to <dir>` unpacks a capsule (custodian shares on stdin, never argv) and marks
the directory as restored. The next start reads that marker once and invalidates what
the capsule carried: sessions, issued tokens, authorization codes and interactions,
MFA and step-up challenges and grants, invitation and reset links, device pairing
tokens, queued back-channel logouts and in-flight delivery fences. Queued outbound
deliveries are closed out with a reason rather than sent, and outbound provisioning is
held on every connector that is not disabled. A `system.restored` audit row records the
counts, and the marker is removed only after that has committed, so an interrupted
start repeats the work rather than skipping it.

A held connector delivers nothing until a repair reconciliation has compared this
directory with what is really on the far side; the Suite sync page shows the hold, a
preview does not release it, and a failed run does not either. This is what stops a
restored outbox from recreating accounts that have since left. Passwords, enrolled
factors and recovery codes are in the capsule and keep working, so the restore runbook
asks for connector credentials to be reviewed for rotation before delivery resumes.
Procedures are in [docs/RUNBOOKS.md](docs/RUNBOOKS.md) and
[docs/RESTORE.md](docs/RESTORE.md); what has and has not been verified for a release is
in [docs/RELEASE-EVIDENCE.md](docs/RELEASE-EVIDENCE.md).

## Integration Requirements

These rules are enforced strictly. Each is a constraint on how a client integrates.

**Redirect URIs must match exactly.** There are no host aliases, port families, trailing
slash tolerance, or per-client fallbacks. A client that needs three callback ports
registers three URIs. This is the single control deciding who receives an authorization
code; anything looser makes registration advisory.

**PKCE (`S256`) is mandatory for public clients**, and `plain` is rejected everywhere. A
public client presents no secret, so the verifier is the only thing binding a code to the
party that requested it.

**Clients are confidential by default.** Registration issues a client secret unless
`"clientType":"public"` is passed explicitly. Every suite service (KyPost, KyDNS,
KyPasswords, KyNotes, KyBookmarks) is a server-side application that can hold one, so it
should be confidential; `public` exists for SPAs and native apps that genuinely cannot.
A confidential client with an empty `client_secret_hash` is rejected rather than
authenticated by existing.

**Rotate or correct a client in place** with `PUT /api/admin/clients/{id}` —
`{"clientType":"confidential"}` promotes a public client and returns a fresh secret,
`{"rotateSecret":true}` rotates an existing one. The secret appears in that response only.
This exists so a misregistration is recoverable; delete-and-recreate would break the
integration it is meant to secure, which guarantees nobody ever does it.

**Access tokens live 15 minutes** and carry a `jti` recorded server-side.
`POST /oauth/revoke` (RFC 7009, client authentication required) invalidates one;
disabling a user, resetting their MFA, changing their password, or revoking their sessions
invalidates all of theirs. Services that validate tokens offline against JWKS cannot see a
revocation until expiry — call `/oauth/userinfo` where revocation must take effect at once.

**Sessions.** Security and devices lists where an account is signed in: each live browser
session with its address, browser, sign-in and last-activity times, expiry and the factor
used, plus the apps currently holding access tokens. `GET /api/user/sessions`,
`DELETE /api/user/sessions/{id}` and `POST /api/user/sessions/revoke-others` act on the
caller's own account; revoking the current session also clears its cookies. Administrators
use `GET /api/admin/users/{id}/sessions`, `DELETE /api/admin/users/{id}/sessions/{sid}` and
`POST /api/admin/users/{id}/apps/{clientId}/revoke` (revoke one app's tokens and pending
codes while the browser session survives). Revoking a session removes its authorization
codes, tokens, step-up grants and pending authorization interactions in the same
transaction as the audit event. These routes need CSRF but no step-up, like the emergency
button. The app list is derived from issued tokens: it shows which apps can still call
KySignOn, not whether the app's own login is alive. The "Sign-out notifications" list
below it shows, per app, whether the back-channel logout for an ended login is pending,
acknowledged or failed; apps without a receiver never appear there.

**RP-initiated logout.** Discovery advertises `end_session_endpoint` at `/oauth/logout`
([OpenID Connect RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)).
Every ID token carries a `sid`: an opaque value minted per client and login, so two apps
cannot correlate a user's sessions through it and no app learns the internal session ID.
An app sends the browser to `/oauth/logout` with `id_token_hint`, optionally `client_id`,
`post_logout_redirect_uri` and `state` (GET or POST). A hint this server signed for that
client whose `sid` names the session held in this browser ends it at once. Without such a
hint, or with a hint for another user or another login of the same user, KySignOn shows a
confirmation page whose form carries a session-bound token; a cross-site POST cannot
confirm on the user's behalf. A cross-site POST carries no session cookie (`SameSite=Lax`),
so it is answered with a 303 to the same request as a top-level GET on this origin rather
than reported as a sign-out.
`post_logout_redirect_uri` must match one of the client's registered post-logout URIs
exactly (register them on the client, https or loopback http only); anything else is a 400
page and nothing is changed, never a redirect. `state` is echoed on the redirect. Expired
hints are accepted, forged or foreign-issuer hints are not. Ending the session revokes its
codes, tokens, step-up grants and pending interactions in the same audited transaction as
the browser logout button.

**Back-channel logout.** Discovery advertises `backchannel_logout_supported` and
`backchannel_logout_session_supported`
([OpenID Connect Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html)).
A client may register one back-channel logout URI (public HTTPS, same guard as
provisioning callbacks). Whenever a login ends, whether by the logout button, RP-initiated
logout, "sign out other sessions", an administrator revoking a session or an app's tokens,
or an account being disabled, KySignOn queues one delivery per client that saw that login
and has a receiver, in the same transaction as the revocation. A worker POSTs
`logout_token=<JWT>` as a form body with no redirects followed, a ten-second timeout and a
fresh token per attempt; 200 or 204 acknowledges, anything else retries with exponential
backoff (30 s doubling, 30 min cap) up to five attempts, then the delivery is marked failed.
Administrators see each delivery in the user's Sessions modal and can retry a stuck one,
which restores the attempt budget; the retry is audited as `admin.logout_retry`. Only
administrators see the transport error text, since it can name the receiver's host.
Deliveries run on four workers with at most one in flight per client, so a receiver that
never answers delays only its own queue. Delivered rows are pruned after seven days; a failed delivery stays until it succeeds
or an administrator retries it, because its absence would read as success.
A session that reaches its idle or absolute limit is dropped without a logout token:
expiry is not a sign-out action, and apps rely on their own session lifetimes for it.

The logout token is an RS256 JWT with header `typ: logout+jwt` and claims `iss`, `aud`
(the client ID), `sub`, `sid` (the client-scoped session ID from the ID token), `iat`,
`exp` (two minutes), `jti` and `events` containing
`http://schemas.openid.net/event/backchannel-logout`. It never carries `nonce` or
`token_use`, and this server rejects it as an ID token hint and as an access token. A
receiver must verify the signature against the JWKS, the issuer, that `aud` is its client
ID, that `typ` is `logout+jwt`, that the events claim is present and `nonce` absent, and
reject a `jti` it has already seen; it should then end every local session tied to that
`sid` (or to `sub` when it keys sessions by subject) and answer 200 with `Cache-Control:
no-store`. An acknowledgement means the receiver accepted the token, not that it proved it
ended a session; "Acknowledged" in the UI carries exactly that meaning. Subject-wide logout
(a token with `sub` and no `sid`) is not sent by this server today: every delivery names one
login.

**Authorization re-authentication (PR05a).** Ordinary requests reuse SSO. Following
[OpenID Connect authentication requests](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest),
`prompt=login` and `max_age=0` require a new password and any enrolled second factor
for each authorization request. A positive `max_age` (whole seconds, at most
2147483647) limits password age at authorization and again when the code is exchanged.
`prompt=none` never opens a login screen; missing or insufficient authentication returns
`login_required` to the validated redirect URI with the original state.

`acr_values` supports `urn:kysignon:acr:password` and `urn:kysignon:acr:mfa`.
The first value is the requested minimum; MFA can satisfy password assurance.
Recovery codes do not satisfy MFA. Unsupported values, unsupported prompt modes,
combined prompts, duplicate parameters, malformed ages, and alternate `request`,
`request_uri`, or `claims` inputs return `invalid_request`. Discovery advertises the
two supported request classes. Administrator passkey requirements strengthen either class
without changing the documented ID-token claim values.

Interactive login uses the existing password, TOTP, push, passkey and recovery screens.
A five-minute, single-use interaction binds the original validated request (including
client, redirect, scope, PKCE, nonce and state) to a signed HttpOnly browser cookie and the
resulting login session. A signed-in user must re-authenticate as that same account.
Up to ten interactions can be outstanding per browser and per account, with a server-wide
cap of 10000. Completing an anonymous login assigns its interaction to that account and
enforces the same bound. Upgrade and capacity recovery trim pre-existing account overages
to ten requests, preferring completed proofs; affected requests must restart authorization.
Expired interactions are cleaned on creation. At capacity, only the oldest anonymous,
unfinished interactions are evicted; account-bound requests and completed proofs are
preserved within the account bound. Every authorization request spends an IP allowance
of 300 requests with five requests/second refill. Browser identities never allocate
rate-limit buckets, so rotating cookies cannot reset the source allowance or fill the
shared limiter map. The separate interaction caps still apply per browser and account.
Throttling uses `temporarily_unavailable` after validating the redirect URI; database
failures use `server_error`. A different tab's login cannot satisfy
another interaction; if the browser's session changes, restart from the app. Cancel
sign-in burns the interaction and returns to the dashboard. If password/MFA verification
has already completed when its interaction expires or is cancelled, the valid login is
preserved and the UI asks the user to restart from the application. The new session
cannot resume the cancelled request; a spent recovery code still bought a valid login.
Concurrent completion and
cancellation serialize at the database; a code already issued cannot be recalled by
cancelling the former interaction. Administrative step-up grants are never accepted.

Choose **App connections → Authentication** on an OAuth app to configure:

- **Reuse SSO**, **Maximum password age**, or **Fresh sign-in every authorization**.
- Password with existing enrollment rules, mandatory ordinary MFA, or password plus
  passkey. Recovery never meets mandatory MFA; TOTP and push cannot meet passkey policy.
- An independent maximum second-factor age. Zero means no additional factor age limit;
  positive ages are whole seconds up to 2147483647. Expired evidence uses the existing
  full password/second-factor flow, with each proof retaining its actual verification time.

Client requests can strengthen these settings but cannot weaken them. Silent requests
with insufficient evidence return `login_required`. An account missing a required factor
receives an enrollment explanation after password verification; sign in normally to the
account dashboard to enroll before restarting from the app. A passkey here means a
verified WebAuthn second factor, not a guarantee about hardware or device-local storage.
Existing apps default to reuse SSO with existing enrollment rules; legacy unknown proof
can still reuse ordinary SSO but cannot satisfy freshness, mandatory MFA or passkey policy.

`PUT /api/admin/app-registry/{id}/authentication-policy` accepts `revision` (the app's
current revision) and `policy`: `mode` (`reuse`, `max_age`, `fresh`), `primaryMaxAge`,
`factor` (`password`, `mfa`, `passkey`), and `factorMaxAge`. Maximum-age mode requires a
positive primary age; other modes require zero. Password-only requirements require zero
factor age. The route requires an OAuth connection, administrator rights, CSRF and
operation-bound step-up. Lists expose `authentication` and `authenticationRevision`.

Every actual policy change increments its policy revision and atomically cancels that
client's pending/completed interactions, deletes pending/spent codes, revokes registered
tokens, and records the audit. Even a relaxation invalidates old grants; reverting a
policy never revives them. Code creation rechecks current policy in its transaction;
token registration checks the app identity, policy revision and the earliest password or
factor deadline atomically. Other apps and the central login session remain usable.
Offline JWT consumers may accept a token for up to 15 minutes, and destination app cookies
may last longer; these settings apply when an app initiates OAuth authorization.
Launcher visibility and provisioning scope remain governed by their existing controls.
On first upgrade, old pending codes and interactions restart without deleting existing
sessions or already-issued tokens. Subsequent startups preserve live requests.

**Required MFA enrollment.** Administrators can preview and apply organization
and administrator requirements under **MFA policies**, and each group's requirement
under **Groups → MFA policy**. Allowed TOTP, signed push and passkey methods intersect
across every applicable policy. Grace is 0–90 days; each user's scope
obligation stores an epoch-second deadline when it first applies, including account
creation, promotion and group membership. The earliest applicable deadline wins. Logins,
longer grace, disabling/re-enabling a policy and removing/re-adding membership never
extend an existing deadline. Deleting a group with an MFA requirement checks compliant
administrator login evidence as well as step-up, then deletes its policy and obligations;
a newly created group has a new identity and starts without an MFA requirement.

Unenrolled users may continue during grace, subject to stricter app policies. Users with
a permitted factor must sign in with it immediately. At the deadline, password-only
sign-in produces an enrollment-only session only for accounts with no enrolled factor.
An existing factor still has to be verified even when policy no longer permits it.
Pairing a new approver phone requires operation-bound step-up, including during enrollment. Recovery sign-in is also restricted when
MFA is required. Such sessions can inspect identity/factors, obtain operation-bound
factor-enrollment grants, enroll and sign out; they cannot access applications, admin
APIs, OAuth codes or online tokens. Completing enrollment does not upgrade that session:
sign out and sign in with password plus a permitted factor. There is no background
heartbeat keeping idle sessions alive; the server checks every authenticated request.

Applying policy requires operation-bound step-up and, whenever the administrator is
covered by the resulting policy, an actual permitted MFA login within five minutes.
Step-up cannot replace that login evidence. The preview and application use the same
transactional rules; revisions prevent stale writes. Applying cancels all outstanding
OAuth sign-ins and revokes registered tokens with its audit event. Online token checks
also enforce deadlines at use time; offline JWTs may remain valid for up to 15 minutes,
and destination app sessions can outlive them. Changing membership in an MFA-required group cancels that user's outstanding OAuth
interactions/codes and revokes registered tokens, even when the change relaxes policy.
An actual membership change requires a current administrator session; if that account
is subject to MFA, its permitted login proof must be within five minutes. Conflicting
factor intersections reject the entire membership or policy transaction. Promotion to
administrator also rejects conflicting requirements. Group previews summarize all applicable requirements for that group's members;
organization/admin previews summarize the directory.
Removing the last compliant factor is
rejected atomically, including concurrent device/passkey removals. Administrator MFA
reset remains available, revokes sessions and ends any remaining enrollment grace.

**Authentication claims describe the login that established the session.** `auth_time`
is the time the password was verified, preserved across later SSO redirects. The second
factor's verification time is recorded separately; completing MFA or issuing a token
does not refresh the password's age. ID tokens expose these method/context values:

| Login | `amr` | `acr` |
|---|---|---|
| Password | `pwd` | `urn:kysignon:acr:password` |
| Password + TOTP | `pwd`, `otp`, `mfa` | `urn:kysignon:acr:mfa` |
| Password + signed push | `pwd`, `urn:kysignon:amr:push`, `mfa` | `urn:kysignon:acr:mfa` |
| Password + passkey | `pwd`, `urn:kysignon:amr:webauthn`, `mfa` | `urn:kysignon:acr:mfa` |
| Password + recovery code | `pwd`, `urn:kysignon:amr:recovery` | `urn:kysignon:acr:recovery` |

These are KySignOn context classes, not NIST assurance levels or assertions that keys
are hardware-backed. Recovery does not claim ordinary MFA. The standard method names
follow [RFC 8176](https://www.rfc-editor.org/rfc/rfc8176.html); the URNs are local contracts.
Administrator per-app freshness policies are implemented as described above; further work
is tracked in [the access lifecycle plan](docs/access-lifecycle-plan.md).

Existing sessions survive the upgrade but omit `auth_time`, `amr` and `acr` until a new
login supplies evidence. Pending legacy authorization codes and MFA flows are invalidated;
users in those flows restart login. New codes and access tokens bind internally to the
originating session: removing it blocks exchange and online UserInfo access. Already-issued
legacy access tokens retain their previous expiry/revocation behavior. Internal session IDs
are listed to their owner and administrators for revocation; ID tokens publish a separate
per-client `sid` for RP-initiated and back-channel logout.

**System pairing requires the PIN** shown next to the token, and callback URLs must be
`https` and resolve off-network unless `KYSIGNON_ALLOW_PRIVATE_CALLBACKS=true` (the
compose file sets this, since services on `kypost-net` address each other privately).
Sync events are queued per paired system; a system only receives what was queued for it.

**Device pairing requires a P-256 public key.** A device without one can never approve a
push, and pairing it previously enrolled push MFA that no response could satisfy.

**`TRUSTED_PROXY_CIDRS` defaults to empty.** Forwarding headers are ignored unless the
immediate peer is a CIDR you named. Set it to your proxy's address and nothing wider: every
host inside a listed range can choose its own rate-limit bucket and its own entry in your
audit log.

**`KYSIGNON_FORWARDED_HEADER` names the one header that is believed, defaulting to
`X-Forwarded-For`.** Behind Cloudflare, set it to `CF-Connecting-IP`. Exactly one header is
honoured per deployment because trying several in turn means whichever one your edge does
*not* overwrite is the one an attacker gets to choose. The value must parse as an IP
address, and the chain is walked from the right past hops inside `TRUSTED_PROXY_CIDRS`, so a
client-supplied entry prepended to the list is never attributed.

**Backups are sealed to the suite recovery key and this server never holds what opens
them.** The key arrives by pairing with KyRecovery, or is pasted from the ceremony page on
the Disaster recovery screen for a server with no KyRecovery. Every capsule is sealed to it
and goes to each configured destination: KyRecovery when paired, and `KYSIGNON_BACKUP_DIR`
when set. Files there are named `<KYSIGNON_APP_NAME>-<capsule-id>.kycap`; the newest
`KYSIGNON_BACKUP_KEEP` (default 7) with that prefix are kept and anything else in the
directory is never listed or deleted. The schedule is set on
the same screen; `KYSIGNON_BACKUP_DEPOSIT_INTERVAL` (default 24h, 15m floor, `0` disables)
is only the default until an admin picks one. Custodian cards come from the KyRecovery
ceremony, and a restore is `kysignon restore -capsule <file.kycap> -to <dir>` with k shares
typed on stdin. A server with no key pinned can run drills but cannot make a capsule.

**KyRecovery must be reached over HTTPS, and by default at a public address.** TLS is not
for the capsule, which is sealed anyway; it protects the recovery public key that arrives at
pairing (trust on first use), the deposit token, and the receipts. For a KyRecovery on your
own network behind a TLS proxy, set `KYSIGNON_BACKUP_ALLOW_PRIVATE_RECOVERY=true`; HTTPS is
still required, the choice is recorded on every pairing, and loopback stays refused. Either
way, pin the key by hand from the ceremony page before pairing, or compare the key ID the
screen shows with the fingerprint in the KyRecovery dashboard; a swapped key then fails
loudly. In Docker, a name that exists only on your LAN may not resolve inside the container when the
host uses a loopback stub resolver; append `docker-compose.lan-dns.yml` to `COMPOSE_FILE` in
`.env` (see the file's header) and recreate with `KYSIGNON_DNS` set to your LAN's resolver. It replaces the host's resolvers for every lookup
the container makes, which is why it is an override and not the default.

**Passkeys are bound to the issuer's origin.** The relying party ID is the hostname of
`KYSIGNON_ISSUER_URL` and the accepted origin is its scheme, host and port. Changing the
issuer URL invalidates every enrolled passkey, because the browser will not offer a
credential registered under a different RP ID. Browsers permit WebAuthn over plain HTTP only
on `localhost`, so a deployment reached by IP or by a name without TLS cannot enrol one.

**Enrolling or removing a passkey spends a step-up grant**, like every other change to an
account's factors. Resetting a user's MFA deletes their passkeys along with their TOTP
secret and recovery codes. Step-up requires your password plus an enrolled TOTP, push,
or passkey factor whenever any factor is enrolled. Recovery codes authorize only
enrolling a replacement TOTP or passkey; the recovery grant cannot directly authorize
administrative actions, factor deletion, or the standalone recovery-code regeneration
endpoint. TOTP enrollment itself reissues recovery codes and signs out other sessions.
A newly enrolled factor can authorize subsequent step-up operations.

Grants last at most five minutes, are single-use, and bind to the current session and
the exact HTTP method and target path. Enrollment preparation shares the grant with
its final enrollment request. Push and passkey step-up challenges are separate from
login challenges. Challenge issuance has a distinct `auth.step_up_challenge` audit event;
locked-account and missing-factor denials remain visible in `auth.step_up` events.
Dismissing the shared prompt aborts the action and cancels any pending challenge or late grant; it does not refresh the session's OIDC authentication evidence.
Upgrading invalidates old, unscoped step-up grants, so an open confirmation must restart.

**Destructive admin operations require step-up re-authentication.** Creating or editing an
account, resetting someone's MFA, deleting a user, registering or deleting an OAuth client,
connecting or removing a paired system, and exporting, pairing, unpairing, pinning a key,
running or rescheduling a backup each
spend a single-use grant that costs your password and an enrolled factor. A stolen session
cookie cannot produce one. Read-only views and the emergency "revoke sessions" button stay
on the session alone, so locking an account down during an incident is not slowed by a
second prompt.

**`KYSIGNON_SECRET_KEY` and `KYSIGNON_ENCRYPTION_KEY` must be exactly 64 hex characters.**
A malformed value is a startup error, never a silently weakened key. Generate with
`openssl rand -hex 32`. Left unset, they are generated into the data directory and reused.

---

## License & Security

Refer to [SECURITY.md](SECURITY.md) for vulnerability disclosure procedures and [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## Outbound provisioning

In **Suite sync**, choose **Generic SCIM 2.0** and enter the target's HTTPS SCIM
base URL and its provisioning Bearer token. KySignOn encrypts the token at rest;
**Replace token** changes it without changing the connector or application identity.
The token is never returned in listings or copied into delivery errors. **Test
connection** performs a filtered Users read; success does not prove write permissions
or that an account has been provisioned.

The target must support `externalId eq "..."` filtering, standard ListResponse totals,
User creation, PUT updates, and PATCH of `active`. Lookup requests ask for the first
two matches: zero permits creation, one identifies the managed account, and more
than one requires intervention. Partial or inconsistent pages fail closed. Responses
are bounded to 1 MiB. KySignOn sends its stable user ID as `externalId` and stores
the remote ID returned by create or lookup. URLs ending in `/Users` from the old
connection form are normalized to their base URL. Generic SCIM requires HTTPS even
with private callbacks enabled; the existing outbound dial restrictions still apply.

A source account deletion deactivates the remote account with `active=false`; it
never sends DELETE. Local MFA resets send no generic SCIM mutation. Suite products
retain their signed webhook events, including the existing deletion contract.

Per connector/user, only the earliest pending event can begin delivery. Backoff holds
later events for that user; other users and connectors continue. A durable attempt
survives process restart and local user deletion. Unsent claims may expire, but an
attempt that might have reached the receiver stays blocked after a transport failure,
HTTP 408/5xx, or asynchronous acceptance (202). A response acknowledging completion
and its event status are persisted atomically. These rules rely on the receiver honoring
its synchronous success/rejection responses; they cannot fence a nonconforming receiver.

In **Suite sync → Deliveries**, inspect in-flight/blocked attempts and read remote state.
Read-back only reports a matching externalId; it neither proves a request has finished
nor resumes delivery. Signed suite webhooks have no read-back contract.

To recover an expired attempt:

1. Stop **all** KySignOn worker instances. Confirm at the receiving service that the
   old request has finished and cannot commit later. A timeout or empty lookup is
   insufficient. If this cannot be established, keep the attempt blocked.
2. Restart one instance, open **Deliveries**, and confirm these steps. **Resume delivery**
   requires fresh operation-bound step-up and records the recovery audit atomically.
3. For a lost create, keep the existing create guard unless the receiver explicitly
   confirms no account was created. The separate fresh-create checkbox additionally
   requires an empty externalId lookup before clearing that guard. Otherwise restore
   the account's correct externalId at the target and resume; lookup recovers its ID.

The oldest 100 attempts are shown; resolving them exposes the next page. A definitive
4xx rejection (except 408) uses ordinary backoff and the five-attempt budget;
Retry-After extends backoff up to one hour. Do not use resync or disconnect/reconnect
as an uncertain-write recovery mechanism. Stop old-version workers before upgrading;
they do not honor the new persisted fences. Existing remote operations must finish
before the upgraded worker starts.

Known KySecurity product types and **Custom signed suite webhook** use a generated
signing secret shown once. They send bare SCIM user bodies with `syncauth` signatures,
never a Bearer header. Legacy `custom` or unknown types show **Protocol review
required** and retain pending events without spending retries. **Review connection**
requires step-up: select the actual protocol, supplying a target-issued token for
SCIM or retaining the existing signing secret for a suite webhook. Review preserves
the destination URL, connection ID, application linkage and assignments.

### Provisioning scope

Each connector provisions exactly the users who hold effective access to its linked
application: the access policy, direct and group assignments, user status, app enabled
state and OAuth client state all apply. Existing connectors migrated with the
all-active-users policy keep their whole-directory scope until an administrator
changes it. A user who gains access is created, or reactivated with `user.updated`
and `active=true`, and a user who loses it is deactivated with `user.updated` and
`active=false`; this is the same event a local disablement sends. Accounts are never
deleted downstream. Generic SCIM never creates an account for an inactive state, and
suite receivers may answer an inactive update for an unknown account with 404.

The access policy preview reports how many users would gain or lose access, which is
the number of downstream account changes a linked connector will receive. Mutation,
audit and provisioning work commit in one transaction. A slower worker pass also
reconciles cascades (client deletion, foreign-key removal) within a minute.

A newer desired state supersedes queued work for the same connector and resource that
has not begun delivery; an attempt that has begun keeps its place and the newer state
queues behind it, so an old create can never undo a later disable. A resource whose
create was never acknowledged is forgotten on loss rather than disabled. Every event
carries a monotonic per-resource revision; suite receivers receive it as `meta.version`
(`W/"<n>"`) and should refuse writes older than one they applied. Conditional
`If-Match` writes to generic SCIM targets are not implemented.

Work that exhausts its attempt budget is not abandoned: each reconcile pass returns it
to the queue with a 30-minute backoff when it still describes current desired state,
and discards it when a newer state has overtaken it. A local deletion is sent to every
enabled connector; only a connector known to hold the account receives the profile,
the rest receive the identifier and `active=false`.

**Resync** re-sends every in-scope account (and assigned group) and never provisions a
user outside scope.

### Reconciliation

**Suite sync → Provisioning** shows, per user, what the directory wants (desired), what
was last queued (queued, with its revision), what the receiver acknowledged, what the
last listing observed, the last delivery outcome with its next retry, and whether an
attempt is blocked. **Retry** re-queues one user's current desired state, superseding
exhausted work.

**Preview drift** and **Repair drift** queue a reconciliation job for a generic SCIM
connector. One job runs per connector at a time under a ten-minute lease; a job
interrupted by a restart is re-run up to three times, which is safe because repair only
queues the same idempotent desired-state work delivery already uses. A job walks the
target's Users (and Groups when group delivery is enabled) page by page. Every page
must answer 200 with a stable `totalResults`; a failed page, a short page, duplicate IDs
or more than 20,000 resources makes the run **incomplete**: the accounts that were seen
are recorded, safe attribute repairs may be queued, and nothing is deactivated or
inferred absent.

Only accounts this connector manages are compared: resources whose `externalId` names a
user with effective access to it, a held desired-state row or a stored remote mapping. A
target cannot make itself the holder of an account by naming an arbitrary local user;
everything else is left alone and counted as unrelated. A preview writes nothing but
observations. Repair stores remote IDs learned from the listing; a target ID that
disagrees with a stored mapping is counted as a conflict and never written through. A complete run classifies each managed
account as **missing** (desired, absent), **stale** (desired, but inactive or with
different userName, displayName or email) or **orphaned** (active at the target without
effective access). Repair queues a create for missing, an update for stale, an inactive
update for orphaned accounts, re-queues assigned groups and deletes managed groups that
are no longer assigned. Repair always lists afresh; a preview is never applied later.
Repair requires operation-bound step-up. Every repair, scheduled or requested, records an
audit event when queued and another with its counts when it finishes; a preview records
only its request. Listings run on their own worker with a two-minute budget per
collection, so a slow target cannot delay outbound delivery to any connector.

Signed suite webhooks have no read contract. Their jobs record every held account as
**unsupported**, so an acknowledgment is never presented as an observed match.

**Scheduled repair every N hours** in Connection settings queues a repair job at that
interval (0 disables it). The last twenty jobs per connector are kept.

### Offboarding

Disabling an account, deleting it, and (when it ships) an account end date all run the
same transaction: every browser session ends and its back-channel logout is queued,
every token, code and step-up grant is revoked, and an inactive desired state is
recorded for every connector that holds the account, including a connector that only
knows the user through a remote ID mapping and never had a tracked grant. Deletion sends
`user.deleted` instead of an inactive profile and then removes the directory row; the
completion state, the remote ID mappings and the audit trail outlive it so retries and
reconciliation still work. A connector with no recorded account still receives a bare
deletion, in case it holds one from whole-directory delivery that predates tracking, and
it appears in the completion view like any other target. Disabling does not send to such
a connector: nothing shows it holds the account, and nothing is hidden from the view. Products are told to deactivate; nothing erases mail, notes
or vaults. Re-enabling records a new desired-state revision, so a deactivation still in
flight cannot land after the reactivation, and the user must sign in again.

**Users → Offboarding status** (also opened automatically after a delete) shows, per
connector, what was queued, whether the connector acknowledged it, and what the last
listing observed, with attempts, next retry and a retry button; below it are the
sign-out notifications. The summary reads *Pending* while any target is outstanding,
*Acknowledged* once every connector and app accepted its delivery (decided over every
delivery, not just the ones listed, and recorded on the connector's state row so it
survives outbox pruning), and *Complete* only when a later listing verified
the account inactive or absent at every connector. A
connector whose listing is unsupported can be acknowledged but never verified, and a
connector whose later listing still shows the account active is marked *Still active at
target* and counts as neither; the view says so rather than rounding up.

### SCIM Groups

Generic SCIM connectors may enable **Deliver SCIM Groups** under Connection settings.
Every group assigned to the connector's application is created at the target with the
group's ID as `externalId`, its name as `displayName`, and `members` holding the
target's IDs of in-scope members that already exist there. Membership, rename, scope
and assignment changes replace the whole member list; a member's first acknowledged
create re-queues its groups. Stored group mappings are re-verified by `externalId`
before every write, and only 200/204 completes a write. Unassigning or deleting a
group deletes the remote group (404 is accepted). Disabling the flag leaves remote groups untouched. Group attempts
appear in Deliveries with the group ID as the resource; read-back and lost-create
recovery use the Groups collection. Suite receivers never receive group events.

## Inbound SCIM

An upstream directory can own accounts here over SCIM 2.0. **Administration → Inbound
SCIM** creates a connector and issues its Bearer tokens (shown once, stored as hashes,
`read` or `write` scope, last use recorded, revocable at any time; issue a new one and
revoke the old to rotate). The base URL is `<issuer>/scim/v2`. Connector tokens work
only there: they never authorize the browser API, and a browser session never
authorizes SCIM. Every request is rate limited per connector, and failed
authentications per address.

**Supported profile.** `GET /ServiceProviderConfig`, `/ResourceTypes`, `/Schemas`
describe exactly this: Users only; create, get, list with one exact-match filter
(`userName`, `externalId`, `emails.value` or `id` with `eq`), `startIndex`/`count`
paging up to 200, replace, PATCH with `add`/`replace` of `active`, `userName`,
`displayName`, `name` and `emails` (single or path-less operations, 50 at most, applied
atomically), and DELETE. Weak ETags are returned and honoured on `If-Match`; a stale
version is refused with 412. Bulk, sorting, other filters and other attributes are
refused with a SCIM error rather than ignored. Password provisioning is unsupported and
a `password` attribute is rejected outright; `roles` are ignored.

**Ownership.** An account the upstream creates is keyed by connector plus its immutable
`externalId`; a changed `externalId` is refused. It starts pending with no credential,
like any invited account: an administrator issues its activation link (or mail delivery
does), and only then can it sign in, be provisioned or hold app access. No activation
link is issued while the upstream marks the account inactive or a local override holds,
and activation never outranks either: the password is set, the status follows the
source state. `userName`,
`displayName`, `name`, the primary email and the `active` flag belong to the upstream
and are read-only for local administrators; role is a local decision the upstream
cannot make. A clash with an existing username or email, local or from another
connector, is a 409, and so is a `userName` equal to some account's email or the
reverse: an upstream never takes over or shadows an account. A connector sees and
touches only its own accounts. DELETE deactivates; nothing is erased.

**Overrides.** A local administrator disabling an upstream account sets an override the
upstream's `active: true` cannot lift; enabling it locally lifts the override and takes
effect only if the upstream also wants the account active. Upstream deactivation runs
the full offboarding transaction. Local accounts, including emergency administrators,
are outside every connector's reach by construction.

**Groups.** `/scim/v2/Groups` maps onto the flat directory groups: create, get, list
with one exact-match filter (`displayName`, `externalId` or `id`), replace, PATCH and
delete. A group's `displayName` and member set belong to the upstream; every member must
be a User of the same connector (a local account, another connector's account or a
group is refused with a clear SCIM error and nothing is applied), and nested groups are
refused. A PATCH is validated in full and applied as one replace, so an invalid
operation anywhere means nothing changes. Weak ETags apply as for Users. Deleting a
group removes what its memberships granted and never deletes a user. A group with a
required MFA policy is refused to the upstream for any change, its name included, since
only a local administrator with a compliant sign-in may change such a group. One request
carries at most 1000 members; a conditional write (`If-Match`) is re-checked inside the
write transaction, so two writes that read the same version cannot both land. Locally, an upstream group's name is
read-only (`source_owned`); its description stays local. Group membership drives app
assignment and downstream provisioning exactly as local membership does.

**Setup.** Create the connector, issue a write token, and add a SCIM provisioning target
in the upstream directory with tenant URL `<issuer>/scim/v2` and the token as the Bearer
secret. Map `userName`, `externalId`, `displayName`/`name`, the primary email and
`active` for users, and `displayName`, `externalId` and `members` for groups; do not map
passwords or roles. Provisioned accounts appear pending on the Users page and take an
activation link; groups appear on the Groups page marked SCIM. Every SCIM write is in
the audit log under `scim.*` with the connector as actor. The supported profile is
proven by the protocol test suite and a local curl run only; it has not yet been
validated against a real upstream tenant, so do not claim compatibility with a
particular directory product until that run is recorded.

**Disconnecting** a connector requires a choice for the accounts it owned: keep them as
ordinary local accounts as they are, or disable them first. Disabling is refused when it
would leave no active administrator. Its groups become ordinary local groups, its
tokens die with it, and the choice is audited.
