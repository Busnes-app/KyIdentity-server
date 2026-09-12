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
cp .env.example .env
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
```bash
docker compose up -d --build
```

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
session may last longer until downstream logout integration ships.

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
are not published as logout `sid` claims; standard downstream logout remains future work.

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
host uses a loopback stub resolver; add the `docker-compose.lan-dns.yml` override with
`KYSIGNON_DNS` set to your LAN's resolver. It replaces the host's resolvers for every lookup
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
