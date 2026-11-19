# Tenancy: single-tenant and multi-tenant (SaaS), design

Date: 2026-11-19. Owner decisions: 2026-11-19 tenancy brief (fixed, listed below). Worker:
tenancy-spec. Status: design only, nothing built.

KyIdentity today is one organisation per install (`AGENTS.md:3`, `design.md:31` defers
multi-tenancy). This spec adds a second mode to the same binary. **Single-tenant** is
today's behaviour, unchanged for existing installs. **Multi-tenant** is a hosted service
where every customer (a person, a household or a business) is an *organisation* (org), all
under one issuer, one sign-in page and one WebAuthn relying party.

Owner decisions (not reopened here):

1. Two modes, same binary. Mode is install-time configuration. An existing install upgrades
   with zero behaviour change.
2. Organisations under one sign-in: one issuer, one sign-in page, one WebAuthn RP. Tokens
   carry the org. KyPost, KyCalendar, KyDrive (later KyNotes and KyMessages) run as shared
   multi-tenant installs that separate data by org.
3. One org per account. No account spans orgs, and there is no org switcher.
4. An outside billing service (Stripe) provisions orgs through a machine-to-machine
   platform provisioning API. KyIdentity has no Stripe code and never sees payment data.
5. No public self-signup in KyIdentity. Orgs are created by the provisioning API or by
   the operator.

Line references are to `master` at `09caf1c`. "Unverified" marks a claim this spec did not
check in code.

## Decisions this spec makes

| # | Decision | Why |
|---|---|---|
| D1 | `KYIDENTITY_TENANCY=single` (default) or `multi`, recorded in `system_settings` at first start. A later start with the other value refuses to start. Added to the shared replica configuration (`internal/config/replica.go:19`). | Install-time, as decided. A replica started with the wrong mode must not serve. |
| D2 | **Multi-tenant requires PostgreSQL.** SQLite stays single-tenant only. Both backends get the same `org_id` columns, so `TestBackendsHaveTheSameColumns` (`internal/store/postgres_test.go:47`) still holds. | Several global uniques must become per-org: `directory_groups.name` (`store.go:139`), `suite_groups.slug` (`suite_groups.go:16`), and the `enrollment_policies` primary key `scope` (`group_enrollment.go:50`). On SQLite an inline `UNIQUE` or a primary key can only be dropped by rebuilding the table. Migrations run inside a transaction (`migrations.go:144`), where `PRAGMA foreign_keys` cannot be turned off. `DROP TABLE directory_groups` with foreign keys on would cascade-delete memberships, assignments and policies. On Postgres these are `ALTER TABLE … DROP CONSTRAINT`. With one org, the global uniques are correct, so SQLite keeps them. |
| D3 | Isolation is enforced in the application, through an org-bound store handle (`OrgStore`). Postgres row-level security is optional extra protection, added later. | The store has one SQL source in SQLite's dialect (`AGENTS.md:192`), and single-tenant installs on SQLite use the same code. App-level scoping is the only mechanism that covers both. |
| D4 | The org is in tokens as an `org_id` claim, **in multi-tenant mode only**. | Zero change for single-tenant relying parties. An absent claim means single-tenant. |
| D5 | Username and email stay globally unique (`pg_schema.go:21,23`). In multi-tenant mode, username = email at creation. | There is one sign-in page, and login looks a user up by username alone (`auth_handlers.go:94`). Using the email means no `alice` collisions between orgs and no new lookup path. |
| D6 | Entitlements reach apps through a suite API pull (`GET /api/suite/orgs`), not a token claim or a webhook. | See Entitlements. |
| D7 | OAuth clients, the app registry, app roles and launcher cards stay global. Each org's access to an app is a new per-org row (`org_apps`). | Owner decision 2 (shared apps). |

## Threat model

| Attacker | Goal | Defence |
|---|---|---|
| Admin or member of org A | Read or change org B's users, groups, assignments, audit or policy by putting B's IDs in admin, SCIM or suite calls | Every org-owned query runs through an `OrgStore` bound to the caller's org. The binding comes from the authenticated principal, never from the request. A cross-org ID is `404`, the same answer as a missing one. Composite foreign keys (`(org_id, user_id)`, `(org_id, group_id)`) make a cross-org membership, policy or deadline impossible to write at the database level. Proven by the cross-org matrix test. |
| Org A admin | Gain access through a global app set to `all_active_users` | Today `app_access_facts` is `app_registry CROSS JOIN users` (`pg_schema.go:512-517`), so that mode means every user on the install. The view gains a required join on `org_apps`/`orgs.all_apps` for the user's org. A test gives one org an app with all-users access and proves the other org's users get no access. |
| Malicious relying party, or a bug in one | Forge or swap `org_id` | Tokens are RS256, signed by KyIdentity (`oauth.go:502`). `org_id` is read from `users.org_id` at issuance, never from the request. `users.org_id` is immutable: a trigger refuses any update, on both backends. Apps must take the org only from a verified token or a suite API answer (see Downstream contract). |
| Thief of a platform token | Create, suspend or delete orgs | Platform tokens are 256-bit, stored hashed, scoped, expiring and revocable, like SCIM connector tokens (`pg_schema.go:343`, `scim_inbound.go:243`). They are accepted only on a separate platform listener that is never published through the public proxy. They are never accepted on the public listener, and browser sessions, SCIM tokens and OAuth clients are never accepted on the platform listener. A token cannot read users' content (see Roles). Delete needs its own scope, and only works after a deletion was scheduled and its grace period has passed. Every call is audited. |
| Replayed or reordered billing calls (Stripe retries, out-of-order webhooks) | Undo a suspension, or apply an old plan | Every mutating call has an `Idempotency-Key` and a per-org `revision`. The same key and body returns the stored answer. The same key with a different body is `422`. A `revision` at or below the stored one is `409 stale_revision`. |
| User of a suspended or deleted org | Keep working | Suspension revokes every session, refresh family, issued token and forward session in one transaction (`revokeSessionGrantsTx`, `sessions.go:136`), and queues back-channel logouts. Every sign-in path checks one `active_principals` view (user active and org active). Access tokens live 15 minutes at most (`oauth.go:22`). `/oauth/userinfo` refuses at once. Apps see `status: suspended` within one poll (≤ 60 s). |
| Org A admin | Take over a person's identity by creating an account with their email (email squatting) | Emails are globally unique, so whoever creates an address first holds it. A pending account cannot sign in, and resets go only to a verified address (`onboarding_handlers.go:209`). A pending, never-activated account gives up its email when its activation token expires (open question 3). Another org's admin can never edit, reset or claim that account. |
| Anyone at the sign-in page | Find out whether an email exists, or which org it is in | Unknown, inactive, locked and suspended-org accounts all answer like a wrong password, after the same Argon2 cost (`auth_handlers.go:100-104`, `loginRefusal` at `:296`). Forgot-password always answers the same way (`onboarding_handlers.go:178-197`). No sign-in or recovery answer names an org. |
| Org A admin or SCIM connector | Find out whether an email exists in another org, from a `409` on create | Unavoidable with global uniqueness (D5). The answer is the existing generic `409` (`admin_handlers.go:127`, `scim_inbound_handlers.go:385`), never "in another org". Creates are rate limited per org. Residual risk. |
| Operator restoring one org's backup | Load org A's data into org B, or roll every org back | v1 has no per-org restore or import. A capsule is the whole install (`internal/backup`, `store.go:2984`). The per-org export is read-only JSON. Any future import must assign the target org from the signed-in owner's context and new IDs, never from the file. |
| Platform operator | Read customers' content | The platform API returns lifecycle data and counts only. There is no platform user account and no platform view of users. Anyone with database or host access can read everything. That is the trust boundary, and it is a residual risk. |

Residual risks (accepted):

- **One writer for every org.** Every Postgres write transaction takes one advisory lock
  (`AGENTS.md:191`, `docs/RUNNING.md:343`). A large SCIM import in one org delays sign-ins
  (which write `sessions`) in every other org. Per-org rate limits soften this but do not
  remove it. Capacity is unmeasured (open question 9).
- **A restore rolls back every org.** Restoring a capsule to fix one customer's problem
  loses every other customer's writes since that capsule was taken.
- **Global uniqueness leaks existence.** One org can tell an email is taken elsewhere
  (see the table). The billing service's checkout must not echo `email_in_use` to an
  anonymous buyer in a way that confirms another customer's address.
- **Offline token validation.** An app that checks JWTs offline keeps serving a suspended
  org for up to 15 minutes, or until its next poll of `/api/suite/orgs`.
- **The operator is trusted** with the database, keys and host.

## Data model

### New tables

```
orgs (
  id TEXT PRIMARY KEY,                 -- UUID; never reused
  name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('person','household','business')),
  status TEXT NOT NULL CHECK (status IN ('active','suspended','deletion_scheduled','deleted')),
  status_reason TEXT NOT NULL DEFAULT '' CHECK (status_reason IN ('','payment','abuse','operator')),
  all_apps BOOLEAN NOT NULL DEFAULT FALSE,  -- TRUE only for the single-tenant default org
  plan TEXT NOT NULL DEFAULT '',
  max_seats BIGINT NOT NULL DEFAULT 0,      -- 0 = unlimited (default org)
  owner_user_id TEXT,                       -- no FK (users references orgs); checked in the store
  billing_ref TEXT UNIQUE,                  -- the billing service's own opaque ID, never a Stripe ID
  billing_revision BIGINT NOT NULL DEFAULT 0,
  revision BIGINT NOT NULL DEFAULT 1,       -- KyIdentity's own version, carried in events
  delete_after BIGINT,                      -- unix seconds, set by schedule-deletion
  created_at, updated_at)
org_apps (org_id, app_id REFERENCES app_registry ON DELETE CASCADE,
  enabled BOOLEAN, access_mode TEXT NULL,   -- NULL = app_registry.access_mode
  quotas_json TEXT NOT NULL DEFAULT '{}',   -- opaque to KyIdentity, ≤ 4 KiB
  PRIMARY KEY(org_id, app_id))
platform_tokens (id, name, token_hash UNIQUE, scopes, created_at, expires_at, last_used_at, revoked_at)
platform_requests (token_id, idempotency_key, request_hash, status, response_json, created_at,
  PRIMARY KEY(token_id, idempotency_key))   -- kept 30 days
platform_events (id, org_id, type, payload_json, status, attempts, next_attempt_at,
  lease_until, claim_token, created_at)     -- outbox, same shape as logout_deliveries
```

A deleted org keeps its `orgs` row as a tombstone (`status='deleted'`, name cleared), so an
ID is never reused. This follows the same rule as `suite_groups` (`suite_groups.go:11-13`).

### `org_id` columns and constraints

Each table marked org-owned in the appendix gets `org_id TEXT NOT NULL`. There are two
named exceptions: `audit_events.org_id` and `alerts.org_id` are nullable, and NULL means a
platform row. Their existence triggers admit NULL, and their immutability triggers also
refuse changing NULL to an org or back.

- On Postgres it gets `REFERENCES orgs(id)`. The default is set for the backfill, then
  dropped.
- On SQLite it keeps `DEFAULT '<default org id>'`, because `ALTER TABLE ADD COLUMN` cannot
  add a `REFERENCES` column with a non-NULL default while foreign keys are on. Two
  `BEFORE INSERT` and `BEFORE UPDATE` triggers stand in for the foreign key: one requires
  the org to exist, one refuses any change to `org_id`.
- Postgres gets the same triggers, so trigger names match on both backends.
- A multi-tenant install has no default org row. An insert that forgets `org_id` hits the
  existence check and fails, instead of landing in an org.

Composite keys make cross-org links impossible to write:

- `users` and `directory_groups` get `UNIQUE(org_id, id)`.
- `group_memberships`, `enrollment_policies`, `enrollment_deadlines`, `suite_groups`,
  `app_group_assignments` and `app_role_group_assignments` reference
  `(org_id, user_id)` and `(org_id, group_id)` wherever they join two org-owned rows. On
  SQLite these are trigger checks.
- Per-org uniques, on Postgres only (D2): `directory_groups(org_id, name)`,
  `suite_groups(org_id, slug)`, and an `enrollment_policies` primary key of
  `(org_id, scope)`.
- `users.username`, `users.email` and `webauthn_credentials.credential_id` stay global
  (D5, one RP).

Views (`app_access.go:58-65`, `group_enrollment.go:68-78`, `pg_schema.go:510-545`):

- `app_access_facts` joins `orgs` and `org_apps` on `u.org_id`. An app counts for a user
  only when `o.all_apps` is set or an `org_apps` row is enabled, and the access mode is
  `COALESCE(oa.access_mode, a.access_mode)`.
- `applicable_enrollment_policies` and `enrollment_requirements` add
  `p.org_id = u.org_id` to the `'organization'` and `'administrators'` scopes.
- `active_principals` is new: users that are active and not ended, joined to an org that is
  `active`. Every sign-in, token and session check reads it, in place of the inline
  `users.status = 'active'` tests spread across the store today (for example
  `store.go:2660`, `pg_schema.go:513`).
- One exception is outside `active_principals`. While its org is `deletion_scheduled`,
  the org owner may sign in with password and second factor.
  - The session is marked restricted. It works like today's `enrollment_only` sessions
    (`pg_schema.go:56`, refused by `mfa_session_access` at `:539`).
  - It reaches only the export page, the export download and sign-out.
  - It issues no codes or tokens and opens no suite or forward session.
  - A test calls every other route with such a session and expects a refusal.

### Migration of an existing install (schema version 6)

One migration (`migrations.go:23` list), on both backends:

1. Create `orgs` and insert the default org: the fixed ID
   `00000000-0000-0000-0000-000000000001`, `all_apps=TRUE`, `max_seats=0`, status
   `active`. Its name comes from `branding_org_name` (`branding.go:14`), or "Organisation".
2. Add `org_id`, defaulting to the default org, to every org-owned table.
3. Add the triggers, the composite uniques and the view changes.
4. Record `tenancy_mode=single`, unless the database is empty and `KYIDENTITY_TENANCY=multi`.
   In that case no default org is created, and step 1 inserts nothing.

With one org and `all_apps=TRUE`, every view returns the same rows as before. That is the
zero-change argument, and the upgrade test proves it.

Converting an existing single-tenant install into a multi-tenant one is out of scope for v1.
The fixed default org ID leaves room to add it later.

### Replicas, Postgres and backups

- `tenancy_mode` joins the replica configuration fingerprint. Replicas cache nothing about
  orgs beyond the existing 30 s forward-auth answer cache, and suspension deletes forward
  sessions anyway.
- Org status is read in the same query as user status, so a suspension takes effect on
  every replica at the next request.
- Backups stay whole-install capsules, unchanged. Per-org backup is not offered. Per-org
  **export** (JSON: org, users without credentials, groups, memberships, assignments, the
  org's audit) is available to the org owner while a deletion is scheduled, and on request.
- `migrate-to-postgres` and `restore` copy `orgs` like any table (`pgcopy.go` is driven by
  the catalogs, `AGENTS.md:194`).

## Isolation enforcement

**`OrgStore`.** `func (s *Store) Org(id OrgID) *OrgStore` returns a handle that holds the
org ID. Every store method that reads or writes an org-owned table moves onto `OrgStore`
and binds `org_id` itself. The `*Store` versions are removed, not kept beside it, so a
handler cannot call the unscoped one.

- `OrgID` is a distinct type. The only way to build one is from an authenticated principal:
  a session's user, a SCIM connector, a suite call's `sub`, or a platform request's path,
  which the platform layer checks against `orgs`.
- A handler gets its `OrgStore` from the request context, put there by middleware. Single
  tenant binds the default org, so handlers have one code path.

**Pre-org lookups** stay on `*Store`, because they find the principal that decides the org.
They are an allowlist in code:

- user by username or email at sign-in and forgot-password (`store.go:937-943`)
- session by token hash
- SCIM token (`scim_inbound.go:243`)
- authorization code, refresh token and step-up token by hash
- passkey by credential ID
- device sign-on JTI

Each returns a principal carrying `org_id`. The caller must go through `OrgStore` for
anything after that.

**Platform-level workers.** The sync dispatcher, reconcile, the housekeeping sweeps and
alerts read across orgs through a `PlatformStore`. That handle exposes only the worker
queries, and every row it returns carries `org_id`, so each payload is stamped with the
row's own org.

**Postgres row-level security** would add a second layer: a non-owner role, policies of
`org_id = current_setting('ky.org')`, and `SET LOCAL` per transaction. The work is real and
unverified. `pgdialect` wraps statements in its own transactions (`AGENTS.md:191`), and the
read pool and every worker would need a bypass role. Deferred (open question 7).

**Tests:**

- `TestEveryTableIsClassified` reads both catalogs (as `TestBackendsHaveTheSameColumns`
  does) and requires every table to appear in exactly one of `orgOwnedTables`,
  `derivedTables` (each with its parent foreign key) or `platformTables`. A new table with
  no classification fails the build.
- `TestOrgOwnedTablesHaveOrgID` requires every org-owned table to have a non-null `org_id`,
  the existence and immutability triggers, and, on Postgres, the foreign key to `orgs`.
  The exceptions are `nullableOrgID = {"audit_events", "alerts"}`, which must be nullable.
  The test fails if any other table appears there.
- `TestOrgSQLNamesOrgID` is a go/ast scan of the string literals in `internal/store`. Any
  SQL that names an org-owned table must also name `org_id`, or be on the pre-org or
  platform allowlist with a reason. It is crude, and it is cheap.
- `TestCrossOrgMatrix` is in the style of `TestPermissionMatrixCoversEveryAdminRoute`
  (`internal/api/permissions_test.go:15`), which enumerates the route table:
  - Set up orgs A and B. Each has an owner, an admin, a helpdesk, an auditor, an app owner,
    a member, a SCIM connector and a suite group.
  - For every admin, account, SCIM and suite route, call it as each A principal with B's
    object IDs. Expect `404`, or an empty list, with B's rows unchanged.
  - Call it again with A's IDs, expecting what the permission matrix already expects.
  - Call every `platform` route (see Roles) as every org persona, owner included. Expect
    `404`, with the global rows unchanged.
  - Runs on Postgres in the `postgres` CI job.
- Token tests: a user's `org_id` reaches the ID token, the access token, userinfo and the
  logout token, and changing `users.org_id` is refused.

## Roles

| Mode | Principal | Can | Cannot |
|---|---|---|---|
| Single | Administrator (`role='admin'`) and delegations (`permissions.go:17-41`) | Unchanged | Unchanged |
| Multi | **Org owner**: an everyday account with a new `owner` delegation kind | Every admin route that acts on its org's rows (below). Export and the deletion state. | Change the plan or seats (billing does that), act in another org, call any `platform` route |
| Multi | **Org admin**: everyday account with a new `admin` delegation kind, or a dedicated `role='admin'` account in the org | Same as owner, except it cannot remove or demote the owner | Same as owner |
| Multi | Helpdesk, auditor, app owner | Unchanged, inside the org | — |
| Multi | Member | Unchanged | — |
| Multi | **Platform operator**: a platform token, or the container-local CLI | Org lifecycle, plan, limits, counts (seats, pending invites, connectors), platform audit, owner recovery | List or read an org's users, groups, audit details, sessions or settings through any API. Sign in as a user. |

Notes:

- The owner and org admins are everyday accounts. In a person's or a household's org the
  owner also uses KyPost, and dedicated admin accounts are left out of the suite directory
  (`docs/SUITE-DIRECTORY.md`, people).
- `accessFor` (`permissions.go:65`) maps the `owner` and `admin` delegations to
  `Access.Admin`, scoped by `OrgStore`.
- `Access.Admin` alone is not enough for routes that write global resources. `permission`
  (`permissions.go:17`) gains a `platform` flag, and every route names it or not, as each
  route already names its permission. In multi-tenant mode a `platform` route answers
  `404` to every org principal and is reached only through the container-local CLI. In
  single-tenant mode the flag changes nothing.
  - **Platform:** OAuth clients (create, edit, delete, secret rotation, back-channel URI);
    paired systems and outbound connectors; app registry policy, linking, `requestable`
    and launcher-card settings; `app_roles` definitions (create, rename, delete,
    administrator flag); launcher cards and icons; proxy apps; mail, session limits, alert
    settings, attestation, rate-limit networks and push relays; backups, the drill and
    recovery keys; installer resources.
  - **Org:** users, groups, memberships, delegations, app and role *assignments*,
    `org_apps.access_mode` for apps the plan enables, access requests and approvals,
    expiry, offboarding, enrollment policies, inbound SCIM connectors and tokens,
    sessions, and the org's audit and alerts.
  - PR 2 adds the flag and fails the build for an admin route that names neither.
- The `administrators` enrollment scope already counts anyone holding a delegation
  (`pg_schema.go:522`), so these kinds are covered with no view change.
- The last-admin rule (`ErrLastActiveAdmin`, `expiry.go:28`) becomes per org, and also
  requires one active owner.

Emergency access:

- **Single-tenant:** unchanged. `bootstrap-admin`, `disable-user` (`docs/RUNNING.md:593-610`).
- **Multi-tenant:** `bootstrap-admin` is refused, because there is no global admin.
  - `kyidentity org owner-recovery --org <id>` (CLI) and
    `POST /platform/v1/orgs/{id}/owner-recovery` (API) issue a reset link to the owner's
    email on file. The CLI prints the link once. The API sends it by mail only.
  - Neither can change the owner's email. If the billing account is taken over, it must not
    lead to taking over the org.
  - Each use is audited in the org's own log, which the owner can see.

**Platform settings in multi-tenant mode.** Some settings are platform-wide (see Per-org
features): mail, session limits, alert settings, attestation, rate-limit exemptions, push
relays and backup pairing.

- Today a global administrator sets them in the admin UI, with step-up.
- Multi-tenant mode has no such account, so they are set with container-local commands:
  `kyidentity platform-settings show|set <area>`, plus the existing environment variables.
  This is the channel `apply-setup` and `disable-user` already use (`AGENTS.md`, installer
  setup), and it needs no listener and no session.
- Each change is audited as a platform event (`org_id` NULL).
- The admin UI routes for these settings answer `404` to org admins.
- Startup does not require mail. Until mail is configured, `POST /platform/v1/orgs` and
  owner recovery answer `503 mail_not_configured` and create nothing. Billing retries with
  the same idempotency key.

## Tokens and suite contracts (multi-tenant)

**Claims.** Added in multi-tenant mode only (D4):

- `org_id` in the ID token and userinfo (`identityClaims`, `oauth.go:619`), the access
  token (`oauth.go:502-511`), the device-assertion token (`device_assertion.go:351`) and
  the back-channel logout token (`backchannel.go:30`).
- `org_id` is an opaque UUID. No org name goes in tokens.
- `ClaimsSupported` (`oauth.go:85`) lists it.

**Suite directory** (`docs/SUITE-DIRECTORY.md`). The caller is a global confidential client
(`suite_handlers.go:42`), so the org comes from the data, never from the client:

- `/api/suite/apps?sub=` and `/api/suite/people?sub=`: the org is the `sub` user's. People
  lists only that org's users. `/apps` without `sub` stays global: launch URLs only.
- `/api/suite/groups` requires `org_id` in multi-tenant mode (`400` without it) and lists
  that org's suite groups.
- **New `/api/suite/orgs`** lists orgs for the calling app: `id`, `status`, `revision`, and
  that app's `enabled` and `quotas` only. It pages, with `since=<revision>` so a poll is
  cheap. Apps poll about every 60 s, as they already poll groups.
- `/api/suite/peer`: the pair secret is per pair, not per org (`suite_handlers.go:159`).
  That is acceptable, since both sides are platform-run. Every peer-to-peer payload must
  carry `org_id`, and the receiver must check it matches its local account's org.
  Unverified: what each pair sends today.

**Outbound sync** to suite apps. The signed webhook body gains `org_id`. `syncauth.Sign`
covers the payload (`sync.go:560`), so the org is authenticated. Generic outbound SCIM
targets (customer-owned) are off in multi-tenant v1 (see Per-org features).

**Downstream contract.** In shared multi-tenant mode an app must:

1. Refuse a token without `org_id`.
2. Key every row by `org_id`.
3. Bind a local account to `(sub, org_id)`, and refuse a known `sub` that arrives with a
   different `org_id`.
4. Take the org only from a verified token, a signed webhook or a suite answer. Never from
   a URL, a form or a header.
5. Stop serving an org whose `/api/suite/orgs` status is not `active`. Keep its data unless
   the status is `deleted`.
6. Enforce its own quotas from `/api/suite/orgs`.

Each app's PR documents its half against this list.

## Platform provisioning API

**Listener.** `KYIDENTITY_PLATFORM_LISTEN` (for example `10.0.0.5:5868`). Unset means no
platform API, and it is always unset in single-tenant mode. Plain HTTP, like the main
listener (`docs/RUNNING.md`), so TLS or mTLS is terminated by a private proxy (open
question 12). Nothing on it is served on the public listener, and nothing from the public
listener is served on it.

**Authentication.**

- `Authorization: Bearer kyp_<id>_<secret>`, 256 bits. Only the SHA-256 is stored, as with
  SCIM tokens.
- Scopes: `orgs:read`, `orgs:write`, `orgs:delete`.
- Created and revoked only with `kyidentity platform-token create|revoke|list`. The CLI
  prints the token once and audits each action.
- Failed authentication is rate limited per IP, and each token is rate limited.
- Every call is audited as `platform.*`, with the token ID as the actor.

**Idempotency and order.**

- Every `POST`, `PATCH` and `DELETE` needs `Idempotency-Key` (1–128 characters).
- `platform_requests` stores the request hash and the response, in the same transaction as
  the change. The same key and hash returns the stored response. The same key with a
  different hash is `422 idempotency_conflict`.
- Writes carry `revision`, a per-org counter the billing service increases. One at or below
  `orgs.billing_revision` is `409 stale_revision` with the current value.
- `billing_ref` is unique. A `POST /orgs` whose `billing_ref` already exists is decided
  first, before the idempotency and revision rules:
  - If the create fields match the stored org, it is `200` with the existing org.
  - If they do not, it is `409 billing_ref_conflict`.
  - A retry under a new key, or after the 30-day `platform_requests` window, therefore
    gets the same answer.

**Endpoints** (`/platform/v1`). Bodies hold no personal data except the owner's name and
email on create.

| Route | Scope | Effect |
|---|---|---|
| `POST /orgs` | write | `{name, kind, plan, max_seats, apps:{client_id:{enabled, quotas}}, owner_email, owner_name, billing_ref, revision}`. Creates the org and a pending owner, and sends an activation invite by mail (`account_tokens`, delivery `email`). `503 mail_not_configured`, creating nothing, until platform mail is set (see Roles). `409 email_in_use` if the email exists anywhere. |
| `GET /orgs/{id}`, `GET /orgs?status=&billing_ref=&cursor=` | read | Status, reason, plan, limits, `seats_used`, `pending_invites`, `owner_activated`, `delete_after`, `revision`. No names or emails of users. |
| `PATCH /orgs/{id}` | write | Plan, `max_seats`, apps and quotas, name. Lowering seats below the number used is accepted: the org is marked `over_limit`, new seats are refused, and nobody is disabled. |
| `POST /orgs/{id}/suspend` | write | `{reason: payment\|abuse, revision}`. Semantics below. |
| `POST /orgs/{id}/resume` | write | From `suspended`, or from `deletion_scheduled` before `delete_after`. Sign-in works again. Sessions do not come back. |
| `POST /orgs/{id}/schedule-deletion` | write | `{grace_days 7–90, revision}`. Suspends the org and sets `delete_after`. The owner can still sign in to a restricted, export-only session (the `active_principals` exception under Views). |
| `DELETE /orgs/{id}` | delete | Only for `deletion_scheduled` once `delete_after` has passed, otherwise `409`. Deletes every org-owned and derived row in one transaction and leaves the tombstone. That includes the org's `audit_events`. This is a second, named audit-deletion path beside `DeleteAuditEventsOlderThan`, and the audit retention contract in `AGENTS.md` must be amended to say so. The org's audit is in the owner's export. In the same transaction, a platform audit row (`org_id` NULL), `platform.org_deleted`, records the org ID, the token and row counts per table, with no content. If it cannot be written, nothing is deleted (fail closed). A test proves both. |
| `POST /orgs/{id}/owner-recovery` | write | See Roles. |

**Suspension**, in one transaction with its audit row:

1. Set `orgs.status`.
2. Revoke every session and token grant of the org's users (`revokeSessionGrantsTx`). This
   ends forward sessions too.
3. Queue back-channel logouts for every client session.
4. Hold the org's inbound SCIM: tokens answer `403`.
5. Queue `org.suspended`.

After that:

- Sign-in, refresh, device sign-on and code exchange are refused, because
  `active_principals` excludes the org. Answers are generic.
- Userinfo is refused.
- Suite people, groups and apps for the org's `sub`s return empty lists.
- `/api/suite/orgs` shows `suspended`.
- No data is changed or deleted.

**Events back to billing.**

- Sent from `platform_events` (outbox) to `KYIDENTITY_PLATFORM_EVENTS_URL`. Each is signed
  with `ky-primitives/syncauth`, using a secret sealed at rest and set by
  `kyidentity platform-events set-secret`.
- Types: `org.created`, `org.owner_activated`, `org.seats_changed` (at most one per org a
  minute), `org.over_limit` and `org.within_limit`, `org.suspended`, `org.resumed`,
  `org.deletion_scheduled`, `org.deleted`.
- `over_limit` is **derived**: `seats_used > max_seats`, with `max_seats > 0`. It is not
  stored, and it is not an `orgs.status` value.
  - A transaction that changes either side (a `PATCH` of `max_seats`, a disable, a
    delete) computes the flag before and after. When it flips, it queues
    `org.over_limit` or `org.within_limit` in the same transaction.
  - Seat-adding transitions are refused while the org is at or over the limit, so they
    never flip it.
  - `GET /orgs/{id}` returns the derived `over_limit`.
- Body: `{event_id, type, org_id, billing_ref, revision, status, seats_used, at}`. No
  personal data.
- Delivery is at least once and unordered. Billing de-duplicates by `event_id` and orders
  by `revision`.

## Entitlements

KyIdentity stores `max_seats` on `orgs`, and per-app enablement and opaque quotas in
`org_apps`. Who enforces what:

- **KyIdentity enforces seats and app enablement.**
  - A seat is an everyday account (`role='user'`) that is active or pending (open
    question 8).
  - Only a transition that adds a seat is checked: a user create, an invite, a SCIM create,
    or re-enabling a disabled account. One that would pass `max_seats` is refused with
    `seat_limit`.
  - Activation never is, because the pending account already holds its seat. An invited
    user can activate even while the org is `over_limit`.
  - A disabled app gives no access: the `app_access_facts` join above means no token and no
    suite listing.
- **Apps enforce their own quotas** (storage, mailboxes) from `GET /api/suite/orgs`.

Why a suite API pull:

- A claim goes stale for a token's lifetime and grows every token.
- A claim shows each app the others' quotas, unless it is filtered per audience, which
  adds work for no gain.
- A webhook needs a new receiver, ordering and retry rules in every app. The suite groups
  spec rejected that for the same reasons (`2026-11-15-suite-groups-design.md`, "How apps
  learn of suite groups").
- Every app already polls the suite directory with its client credentials.

## Per-org features

| Feature | Multi-tenant v1 | Notes |
|---|---|---|
| Users, groups, delegations, access requests, expiry, offboarding | Per org | `OrgStore` |
| App assignment, app roles assignment | Per org | Roles themselves are global (appendix) |
| MFA enrollment policies (`enrollment_policies`) | Per org | The `organization` scope becomes the org's |
| Inbound SCIM connectors | Per org, plan-gated | A connector's token authenticates into its org. Seats apply. |
| Outbound to suite apps (`paired_systems` of suite types) | Platform | Payload carries `org_id` |
| Generic outbound SCIM to customer targets | Disabled | Would need per-org `paired_systems`, held per org |
| HR provisioning | Disabled | Reserves a KyPost address per `domain` (`hr.go:46`). Per-org domain ownership is not designed. |
| Forward-auth proxy apps | Disabled | Hosts and edge secrets are install-wide (`2026-11-15-forward-auth-design.md`) |
| Custom launcher cards (`applications`) | Disabled for orgs | Platform cards only |
| Upstream SSO / federation | Absent | Does not exist today (`docs/access-lifecycle-plan.md:73`, `design.md:32`) |
| Branding (`branding_org_name`, `branding_logo`) | Platform only | The sign-in page comes before the org is known. The org name shows after sign-in (open question 6). |
| Session limits, mail, alerts settings, attestation, rate-limit exemptions, push relays | Platform | `system_settings` keys (`session_limits.go:13`, `sealed.go:30`) |
| Installer setup (`apply-setup`, `proxy-app`) | Refused | The installer channel is single-tenant |
| Backups, restore, drill | Platform | Whole install |
| Audit log | Per org view, plus platform | `audit_events.org_id`, NULL for platform events |

## Phased build plan

Each PR is shippable on its own, with single-tenant behaviour unchanged. `KYIDENTITY_TENANCY=multi`
is refused at startup until PR 6 lands. Before then, an org could have an owner who cannot
administer it, or a plan whose seats are not enforced. Until PR 6, multi-tenant code runs
only in tests.

1. **Org model and default-org migration.**
   - Adds schema version 6 on both backends: the tables, columns, triggers and views above,
     and `tenancy_mode`.
   - On Postgres only, it widens the `admin_delegations.kind` CHECK (`delegations.go:29`)
     to admit `owner` and `admin`, so no later schema change is needed for them.
     - On SQLite a CHECK changes only by a table rebuild, which D2 rules out. SQLite is
       single-tenant only and never uses these kinds, so it keeps the CHECK.
     - `TestBackendsHaveTheSameColumns` compares names, not CHECKs, so it is unaffected.
   - Tests:
     - An upgrade test from a version 5 database on both backends (`upgrade_test.go`
       style). Every view returns the same rows before and after.
     - `TestEveryTableIsClassified` and `TestOrgOwnedTablesHaveOrgID`.
     - `TestBackendsHaveTheSameColumns` still passes.
     - The full `go test -race ./...` and the `postgres` job.
2. **Store scoping.** `OrgStore`, `PlatformStore` and the pre-org allowlist. Split by area so
   each PR stays reviewable: (a) users, groups and memberships, (b) apps, assignments and
   roles, (c) sessions and credentials, (d) provisioning, SCIM and audit.
   - Tests: `TestOrgSQLNamesOrgID`, and `TestCrossOrgMatrix`, which grows with each sub-PR.
     It runs with a test-only multi-org constructor on Postgres. Existing tests pass
     unchanged on the default org.
3. **Org claim, suite APIs and webhooks.**
   - Adds `org_id` in tokens, userinfo and the logout token, and `org_id` scoping on the
     suite routes. Adds `/api/suite/orgs` and `org_id` in sync payloads, all gated on mode.
   - Tests: single-tenant golden tokens are byte-identical apart from `jti`, `iat` and
     `exp`. Multi-org suite tests. A `ky-primitives/suitedir` `Orgs` method.
4. **Platform provisioning API.** The listener, tokens and CLI, idempotency, revision,
   create, update, suspend, resume, deletion and owner recovery, the events outbox and
   `active_principals`. The `owner` and `admin` delegations take effect here, mapped to
   `Access.Admin` and kept off `platform` routes, so an activated owner can administer
   the org. The per-org last-owner rule also lands here.
   - Tests:
     - Replay, conflict and stale-revision cases.
     - Suspension ends every grant: a table of every credential type, like
       `TestForwardRevocationWithin30Seconds`.
     - Every sign-in path refuses a suspended org.
     - Delete removes every org row, checked against the table classification.
     - Platform tokens are refused on the public listener, and browser and SCIM
       credentials are refused on the platform listener.
     - Events are signed and retried.
5. **Org owner and admin UI.**
   - Adds the UI for owner and admin delegations, per-org last-admin rules, a seats
     display, the export, the scheduled-deletion banner, and per-org enrollment policy UI.
   - Tests: the extended permission matrix, the existing UI verification flow
     (`UI-VERIFICATION.md`), and the export's content proven to hold no other org's rows.
6. **Entitlements.**
   - Seat enforcement on every create path (admin, SCIM, invite, activation), `over_limit`,
     `org_apps` from the platform API, and quotas in `/api/suite/orgs`.
   - Tests: the seat limit on each path under concurrency (two replicas, the
     `replica_proofs_test.go` style), and app disablement removing access and suite
     listing.
7. (Optional) **Postgres row-level security** as extra protection.

## Open questions for the owner

1. **Multi-tenant only on Postgres?**
   - (a) Yes.
   - (b) Also SQLite, through table rebuilds outside a transaction (a new kind of migration,
     with foreign keys off).
   - Recommend (a). The SaaS runs on Postgres replicas anyway, and (b) risks cascading
     deletes during a rebuild.
2. **`org_id` in single-tenant tokens?**
   - (a) Never.
   - (b) Always, with the default org's ID.
   - Recommend (a) for zero change. Apps treat an absent claim as single-tenant.
3. **Email squatting by a pending account in another org.**
   - (a) First come, first served, released by the operator.
   - (b) A pending, never-activated account is deleted when its activation token expires,
     which frees the address.
   - Recommend (b), with a 7-day activation lifetime in multi-tenant mode.
4. **Dedicated admin accounts in multi-tenant orgs?**
   - (a) Allowed.
   - (b) Only everyday accounts with owner or admin delegations.
   - Recommend (a), optional. The owner is always an everyday account.
5. **What a suspended org's user sees after a correct password and second factor.**
   - (a) The generic invalid-credentials answer.
   - (b) "Your organisation is suspended".
   - Recommend (b). Only a holder of valid credentials learns anything.
   - Either way, the owner's export-only session during scheduled deletion stays as
     designed above.
6. **Per-org branding.**
   - (a) Never.
   - (b) After sign-in only (launcher, account pages), later.
   - Recommend (b), after v1.
7. **Postgres row-level security.**
   - (a) In v1.
   - (b) After PR 2's app-level isolation is proven.
   - Recommend (b).
8. **What is a seat?**
   - (a) Active and pending everyday accounts.
   - (b) Active only.
   - (c) Every account, dedicated admins included.
   - Recommend (a): an invite reserves a seat, so a plan cannot be exceeded by inviting.
9. **Capacity of the single writer.** Accept for v1, and set a measured target (orgs,
   sign-ins a minute) before launch? Recommend yes. Revisit per-org write locks only if the
   measurement fails.
10. **Inbound SCIM in v1, for business orgs?**
    - (a) Yes, plan-gated.
    - (b) Later.
    - Recommend (a). The connector is already scoped to its own accounts (`docs/PROVISIONING.md`, Inbound SCIM).
11. **Grace period and export.** Bounds of 7–90 days, and the owner downloads the export. Or
    should billing also get a copy? Recommend the owner only: the billing service never
    holds users' data.
12. **Platform API transport.**
    - (a) Bearer token on a private listener.
    - (b) (a) plus mTLS at a private proxy.
    - (c) (a) plus a `syncauth` HMAC signature on every request.
    - Recommend (a) when billing runs on the same private network, and (b) otherwise. (c)
      adds little when the bearer travels on the same channel.

## Appendix: table inventory

Classes:

- **O** (org-owned): gets `org_id`.
- **D** (derived): scoped through the parent named, no column of its own.
- **P** (platform): global.
- **I**: interim. A class is fixed for PR 1, and the reasoning says what would change it.

SQLite sources are listed. The Postgres v1 definitions are in `pg_schema.go`, at the line
given. Migrations 2–4 use one SQL text on both backends, with only the column types substituted.

| Table | SQLite | PG | Class | Reasoning |
|---|---|---|---|---|
| `schema_migrations` | `migrations.go:50` | `:12` | P | Schema version |
| `leases` | `shared_state.go:29` | `:17` | P | Process coordination across replicas |
| `users` | `store.go:122` | `:19` | O | Root of every org's data. Username and email stay global (D5). |
| `installer_setup_resources` | `store.go:134` | `:31` | P | Installer channel, single-tenant only. Its objects are in the default org. |
| `directory_groups` | `store.go:139` | `:36` | O | Per-org name unique (Postgres) |
| `group_memberships` | `store.go:143` | `:41` | O | Joins two org-owned rows. A composite FK keeps both in one org. |
| `sessions` | `store.go:150` | `:47` | D | `user_id` FK. Found by token hash, a pre-org lookup. |
| `login_failures` | `store.go:163` | `:58` | D | `user_id` FK |
| `paired_systems` | `store.go:171` | `:66` | I: P | Suite app targets are shared. Customer-owned generic SCIM targets (disabled in v1) would need a nullable `org_id` later. |
| `account_sync_events` | `store.go:184` | `:79` | O | `user_id` has no FK, and events outlive the user. The payload needs the org after deletion. |
| `native_devices` | `store.go:724` | `:95` | D | `user_id` FK |
| `device_pairing_tokens` | `store.go:202` | `:118` | D | `user_id` FK |
| `device_signon_jtis` | `store.go:215` | `:130` | P | Replay ledger. JTIs are globally unique. |
| `mfa_methods` | `store.go:220` | `:135` | D | `user_id` FK |
| `mfa_challenges` | `store.go:233` | `:146` | D | `user_id` FK |
| `mfa_tokens` | `store.go:245` | `:157` | D | `user_id` FK |
| `recovery_codes` | `store.go:257` | `:168` | D | `user_id` FK |
| `oauth_clients` | `store.go:266` | `:176` | P | Owner decision: apps are global |
| `authorization_codes` | `store.go:280` | `:190` | D | `user_id` FK. Found by hash. |
| `launcher_icons` | `store.go:296` | `:205` | P | Icons of platform cards |
| `applications` | `store.go:303` | `:212` | I: P | Custom org cards are disabled in v1. Becomes O if orgs get their own cards. |
| `issued_tokens` | `store.go:317` | `:223` | D | `user_id` FK |
| `audit_events` | `store.go:328` | `:232` | O | Nullable `org_id`: NULL means a platform event. This is the one nullable exception (`nullableOrgID`, and the NULL case in its triggers). |
| `system_settings` | `store.go:343` | `:246` | P | Platform settings. Future per-org settings go into a new `org_settings` table, never prefixed keys. |
| `step_up_tokens` | `store.go:352` | `:252` | D | `user_id` FK |
| `webauthn_credentials` | `store.go:363` | `:262` | D | `user_id` FK. `credential_id` is global (one RP). |
| `webauthn_challenges` | `store.go:378` | `:276` | D | `user_id` FK |
| `scim_user_links` | `scim.go:10` | `:287` | O | `local_id` has no FK, is a user or a group, and survives local deletion. Same reason as `account_sync_events`. |
| `sync_delivery_attempts` | `sync_delivery.go:24` | `:295` | O | No FK on `user_id`. Giving it `org_id` is cheaper than proving every reader joins `users`. |
| `step_up_challenges` | `stepup.go:34` | `:300` | D | `user_id` and `session_id` FKs |
| `app_registry` | `app_registry.go:70` | `:308` | P | One record per global client, card or system. Per-org mode lives in `org_apps`. |
| `app_user_assignments` | `app_access.go:34` | `:316` | D | `user_id` FK. The app is global. |
| `app_group_assignments` | `app_access.go:37` | `:320` | D | `group_id` FK |
| `authorization_interactions` | `authorization_interactions.go:34` | `:324` | P | Pre-sign-in flow state, keyed by hash and browser. `user_id` is `''` until bound, then it is checked against the session's user, whose org scopes everything after. |
| `oidc_client_sessions` | `client_sessions.go:19` | `:329` | D | `session_id` FK |
| `account_tokens` | `onboarding.go:30` | `:333` | D | `user_id` FK |
| `scim_connectors` | `scim_inbound.go:42` | `:339` | O | A connector belongs to one org. Its token decides the org. |
| `scim_connector_tokens` | `scim_inbound.go:45` | `:343` | D | `connector_id` FK |
| `app_roles` | `app_roles.go:76` | `:348` | I: P | Roles describe a global app, and their definitions are `platform` routes. Becomes O if orgs define their own roles. |
| `app_role_user_assignments` | `app_roles.go:80` | `:352` | D | `user_id` FK |
| `app_role_group_assignments` | `app_roles.go:83` | `:356` | D | `group_id` FK |
| `admin_delegations` | `delegations.go:27` | `:360` | D | `user_id` FK. New `owner` and `admin` kinds. |
| `access_requests` | `access_requests.go:70` | `:367` | D | `user_id` FK |
| `logout_deliveries` | `logout_deliveries.go:34` | `:376` | O | `user_id` has no FK, and deliveries outlive the user. The logout token carries `org_id`. |
| `enrollment_policies` | `group_enrollment.go:50` | `:382` | O | Primary key becomes `(org_id, scope)` on Postgres. The `organization` scope is per org. |
| `enrollment_deadlines` | `group_enrollment.go:55` | `:388` | O | FK to `(org_id, scope)` |
| `sync_resource_state` | `provisioning.go:35` | `:391` | O | `resource_id` has no FK, and offboarded rows persist after deletion |
| `sync_reconcile_jobs` | `reconcile.go:30` | `:398` | P | Per system, across every org. Per-org repair is later. |
| `alerts` | `alerts.go:82` | `:408` | O | Nullable `org_id` (`nullableOrgID`). Org rules (failed sign-ins) go to the org's admins. Platform alerts (NULL) have no user recipient, only the log, until a platform channel exists. |
| `alert_queue` | `alerts.go:92` | `:417` | D | `event_id` FK to `audit_events` |
| `alert_deliveries` | `alerts.go:98` | `:421` | D | `alert_id` FK. The recipient is an org admin. |
| `launcher_prefs` | `launcher_prefs.go:82` | `:430` | D | `user_id` FK |
| `refresh_families` | `refresh_tokens.go:52` | `:436` | D | `jti` FK to `issued_tokens` |
| `refresh_tokens` | `refresh_tokens.go:63` | `:448` | D | `family_jti` FK |
| `rate_limits` | `shared_state.go:20` | `:456` | P | Buckets keyed by IP and principal IDs |
| `push_relay_keys` | `shared_state.go:22` | `:458` | P | Install's relay registration |
| `proxy_apps` | `forward_auth.go:19` | (migration 2) | P | Disabled in multi-tenant v1. The host is install-wide. |
| `forward_codes` | `forward_auth.go:23` | (migration 2) | D | `user_id` and `session_id` FKs |
| `forward_sessions` | `forward_auth.go:29` | (migration 2) | D | `user_id` FK |
| `hr_connections` | `hr.go:46` | (migration 3) | D | `connector_id` FK to `scim_connectors`. Disabled in multi-tenant v1. |
| `hr_workers` | `hr.go:51` | (migration 3) | D | `connector_id` FK |
| `suite_groups` | `suite_groups.go:16` | (migration 4) | O | A tombstone with no FK, so it needs its own `org_id`. Slug unique per org. Unverified: whether any app uses the slug in a global namespace (for example KyPost list addresses). |
| `suite_group_apps` | `suite_groups.go:19` | (migration 4) | D | `group_id` FK to `suite_groups` |

`account_sync_events_new` (`store.go:872`) is a temporary name inside the legacy rebuild,
not a live table.
