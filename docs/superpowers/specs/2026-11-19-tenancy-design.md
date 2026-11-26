# Tenancy: single-tenant and multi-tenant (SaaS), design

Date: 2026-11-19. Owner decisions: 2026-11-19 tenancy brief (fixed, listed below). Worker:
tenancy-spec. Status: approved design. PRs 1–3 are built. Amended 2026-11-21 with Delete everything and
the `export_only` claim (K open question 4 (a)), and with Mailbox address (multi-tenant), from the owner
answer to KyPost open question 1. Amended 2026-11-22 with Home region (owner decision on multi-region apps).
Amended 2026-11-23 with Plans and orgs (owner decisions: every paid plan, Business included, is an org on
the shared install; only Enterprise gets a dedicated one), and with Org storage pool (owner decisions:
one storage quota per org across all apps, held by KyIdentity; the over-quota rule for a seat change).
Amended 2026-11-23 again with the owner's answers to Plans and orgs owner questions 1, 7 and 8, shared
content under Delete everything, no automatic version pruning, and object storage only in multi-tenant
mode (ky-launch#4).

KyIdentity today is one organisation per install (`AGENTS.md:3`, `design.md:31` defers
multi-tenancy). This spec adds a second mode to the same binary. **Single-tenant** is
today's behaviour, unchanged for existing installs. **Multi-tenant** is a hosted service
where every paid account (Personal, Couple, Family or Business) is an *organisation* (org), all under one
issuer, one sign-in page and one WebAuthn relying party. Our own staff administer it.

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
6. In multi-tenant mode, nobody in a customer org is an administrator. The only
   administrators are our own staff. There are no org owners, no org admins and no
   delegations inside customer orgs. Every customer account is a member. Single-tenant is
   not affected: self-hosted installs keep today's administrators and delegations
   unchanged.
7. *Superseded 2026-11-23* (see Plans and orgs). Every paid plan is an org on the shared
   multi-tenant service: Personal (1 member), Couple (2), Family (up to 6) and Business (N
   seats, small teams). Only **Enterprise** gets a dedicated install (cloud or on-prem), in
   single-tenant mode with its own administrators and delegations. Staff-only administration
   (decision 6) applies to the shared service, Business orgs included.

Line references are to `master` at `09caf1c`. "Unverified" marks a claim this spec did not
check in code.

## Decisions this spec makes

| # | Decision | Why |
|---|---|---|
| D1 | `KYIDENTITY_TENANCY=single` (default) or `multi`, recorded in `system_settings` at first start. A later start with the other value refuses to start. Added to the shared replica configuration (`internal/config/replica.go:19`). | Install-time, as decided. A replica started with the wrong mode must not serve. |
| D2 | **Multi-tenant requires PostgreSQL.** SQLite stays single-tenant only. Both backends get the same `org_id` columns, so `TestBackendsHaveTheSameColumns` (`internal/store/postgres_test.go:47`) still holds. | Two global uniques must become per-org: `directory_groups.name` (`store.go:139`) and `suite_groups.slug` (`suite_groups.go:16`). On SQLite an inline `UNIQUE` can only be dropped by rebuilding the table. Migrations run inside a transaction (`migrations.go:144`), where `PRAGMA foreign_keys` cannot be turned off. `DROP TABLE directory_groups` with foreign keys on would cascade-delete memberships, assignments and policies. On Postgres these are `ALTER TABLE … DROP CONSTRAINT`. With one org, the global uniques are correct, so SQLite keeps them. |
| D3 | Isolation is enforced in the application, through an org-bound store handle (`OrgStore`). Postgres row-level security is optional extra protection, added later. | The store has one SQL source in SQLite's dialect (`AGENTS.md:192`), and single-tenant installs on SQLite use the same code. App-level scoping is the only mechanism that covers both. |
| D4 | The org is in tokens as an `org_id` claim, **in multi-tenant mode only**. | Zero change for single-tenant relying parties. An absent claim means single-tenant. |
| D5 | Username and email stay globally unique (`pg_schema.go:21,23`). In multi-tenant mode, username = email at creation. | There is one sign-in page, and login looks a user up by username alone (`auth_handlers.go:94`). Using the email means no `alice` collisions between orgs and no new lookup path. |
| D6 | Entitlements reach apps through a suite API pull (`GET /api/suite/orgs`), not a token claim or a webhook. | See Entitlements. |
| D7 | OAuth clients, the app registry, app roles and launcher cards stay global. Each org's access to an app is a new per-org row (`org_apps`). | Owner decision 2 (shared apps). |
| D8 | Staff are accounts in one internal staff org (`orgs.kind='staff'`): `role='admin'`, or everyday accounts with today's delegations. In multi-tenant mode the store refuses `role='admin'` and any `admin_delegations` row for an account outside the staff org. | Owner decision 6. No new role or delegation kind, so `accessFor` (`permissions.go:66`) and the permission matrix stay as they are. |
| D9 | One member of each customer org may be the **account holder** (`orgs.account_holder_user_id`), named by billing. It is a pointer, not a role: it maps to no `Access` field. | Export, the deletion banner and member-change notices need a person to go to. Billing already knows who pays. |
| D10 | In multi-tenant mode, MFA enrollment policies are platform-wide, set by staff. `group:` scopes are refused. *Amended 2026-11-23:* staff may also require MFA for one customer org's members (scope `org:<org_id>`, Plans and orgs P5). It only adds a requirement, never removes one. | A household has nobody to ask for a different policy. A business may ask staff to require MFA for its members; the `org:` scope key is globally unique (the org ID), so it needs no per-org primary key (D2). Staff stay the only administrators. |

## Threat model

| Attacker | Goal | Defence |
|---|---|---|
| Member of org A, or staff working in org A | Read or change org B's users, groups, assignments, audit or policy by putting B's IDs in account, suite or admin calls | Every org-owned query runs through an `OrgStore`. For a member or a suite call it is bound to the authenticated principal's org, never to the request. For staff it is bound to the org the staff member selected (see Roles), and only after the caller is proven to be staff. A cross-org ID is `404`, the same answer as a missing one. Composite foreign keys on `group_memberships` make a cross-org membership impossible to write at the database level. An assignment has only one org-owned side, so it cannot span two orgs. Proven by the cross-org matrix test. Inbound SCIM and HR connectors are off in multi-tenant mode (see Per-org features), so they are no path. |
| Member of org A | Gain access through a global app set to `all_active_users` that A's plan does not enable | Today `app_access_facts` is `app_registry CROSS JOIN users` (`pg_schema.go:512-517`), so that mode means every user on the install. The view gains a required join on `org_apps`/`orgs.all_apps` for the user's org. A test gives one org an app with all-users access and proves the other org's users get no access. |
| Malicious relying party, or a bug in one | Forge or swap `org_id` | Tokens are RS256, signed by KyIdentity (`oauth.go:502`). `org_id` is read from `users.org_id` at issuance, never from the request. `users.org_id` is immutable: a trigger refuses any update, on both backends. Apps must take the org only from a verified token or a suite API answer (see Downstream contract). |
| Thief of a platform token | Create, suspend or delete orgs; add or remove members | Platform tokens are 256-bit, stored hashed, scoped, expiring and revocable, like SCIM connector tokens (`pg_schema.go:343`, `scim_inbound.go:243`). They are accepted only on a separate platform listener that is never published through the public proxy. They are never accepted on the public listener, and browser sessions, SCIM tokens and OAuth clients are never accepted on the platform listener. An `orgs:*` token (billing service) reads lifecycle data and counts only, and no user data. A `members:*` token (customer portal) also reads member emails and statuses, and nothing else. A token never holds both kinds. Delete needs its own scope, and only works after a deletion was scheduled and its grace period has passed. Every call is audited. |
| Compromised billing portal (the customer portal of our billing service) | Add or remove members, resend invites, or join an org by adding an attacker's address | The portal's token holds only `members:read` and `members:write`, not the org lifecycle scopes. Member writes are rate limited per org and per token. Each is audited in the org's log, queues an `org.member_changed` event, and mails a notice to the account holder. The added person gets an activation invite at their own address. A new member gets member rights only: no admin route, no export, no recovery of another member. Removing members is disruptive, and staff undo it. Whether member writes also need the account holder's own sign-in is open question 11. |
| Staff abuse, or a stolen staff account | Read or change any org's directory: blast radius is every org | Staff need a passkey second factor, and step-up stays on sensitive routes (see Roles). Every staff read or write in a customer org is audited in that org's log, naming the org, and staff admins read the audit across orgs by actor. There is no impersonation: no "sign in as user", no password set on a customer account, no email change, and activation and reset links go only by mail to the address on file, never to the screen. Residual risk: staff see every org's directory. |
| Replayed or reordered billing calls (Stripe retries, out-of-order webhooks) | Undo a suspension, or apply an old plan | Every mutating call has an `Idempotency-Key`, and every org lifecycle write (`POST /orgs`, `PATCH`, suspend, resume, schedule-deletion) a per-org `revision`. `DELETE` has none: it works only from `deletion_scheduled` after `delete_after`, so a late one after a resume does nothing. The same key and body returns the stored answer. The same key with a different body is `422`. A `revision` at or below the stored one is `409 stale_revision`. |
| User of a suspended or deleted org | Keep working | Suspension revokes every session, refresh family, issued token and forward session in one transaction (`revokeSessionGrantsTx`, `sessions.go:136`), and queues back-channel logouts. Everything that grants or uses access checks one `active_principals` view (user active and org active). Only the credential steps of interactive sign-in skip it, and they grant nothing (see Views). Access tokens live 15 minutes at most (`oauth.go:22`). `/oauth/userinfo` refuses at once. Apps see `status: suspended` within one poll (≤ 60 s). |
| Customer of org A, adding members through the billing portal | Take over a person's identity by creating an account with their email (email squatting) | Emails are globally unique, so whoever creates an address first holds it. A pending account cannot sign in, and resets go only to a verified address (`onboarding_handlers.go:209`). A pending, never-activated account gives up its email when its activation token expires (open question 3). Nobody in another org can edit, reset or claim that account. |
| Anyone at the sign-in page | Find out whether an email exists, or which org it is in | Unknown, inactive and locked accounts all answer like a wrong password, after the same Argon2 cost (`auth_handlers.go:100-104`, `loginRefusal` at `:296`). A suspended org's account gives the same answers until every factor has passed. Only then does it get `org_suspended` (owner answer 4, see Suspension), which only a holder of valid credentials can reach. Forgot-password always answers the same way (`onboarding_handlers.go:178-197`). No sign-in or recovery answer names an org. |
| Customer of org A, adding members through the billing portal | Find out whether an email exists in another org, from a `409` on add | Unavoidable with global uniqueness (D5). The answer is `409 email_in_use`, never "in another org". Adds are rate limited per org. Residual risk. |
| A thief holding a member's password and second factor | Delete the member's data, or a holder's whole org | Step-up with a second factor, the typed address, and an audit row. Step-up and the address stop a stray click, not a thief: residual risk (K). |
| Billing, staff or the holder, after a Delete everything | Take the request back | `org_erasures` rows cannot change or be deleted, and `orgs_erasure_held` refuses `resume` and a new `delete_after` in the database. |
| Operator restoring one org's backup | Load org A's data into org B, or roll every org back | v1 has no per-org restore or import. A capsule is the whole install (`internal/backup`, `store.go:2984`). The per-org export is read-only JSON. Any future import must assign the target org from the org staff selected and new IDs, never from the file. |

Residual risks (accepted):

- **One writer for every org.** Every Postgres write transaction takes one advisory lock
  (`AGENTS.md:198`, `docs/RUNNING.md:343`). A burst of writes in one org delays sign-ins
  (which write `sessions`) in every other org. Per-org rate limits soften this but do not
  remove it. Capacity is unmeasured (open question 8).
- **A restore rolls back every org.** Restoring a capsule to fix one customer's problem
  loses every other customer's writes since that capsule was taken.
- **Global uniqueness leaks existence.** One org can tell an email is taken elsewhere
  (see the table). The billing service's checkout and portal must not echo `email_in_use`
  to a buyer in a way that confirms another customer's address.
- **Offline token validation.** An app that checks JWTs offline keeps serving a suspended
  org for up to 15 minutes, or until its next poll of `/api/suite/orgs`.
- **Staff see every org's directory** (users, groups, sessions, audit), though not app
  content, which lives in the apps.
- **The operator is trusted** with the database, keys and host.

## Data model

### New tables

```
orgs (
  id TEXT PRIMARY KEY,                 -- UUID; never reused
  name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('default','customer','staff')),
                                       -- 'default': the single-tenant org; one 'staff' org in multi;
                                       -- 'customer': every paid plan (Plans and orgs P1)
  status TEXT NOT NULL CHECK (status IN ('active','suspended','deletion_scheduled','deleted')),
  status_reason TEXT NOT NULL DEFAULT '' CHECK (status_reason IN ('','payment','abuse','operator')),
  all_apps BOOLEAN NOT NULL DEFAULT FALSE,  -- TRUE only for the single-tenant default org
  plan TEXT NOT NULL DEFAULT '',
  max_seats BIGINT NOT NULL DEFAULT 0,      -- 0 = unlimited (default and staff orgs)
  account_holder_user_id TEXT,              -- D9. No FK (users references orgs); guarded by
                                            -- triggers, see "Account holder guard"
  billing_ref TEXT UNIQUE,                  -- the billing service's own opaque ID, never a Stripe ID
  create_request_hash TEXT,                 -- hash of the POST /orgs body; write-once
  billing_revision BIGINT NOT NULL DEFAULT 0,
  revision BIGINT NOT NULL DEFAULT 1,       -- KyIdentity's own version, carried in events
  delete_after BIGINT,                      -- unix seconds, set by schedule-deletion
  storage_bytes, storage_per_seat_bytes, storage_over_since,  -- Org storage pool (2026-11-23)
  created_at, updated_at)
org_apps (org_id, app_id REFERENCES app_registry ON DELETE CASCADE,
  enabled BOOLEAN, access_mode TEXT NULL,   -- NULL = app_registry.access_mode
  quotas_json TEXT NOT NULL DEFAULT '{}',   -- opaque to KyIdentity, ≤ 4 KiB
  PRIMARY KEY(org_id, app_id))
platform_tokens (id, name, token_hash UNIQUE, scopes, created_at, expires_at, last_used_at, revoked_at)
                                            -- scopes: orgs:read|write|delete, members:read|write
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
- `group_memberships` is the only table that joins two org-owned rows (a user and a
  group). It references `(org_id, user_id)` and `(org_id, group_id)`. On SQLite these are
  trigger checks.
- `suite_groups` has no foreign key (it is a tombstone). A `BEFORE INSERT` trigger requires
  its `org_id` to equal the `directory_groups` row's, and the immutability trigger keeps it.
- The four assignment tables (`app_user_assignments`, `app_group_assignments`,
  `app_role_user_assignments`, `app_role_group_assignments`) join one org-owned row to a
  global app or role. They have no second org to disagree with, so they stay derived (no
  `org_id`) and take the org of their user or group. Assigning org B's group while working
  in org A fails earlier: `OrgStore` resolves the group by `(org_id, id)` and answers
  `404`.
- Per-org uniques, on Postgres only (D2): `directory_groups(org_id, name)` and
  `suite_groups(org_id, slug)`.
- `users.username`, `users.email` and `webauthn_credentials.credential_id` stay global
  (D5, one RP).

Views (`app_access.go:58-65`, `pg_schema.go:510-545`):

- `app_access_facts` joins `orgs` and `org_apps` on `u.org_id`. An app counts for a user
  only when `o.all_apps` is set or an `org_apps` row is enabled, and the access mode is
  `COALESCE(oa.access_mode, a.access_mode)`.
- The enrollment views (`group_enrollment.go:68-78`) do not change. With platform-wide
  policies (D10), the `organization` scope means every account, and the `administrators`
  scope means staff, since only staff hold `role='admin'` or delegations (D8).
- Two named predicates replace the inline `users.status = 'active'` tests spread across
  the store today (for example `store.go:2660`, `pg_schema.go:513`):
  - **`credential_principals`**: users that are active and not ended, with the org's
    state ignored. This is today's check, under a name. Only the credential steps of
    interactive sign-in read it: the user lookup, password verification, lockout, the MFA
    token store and `resolveMFAToken`, and passkey assertion. These steps grant nothing.
  - **`active_principals`** (a view): the same users, joined to an org that is `active`.
    Everything that grants or uses access reads it: session creation, code and token
    issuance, refresh, device sign-on, code exchange, userinfo, forward sessions, session
    checks and the suite APIs.
  - Interactive sign-in ends in one session-creation function. Inside its transaction it
    re-reads the user through `active_principals`. A user who passed every credential step
    but whose org is not `active` gets `ErrOrgSuspended` and no session (see Suspension).
    That function is also the only place the export-only exception below is made.
  - `TestOrgSQLNamesOrgID`'s allowlist names the `credential_principals` call sites. A new
    one fails the build until it is listed with a reason.
  - The account flows outside sign-in keep today's per-flow user rules, which include
    pending accounts where they must. Each adds one condition, **`org_active`**: the user's
    org has `status='active'`. They do not read `active_principals`, which holds no pending
    user. None of them is on the allowlist:

    | Flow | User rule (today's, unchanged) | Org condition | In an org that is not `active` |
    |---|---|---|---|
    | Activation invite and resend-invite (`IssueAccountToken`, activation) | pending (`onboarding.go:45`) | `org_active` | Refused. The member endpoints answer `409 org_not_active`. |
    | Reset link (`IssueAccountToken`, reset) | active and not pending (`onboarding.go:47`) | `org_active` | Refused |
    | Forgot-password | as reset | `org_active` | The usual identical answer, and no mail is sent |
    | Activation and reset redemption (`RedeemAccountToken`) | the issuance rule, re-asserted in its transaction (`onboarding.go:113`) | `org_active`, read in the same transaction | Refused like an expired link. Nobody activates, sets a password or clears a lockout. |
    | Step-up | `active_principals` (a signed-in, activated user) | included | Refused. The export-only session cannot step up, because it reaches no route that needs it. |

    - `org_active` is one SQL fragment shared by these call sites,
      `EXISTS (SELECT 1 FROM orgs o WHERE o.id = users.org_id AND o.status = 'active')`, so
      the four flows cannot drift apart.
    - Suspension and schedule-deletion also expire the org's outstanding account tokens,
      in the same transaction (as `revokeUserAccessTx` does). The redemption check is the
      backstop.
    - After a resume, pending members need a new invite (`resend-invite`).
    - An account holder who cannot sign in while the org is `deletion_scheduled` gets no
      reset. Staff export on request instead (open question 9, (c)). This keeps the
      export-only exception to one place, session creation.
- One exception is outside `active_principals`. While its org is `deletion_scheduled`,
  the org's account holder may sign in with password and second factor.
  - The session is marked restricted. It works like today's `enrollment_only` sessions
    (`pg_schema.go:56`, refused by `mfa_session_access` at `:539`).
  - It reaches only the export page, the export download and sign-out.
  - It opens no suite or forward session. It issues codes and tokens only to suite apps,
    carrying the `export_only` claim (amendment, Delete everything). The same session is
    given to the other members after a holder's Delete everything, and refused to that
    holder.
  - A test calls every other route with such a session and expects a refusal.

### Migration of an existing install (the tenancy schema version)

One migration (`migrations.go:23` list), on both backends:

1. Create `orgs` and insert the default org (`kind='default'`): the fixed ID
   `00000000-0000-0000-0000-000000000001`, `all_apps=TRUE`, `max_seats=0`, status
   `active`. Its name comes from `branding_org_name` (`branding.go:14`), or "Organisation".
2. Add `org_id`, defaulting to the default org, to every org-owned table.
3. Add the triggers, the composite uniques and the view changes.
4. Record `tenancy_mode=single`, unless the database is empty and `KYIDENTITY_TENANCY=multi`.
   In that case no default org is created, and step 1 inserts nothing. The staff org is
   created by the first-start bootstrap (see Roles).

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
- **Multi-server (amendment, 2026-11-22).** The owner decided that multi-tenant needs
  multi-server. `config.Load` refuses `KYIDENTITY_TENANCY=multi` unless
  `KYIDENTITY_REPLICATED=true`. That flag already requires a PostgreSQL URL (D2) and the four
  keys from outside the data directory, so a multi-tenant install can gain a replica without
  moving its keys. A single server may still run with the flag. The check comes before the
  release gate, so `multi` stays refused until PR 6.
  - **The `kye2e` gate (2026-11-25).** The release gate is the constant `multiTenantBuild`
    (`internal/config/gate_release.go`, `false`). Only `go build -tags kye2e` selects
    `gate_kye2e.go` (`true`), for the cross-app end-to-end harness (KyCalendar
    `docs/superpowers/specs/2026-11-24-multi-tenant-e2e-design.md`); no variable, flag or
    `-ldflags -X` reaches a constant. A tagged binary refuses an issuer whose host is not under
    `.test`. CI keeps the tag out of every build file and workflow and fails an image built
    with it or one that starts in `multi`, both before `:latest` and before a release push.
  - With the flag, a cached forward-auth answer that admits the request is first checked
    against its `forward_sessions` row (`Store.ForwardSessionLive`). A logout or revocation
    on one replica then holds on every replica at the next request.
  - The housekeeping that runs on every replica with no lease (`purgeExpired`,
    `RunDueExpiries`, `ReconcileProvisioning`, `ScheduleReconcileJobs`, `ExpireADPasswords`,
    `FinishDueErasures`) re-checks its rows inside serialised write transactions. Passes that
    overlap apply each change once: `TestProofConcurrentWorkerPassesDoNotDuplicate` and
    `TestHousekeepingPurgesOnEveryReplicaAtOnce`.
- Backups stay whole-install capsules, unchanged. Per-org backup is not offered. Per-org
  **export** (JSON: org, users without credentials, groups, memberships, assignments, the
  org's audit) is available to the account holder while a deletion is scheduled, and on
  request through staff (open question 9).
- `migrate-to-postgres` and `restore` copy `orgs` like any table (`pgcopy.go` is driven by
  the catalogs, `AGENTS.md:194`).

## Isolation enforcement

**`OrgStore`.** `func (s *Store) Org(id OrgID) *OrgStore` returns a handle that holds the
org ID. Every store method that reads or writes an org-owned table moves onto `OrgStore`
and binds `org_id` itself. The `*Store` versions are removed, not kept beside it, so a
handler cannot call the unscoped one.

- `OrgID` is a distinct type. The only way to build one is from an authenticated principal:
  a session's user, a SCIM connector (single-tenant only), a suite call's `sub`, or a
  platform request's path, which the platform layer checks against `orgs`.
- The one request-chosen org is a staff member's org selection on an org-bound admin route
  (see Roles). Middleware builds it only after `accessFor` has found a staff principal, and
  checks it against `orgs`. A member's session never reaches this path.
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

**Platform-level workers and staff.** The sync dispatcher, reconcile, the housekeeping
sweeps and alerts read across orgs through a `PlatformStore`. So do the few cross-org staff
reads: the org list with counts, finding an org by a member's exact email, and the audit
by actor. That handle exposes only those queries, and every row it returns carries
`org_id`, so each payload or audit row is stamped with the row's own org. No handler gets an
unscoped `*Store` for org-owned tables.

**Postgres row-level security** would add a second layer: a non-owner role, policies of
`org_id = current_setting('ky.org')`, and `SET LOCAL` per transaction. The work is real and
unverified. `pgdialect` wraps statements in its own transactions (`AGENTS.md:198`), and the
read pool and every worker would need a bypass role. Deferred (open question 6).

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
  - Set up orgs A and B. Each has an account holder, a member and a suite group. Set up the
    staff org with a staff admin, a staff helpdesk and a staff auditor.
  - For every account and suite route, call it as each A principal with B's object IDs.
    Expect `404`, or an empty list, with B's rows unchanged.
  - For every org-bound admin route, call it as each staff persona with org A selected and
    B's object IDs. Expect `404`, B's rows unchanged, and an audit row in A's log only.
  - For every member endpoint, call it with A in the path and B's user IDs. Expect `404`.
  - Call every admin and platform-listener route as A's account holder and member. Expect
    the refusal a non-admin gets today, with nothing changed.
  - Try to give an A account `role='admin'` or a delegation through every write path
    (admin API, platform API). Expect a refusal.
  - Call every inbound SCIM and HR route. Expect `404` (off in multi-tenant v1).
  - Runs on Postgres in the `postgres` CI job.
- Token tests: a user's `org_id` reaches the ID token, the access token, userinfo and the
  logout token, and changing `users.org_id` is refused.

## Roles

| Mode | Principal | Can | Cannot |
|---|---|---|---|
| Single | Administrator (`role='admin'`) and delegations (`permissions.go:17-41`) | Unchanged. This includes Enterprise installs (decision 7). | Unchanged |
| Multi | **Staff**: accounts in the staff org (D8), admins and staff with today's delegations | The admin UI in any customer org, one selected org at a time, with today's permissions. Staff admins also use `platform` routes. | Sign in as a user, set a customer's password, change a customer's email, see an activation or reset link, read app content |
| Multi | **Member**: every customer account | Its own account pages, and the apps its org's plan enables | Any admin route (refused as today, `writeForbidden` at `permissions.go:84`), any platform-listener route |
| Multi | **Account holder**: one member (D9) | What a member can, plus the export-only session while a deletion is scheduled, the deletion banner, and member-change notices by mail | Anything a member cannot. It maps to no `Access` field and passes no permission check. |
| Multi | **Billing service**: a platform token with `orgs:*` | Org lifecycle, plan, seats, apps, account holder (by `user_id`), counts | Read any user data, member emails and statuses included: those are `members:*` only |
| Multi | **Billing portal**: a platform token with `members:*` | Member endpoints, which read member emails and statuses | Org lifecycle |

**Staff.**

- **Passkey MFA.** Today an administrator needs no second factor unless an operator turns
  on the `administrators` enrollment policy. That policy is created not required, with
  every factor allowed (`group_enrollment.go:52,66`). Its scope covers `role='admin'` and
  every delegation holder (`:70`). Step-up guards sensitive routes (`require` at
  `permissions.go:90`, `requireStepUp` at `server.go:536`). In multi-tenant mode the
  policy is pinned: required, passkey only (`allowed_mask=4`, `enrollment_policy.go:30`),
  grace 0. The admin API refuses any change to it. A new staff account gets an
  enrollment-only session until it registers a passkey. Step-up stays as it is.
- **Org selection.** The admin UI gains an org selector. Staff find an org by ID,
  `billing_ref` or a member's exact email. The UI sends the selection as an `X-Ky-Org`
  header on org-bound admin routes. In multi-tenant mode, an org-bound route without the
  header answers `400 org_required`. Single-tenant ignores the header and binds the default
  org.
- **Route classes.** `permission` (`permissions.go:17`) gains a `platform` flag, and every
  admin route names it or not, as each route already names its permission. The flag no
  longer keeps anyone out, since every admin principal is staff. It decides which store
  the request gets, and it still earns its place for that:
  - An **org** route gets an `OrgStore` bound to the selected org: users, groups,
    memberships, app and role *assignments*, `org_apps.access_mode` for apps the plan
    enables, access requests and approvals, expiry, offboarding, sessions, and the org's
    audit and alerts. A **staff org** route also gets an `OrgStore` and requires the
    staff org as the selection.
  - A **platform** route gets no `OrgStore`, and needs `Access.Admin`. That matches today's
    rule that only global administrators change global policy (`permissions.go:11-16`).
    These are: OAuth clients (create, edit, delete, secret rotation, back-channel URI);
    paired systems; app registry policy, linking, `requestable` and launcher-card
    settings; `app_roles` definitions; launcher cards and icons; proxy apps; enrollment
    policies (D10); delegations (staff org only, D8); mail, session limits, alert settings,
    attestation, rate-limit networks and push relays; backups, the drill and recovery keys;
    installer resources.
  - In single-tenant mode the flag changes nothing.
  - Route registration rejects an admin route with an invalid scope.
- **Audit.** Every staff request on an org route writes an audit row in the selected org's
  log, naming the staff user and the org. Reads write `staff.read` with the route. Writes
  keep their existing audit rows, now carrying the org. A cross-org staff read writes one
  platform row (`org_id` NULL) that names every org whose rows it returned. Staff admins
  read the audit across orgs by actor, so staff leads see what each staff member did.
- **What staff see.** Directory data: users, groups, sessions, assignments and audit.
  KyIdentity holds no app content, so none is reachable from here.
- **No credential for a customer account.** For a customer account in multi-tenant mode,
  the admin API refuses passwords on create and update and refuses any email change
  (`403 customer_credentials_protected`). Activation and reset use mail delivery to the
  address read in the token transaction. The response reports delivery and expiration.
  Creating or updating an inbound connector, issuing its SCIM tokens and configuring HR
  require the staff org selection (`403 customer_credentials_protected` for customer orgs).
  Staff can still list customer connectors, view HR status, revoke tokens and delete connectors.
- The last-admin rule (`ErrLastActiveAdmin`, `expiry.go:28`) is unchanged and applies to
  the staff org, the only org with administrators. There is no per-org rule.

**Emergency access and recovery.**

- **Single-tenant:** unchanged. `bootstrap-admin`, `disable-user` (`docs/RUNNING.md:593-610`).
- **Multi-tenant:** `bootstrap-admin`, and the first-start bootstrap (`CountAdmins` at
  `cmd/kyidentity/main.go:435`), create the staff org if it is missing, and the first staff
  admin in it. That admin must register a passkey at first sign-in. `disable-user` is
  unchanged.
- **Account-holder recovery.** The account holder recovers like any member: forgot-password
  sends a link to the verified address (`onboarding_handlers.go:178-197`). If the second
  factor is lost too, staff reset it (`reset-mfa`, `server.go:260`) after billing confirms
  the person, and the reset link is mailed. There is no platform API for recovery: the
  password path needs none, and an MFA reset needs a human check. If the portal could reset
  MFA, a portal compromise could strip second factors. A lost mailbox is open question 12.

**Platform settings in multi-tenant mode** (mail, session limits, alert settings,
attestation, rate-limit exemptions, push relays, backup pairing) stay in the admin UI as
`platform` routes, for staff admins with step-up, as today. There is no separate
container-local channel. Staff now have the admin UI, which is already step-up protected
and audited. A second channel would need host access, which is a broader privilege to hand
out, and it would add code.

- Each change is audited as a platform event (`org_id` NULL).
- Startup does not require mail. Until mail is configured, `POST /platform/v1/orgs` and
  member adds answer `503 mail_not_configured` and create nothing. Billing retries with the
  same idempotency key.

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
targets are off in multi-tenant v1 (see Per-org features).

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
7. *Amended 2026-11-23:* report its stored bytes per org to `POST /api/suite/storage`, and
   refuse any write that adds bytes beyond the grant it holds (Org storage pool).

Each app's PR documents its half against this list.

## Platform provisioning API

**Listener.** `KYIDENTITY_PLATFORM_LISTEN` (for example `10.0.0.5:5868`). Unset means no
platform API, and it is always unset in single-tenant mode. Plain HTTP, like the main
listener (`docs/RUNNING.md`), so TLS or mTLS is terminated by a private proxy (open
question 10). Nothing on it is served on the public listener, and nothing from the public
listener is served on it.

**Authentication.**

- `Authorization: Bearer kyp_<id>_<secret>`, 256 bits. Only the SHA-256 is stored, as with
  SCIM tokens.
- Scopes: `orgs:read`, `orgs:write`, `orgs:delete` for the billing service, and
  `members:read`, `members:write` for the customer portal. A token never holds both kinds.
- Created and revoked only with `kyidentity platform-token create|revoke|list`. The CLI
  prints the token once and audits each action.
- Failed authentication is rate limited per IP, and each token is rate limited. Member
  writes are also rate limited per org.
- Every call is audited as `platform.*`, with the token ID as the actor. A call on one org
  is audited in that org's log.

**Idempotency and order.**

- Every `POST`, `PATCH` and `DELETE` needs `Idempotency-Key` (1–128 characters).
- `platform_requests` stores the request hash and the response, in the same transaction as
  the change. The same key and hash returns the stored response. The same key with a
  different hash is `422 idempotency_conflict`.
- Org lifecycle writes carry `revision`, a per-org counter the billing service increases.
  One at or below `orgs.billing_revision` is `409 stale_revision` with the current value.
- Order of checks for every write:
  1. The `platform_requests` lookup. A retry with the same key and body gets its stored
     answer, whatever has happened to the org since, including a later `PATCH`.
  2. On `POST /orgs` only, `billing_ref` (below).
  3. `revision`. Only a call under a new key reaches this check, so a same-key retry is
     never `stale_revision`.
- Member writes carry no `revision`. They are synchronous user actions from the portal, not
  replayed webhooks, and each is idempotent on its target state.
- `billing_ref` is unique. A new-key `POST /orgs` whose `billing_ref` already exists is
  compared with the org's original create request, not its current state:
  - `orgs.create_request_hash` keeps the hash of the request that created the org. It is
    written once and never changes, so a later `PATCH` does not affect the comparison.
  - The same hash is `200` with the existing org. A different hash is
    `409 billing_ref_conflict`.
  - A retry under a new key, or after the 30-day `platform_requests` window, therefore gets
    the same answer as the first create.

**Org endpoints** (`/platform/v1`). Bodies hold no personal data except the account
holder's name and email on create.

| Route | Scope | Effect |
|---|---|---|
| `POST /orgs` | `orgs:write` | `{name, home_region, plan, max_seats, storage_bytes, storage_per_seat_bytes, apps:{client_id:{enabled, quotas}}, holder_email, holder_name, holder_mailbox_address?, billing_ref, revision}`. Creates the org and a pending account holder (with its mailbox address when given; see Mailbox address), and sends an activation invite by mail (`account_tokens`, delivery `email`). `503 mail_not_configured`, creating nothing, until platform mail is set (see Roles). `409 email_in_use` if the email exists anywhere or the holder's mailbox address collides, `400 mailbox_domain` for a mailbox address off the suite domains, `400 invalid_home_region` (see Home region), `400 invalid_max_seats` outside 1–`MaxSeats` (Plans and orgs P2), `400 invalid_storage` (Org storage pool S3). The org is `kind='customer'`; the body has no `kind`. |
| `GET /orgs/{id}`, `GET /orgs?status=&billing_ref=&cursor=` | `orgs:read` | Status, reason, plan, limits, `seats_used`, `pending_invites`, `holder_activated`, `delete_after`, `revision`, and the storage figures (Org storage pool). No names or emails of users. |
| `PATCH /orgs/{id}` | `orgs:write` | `{revision}` plus any of: plan, `max_seats`, `storage_bytes`, `storage_per_seat_bytes`, apps and quotas, name, `account_holder_user_id` (a live member of the org, pending or activated: see Account holder guard). `max_seats` below the seats in use is `409 seats_in_use` with `seats_used`, and nothing changes: billing removes members first (Plans and orgs P3). A change that lowers the pool to below the org's usage is `409 storage_over_pool` without `storage_over_pool_ack` (Org storage pool). `400 invalid_max_seats` and `400 invalid_storage` as for `POST`. |
| `POST /orgs/{id}/suspend` | `orgs:write` | `{reason: payment\|abuse, revision}`. Semantics below. |
| `POST /orgs/{id}/resume` | `orgs:write` | `{revision}`. From `suspended`, or from `deletion_scheduled` before `delete_after`. Sign-in works again. Sessions do not come back. |
| `POST /orgs/{id}/schedule-deletion` | `orgs:write` | `{grace_days 7–90, revision}`. Suspends the org and sets `delete_after`. The account holder can still sign in to a restricted, export-only session (the `active_principals` exception under Views). |
| `DELETE /orgs/{id}` | `orgs:delete` | No `revision`: the state gate replaces it. Only for `deletion_scheduled` once `delete_after` has passed, otherwise `409`, so a late `DELETE` after a resume does nothing. Deletes every org-owned and derived row in one transaction and leaves the tombstone. That includes the org's `audit_events`. This is a second, named audit-deletion path beside `DeleteAuditEventsOlderThan`, and the audit retention contract in `AGENTS.md` must be amended to say so. The org's audit is in the account holder's export. In the same transaction, a platform audit row (`org_id` NULL), `platform.org_deleted`, records the org ID, the token and row counts per table, with no content. If it cannot be written, nothing is deleted (fail closed). A test proves both. |

**Member endpoints.** A customer org (a household or a business) still invites and removes
its people, and resends invites. With no org admin (decision 6), the billing service's customer portal does it for
the account holder through these endpoints. Staff do the same in the admin UI. Every
member is an everyday account (`role='user'`), and the endpoints reach no other kind.

| Route | Scope | Effect |
|---|---|---|
| `GET /orgs/{id}/members` | `members:read` | `{user_id, email, status: pending\|active\|disabled, account_holder}` for each member. No names, sessions or factors. |
| `POST /orgs/{id}/members` | `members:write` | `{email, name, mailbox_address?}`. Creates a pending member (username = email, D5), with its mailbox address when given (see Mailbox address), and mails an activation invite. Answers `{user_id, status}`. An existing member of this org with that email is `200` with the same. `409 email_in_use` if the email is elsewhere or either address collides (Mailbox address), `400 mailbox_domain` for a mailbox address off the suite domains, `409 mailbox_address_set` when the existing member holds a different one, `409 seat_limit`, `503 mail_not_configured`. |
| `POST /orgs/{id}/members/{user_id}/resend-invite` | `members:write` | Pending members only, otherwise `409`. Issues a new activation token, which ends the old one, and mails it. Rate limited per member. |
| `POST /orgs/{id}/members/{user_id}/disable`, `…/enable` | `members:write` | Disable revokes every grant (`revokeSessionGrantsTx`). Enable adds a seat, so it is checked. |
| `DELETE /orgs/{id}/members/{user_id}` | `members:write` | Deletes the account through the existing path (`DeleteUserWithSyncEvents`, `store.go:1073`), so apps get the usual deprovisioning event. |

- The account holder cannot be disabled or deleted here (`409 account_holder`). Billing
  first moves the role with `PATCH /orgs/{id}`.
- Every member write is audited in the org's log, queues `org.member_changed`, and mails a
  notice to the account holder (new mail text, no link).

**Account holder guard.** The pointer is guarded in the database, so every path is covered:
the member endpoints, the staff admin UI, `disable-user`, expiry (`RunDueExpiries`,
`expiry.go:97`) and the pending-account cleanup of open question 3.

A pending account is stored `status='disabled'`, `pending=TRUE`, and activation sets it
`active` and not pending (`AGENTS.md:173`, `onboarding.go:113`). So the guard is not
"status is active". It is one predicate, a **live holder**:
`(pending OR status='active') AND ends_at IS NULL`. Pending and activated holders are both
live. A disabled activated account, or one with an end date, is not. Triggers on both
backends:

- `users` `BEFORE DELETE`: refused while an `orgs` row names the user as account holder.
- `users` `BEFORE UPDATE`: refused when an `orgs` row names the user, and the new row is not
  live or has a different `org_id`. Activation (pending to active) keeps the row live, so it
  passes. Disabling an activated holder or setting an end date fails.
- The store maps both refusals to `ErrAccountHolder` (`409 account_holder` in the API, the
  same message in the admin UI). A holder row already due for expiry when the trigger
  lands is skipped and audited by `RunDueExpiries`, like its other per-account failures.
- `orgs` `BEFORE INSERT`: the pointer must be NULL. No user of a new org can exist yet,
  because `users.org_id` references `orgs(id)` (the Postgres FK, or the SQLite existence
  trigger).
- `orgs` `BEFORE UPDATE` of `account_holder_user_id`: the new value must be a live user of
  the same org. Changing a set pointer to NULL is refused unless the same `UPDATE` moves
  the org from `deletion_scheduled` to `deleted`. That is, the predicate for NULL is
  `OLD.status = 'deletion_scheduled' AND NEW.status = 'deleted'`.
- `orgs` `BEFORE UPDATE` of `status`: `deleted` can only be entered from
  `deletion_scheduled` with `delete_after` at or before the database's current time
  (`unixepoch()` on SQLite, `extract(epoch from now())` on Postgres). It is terminal: a
  `deleted` row never changes status again. So the NULL exception cannot be reached from
  any other path, or before the grace period ends.
- `POST /orgs`, in one transaction: insert the org with a NULL pointer, create the pending
  user in it, then set the pointer. The NULL never commits.
- Org deletion, in one transaction: one `UPDATE orgs SET status='deleted', name='', account_holder_user_id=NULL`, then the users and every other org row are deleted.

A pending holder whose activation token expires is not deleted. The open question 3 cleanup
skips any account named as holder. The org stays `active` with `holder_activated: false`, and
a new `org.holder_invite_expired` event tells billing. Billing then calls `resend-invite`
(the holder is still pending) or names another member with `PATCH /orgs/{id}`. If such an
org reaches scheduled deletion, nobody can open the export session, so staff export on
request (open question 9, (c)).

**Suspension**, in one transaction with its audit row:

1. Set `orgs.status`.
2. Revoke every session and token grant of the org's users (`revokeSessionGrantsTx`). This
   ends forward sessions too. Expire their outstanding account tokens (invites and resets).
3. Queue back-channel logouts for every client session.
4. Queue `org.suspended`.

After that:

- Refresh, device sign-on and code exchange are refused with their generic answers, because
  `active_principals` excludes the org.
- Interactive sign-in (owner answer 4, option (b)):
  - The password and second-factor steps read `credential_principals`, so they run as for
    any active account. They take the same Argon2 cost, give the same wrong-password
    answer, and apply the same lockout. A wrong credential never reveals the org's state.
    The MFA token they store is the usual short-lived challenge token, and it grants
    nothing by itself.
  - Only after every factor the account requires has passed does session creation read
    `active_principals`, refuse, and answer `org_suspended` ("Your organisation is
    suspended"). It issues no session, code or token, and the MFA token is spent.
  - The factors required are whatever the platform-wide enrollment policy (D10) requires
    of that account. Where it requires a second factor, the answer needs both. A member it
    leaves with a password only sees the answer after a correct password.
  - Unknown, pending, disabled and locked accounts are unchanged: they get the
    wrong-password answer.
- Userinfo is refused.
- Suite people, groups and apps for the org's `sub`s return empty lists.
- `/api/suite/orgs` shows `suspended`.
- No data is changed or deleted.

**Events back to billing.**

- Sent from `platform_events` (outbox) to `KYIDENTITY_PLATFORM_EVENTS_URL`. Each is signed
  with `ky-primitives/syncauth`, using a secret sealed at rest and set by
  `kyidentity platform-events set-secret`.
- Types: `org.created`, `org.member_changed` (`change`: `added`, `activated`, `disabled`,
  `enabled` or `removed`, for any member including the account holder), `org.suspended`,
  `org.resumed`, `org.deletion_scheduled`, `org.deleted`, `org.holder_invite_expired`.
- **`org.resumed` is the canonical name** for an org leaving `suspended` or
  `deletion_scheduled` for `active` (the `resume` route). There is no `org.unsuspended`: a
  resume from `deletion_scheduled` is not an unsuspension. Any later org lifecycle webhook to
  apps (Home region, "Not covered") uses the same names.
- *Amended 2026-11-23:* there is no `org.over_limit` or `org.within_limit`. Seats can no
  longer pass `max_seats` (Plans and orgs P3), so there is nothing to derive.
- Body: `{event_id, type, org_id, home_region, billing_ref, revision, status, seats_used,
  user_id?, change?, at}`. `user_id` is the opaque KyIdentity ID. No personal data.
- Delivery is at least once and unordered. Billing de-duplicates by `event_id` and orders
  by `revision`.

## Delete everything (amendment, 2026-11-21)

The owner asked for a **Delete everything** button that cannot be undone, and approved K open
question 4 option (a) (KyPost `docs/superpowers/specs/2026-11-20-tenancy-design.md`, "Delete
everything", called K here). Multi-tenant only: in a single-tenant install every route below is
`404`, no row is written, and the golden files do not change.

**Who deletes what.** The clicker deletes their own data, and nobody else's without warning.

| Clicker | Other live members (`liveHolder`) | Effect |
|---|---|---|
| Account holder | none | The org goes straight to `deleted` in one transaction. Every member is first offboarded as a member is below: access revoked with back-channel logouts queued, `user.erased` to suite apps, `user.deleted` to SCIM and AD, and a tombstone. Then the org's rows are deleted, and the `orgs` tombstone stays. The provisioning and logout rows (`account_sync_events` except delivered ones, `sync_delivery_attempts`, `sync_resource_state`, `scim_user_links`, `logout_deliveries`) stay too, as they do for any deleted user. They hold opaque IDs and bare payloads only, so the queued removals and logouts are delivered and held evidence is kept. |
| Account holder | one or more | The org goes to `deletion_scheduled` with `delete_after` 7 days on. Every session and grant of the org ends at once (as suspension). The holder can never sign in again. Each activated member is owed a notice, queued in the same transaction (`erase_notices`) and mailed by the worker with retries until it is sent or the org is deleted, and may sign in to an export-only session until `delete_after`. The housekeeping sweep then deletes the org as above. |
| Any other member | — | Only their own account: `user.erased` (below), then their rows are deleted. |

Staff and `default` org accounts have no button. A pending account cannot sign in, so it
cannot click.

**Confirming.** `POST /api/user/erase` with `{"address"}`.

- It spends an operation-bound step-up grant that proved the password **and** a second factor
  (`step_up_tokens.factor_method` is `totp`, `push` or `webauthn`; password-only and recovery
  grants are refused). The grant is spent in the erasure's own transaction, so a refused
  erasure spends nothing and a replayed grant erases nothing.
- `address` must equal the account's mailbox address, or its sign-in email when it has none,
  compared after trimming and case folding. A mismatch is
  `400 address_mismatch` and changes nothing.
- The account page shows the dialog. It lists each app the account can open, with a link to
  that app's export, before the address field. Nothing can be recovered afterwards.
- A replay changes nothing: the grant is single-use, and the clicker's sessions end with the
  first call, so a second call from the same browser is a `401`. A second request for the
  same org fails on the `org_erasures` primary key.

**The record and the trigger path.** The holder's request is a row in a new platform table:

```
org_erasures (org_id TEXT PRIMARY KEY REFERENCES orgs(id), holder_user_id TEXT NOT NULL,
  immediate BOOLEAN NOT NULL, requested_at)
```

- `org_erasures_holder` (`BEFORE INSERT`): the row names the org's current account holder,
  the org is `active` and of kind `customer` (Plans and orgs), and `immediate` is true exactly
  when the org has no other live member.
- `org_erasures_kept` (`BEFORE UPDATE`, `BEFORE DELETE`): refused always. A row never changes
  and is never removed, so nobody can take a request back: not billing, staff or the holder.
- `orgs_status` gains one named path, **`holder_erased`**: `deleted` may also be entered from
  `active` when an `org_erasures` row for the org has `immediate` set and the org still has no
  live member other than that holder. `status_bad_change` is otherwise unchanged.
- `orgs_account_holder_update` gains the same path: clearing the pointer is allowed in the
  update that enters `deleted` by `holder_erased`, as it is for `deletion_scheduled`.
- New `orgs_erasure_held` (`BEFORE UPDATE`): while an `org_erasures` row exists and the org is
  `deletion_scheduled`, the only status change allowed is to `deleted`, and `delete_after`
  cannot change. So `resume` (from billing, staff or anyone) and a second
  `schedule-deletion` are refused in the database. T's own grace and `resume` stay for
  billing-driven deletion, which has no `org_erasures` row.
- The store maps these refusals to `ErrOrgErased` (`409 org_erased`).

**A member deletes only themselves.** In one transaction:

1. Refuse the account holder (`409 account_holder`), a non-`active` org and a non-member.
2. Revoke every session and grant (`revokeUserAccessTx`).
3. Queue **`user.erased`** to every enabled suite webhook connector, whether or not it held
   the account (as deletion's fan-out). The body is the bare inactive SCIM user (`id`,
   `externalId`, `active: false`) with `org_id`, signed by `syncauth` with the event type.
   It means "delete this person's data"; `user.deleted` keeps meaning "disable", as now.
   Generic SCIM and AD connectors (off in multi-tenant v1) get `user.deleted`. It is a
   removal: retried until delivered, never fenced, and a `404` acknowledges it.
4. Add the subject to `erased_subjects`.
5. Delete the org's audit rows and alerts that name the user, and their delivered sync events,
   which hold their name and email. An audit row names them as actor or target, or by a
   string equal to their ID, username or email under a key of its details that names a person
   (`member`, `user`, `userId`, `username`, `email`, their plurals, `recipients`; a group change
   records its members' usernames). An alert names them by its key. Only exact, case-sensitive
   values under those keys match. Matching a display name, a part of a value or any other key's
   value (`"role":"user"`) would take other people's rows. Write one `account.erased` row in the org's log naming only the
   opaque user ID. This is a third named audit-deletion path, beside
   `DeleteAuditEventsOlderThan` and org deletion.
6. Delete the `users` row, which cascades to every derived row.

**Shared content (owner decision, 2026-11-23).** Erasing a person deletes their own data and
nothing other members wrote. For each shared item in an app (a shared folder, notebook,
calendar or room) that the erased person owns:

- Ownership passes to the member of that item who has held its admin role longest, else to
  the longest-standing editor, else to the longest-standing other member. Only an item with
  no other member is deleted with the person.
- The person's messages in shared rooms become tombstones: the entry stays in its place,
  with its text and attachments deleted and the author shown as a deleted account.
- Content other members wrote in a shared item is kept, whoever owned the item.

This is each app's rule on `user.erased` and `GET /api/suite/erased` (`docs/SUITE-DIRECTORY.md`);
each app knows its own sharing roles, and KyIdentity sends nothing more. It covers a member
erasing themselves, the only path where other members stay. A holder's request deletes the
whole org after the export window (P7), so every member's data goes with it.

**Tombstones.**

```
erased_subjects (subject TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES orgs(id),
  revision BIGINT NOT NULL UNIQUE, erased_at)
```

- Every erased member, and every user of an org deleted by `holder_erased` or by the sweep
  after a holder's request, gets a row. `revision` is one past the table's highest.
- `erased_subjects_kept` refuses every update and delete. `users_erased_subject` refuses a
  `users` insert whose `id` is listed, so a subject is never reused.
- Both new tables are platform class (`platformTables`): they hold opaque IDs only and must
  outlive the org's rows.

**`GET /api/suite/erased`.** Suite client authentication, rate limits and `no-store`, as
`/api/suite/orgs`. `404` in single-tenant mode. Lists `{sub, org_id, revision}` for subjects
whose org the caller is told about (`suiteOrgVisibleSQL`), ordered by `revision`, after
`since=<revision>`, `limit` 1–500 (default 100); a full page carries `next` (a revision) to
pass back as `since`. Apps re-read it from `since=0` after a restore, with `/api/suite/orgs`
(K "A restore does not bring it back").

**The `export_only` claim (K open question 4, option (a)).** While an org is
`deletion_scheduled`, session creation makes the one exception to `active_principals`
described under Views. This amendment widens it:

- Who: the account holder, when the deletion came from billing (no `org_erasures` row), and
  every other activated member, when it came from the holder's request. The holder who asked
  is refused like a suspended org (`org_suspended`).
- The session is restricted as before, and it may now complete an authorization-code flow
  for a suite app that its org's plan enables. The tokens carry `"export_only": true` in the
  ID token, the access token and UserInfo. They carry no refresh token, `scope` is cut to
  `openid email profile`, and device sign-on, forward-auth, workstation login and the device
  grant stay refused.
- Apps admit only their export routes under the claim (K). `claims_supported` lists it in
  multi-tenant mode only.
- A golden test pins the multi-tenant claim, and the single-tenant golden files stay identical.

**Billing.** `org.deletion_scheduled` and `org.deleted` are queued in `platform_events` in
the same transactions, as for billing's own calls. A billing `DELETE /orgs/{id}` after a
holder's request finds the org already `deleted`, or still inside its grace (`409`).

**Restore.** A KyIdentity capsule taken before the click brings the org back, because a
restore rolls every org back (Residual risks). The apps' own restores are covered by the
`deleted` tombstone and `erased_subjects` (K).

**Tests.** Every new trigger path and its refusals (immediate with another live member,
scheduled with none, a non-holder, a non-`active` org, `resume` and a new `delete_after` under
a request, updating or deleting either new table, reusing an erased subject); replay and
idempotency of both paths and of `user.erased`; cross-org refusals; a step-up without a second
factor; the single-tenant golden files and `404`s; browser screenshots of the dialog.

## Mailbox address (multi-tenant)

Owner answer to KyPost's tenancy note, open question 1 (KyPost
`docs/superpowers/specs/2026-11-20-tenancy-design.md`, "Mailbox addresses and domains in
hosted mode"): KyIdentity holds each hosted member's **mailbox address**, and KyPost
provisions the mailbox from it. A member's `email` is their sign-in address (D5). It is
usually on someone else's domain, so it cannot be the mailbox.

- **Field.** `users.mailbox_address` (schema version 12), one per user, NULL when unset. It is
  separate from `email`: sign-in, activation, reset and every mail KyIdentity sends still go
  to `email`, never to the mailbox address. A member reads their own (`User.mailboxAddress`)
  and cannot change it.
- **Form.** `<local>@<domain>`, stored lowercase, with the domain in punycode
  (`store.NormalizeMailboxAddress`). The local part is ASCII letters, digits, `.`, `-` and
  `_`, at most 64 bytes, not starting or ending with a `.` and with no `..`. `+` is refused,
  because KyPost reads it as plus addressing. The whole address is at most 254 bytes.
- **Domain.** It must be on the `suite_email_domains` list (KyIdentity #277). KyPost serves a
  domain only when it is on the list *and* proved by its own TXT record (KyPost note).
- **Uniqueness.** Global, on the stored form, so `Bob@Bücher.example` and
  `bob@xn--bcher-kva.example` are the same address. The partial unique index
  `users_mailbox_address` decides it. A mailbox address also may not equal another user's
  sign-in `email` (case-insensitive), and a sign-in email may not equal another user's
  mailbox address. Otherwise mail for one person's sign-in address, resets included, would
  land in someone else's mailbox. Triggers `users_mailbox_insert` and `users_mailbox_update`
  enforce this on every write path, and their refusal is a unique violation. So
  `POST /orgs` and member adds answer it as `409 email_in_use`, and the admin route as
  `409 mailbox_address_taken`. Writes are serialised (one SQLite writer, one Postgres writer
  lock), so two racing writes cannot both pass. A sign-in email written with the Unicode
  form of an IDN suite domain is not matched against the punycode mailbox address. Residual,
  unverified risk.
- **Reuse.** Deleting an account frees its mailbox address in KyIdentity. KyPost's ledger never
  reuses an address (its tombstones), so it refuses the freed address for anyone else. That
  shows up as KyPost's durable allocation failure, shown to staff (KyPost note).
- **Customer accounts only.** The same triggers refuse a mailbox address for any account
  outside a `customer` org. That includes staff (KyPost gives staff no
  mailbox) and the single-tenant `default` org, so a single-tenant install cannot hold one
  on any path.
- **Write-once.** It is set when the member is added: billing's `POST /orgs` sets it for the
  account holder, and `POST /orgs/{id}/members` for the others (optional `mailbox_address`
  in both bodies; see Platform provisioning API). Setting the same value again does nothing,
  so a retry is safe. Setting a different value is `409 mailbox_address_set`. Only staff
  change it afterwards (`PUT /api/admin/users/{id}/mailbox-address`, an org route,
  `permAdmin` with step-up). Each staff change is audited as
  `admin.user_mailbox_address_changed` in the org's log. The details hold the old and new
  *domains* only. Local parts stay out of the audit log, as names do from logs. It cannot
  be cleared, since a cleared field would orphan the KyPost mailbox. A staff change does not
  touch sign-in or recovery: unlike a sign-in email change (refused for customer accounts,
  see Staff), it moves no credential.
- **Inbound SCIM and HR** never write it. No inbound path names the column, and inbound
  SCIM is off in multi-tenant mode anyway (Per-org features). A connector's `emails` still
  sets only the sign-in email, as today.
- **Removing a domain.** `PUT /api/admin/suite-settings/email-domains` refuses to drop a
  domain that any mailbox address uses: `409 domain_in_use`, naming the domain and the
  count. Staff first move those addresses to another listed domain. The check runs in the
  save's transaction, so a racing mailbox write cannot slip past it. The list cannot drop a
  live mailbox's domain, so no address is ever orphaned silently. Adding domains, or
  removing unused ones, is unchanged.
- **Wire.** In the signed suite webhook body (multi-tenant only, beside `org_id`), the
  mailbox address is a second `emails` entry `{"value": "…", "type": "mailbox", "primary": false}`, after the
  sign-in entry (`type: "work"`, `primary: true`). It is never `primary`. A change goes out as
  `user.updated`. Generic SCIM and Active Directory bodies never carry it. Contract:
  `docs/SUITE-DIRECTORY.md`, "Mailbox address".
- **Downstream (KyPost).** In multi-tenant mode KyPost allocates the mailbox from the
  `mailbox` entry, never from the primary one, and treats an absent entry as "no mailbox
  yet". What KyPost does when staff change an allocated address (add an alias, or move the
  mailbox) is KyPost's to decide. Unverified here.

Owner questions, each with the default this design applies:

1. Is the mailbox address required on `POST /orgs` and member adds? *Default: optional.* A
   plan without KyPost needs none, and staff can set it later.
2. Should the staff-change audit row name the full old and new addresses? *Default: no,
   only the domains.* The current address is visible on the user's admin page.
3. Can staff clear an address? *Default: no.* Clearing would orphan the KyPost mailbox.
   Deleting the member is the way to end it.

## Home region (amendment, 2026-11-22)

Owner decision, 2026-11-22: KyIdentity is the source of truth for each org's **home region**.
The suite's multi-tenant apps run in several regions, KyMessages-Native first
(KyMessages-Native `docs/superpowers/specs/2026-11-22-tenancy-design.md` §6.2). Each org lives
in exactly one region: its app data, media server and attachment store are there, and
nothing is written across regions. Each region is its own app URL (for example
`us.chat.<domain>` and `eu.chat.<domain>`), not one hostname behind an edge router, and each
region runs its own LiveKit SFU. So an app learns where an org lives from KyIdentity, and a
caller learns which URL serves it.

| # | Decision | Why |
|---|---|---|
| H1 | `orgs.home_region` (schema version 15), a slug matching `^[a-z][a-z0-9-]{1,31}$`, `NOT NULL`. Existing orgs, the single-tenant `default` org and the `staff` org are `local`. | One field, set once. `local` is what a single-region app already assumes (KyMessages-Native §6.2 item 5). |
| H2 | **Immutable.** Trigger `orgs_home_region_immutable` refuses every change, on both backends and on every path, staff included. A deleted org's tombstone keeps it. | A move copies every app's data to another region. No app can do that yet, so a changed field would only point apps at a region that holds none of the org's data. A later move must be its own audited flow, designed with the apps, that lifts the trigger on one named path (as `holder_erased` does for the account holder). |
| H3 | Set at provisioning. `POST /orgs` takes a required `home_region`; missing or malformed is `400 invalid_home_region` (`store.ValidHomeRegion`). A single-region service sends `local`. | Billing chooses the region at checkout. On Postgres the column has no default (dropped after the backfill, like `org_id` in version 10), so an insert that forgets it fails. SQLite keeps `DEFAULT 'local'` (a column default cannot be dropped there), and SQLite is single-tenant only (D2). The `CHECK` refuses a malformed value on both. |
| H4 | Published in `/api/suite/orgs` (`home_region` on each entry; ky-primitives `suitedir.Org.HomeRegion`) and in every platform event body (`home_region`). **Not a token claim.** | An app must already read `/api/suite/orgs` before serving an org (status, `enabled`, quotas), and the value never changes, so a cached entry is exact. A claim would add an `orgs` read to every issuance and change every multi-tenant token for no new fact. |
| H5 | Per-region app URLs: `client_region_origins (client_id, region, origin)`, a platform table. Each origin is the HTTPS origin of one of that client's redirect URIs. | One OAuth client per app, as today: every region is a redirect origin of the same client, so a region URL adds no new place KyIdentity sends a user or a signed request to. |

**Setting region URLs.** `GET` and `PUT /api/admin/clients/{id}/regions`,
`{"regions": {"us": "https://us.chat.example"}}`. Platform routes, multi-tenant only (`404` in
single-tenant), `PUT` with step-up. `PUT` replaces the whole map (at most 32 entries; `{}`
clears it) and commits `admin.client_regions_changed` with the map in the same transaction.
`400 invalid_regions` for a malformed region, an origin that is not exactly
`https://host[:port]`, or one that is not among the client's redirect origins. Reads re-check
that last rule, so an origin whose redirect URI was later removed is ignored rather than
used; `GET` answers `regions` as served and lists such entries apart under `stale`, so the
admin view matches what apps get. Deleting the client deletes its rows.

**Resolving an app's URL for an org.** A client with no rows is one URL, as today. A client
with rows serves an org only through the row for that org's home region; with none it does not
serve the org at all, and the URL is never guessed.

- The launcher and `/api/suite/apps?sub=` (the `sub` user's org) replace the launch URL's
  origin with the region's origin, keeping its path, and leave out a regioned app that has no
  origin for the viewer's region. `/api/suite/apps` without `sub` stays global.
- `/api/suite/peer` adds `regions` (`{region: origin}`) when the peer has rows. `url` stays
  the redirect origin. A caller sends an org's requests to `regions[home_region]`, with the
  home region from `/api/suite/orgs`; an org whose region has no entry gets no peer feature.
  ky-primitives `suitedir.Peer.URLFor(region)` applies this rule. KyPost and KyCalendar
  reach the KyMessages region that owns an org this way.

**Single-tenant.** The column exists and holds `local`, but nothing publishes it: no token,
UserInfo, webhook, launcher or suite answer changes, and the region routes are `404`, so
`client_region_origins` stays empty. The golden files are unchanged.

**Not covered.**

- Signed suite webhooks (`user.*`) still go to the connector's one endpoint. A multi-region
  app forwards one for an org homed elsewhere, as KyMessages-Native §6.2 item 3 already does
  for peer calls. Delivering to the home region's endpoint directly is a later change.
- KyIdentity sends no org lifecycle webhooks to apps. `org.*` platform events go to billing
  only, and apps learn an org's status from `/api/suite/orgs`. KyMessages-Native §5 and §6.2
  item 4 assume signed `org.suspended`, `org.resumed` and `org.deleted` webhooks from
  KyIdentity; until that is designed, they poll.

Tests: `TestHomeRegion` (format on both backends, `ValidHomeRegion` and the `CHECK` agree,
immutability, `local` for the default org, the Postgres insert without a region refused),
`TestSuiteOrgsCarryTheHomeRegion`, the platform event body, `TestClientRegions` (the admin
routes, refusals and the single-tenant `404`), `TestRegionalLaunchURLs` (launcher, apps and
peer), and the single-tenant golden files unchanged.

## Cells (amendment, 2026-11-24)

Owner decision, 2026-11-24: the shared install scales by **cells**, not by a database per org.
A cell is one deployment of an app: its replicas, its PostgreSQL database and its object
storage prefix, holding many orgs in the shared `org_id` tables every app already has. Every
org lives in exactly one cell. The driver is scale; isolation stays the `org_id` model and its
cross-org tests.

A cell is a home region with a finer slug, so the Home region mechanism above routes it
unchanged and KyIdentity needs no new code:

| # | Decision | Why |
|---|---|---|
| C1 | A `home_region` value names a cell: `<geography>-<n>`, for example `us-east-1`, `us-east-2`, `eu-central-1`. `local` stays the one cell of a single-region install. | H1's slug already allows it, and an org's cell has every property H2 gives its region: fixed, set at provisioning, never in a token. |
| C2 | Each app chooses how many databases serve the cells. An app's region map may point several cells at one origin (`client_region_origins` is keyed by region, not origin): KyCalendar can serve `us-east-1` and `us-east-2` from one deployment while KyDrive runs one per cell. | Apps grow at different rates. One suite-wide slug per org keeps every app's lookup the same (`suitedir.Peer.URLFor(home_region)`), and splitting a deployment later only adds rows. |
| C3 | Billing picks the cell at checkout (H3): the open cell of the chosen geography. Staff keep the list of open cells; KyIdentity does not place orgs. | H3 already takes `home_region` from `POST /orgs`. Placement is capacity policy, which billing already owns for plans. |
| C4 | A cell's orgs never move at launch (H2). Rebalancing is the later audited move flow H2 describes, now for cells as well as regions. | Moving an org copies every app's data. Opening a new cell for new orgs handles growth without it. |
| C5 | A deployment serves only orgs whose `home_region` is one of its configured cells, and refuses every other org on every way in, as an org that does not serve. | Every deployment sees the whole `/api/suite/orgs` list. Without this check two cells could both accept one org and split its data. |

**What each multi-tenant app adds.** A list of the cells it serves (for example `KY_CELLS`,
which replaces a single `KY_REGION`), required in multi-tenant mode and checked at startup
against its region map; the C5 refusal, with a test that an org of another cell is refused on
every credential type; and a cell-scoped object storage prefix. An app with no region map is
one URL serving the `local` cell, as today.

**Limits.** At most 32 cells per app (the region map's cap). Each cell is its own app
hostname (`us-east-2.calendar.<domain>`), because regions are hostnames, not an edge router;
CalDAV, WebDAV and mail clients are configured with that host once, and C4 keeps it valid.

**Owner answers, 2026-11-24** (the proposed defaults, approved):

1. Slugs are `<geography>-<n>`, and the geography is the slug without its trailing number. A
   residency label, if billing needs one, is billing's data.
2. A cell closes to new orgs when its app's load test shows less than 30 % headroom on its
   busiest database; each app's load tests set the number.
3. The 32-cell cap stays until an app needs more.

**Owner decision, 2026-11-25:** To start, the billing page shows where the customer's data is
stored, mapping the org's `home_region` geography to a human-readable hosting location /
residency label (billing's data, per answer 1 above). KyIdentity and the individual apps do
not add a separate data-location display yet.

Tests: none new in KyIdentity (the Home region tests cover the slug and the map). Each app's
own spec adds the C5 tests.

## Plans and orgs (amendment, 2026-11-23)

Owner decisions, 2026-11-23 (fixed): every paid account is an org. Personal is an org of 1
member, Couple 2, Family up to 6, and Business N seats (small teams). All four run on the
shared multi-tenant install, which runs as several replicas across hosts (Replicas,
Postgres and backups). Only Enterprise gets a dedicated install (Enterprise installs). This
supersedes owner decision 7 as first written, and every line that kept businesses off the
shared service. Every plan sells all seven apps (email, contacts, calendar, tasks, notes,
drive, messages); which apps an org has is still `org_apps`, set by billing.

| # | Decision | Why |
|---|---|---|
| P1 | **One `customer` kind** replaces `person` and `household`: `orgs.kind IN ('default','customer','staff')`. The plan is `orgs.plan` (billing's opaque name) and its size is `max_seats`. KyIdentity never branches on `plan`. | The smallest safe change. No shipped code tells `person` from `household`: every check names both (`internal/store/erasure.go:61,163,254`, `internal/store/mailbox_address.go:42,187`). Plans do not map onto kinds (Couple has none), so a `business` kind would be one more name with no behaviour, and each new plan would change the `CHECK` again. SQLite cannot change a `CHECK` without rebuilding `orgs` (D2), and every Postgres backup is a fresh SQLite file built by the migrations (`internal/store/pgcopy.go:367`), so it must accept every kind Postgres holds. With one customer kind, a new plan needs no migration. |
| P2 | `max_seats` of a customer org is 1 to `MaxSeats` (1000). `0` (unlimited) stays for the `default` and `staff` orgs only. Set by billing (`POST /orgs`, `PATCH`) or by staff (the org page, PR 5, step-up, audited in the org's log); never by the holder. Out of range is `400 invalid_max_seats`. | Validate at the boundary. A customer org always has a cap, so a missing field cannot mean unlimited. Above the ceiling is Enterprise. |
| P3 | Seats (Entitlements): a seat is an active or pending everyday account (owner answer 7). Checked at every add (member add, admin create, enable), and again at activation. **A downgrade below the seats in use is refused** (`409 seats_in_use`, nothing changes); billing removes members, pending invites included, first. | The safe rule. An org never holds more seats than it pays for, nobody is disabled by surprise, and there is no `over_limit` state to derive, signal or reconcile. |
| P4 | The account holder (D9) is the same for every plan: a pointer, not a role, with no admin route. A business's holder is its billing contact. Member invites and removals go through the billing portal (`members:*`) or staff, for every plan. | Owner decision 6: staff stay the only administrators. A business that needs its own administrators or delegations buys Enterprise. |
| P5 | **Per-org MFA requirement.** Staff may add one required enrollment policy for a customer org, scope `org:<org_id>`, on an org route (`permAdmin`, step-up, audited in the org's log). It joins today's intersection: factors intersect with the platform policies and the earliest per-user deadline wins (`AGENTS.md`, MFA enrollment), so it adds a requirement and removes none. The holder and billing cannot set or clear it. | A business may need MFA for its members, and staff are its only administrators. A billing token that could clear it would strip a second factor from a whole org. The scope key is the org's ID, globally unique, so D2's per-org key problem does not arise. Build note: the `enrollment_policies` `CHECK` (`internal/store/group_enrollment.go:54`) admits only `organization`, `administrators` and `group:`, so widening it has P1's SQLite constraint and uses P1's method. |
| P6 | **The storage a customer buys is one pool per org, across all apps, held by KyIdentity** (Org storage pool). Per-app quotas (`org_apps.quotas_json`, opaque, ≤ 4 KiB, set by billing) stay for each app's safety limits (per upload, per mailbox, sending), already settable per org. | Plans and orgs owner question 5, decided 2026-11-23. A per-app key cannot hold one figure all apps share, so the pool is an org field with usage reports (S1, S4). |
| P7 | Delete everything (amendment, 2026-11-21) applies to every customer org: the holder alone deletes at once, a holder with members schedules deletion with the 7-day export window (`erasureGrace`), and a member deletes only themselves. The notice mail says "organisation", not "household". | One rule for every plan. Apps export a member's own data, so the window does not hand a member the business's other data. |
| P8 | The business features under Per-org features (inbound SCIM, HR, upstream federation, outbound SCIM, forward-auth) stay off for every customer org. | Each needs per-org connectors or secrets the shared install does not have. Enterprise has them all. |

**Migration (schema version 16, `customer_kind`).** No customer org exists in any database
yet: `KYIDENTITY_TENANCY=multi` is refused at startup until PR 6, and `person`/`household`
rows come only from tests. So:

- Schema version 7's DDL is shipped and does not change (`AGENTS.md`, Schema versions): every
  install, fresh or upgraded, creates the old `CHECK` there and version 16 replaces it.
- Postgres: version 16 swaps the constraint (`orgs_kind_check`) after moving any
  `person`/`household` row to `customer`.
- SQLite: a `CHECK` cannot be altered, and rebuilding `orgs` would trip the three foreign keys
  to it (`org_erasures`, `erased_subjects`, `erase_notices`). So version 16 edits the `CHECK`
  text in `sqlite_schema` under `writable_schema`, SQLite's documented procedure for changing
  a constraint, bumps `schema_version`, moves any old row, and runs
  `PRAGMA integrity_check(orgs)`. A fresh file and an upgraded one end with the same `orgs`
  definition, so a Postgres snapshot of customer orgs restores into either.
- Both backends recreate the triggers that named the old kinds: `org_erasures_holder` and
  `users_mailbox_insert`/`users_mailbox_update` (on Postgres, the function
  `users_mailbox_check`). Versions 12 and 13, which created them, are
  shipped and keep their `person`/`household` text; version 16 carries the customer text
  itself, and `TestShippedMigrationsUnchanged` fails if any shipped version's schema changes.
- Single-tenant behaviour and the golden files do not change.

**Events.** The canonical name for a resume is `org.resumed` (Events back to billing).
KyMessages-Native still names `org.unsuspended` in `docs/PRODUCT.md:75` and
`docs/INSTALLER_SETUP.md:71`; its tenancy design already plans to accept `org.resumed`
(`docs/superpowers/specs/2026-11-22-tenancy-design.md:89`). KyIdentity sends no `org.*`
event to anyone yet: the outbox is PR 4.

**Storage backend.** Decided 2026-11-23 (Plans and orgs owner question 6): in multi-tenant
mode, primary app content goes in S3-compatible object storage **only**. There is no
disk-volume fallback: an app started in multi-tenant mode without object storage configured
refuses to start. Single-tenant installs keep their volumes, unchanged. Each app's spec owns
its backend. KyIdentity stores no content: its database stays in PostgreSQL and is small, so
it has no object-storage backend, and no bucket key reaches it.

Owner questions. 2 to 4 keep the default this design applies; the rest are decided.

1. *Decided 2026-11-23:* the seat ceiling `MaxSeats` is 1000; above it is Enterprise.
2. A downgrade below the seats in use. *Default: refused* (P3). The alternative is to accept
   it, refuse new seats, disable nobody, and signal `org.over_limit`, as first written.
3. Who sets the per-org MFA requirement. *Default: staff only* (P5). Billing never.
4. The export window when a business's holder deletes everything. *Default: 7 days, as for
   every plan* (P7).
5. *Decided 2026-11-23:* one storage pool per org across apps (Org storage pool).
6. *Decided 2026-11-23:* object storage only for app content in multi-tenant mode, with no
   disk-volume fallback (Storage backend). This replaces "launch may run on volumes".
7. *Decided 2026-11-23:* a Business pool counts paid seats, `max_seats` (S2), not the
   members in use.
8. *Decided 2026-11-23:* incoming mail while over the pool gets 7 days' grace and up to +10%
   of the pool (at least 2 GB), whichever ends first, then `452 4.2.2` for 3 days, then
   `552 5.2.2`. Org status wins (Org storage pool, "Incoming mail while over the pool").
   KyPost's spec applies it.
9. *Decided 2026-11-23:* under Delete everything, shared content passes to another member,
   a member's messages become tombstones, and nothing other members wrote is deleted
   (Delete everything, "Shared content").
10. *Decided 2026-11-23:* no automatic version pruning at launch (S7).

Tests (code PR): the `CHECK` and the renamed kind on both backends (a customer org is
accepted, `person` and `household` are refused, an upgraded Postgres database lands on the
same constraint as a fresh one), Delete everything and the mailbox address for a `customer`
org on both backends, a Postgres snapshot of a customer org restoring through SQLite, and
`testdata/tenancy-golden` unchanged.

## Org storage pool (amendment, 2026-11-23)

Owner decisions, 2026-11-23 (fixed). **One storage quota per org, across all seven apps,
required for launch.** It is one number per org, shared by every member: Personal 20 GB,
Couple 40 GB, Family 100 GB, Business 30 GB × its seats (pooled across the team, recalculated
whenever seats are added or removed), Enterprise custom. **KyIdentity holds the pool.** Each
app checks it before a write that adds bytes, and reports its usage. Per-app limits that exist
today (per upload, per user, per mailbox) stay as safety limits, but the figure a customer
buys is the pool. **When a seat change leaves a Business org over its pool** (approved rule):
(1) new uploads and new stored content are blocked until the org is back under the pool,
(2) no data is ever deleted, (3) the org's admin is warned before the seat change takes
effect. Primary content on the hosted install goes in S3-compatible object storage only, with
no disk-volume fallback (Plans and orgs owner question 6, Storage backend); that is each app's spec.
KyIdentity stores no content, so it has no object-storage backend and is not counted in the
pool. Line references in this section are to `master` at `5604cd9`.

Single-tenant installs (Enterprise included) have no pool: every route below answers `404`,
the columns stay at their defaults, and apps keep their install limits. Enterprise "custom"
is those install limits.

| # | Decision | Why |
|---|---|---|
| S1 | **The pool is an org field**, not a `quotas_json` key: `orgs.storage_bytes` (a fixed part) and `orgs.storage_per_seat_bytes`. The pool is `storage_bytes + storage_per_seat_bytes × max_seats`, computed by KyIdentity in the transaction that changes any of the three. Personal is `20 GB + 0`, Business `0 + 30 GB`. KyIdentity never branches on `plan`. | `quotas_json` is per app and opaque, so it cannot hold one figure that all apps share, and KyIdentity cannot compute with it. Deriving the Business pool from `max_seats` means a seat change and the pool change are one write: billing cannot change one and forget the other, and two writes cannot race. |
| S2 | **"Seats" means paid seats, `max_seats`**, not the members in use. | A Business customer buys seats; the pool follows what is paid. Using members in use would shrink the pool when a member leaves without any change to the bill. Owner question 7. |
| S3 | Billing sets both fields on `POST /orgs` (required for a customer org) and `PATCH`; staff set them on the org page (PR 5, step-up, audited in the org's log); never the holder. Each is a whole number of bytes, `storage_bytes` 0 to 2^50 and `storage_per_seat_bytes` 0 to 2^44; a customer org's pool must be at least 1 GiB. Otherwise `400 invalid_storage`. The default and staff orgs keep `0, 0`: no pool. | Validate at the boundary. A missing field must not mean unlimited. The bounds keep `per_seat × MaxSeats` far inside a signed 64-bit integer. |
| S4 | **Usage is reported per org and per app** to `POST /api/suite/storage`, with a sequence number, and the answer is that app's **headroom grant**: a ceiling it may fill until the grant expires. The pool and the reports live in PostgreSQL (`org_storage`); no replica holds any of it. | A grant reserves bytes for one app, so two apps cannot both fill the last bytes, and an app checks every write against its ceiling locally, with no round trip per write. |
| S5 | **A write over the pool is refused, never deleted.** An org whose usage passes its pool (after a pool reduction, or by the mail overage of owner question 8) gets grants of zero. Every app then refuses writes that add bytes and allows every write that removes or keeps bytes. | The approved rule, and the safe default for every plan, not only Business. |
| S6 | **"The admin" is the account holder** (D9). Staff stay the only administrators (owner decision 6 at the top of this spec): the holder is warned, not made an administrator. | The holder is the billing contact who asks for the seat change. |
| S7 | **No automatic version pruning at launch.** Every kept older version of an item counts in the pool until a person deletes it. No app removes a version on its own, over the pool or not. | Decided 2026-11-23. It follows S5: nothing is deleted unless a person asks. Pruning can come later as a choice the holder makes. |

### Schema

```
orgs (…,
  storage_bytes BIGINT NOT NULL DEFAULT 0,          -- S1; 0 for the default and staff orgs
  storage_per_seat_bytes BIGINT NOT NULL DEFAULT 0, -- S1
  storage_over_since BIGINT)                        -- unix seconds; NULL while within the pool
org_storage (org_id REFERENCES orgs, app_id REFERENCES app_registry ON DELETE CASCADE,
  used_bytes BIGINT NOT NULL,      -- the app's last accepted report
  seq BIGINT NOT NULL,             -- that report's sequence number
  ceiling_bytes BIGINT NOT NULL,   -- used_bytes + the grant; reserved until the next report
  reported_at BIGINT NOT NULL,
  PRIMARY KEY(org_id, app_id))
```

`org_storage` is org class (O): `org_id` is in its key, `DELETE /orgs/{id}` and Delete
everything remove it with the org's other rows (`orgRowTables`). It holds byte counts only,
no names, paths or content. Both backends get the schema in one version (with the `CHECK`s
for S3's bounds); on SQLite it stays empty, since SQLite holds no customer org (D2).

### `POST /api/suite/storage` (suite contract)

Suite client authentication (HTTP Basic, a confidential client, `Authenticate`), rate limit
and `no-store`, as `/api/suite/orgs`. The app is the caller's `app_registry` row
(`suiteAppID`), never a body field. `404` in single-tenant mode.

```
{"reports": [{"org_id", "used_bytes", "seq", "want_bytes"}]}          -- 1 to 500 entries
{"results": [{"org_id", "result": "ok"|"stale"|"unknown_org",
              "seq", "ceiling_bytes", "ttl_seconds",                   -- this app's grant
              "pool_bytes", "org_used_bytes", "over_since"}]}          -- the org, all apps
```

- **Validation.** Body ≤ 64 KiB; `org_id` a UUID, at most once per request; `used_bytes`
  and `want_bytes` 0 to 2^53; `seq` 1 to 2^63−1. Anything else is `400 invalid_request` for
  the whole request, and nothing is applied.
- **Which orgs.** An org the app is not told about (`suiteOrgVisibleSQL`), or `deleted`,
  answers `unknown_org`, the same for both, so the route reveals no other org. An app whose
  access was turned off still reports (its bytes still count) but gets no grant.
- **Sequence.** `seq` is strictly increasing per org and per app, and comes from the app's
  shared database (for example a PostgreSQL sequence), never from one replica's clock. A
  report is applied only when its `seq` is above the stored one, in one
  `UPDATE … WHERE seq < ?` (or the first insert), so a stale report cannot overwrite a newer
  one in any order. The same `seq` with the same `used_bytes` is a replay: `ok`, with the
  stored grant unchanged (idempotent). A lower `seq`, or the same one with other bytes, is
  `stale` with the stored `seq` and changes nothing; the app keeps its current grant until it
  expires. A renewal therefore needs a new `seq`.
- **Grant.** In the same write transaction (serialised on every replica: one Postgres
  advisory lock, `AGENTS.md:198`), for an accepted report:
  - `used` is the sum of every app's `used_bytes` for the org, this report included;
    `held` is the sum of every *other* app's grant, `ceiling_bytes − used_bytes`. A grant
    stays held after it expires, until that app's next report replaces it: an app may have
    filled it before expiry without reporting yet, so releasing it on a clock would
    under-count. No clock comparison happens in KyIdentity, so skew cannot matter;
  - `grant = max(0, min(want_bytes, pool − used − held, cap − held))`, where
    `cap = min(pool / 8, 64 GiB)` bounds every grant an org holds at once;
  - the grant is `0` when the org is not `active`, the app is not enabled for it, or the org
    is over its pool (S5);
  - the row stores `ceiling_bytes = used_bytes + grant`. The answer carries
    `ttl_seconds: 900`, the app's own limit on using it.
- **Over the pool.** The same transaction sets `orgs.storage_over_since` to now when `used`
  first passes the pool, and clears it when `used` is back within it. Either change takes a
  new org revision (`nextOrgRevisionSQL`), so it reaches apps through `/api/suite/orgs`.
  A `PATCH` that changes the pool does the same.
- **Audit.** Reports are not audited one by one (they are metering, not changes). A flip of
  `storage_over_since` writes `org.storage_over` or `org.storage_within` in the org's log,
  with the two byte figures only.

**`/api/suite/orgs` gains** `storage: {pool_bytes, over_since}` on each customer org, so
KyPost and the others read the over-quota state on the poll they already make. Usage itself
changes too often to take an org revision; it is in the storage answer only.

**Platform API.** `GET /orgs/{id}` adds `storage_bytes`, `storage_per_seat_bytes`,
`pool_bytes`, `used_bytes`, `used_by_app` (`{app_id: bytes}`) and `over_since`. Byte counts
only.

### The check an app makes

- An app keeps its grant (`ceiling_bytes` and an expiry) in its own shared database, so every
  replica checks the same figure. The expiry is the time the app **sent** the request plus
  `ttl_seconds`, by the app's clock, so a slow answer or a skewed KyIdentity clock can only
  shorten it.
- A write that adds `n` bytes is allowed only when the app's committed usage plus `n` is at
  most `ceiling_bytes`, the grant has not expired, and the check runs inside the write's own
  transaction (so the app's own replicas cannot both take the last bytes). A write that adds
  nothing (a delete, a move, a shrink, a metadata edit) is always allowed.
- The app reports about every 60 s for each org whose usage changed, at once when it has
  used half its grant or wants more than it holds (`want_bytes` sized to its recent rate),
  and at least once per `ttl_seconds` for every org it holds a grant for, renewing it or
  releasing it with `want_bytes: 0`, in batches. An app that stops reporting keeps its last
  grant reserved (at most the org's cap) until it reports again. A write larger than the grant cap is written in parts, each checked, or
  refused by the app's own per-write limit. The cap is 2.5 GB for Personal, the smallest
  plan, and larger for every other plan; a smaller custom pool (S3 allows 1 GiB) has a
  proportionally smaller cap, down to 128 MiB, and its apps write in smaller parts.
- **KyIdentity unreachable:** once the grant expires (at most 15 minutes), writes that add
  bytes are refused until a report succeeds. Reads, deletes and mail already accepted are not
  affected. That fails closed; the staleness bound is the 15-minute grant.
- **What "used" counts** is each app's spec: every stored byte it keeps for the org (bodies,
  attachments, previews and indexes if the app counts them), the same figure it reports.
  An app with no stored content (if any) reports `0` and asks for nothing.
- **After a restore** of an app's database, its `seq` source may restart below KyIdentity's.
  Its reports are then `stale` with the stored `seq`; the operator's restore step advances
  the app's sequence past that value, and the next report wins. An app never advances it on
  its own, so a stale replica cannot overwrite a newer figure. After a restore of
  KyIdentity, the stored rows are older, and the apps' next reports (higher `seq`) replace
  them.

**Worst-case overshoot.**

- With the pool unchanged: **none**. Every byte an app may add is reserved for it alone
  (`used + held + grant ≤ pool`), and each app checks inside its write transaction.
- After a pool reduction (a seat removed, a downgrade): the grants already handed out, at
  most `min(old pool / 8, 64 GiB)` for the whole org, for at most 15 minutes. After that every
  grant is zero until the org is back within the pool.
- Plus incoming mail (owner question 8): at most `max(pool / 10, 2 GB)`, accepted for at
  most 7 days after `over_since`, which KyPost bounds.
- Not bounded by this design: an app that reports less than it stores. Apps are
  platform-run and trusted for their own figure (threat model, "The operator is trusted").

### The seat change that leaves an org over its pool (approved rule)

- `PATCH /orgs/{id}` that lowers the pool to below the org's current `used` (a lower
  `max_seats` for Business, or new storage fields on any plan) is refused with
  `409 storage_over_pool {pool_bytes, used_bytes}` unless the body carries
  `"storage_over_pool_ack": true`. Billing sets it only after the holder has confirmed the
  warning in the customer portal, which shows both figures and says that new uploads and new
  content stop until the org is back under the pool and that nothing is deleted. The staff
  org page shows the same warning in its confirm dialog. The flag is not stored; the audit
  row of the change records that it was given.
- So the warning comes **before** the change takes effect, on every path: the change cannot
  be made without the acknowledgement.
- Once applied, the org is over its pool (`storage_over_since` set), every grant is zero, and
  each app blocks new stored content through the same check. For example (each app's spec
  states its exact list and what members see, a banner with the two figures): KyDrive
  refuses uploads and new versions, KyNotes and KyCalendar refuse writes that grow the org,
  KyMessages refuses new attachments, and KyPost refuses new stored mail, with receiving
  under owner question 8. Nothing
  is deleted, nothing is locked, reads and exports work, and deleting content brings the
  org back.
- The org is back within its pool when the apps' reports sum to the pool or less; KyIdentity
  then clears `storage_over_since` and grants resume. Billing can also add seats.

**Incoming mail while over the pool (owner question 8, decided 2026-11-23).** Rejecting mail
bounces it to outside senders, who did nothing wrong, so the rule is a grace period with a
bounded overage, then a temporary failure, then a permanent one.

- **Grace:** from `over_since`, KyPost keeps accepting mail for the org's mailboxes beyond its
  grant until **7 days** have passed or the mail accepted beyond the grant reaches
  **`max(pool / 10, 2 GB)`**, whichever comes first (Personal: 2 GB; a 50-seat Business org:
  150 GB). It reports that mail as usage like any other. Members and the holder see a banner
  in KyPost: "Your organisation is over its storage. Mail is still arriving until <date>."
- **Then a temporary failure:** `452 4.2.2` ("mailbox full", retry later) to senders for
  **3 days** from the end of the grace, which most senders retry for about 4 to 5 days
  before they give up, so freeing space in that time still gets the mail.
- **Then a permanent failure:** `552 5.2.2`, mail bounces, the sender is told the mailbox is
  full. Nothing already stored is touched.
- Once the org is back within its pool, KyIdentity clears `over_since` and mail is accepted
  normally. A later overrun sets a new `over_since`, so the steps start again.
- **Org status wins.** A suspended or `deletion_scheduled` org gets K's answers (`550` during
  scheduled deletion, owner decision), whatever its storage. The receiving tier (K's hosted
  receiving spec) checks the org row KyPost already caches from `/api/suite/orgs`, which now
  carries `over_since`; it needs no new call to KyIdentity.
- **The contract KyPost needs is `over_since`**, with `pool_bytes`; `org_used_bytes` comes
  in the storage answer. KyPost records when its own grace ended (by time or by overage)
  in its database. The days, the overage and the SMTP codes are KyPost's rule (K), not
  KyIdentity's: KyIdentity computes none of them.

Tests (build; the owner approved it on 2026-11-23): the pool formula and S3's bounds on both backends;
a stale `seq` in either order, a replay, the same `seq` with other bytes; two apps asking for
the last bytes at once (one gets them); a grant of zero for a suspended org, a disabled app
and an over-pool org; `unknown_org` for another app's org and a deleted one, identical; an
oversize body, 501 entries, a repeated `org_id`; the `PATCH` refusal and the acknowledged
change; `storage_over_since` set and cleared with a new revision; four handles on one
Postgres database reporting at once; single-tenant `404` and the golden files unchanged.

## Entitlements

KyIdentity stores `max_seats` on `orgs`, and per-app enablement and opaque quotas in
`org_apps`. Who enforces what:

- **KyIdentity enforces seats and app enablement.**
  - A seat is an everyday account (`role='user'`) that is active or pending (open
    question 7).
  - A transition that adds a seat is checked: a member add (platform API or admin UI)
    or re-enabling a disabled account. SCIM and HR creates are off in multi-tenant v1.
    One that would pass `max_seats` is refused with `seat_limit`.
  - *Amended 2026-11-23:* activation (first sign-in) is checked again, in the redemption's
    transaction: it is refused like an expired link when the org's activated seats already
    reach `max_seats`. The pending account holds its seat, so this never fires while the
    seat invariant holds. It is the backstop for a path that skipped the add check.
  - A `PATCH` that lowers `max_seats` below the seats in use is refused (Plans and orgs P3),
    so a customer org never holds more seats than its plan.
  - One store function counts and inserts inside the write transaction. Postgres write
    transactions are already serialised on one advisory lock across every replica
    (`AGENTS.md:198`), so count-then-insert cannot race. No per-org lock or seat counter
    column is needed.
  - A disabled app gives no access: the `app_access_facts` join above means no token and no
    suite listing.
- **Apps enforce their own quotas** (per-app safety limits, mailboxes) from
  `GET /api/suite/orgs` (`org_apps.quotas_json`, per org and per app).
- *Amended 2026-11-23:* **KyIdentity holds the org's storage pool** and grants each app
  headroom against it; each app refuses a write that adds bytes beyond its grant (Org
  storage pool).

Why a suite API pull:

- A claim goes stale for a token's lifetime and grows every token.
- A claim shows each app the others' quotas, unless it is filtered per audience, which
  adds work for no gain.
- A webhook needs a new receiver, ordering and retry rules in every app. The suite groups
  spec rejected that for the same reasons (`2026-11-15-suite-groups-design.md`, "How apps
  learn of suite groups").
- Every app already polls the suite directory with its client credentials.

## Per-org features

Customer orgs are every paid plan, Business included (Plans and orgs). The business features
marked below stay off for every customer org, and an Enterprise install has them all (see
Enterprise installs).

| Feature | Multi-tenant v1 | Notes |
|---|---|---|
| Users, groups, access requests, expiry, offboarding | Per org, run by staff | `OrgStore` |
| Delegations | Staff org only | D8 |
| App assignment, app roles assignment | Per org, run by staff | Roles themselves are global (appendix) |
| MFA enrollment policies (`enrollment_policies`) | Platform-wide, set by staff, plus an optional per-org requirement set by staff (`org:` scope) | D10, Plans and orgs P5. Staff are pinned to passkeys (Roles). |
| Inbound SCIM connectors | Disabled | Syncs a business directory. A small team has none; Enterprise does. |
| HR provisioning | Disabled | Feeds a business HR system, and reserves a KyPost address per `domain` (`hr.go:46`). |
| Upstream SSO / federation per org | Absent | Does not exist today (`docs/access-lifecycle-plan.md:73`, `design.md:32`). It serves a business's own IdP. |
| Generic outbound SCIM to customer targets | Disabled | Provisions a business's own apps, and would need per-org `paired_systems`. |
| Outbound to suite apps (`paired_systems` of suite types) | Platform | Payload carries `org_id` |
| Forward-auth proxy apps | Disabled | Hosts and edge secrets are install-wide (`2026-11-15-forward-auth-design.md`) |
| Custom launcher cards (`applications`) | Disabled for orgs | Platform cards only |
| Branding (`branding_org_name`, `branding_logo`) | Platform only | The sign-in page comes before the org is known. The org name shows after sign-in (open question 5). |
| Suite mail domains and default theme (`suite_email_domains`, `suite_default_theme`) | Platform only | Owner decision 2026-11-20: one list and one default for the install or hosted platform, set by staff there. In multi-tenant mode the list bounds mailbox addresses, and a domain in use cannot be removed (Mailbox address). |
| Session limits, mail, alerts settings, attestation, rate-limit exemptions, push relays | Platform | `system_settings` keys (`session_limits.go:13`, `sealed.go:30`) |
| Installer setup (`apply-setup`, `proxy-app`) | Refused | The installer channel is single-tenant |
| Backups, restore, drill | Platform | Whole install |
| Audit log | Per org view, plus platform | `audit_events.org_id`, NULL for platform events |

The disabled features answer `404` in multi-tenant mode, and their admin routes refuse to
create a connector, as the cross-org matrix test checks.

## Enterprise installs

*Amended 2026-11-23.* Business plans are customer orgs on the shared service (Plans and
orgs). Only an **Enterprise** customer gets its own dedicated KyIdentity install, in the
cloud or on-prem, in single-tenant mode (SQLite is fine there), with its own administrators
and delegations. That is today's self-hosted behaviour, with every business feature above.
For now staff set these installs up by hand. The billing service only bills them and does
not deploy them. They are outside this spec.

## Phased build plan

Each PR is shippable on its own, with single-tenant behaviour unchanged. `KYIDENTITY_TENANCY=multi`
is refused at startup until PR 6 lands. Before PR 5, staff cannot work in a customer org.
Before PR 6, member adds do not enforce seats. Until PR 6, multi-tenant code runs only in
tests.

1. **Org model and default-org migration.**
   - Adds the next free schema version on both backends (6 is workstation login, and 7 is Active Directory if PR 256 lands first): the tables, columns, triggers and views above,
     and `tenancy_mode`. No delegation kind changes. The account holder guard triggers
     land here too. Single-tenant never sets the pointer, so they never fire there.
   - Tests:
     - An upgrade test from the previous version's database on both backends (`upgrade_test.go`
       style). Every view returns the same rows before and after.
     - `TestEveryTableIsClassified` and `TestOrgOwnedTablesHaveOrgID`.
     - `TestBackendsHaveTheSameColumns` still passes.
     - The full `go test -race ./...` and the `postgres` job.
2. **Store scoping.** `OrgStore`, `PlatformStore`, the pre-org allowlist, the `platform`
   route flag, and the staff-org rule for `role='admin'` and delegations (D8). Split by
   area so each PR stays reviewable: (a) users, groups and memberships, (b) apps,
   assignments and roles, (c) sessions and credentials, (d) provisioning and audit.
   - Tests: `TestOrgSQLNamesOrgID`, and `TestCrossOrgMatrix`, which grows with each sub-PR.
     It runs with a test-only multi-org constructor on Postgres. Existing tests pass
     unchanged on the default org.
3. **Org claim, suite APIs and webhooks.**
   - Adds `org_id` in tokens, userinfo and the logout token, and `org_id` scoping on the
     suite routes. Adds `/api/suite/orgs` and `org_id` in sync payloads, all gated on mode.
   - Tests: single-tenant golden tokens are byte-identical apart from `jti`, `iat` and
     `exp`. Multi-org suite tests. A `ky-primitives/suitedir` `Orgs` method.
4. **Platform provisioning API.** The listener, tokens and CLI, idempotency, revision,
   create, update, suspend, resume and deletion, the member endpoints (with the optional
   mailbox address, set through `OrgStore.SetMailboxAddress` without overwrite), the account holder
   and its notices, the events outbox, and `active_principals`.
   - Tests:
     - Replay, conflict and stale-revision cases, including a retry of a successful
       suspend under the same key and body, which must get the stored answer and not
       `stale_revision`. Also a create whose response was lost, then a `PATCH`, then the
       create retried under the same key (stored answer) and under a new key (`200`, from
       `create_request_hash`).
     - Every `credential_principals` call site is on the allowlist. A suspended-org user
       reaches the second factor and gets `org_suspended` only from session creation.
     - Suspension ends every grant: a table of every credential type, like
       `TestForwardRevocationWithin30Seconds`.
     - In a suspended or `deletion_scheduled` org, each account flow in the Views table
       refuses: issuance, forgot-password (no mail), redemption of a link issued before the
       suspension, and step-up. A pending member cannot activate.
     - In an `active` org, the full pending path works: `POST /orgs` mails the holder's
       invite, `resend-invite` issues a new one, the holder and a member each activate,
       and a reset link works for an activated member.
     - Every sign-in path refuses a suspended org. Interactive sign-in gives the
       wrong-password answer for a wrong credential, and `org_suspended` only after every
       required factor has passed, with no session created.
     - Clearing the account holder pointer is refused on an `active`, `suspended` or
       `deletion_scheduled` org, and in a move to `deleted` before `delete_after`. It is
       allowed only in the deleting `UPDATE`. A `deleted` org's status cannot change.
     - A late `PATCH` or `resume` under a new key, with a revision at or below the stored
       one, is `stale_revision` and changes nothing.
     - A pending holder activates through `RedeemAccountToken` despite the guard.
       `POST /orgs` with a pending holder succeeds.
     - Delete removes every org row, checked against the table classification.
     - Platform tokens are refused on the public listener, and browser and SCIM
       credentials are refused on the platform listener. An `orgs:*` token is refused on every member endpoint. A `members:*` token is refused on
       every org lifecycle route.
     - The account holder cannot be deleted, disabled or ended through any path: the
       member endpoints, the admin UI routes, `disable-user`, `RunDueExpiries` and the
       pending-account cleanup. Each is called on the holder, and the pointer must still name
       a live member afterwards. A pending holder past its token's expiry stays, and
       `org.holder_invite_expired` is queued once.
     - Events are signed and retried.
   - **Status (2026-11-25).** Built in two stacked PRs. The first: the listener, tokens and
     CLI, idempotency, revision, create, read, update, suspend, resume, schedule-deletion and
     deletion, the account holder at create, `org_active` in the account flows, and their
     tests. A replayed or refused call is audited too; only answers are stored under a key, so
     a refusal (including `503 mail_not_configured`) can be retried under the same key. The
     second: the member endpoints with the mailbox address, the holder's notices, outbox
     delivery and `org.holder_invite_expired`, and the `credential_principals` allowlist.
     The holder's notice is mailed after the change commits, best effort (a failure is
     audited), not from an outbox. `org.holder_invite_expired` is queued when the expired
     link is purged, in the same transaction, so once per expiry without a new column.
     Disabling a pending member is `409 member_state`: delete it or re-invite it instead.
     E8 of the cross-app e2e design: a customer member signs in with a password alone in
     multi-tenant mode unless staff require a second factor with an enrollment policy
     (D10); no passkey is pinned for customer members (only staff are pinned, PR 5).
     `org_apps` written by the platform API is step 6 (Entitlements).
   - **Mailbox address** (landed before PR 4, see Mailbox address): the column, its index
     and triggers, `OrgStore.SetMailboxAddress`, the `mailbox` webhook entry, the domain
     removal refusal, and the staff route and edit field. An org route binds the org staff select
     (PR 5), so the staff path sets a customer's mailbox address. Tests: uniqueness races, domain refusal, cross-org
     refusals, the single-tenant golden files unchanged, and a multi-tenant webhook golden.
5. **Staff admin UI.**
   - Adds the org selector and `X-Ky-Org`, staff read audit and the cross-org audit by
     actor, the pinned passkey policy, the customer-account guards (no password, no email
     change, links only by mail), and the account holder's export page and deletion
     banner.
   - Tests: the extended permission matrix with staff personas, a refusal of every change
     to the pinned policy, the existing UI verification flow (`UI-VERIFICATION.md`), and
     the export's content proven to hold no other org's rows.
   - **Status (2026-11-25).** Org selection and the pinned passkey are built. In multi-tenant
     mode an org route needs `X-Ky-Org` (`400 org_required`), checked against `orgs` after
     the caller is proven staff (a customer org or the staff org, else `404 unknown_org`),
     and a staff read writes `staff.read` in the selected org's log. The finder is
     `GET /api/admin/orgs?q=` (ID, `billing_ref` or a member's exact email; empty is the
     staff org), audited as one platform row `staff.orgs_read` naming the orgs returned. The
     admin UI starts in the staff org and sends the header on admin calls. Every multi-tenant
     start pins the `administrators` policy (required, passkey only, grace 0), and the admin
     API refuses any change to it (`409 pinned_policy`). The cross-org matrix runs
     multi-tenant with staff in org A. The HTTP tests cover the customer credential guards.
     Remaining: the cross-org audit by actor, the holder's export page and deletion banner, the staff seat
     and pool fields (P2, S3) and the `org:` MFA scope (P5).
6. **Entitlements.**
   - Seat enforcement on every seat-adding path (member add, admin create, re-enable),
     `over_limit`, `org_apps` from the platform API, and quotas in `/api/suite/orgs`.
   - Tests: the seat limit on each path, two parallel adds on Postgres with one seat free
     (one succeeds), and app disablement removing access and suite listing.
   - **Status (2026-11-25).** Built. Seats were already enforced by triggers on every path,
     with the activation backstop (Org storage pool); `over_limit` is gone (P3). `apps` on
     `POST /orgs` and `PATCH` is `{client_id: {enabled, quotas?}}`: an unregistered client, a
     missing `enabled` or quotas that are not a JSON object of at most 4 KiB are
     `400 invalid_apps` and change nothing; quotas omitted keep the stored ones; staff's
     `access_mode` is untouched. A change takes a new org revision, so `/api/suite/orgs`
     lists it after `since`; disabling an app also ends the org's tokens, codes and client
     sessions for it, as any lost access does. Tests: `TestPlatformOrgApps`,
     `TestSeatRaceAcrossReplicas`, both backends.
7. (Optional) **Postgres row-level security** as extra protection.
8. **Delete everything** (amendment). Stacked PRs, each multi-tenant only:
   - (a) This amendment, `org_erasures`, `erased_subjects` and their triggers, the holder's
     two paths and the sweep, `user.erased`, `POST /api/user/erase` and
     `GET /api/suite/erased`.
   - (b) The org gate at session creation, the export-only session for the cases above, and
     the `export_only` claim. Ahead of PR 4, the gate is one SQL condition at the choke points
     every grant passes (session creation, code creation, token registration and the token
     check) rather than a read of the `active_principals` view: the same rows, and the
     `credential_principals` naming stays PR 4's.
   - (c) The account page button and dialog.
9. **Plans and orgs** (amendment, 2026-11-23). Stacked PRs:
   - (a) This amendment.
   - (b) Schema version 16 `customer_kind` and the kind checks it renames (P1, P7), on both
     backends. Nothing else is shipped yet that the amendment changes.
   - Folded into later PRs: PR 4 drops `kind` from `POST /orgs`, validates `max_seats`
     (P2) and refuses a downgrade (P3); PR 5 adds the staff seat field and the `org:` MFA
     scope (P5); PR 6 adds the activation backstop (P3).
   - (c) Org storage pool (approved for building 2026-11-23): the schema version, the `orgs`
     fields with `POST /orgs`/`PATCH`/`GET` (or with PR 4 if it has not merged),
     `POST /api/suite/storage`, `storage` in `/api/suite/orgs`, and `docs/SUITE-DIRECTORY.md`.
     It is required for launch, so `KYIDENTITY_TENANCY=multi` stays refused until it merges.

## Owner answers

On 2026-11-19 the owner approved every recommendation below. Where a recommendation is
conditional (10, 11), the condition decides it when the billing service is designed.

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
   - (a) First come, first served, released by staff.
   - (b) A pending, never-activated account is deleted when its activation token expires,
     which frees the address.
   - Recommend (b), with a 7-day activation lifetime in multi-tenant mode. An account named
     as holder is never deleted this way (see Account holder guard).
4. **What a suspended org's user sees after a correct password and second factor.**
   - (a) The generic invalid-credentials answer.
   - (b) "Your organisation is suspended".
   - Recommend (b). Only a holder of valid credentials learns anything.
   - Either way, the account holder's export-only session during scheduled deletion stays
     as designed above.
5. **Per-org branding.**
   - (a) Never.
   - (b) After sign-in only (launcher, account pages), later.
   - Recommend (b), after v1.
6. **Postgres row-level security.**
   - (a) In v1.
   - (b) After PR 2's app-level isolation is proven.
   - Recommend (b).
7. **What is a seat?**
   - (a) Active and pending everyday accounts.
   - (b) Active only.
   - Recommend (a): an invite reserves a seat, so a plan cannot be exceeded by inviting.
8. **Capacity of the single writer.** Accept for v1, and set a measured target (orgs,
   sign-ins a minute) before launch? Recommend yes. Revisit per-org write locks only if the
   measurement fails.
9. **Who gets the export.** Bounds of 7–90 days for the grace period. Then:
   - (a) The account holder, signed in to the export-only session.
   - (b) A one-time download link mailed to the account holder.
   - (c) Staff, on the account holder's request.
   - Recommend (a), with (c) for a holder who cannot sign in. (b) leaves a bearer link to
     the whole org's directory in a mailbox. The billing service never gets a copy: it
     never holds users' data.
10. **Platform API transport.**
    - (a) Bearer token on a private listener.
    - (b) (a) plus mTLS at a private proxy.
    - (c) (a) plus a `syncauth` HMAC signature on every request.
    - Recommend (a) when billing runs on the same private network, and (b) otherwise. (c)
      adds little when the bearer travels on the same channel.
11. **What authorises a member write.**
    - (a) The portal's `members:write` token alone. The portal has signed in the account
      holder in its own way.
    - (b) The portal also passes a KyIdentity access token of the account holder, and
      KyIdentity checks its `sub` is that org's holder.
    - Recommend (b) if the portal signs customers in through KyIdentity anyway (unverified).
      A stolen portal token then cannot add members to any org on its own. Otherwise (a),
      with the defences in the threat model.
12. **Account holder with a lost mailbox.** Staff cannot change a customer's email.
    - (a) Keep that in v1. Billing names another member as account holder, or the person
      gets a new account.
    - (b) Staff change the email after billing confirms the person, with a notice to the
      old address and a delay before it takes effect.
    - Recommend (a) for v1. A staff email change is exactly the takeover path the
      staff-abuse defence closes. Revisit (b) if support load shows the need.

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
| `paired_systems` | `store.go:171` | `:66` | P | Suite app targets are shared. Customer-owned generic SCIM targets are business features, single-tenant (Enterprise) only. |
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
| `audit_events` | `store.go:328` | `:232` | O | Nullable `org_id`: NULL means a platform event (`nullableOrgID`, and the NULL case in its triggers). |
| `system_settings` | `store.go:343` | `:246` | P | Platform settings. Future per-org settings go into a new `org_settings` table, never prefixed keys. |
| `step_up_tokens` | `store.go:352` | `:252` | D | `user_id` FK |
| `webauthn_credentials` | `store.go:363` | `:262` | D | `user_id` FK. `credential_id` is global (one RP). |
| `webauthn_challenges` | `store.go:378` | `:276` | D | `user_id` FK |
| `scim_user_links` | `scim.go:10` | `:287` | O | `local_id` has no FK, is a user or a group, and survives local deletion. Same reason as `account_sync_events`. |
| `sync_delivery_attempts` | `sync_delivery.go:24` | `:295` | O | No FK on `user_id`. Giving it `org_id` is cheaper than proving every reader joins `users`. |
| `step_up_challenges` | `stepup.go:34` | `:300` | D | `user_id` and `session_id` FKs |
| `app_registry` | `app_registry.go:70` | `:308` | P | One record per global client, card or system. Per-org mode lives in `org_apps`. |
| `app_user_assignments` | `app_access.go:34` | `:316` | D | `user_id` FK. The app is global. |
| `app_group_assignments` | `app_access.go:37` | `:320` | D | `group_id` FK. The app is global, so the group is the only org-owned side. |
| `authorization_interactions` | `authorization_interactions.go:34` | `:324` | P | Pre-sign-in flow state, keyed by hash and browser. `user_id` is `''` until bound, then it is checked against the session's user, whose org scopes everything after. |
| `oidc_client_sessions` | `client_sessions.go:19` | `:329` | D | `session_id` FK |
| `account_tokens` | `onboarding.go:30` | `:333` | D | `user_id` FK |
| `scim_connectors` | `scim_inbound.go:42` | `:339` | O | A connector belongs to one org, and its token decides the org. Single-tenant only in v1, so every row is in the default org. |
| `scim_connector_tokens` | `scim_inbound.go:45` | `:343` | D | `connector_id` FK |
| `app_roles` | `app_roles.go:76` | `:348` | I: P | Roles describe a global app, and their definitions are `platform` routes. Becomes O if orgs define their own roles. |
| `app_role_user_assignments` | `app_roles.go:80` | `:352` | D | `user_id` FK |
| `app_role_group_assignments` | `app_roles.go:83` | `:356` | D | `group_id` FK. The role is global (above), so the group is the only org-owned side. |
| `admin_delegations` | `delegations.go:27` | `:360` | D | `user_id` FK. Kinds unchanged. Multi-tenant: staff org accounts only (D8). |
| `access_requests` | `access_requests.go:70` | `:367` | D | `user_id` FK |
| `logout_deliveries` | `logout_deliveries.go:34` | `:376` | O | `user_id` has no FK, and deliveries outlive the user. The logout token carries `org_id`. |
| `enrollment_policies` | `group_enrollment.go:50` | `:382` | P | Platform-wide in multi-tenant mode (D10), where `group:` scopes are refused. In single-tenant a `group:` row references a default-org group. |
| `enrollment_deadlines` | `group_enrollment.go:55` | `:388` | D | `user_id` FK |
| `sync_resource_state` | `provisioning.go:35` | `:391` | O | `resource_id` has no FK, and offboarded rows persist after deletion |
| `sync_reconcile_jobs` | `reconcile.go:30` | `:398` | P | Per system, across every org. Per-org repair is later. |
| `alerts` | `alerts.go:82` | `:408` | O | Nullable `org_id` (`nullableOrgID`). An org's alerts (failed sign-ins) go to staff, tagged with the org. Platform alerts (NULL) have no user recipient, only the log, until a platform channel exists. |
| `alert_queue` | `alerts.go:92` | `:417` | D | `event_id` FK to `audit_events` |
| `alert_deliveries` | `alerts.go:98` | `:421` | D | `alert_id` FK. The recipient is an administrator: staff in multi-tenant mode. |
| `launcher_prefs` | `launcher_prefs.go:82` | `:430` | D | `user_id` FK |
| `refresh_families` | `refresh_tokens.go:52` | `:436` | D | `jti` FK to `issued_tokens` |
| `refresh_tokens` | `refresh_tokens.go:63` | `:448` | D | `family_jti` FK |
| `rate_limits` | `shared_state.go:20` | `:456` | P | Buckets keyed by IP and principal IDs |
| `push_relay_keys` | `shared_state.go:22` | `:458` | P | Install's relay registration |
| `proxy_apps` | `forward_auth.go:19` | (migration 2) | P | Disabled in multi-tenant v1. The host is install-wide. |
| `forward_codes` | `forward_auth.go:23` | (migration 2) | D | `user_id` and `session_id` FKs |
| `forward_sessions` | `forward_auth.go:29` | (migration 2) | D | `user_id` FK |
| `hr_connections` | `hr.go:46` | (migration 3) | D | `connector_id` FK to `scim_connectors`. Single-tenant only in v1. |
| `hr_workers` | `hr.go:51` | (migration 3) | D | `connector_id` FK |
| `suite_groups` | `suite_groups.go:16` | (migration 4) | O | A tombstone with no FK, so it needs its own `org_id`. Slug unique per org. Unverified: whether any app uses the slug in a global namespace (for example KyPost list addresses). |
| `suite_group_apps` | `suite_groups.go:19` | (migration 4) | D | `group_id` FK to `suite_groups` |

Tables this spec adds (the tenancy migration, both backends):

| Table | Class | Reasoning |
|---|---|---|
| `orgs` | P | The tenant registry. It is the target of every `org_id`, not a row in an org. `DELETE /orgs/{id}` keeps it as a tombstone. |
| `org_apps` | O | `org_id` is part of its primary key. `DELETE /orgs/{id}` removes it with the org's other rows. |
| `platform_tokens` | P | Credentials of the billing service and portal, which span every org |
| `platform_requests` | P | Idempotency records, keyed by token and kept 30 days. Stored responses hold IDs and states only (member writes answer `{user_id, status}`), so no user data outlives a deleted org here. |
| `platform_events` | P | Outbox to billing. `org_id` is a plain reference with no FK, because `org.deleted` must still be delivered after the org's rows are gone. Bodies carry no personal data (see Events back to billing). Delivered rows are removed after 30 days. |
| `org_erasures` | P | A holder's Delete everything request (amendment). Opaque IDs only, never changed or deleted, and it must outlive the org's rows, which its trigger path deletes. |
| `erased_subjects` | P | Tombstones of erased subjects, listed by `GET /api/suite/erased`. Opaque IDs only, never changed or deleted. |
| `org_storage` | O | Each app's reported bytes and grant for one org (Org storage pool). `org_id` is in its key; removed with the org. Byte counts only. |

`account_sync_events_new` (`store.go:872`) is a temporary name inside the legacy rebuild,
not a live table.
