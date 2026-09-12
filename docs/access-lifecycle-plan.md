**Repo:** kysignon-server
**Worktree:** /home/yoshi/busness.app/kysignon-server (branch feat/provisioning-ordering)

# KySignOn access and identity lifecycle implementation plan

Date: 2026-09-05. Status: implementation started. PR 01 merged as GitHub PR #24;
PR 02 merged as GitHub PR #25; PR 03 merged as GitHub PR #26. PR 04 is split into
04a (application identity and explicit linking, merged as GitHub PR #27) and
04b (assignments and enforcement, merged as GitHub PR #28).
PR05 is split into 05a (OIDC re-authentication requests and bound interactions, merged as GitHub PR #29)
and 05b (administrator per-app policies, factor freshness and policy revision enforcement,
merged as GitHub PR #30). PR06 is split into 06a (organization/admin enrollment policy,
merged as GitHub PR #31) and 06b (group-specific requirements, merged as GitHub PR #32).
PR07 merged as GitHub PR #33 with CI passed and both findings resolved.
PR08 is split into 08a (resource ordering and uncertain-write recovery, merged as
GitHub PR #34) and 08b (assignment-aware desired state, revisions and group delivery,
merged as GitHub PR #35). PR09 is implemented on feat/provisioning-reconciliation.
PRs 09–23 and D1–D4 remain planned.
PR33 review limitations remain: truncated input omitted frontend source; the reviewer
performed no dynamic real-target SCIM exercise. It was not an exhaustive whole-PR audit.
PR32 review limitations remain: some frontend source hunks were omitted from review
input, and the reviewer could not execute tests; implementation-agent runs and CI
provided test evidence. It was not an exhaustive whole-PR audit.
PR numbers below are sequence labels, not GitHub PR numbers.

## Outcome and scope

Implement all twelve proposed features: per-app authentication policies, groups and
assignments, mandatory MFA, complete offboarding, inbound SCIM, provisioning
reconciliation, invitations and activation, session management, app roles and claims,
delegated administration, temporary access, and access explanations and alerts.
Include access requests and approvals, which were proposed as the follow-on to
temporary access. Ship in independently reviewable PRs with functional UI increments.

KySignOn remains a single-organization authority for downstream access. An upstream
directory may own selected users and attributes; KySignOn still decides suite access.
Inbound SCIM is provisioning, not upstream login federation. SAML, external OIDC login,
LDAP, refresh tokens, passwordless primary login, device posture, nested/dynamic groups,
and a general policy scripting language are outside this feature set.

The program comprises 23 KySignOn PRs and four required downstream adoption PRs.
A shared-library change is conditional on an actual gap in the released primitives.
The labels permit splitting an oversized PR further without changing acceptance gates.

## Current implementation and prerequisites

- `internal/api/oauth_handlers.go`: authorization accepts an authenticated session;
  no app assignments, `prompt`, or `max_age` enforcement.
- `internal/oauth/oauth.go`: `auth_time` comes from code creation rather than actual
  authentication; no `amr`, `acr`, or session binding for downstream logout.
- `internal/api/stepup.go`: factor enforcement is conditional on TOTP enrollment;
  passkey-only accounts can obtain grants with a password alone.
- `internal/store/models.go`: global user/admin role, separate OAuth clients,
  launcher-only applications and paired provisioning systems; no groups or access model.
- `internal/sync/sync.go`: durable outbox, leases, bounded retries and full resync exist.
  Generic SCIM delivery currently uses suite signing without Bearer authentication,
  constructs downstream paths from local IDs, and accepts create conflicts as success.
  Correct these before calling generic SCIM provisioning reliable.
- `internal/api/server.go`: no inbound SCIM, self-service password recovery/session
  management, or standard OIDC logout routes.
- Audit events already reach SQLite and structured process logs. Extend their search,
  explanations and operational use; do not build a second audit subsystem.
- Sealed backup and restore infrastructure already exists. Extend its verification for
  new identity state; do not replace it or duplicate recoveryclient.

Recheck these facts against the branch at implementation time. Shared handoff notes are
historical evidence, not current wire specifications. Preserve released `syncauth` and
`oidcverify` contracts and inspect their current APIs before adding helpers.

## Decisions that apply across PRs

### Application identity and compatibility

Use one application access record with a stable ID, an optional unique OAuth client
reference and an optional unique provisioning-system reference. Reuse existing launcher
records where appropriate; retain client IDs, secrets, callback URLs and launcher IDs.
Do not guess that two entries are the same app from their names or URLs. Migration
creates separate records where linkage is unknown; admins explicitly link them later.
Keep the old launcher/API representation compatible during migration.

Existing apps and provisioning systems retain an explicit `all_active_users` mode.
New apps default to `assigned_only` and initially grant nobody access. Show broad legacy
access clearly and offer a preview of who loses access before changing it. Enabling
assignments must not silently deprovision a whole existing installation.

Flat groups and direct user assignments grant access by union. Removing one grant does
not remove access while another valid grant remains. Disabled/expired users and disabled
apps always deny. Global administrators do not implicitly bypass app assignments.
Keep the identity administration UI separate from launcher app entitlements.

### Policy semantics

Implement a small shared decision function, not a policy engine dependency. Return an
allow/deny/interaction-required decision and stable reason codes using the same logic
for authorization, token exchange, provisioning selection and admin explanations.

Combine organization, applicable group and app requirements restrictively: required MFA
cannot be weakened, the shortest maximum age wins, and allowed factor sets intersect.
Reject impossible combinations with an explanation before activation. Policy changes
carry a revision so grants and authorization codes can be checked against current state.

Track actual primary authentication time, factor verification time and methods separately
from session creation/activity. Never infer freshness from token issuance. Authentication
requirements apply to each authorization transaction; sensitive actions inside an app
must explicitly initiate re-authentication and validate its result.

### Mutation and revocation semantics

Account/group/assignment changes, security audit rows, invalidation of outstanding grants,
and required outbox work commit in the same SQLite transaction. Token issuance and access
removal must serialize their final permission check and token registration so racing
requests cannot mint unrevoked access after removal. Network work occurs after commit.

Access removal revokes affected client grants and tokens. Account disablement revokes all
sessions, codes, tokens, step-up grants, pending MFA/pairing/enrollment/activation/recovery
flows as applicable. Re-enablement never revives old credentials or sessions.

Local revocation takes effect at commit. Offline JWT consumers retain the documented
15-minute access-token bound; app cookies may last longer until the downstream logout
integration ships. Report these limitations by app capability. Never label an HTTP 2xx
as verified account removal unless the integration contract actually guarantees it.

Deprovision by disabling access; do not erase mail, notes or vaults. Destructive data
deletion is a separate product operation. Preserve remote ID mappings/tombstones long
enough to retry after a local account is deleted.

### Implementation constraints

Reuse the existing store, audit, MFA, netguard, outbox, React components and Ky primitives.
No message broker, workflow engine, new database or arbitrary claim templates. Use an
ordinary worker with persisted due times and leases. Boundary input limits, parameterized
SQL, CSRF on browser mutations, scoped machine authentication, `no-store`, URL validation
and secret redaction apply to every new route. Machine routes do not accept browser
cookies as an alternate credential.

## Release A: reliable authentication and app access

### PR 01 — Record real authentication evidence

Depends on: none. Touch: store models/migrations, auth and WebAuthn handlers, OAuth engine.

- Record primary/factor times and verified methods for every login completion path,
  including push, WebAuthn, TOTP and recovery. Preserve evidence through authorization
  codes; emit accurate `auth_time` and `amr`, plus documented `acr` values only when met.
- Bind new codes and issued tokens to their originating session. Update discovery only
  for claims that are actually emitted with defined semantics.
- Treat legacy sessions with missing evidence as unknown; require fresh authentication
  for freshness-sensitive requests. Expire outstanding legacy codes during migration.

Acceptance: an hours-old login issuing a new code retains its old authentication time;
all factors produce correct evidence; token exchange cannot invent MFA; old databases
migrate safely and existing ordinary SSO remains usable.

### PR 02 — Complete account step-up for all enrolled factors

Depends on: 01. Touch: step-up/MFA/WebAuthn handlers, StepUpPrompt, tests.

- Support passkey, push and TOTP verification for a step-up transaction. Retain password
  proof in the current authentication model. Keep grants short-lived and single-use.
- Bind evidence to user, session and requested operation; reuse MFA challenge storage
  where semantics fit. Recovery use issues restricted recovery capability, not a passkey
  assurance claim. Factor removal cannot lower a required enrollment policy later.
- Preserve modal stacking, keyboard focus and cancellation semantics.

Acceptance: password alone fails for passkey-only and push-only enrolled users; replay,
cross-session spending, expired challenge and concurrent spending fail; cancellation
does not execute the original mutation.

### PR 03 — Groups with working admin management

Depends on: none. Touch: store, admin routes, new group view and user membership controls.

- Add stable group IDs, unique names, descriptions and explicit user membership.
- Provide paginated CRUD and add/remove membership APIs and UI; use step-up and atomic
  audit records for mutations. Keep global administrator status out of group membership.
- Add source metadata only when inbound SCIM needs it in PR 14, avoiding unused adapters.

Acceptance: duplicate membership is idempotent, deleted users leave no dangling rows,
concurrent membership edits preserve integrity, non-admin access is denied.

### PR 04 — Application records and enforced assignments

Split for independent review:
- **04a — Application identity and explicit linking:** migrate a stable registry over
  existing OAuth clients, launcher cards and paired systems; provide searched/paginated
  admin linking and reversible unlinking with step-up, revisions and atomic audit.
  Preserve connection IDs, credentials and current access. No assignment controls yet.
- **04b — Assignments and enforcement:** add direct/group grants, compatibility access
  modes, effective-access previews, launcher filtering, authorization/token checks and
  transactional revocation. Ship the access controls with enforcement, not before it.

The acceptance criteria below remain required across both increments.

Depends on: 01, 03. Touch: store, OAuth engine/handlers, client/system/launcher admin UI.

- Introduce the application linkage and migration described above. Support direct-user
  and group assignment with current effective-access previews.
- Enforce access in authorize and again at token exchange; filter the launcher through
  the same decision function. Revoke affected grants/tokens on effective access loss.
- Existing systems retain broad provisioning until PR 08 adds assignment-aware delivery;
  do not expose scoped provisioning as implemented before that PR.
- For bookmarks show that assignment controls visibility only. For OIDC apps explain
  access denial without revealing privileged group details to the end user.

Acceptance: a hidden app cannot be accessed by a direct authorization URL; removing
membership after code issuance blocks exchange; an alternative grant preserves access;
ID/secret-preserving migrations and merge/link collision checks pass.

### PR 05 — Per-app re-authentication policies

Split for independent review:
- **05a — OIDC re-authentication:** strict `prompt`, `max_age`, supported assurance
  requests, silent protocol errors, bounded one-use login interactions, and proof age
  enforcement at token registration. Reuse the existing login and MFA screens.
- **05b — Administrator policy:** per-app settings and UI, independent factor age,
  password-plus-passkey requirements, policy revisions, and stricter-policy invalidation
  at code exchange. Complete the acceptance criteria below across both increments.

Depends on: 01, 02, 04. Touch: policy decision, authorize/login flow, app policy UI.

- Offer reuse SSO, maximum authentication age and fresh authentication every authorization;
  offer password, MFA, or password plus passkey requirements with factor freshness.
- Implement OIDC `prompt=login`, `max_age`, `prompt=none` and supported `acr_values`
  semantics. An app may strengthen but not weaken administrator policy. Unsupported
  assurance requests fail explicitly; silent requests return protocol errors without UI.
- Store a bounded, one-use authorization interaction bound to client, redirect, scope,
  PKCE, nonce and session. Mark the interaction satisfied after re-authentication so
  returning to `prompt=login` does not loop; another request must prove freshness again.
- Existing admin step-up grants are not reusable authorization grants. Reject stale
  evidence or stricter policy changes at code exchange and require a fresh authorization.

Acceptance: KyNotes reuses SSO while KyPasswords prompts; `max_age=0`, malformed/negative
ages, incompatible prompt combinations, concurrent tabs, cancellation and replay behave
correctly. A weaker factor never satisfies a passkey policy.

### PR 06a — Organization and administrator MFA enrollment

Depends on: 02, 03, 05. Touch: policy storage/UI, login/enrollment routes, recovery rules.

- Add organization requirements, administrator policy, allowed factor methods,
  enrollment deadline and impact preview. Store a stable deadline; subsequent logins
  cannot restart grace. A stricter sensitive-app policy applies even during grace.
- After deadline, issue only a restricted enrollment session until requirements are met.
  Allow the minimum account/factor setup routes, never OAuth authorization or admin APIs.
- Prevent removal of the final compliant factor; reset/recovery requires re-enrollment.
- Require a tested compliant local emergency administrator before activating an
  organization policy that could lock out all administrators. Never create a hidden bypass.

Acceptance: grace ends at the exact persisted deadline, factor removal cannot bypass
policy, restricted sessions cannot reach apps, and policy preview detects admin lockout.

### PR 06b — Group-specific MFA requirements

Depends on: 03, 06a. Reuse the persisted deadline, effective factor, preview and restricted
session enforcement introduced in 06a. Add per-group policies and combine every applicable
requirement by factor intersection and earliest deadline. Membership and policy mutations
must reject empty intersections, preserve tested administrator access, and invalidate
OAuth grants atomically. Removing and re-adding membership must never restart grace.
Includes group impact controls and membership-change race tests. Implemented on
`feat/group-mfa-policy`; policy controls live under Groups, with shared activation and
preview rules. Actual changes to membership in required-policy groups require a compliant
admin session and revoke affected OAuth grants transactionally. Membership re-addition
preserves prior deadlines; PR06a schema upgrade preserves policy revisions and deadlines.

Release A gate: demonstrate two users, two groups and two apps with different freshness
and factor requirements, including direct-URL denial and removal during code exchange.

## Release B: provisioning and access removal

### PR 07 — Correct generic outbound SCIM interoperability

Depends on: none. Touch: sync/store, system connection UI, HTTP contract fixtures.

- Make connector type explicit. Generic SCIM uses its configured Bearer token, encrypted
  at rest; suite webhooks retain bare SCIM bodies signed by `ky-primitives/syncauth`
  without putting the sync secret in Authorization. Remove URL-based protocol guessing
  after migrating known legacy types; require review for ambiguous custom connectors.
- Persist remote user IDs from create/lookup responses, keyed by connector and local ID.
  Use those IDs for updates and deactivation. Recover a lost create response through a
  stable external reference lookup; an unrelated 409 must never count as successful sync.
- Support bounded responses, pagination where needed, explicit errors, Retry-After,
  connection testing and redacted logs. Preserve existing HTTPS/netguard behavior.

Implementation: uses released `ky-primitives/scim` resource writes, a strict bounded
externalId collection lookup, persisted remote IDs and uncertain-create markers.
Generic deletion uses active=false PATCH. The connection UI accepts target-issued
tokens, supports token replacement and tests, and requires explicit review of legacy
custom connectors. Full setup, protocol requirements and ordering limitations are
in README.md, Outbound provisioning.

Acceptance: a SCIM fixture assigning unrelated IDs completes create/update/disable;
timeout-after-create does not duplicate users; wrong Bearer credentials fail; suite
fixture proves exact signature/body and absence of Authorization. No secrets follow
redirects or appear in logs.

### PR 08 — Assignment-aware provisioning and group delivery

08a provides FIFO delivery per connector/user, durable attempts that survive crash and
local deletion, stale-claim rejection, and a functional blocked-delivery recovery UI.
Transport uncertainty does not expire with a lease; recovery requires operator-proven
quiescence, step-up and audit. Read-back is diagnostic only. Explicit no-create
confirmation plus empty lookup permits clearing a lost-create guard. See README.md.
This conservative foundation does not claim automated convergence after uncertainty.
08b implements the desired-state, scope, supersession, revision and group requirements
below with `sync_resource_state`; README.md "Provisioning scope" and "SCIM Groups"
describe the behavior. Conditional writes (`If-Match`) are not implemented; read-back
and reconcile after uncertainty remain operator-driven until PR09.

Depends on: 03, 04, 07. Touch: sync/store, app-to-system linking and assignment UI.

- Compute desired downstream accounts from effective access. Queue create/reactivate on
  gain and deactivate on loss; member/profile/role changes update current desired state.
- Support downstream SCIM Groups/members with remote group mappings when supported.
  Capability flags prevent attempting group delivery to user-only suite receivers.
- Preserve ordering per connector/resource, supersede stale queued desired-state work,
  and never let an old create/reactivate retry undo a later disable. Carry a monotonic
  resource revision for suite receivers; ordinary SCIM delivery serializes remote writes.
  A timed-out SCIM write has an uncertain outcome: read back and reconcile before
  advancing that resource, and surface unresolved ambiguity rather than claiming ordering
  from the local lease alone. Use conditional writes where the target supports them.
- Offer a scope-change preview and persist mutation, audit and work atomically.

Acceptance: removing one of two grants keeps the account; final removal disables it;
out-of-order retries cannot restore access; resync never provisions unassigned users;
crash/restart and two workers preserve event ordering and eventual convergence.

### PR 09 — Provisioning operations and reconciliation

Depends on: 07, 08. Touch: sync worker, admin system view, durable reconciliation records.

- Show per-user desired/observed state, last attempt, reason, next retry and terminal
  failures. Add targeted retry and initial/full reconciliation, with leased bounded jobs.
- Read remote Users/Groups where supported and compare only accounts managed by this
  connector. Show drift preview before repair; refuse destructive inference from partial
  listings, a failed page or an incomplete run. Revalidate the preview at execution.
- Track unsupported verification separately for webhook-only integrations. A remote
  acknowledgment and an observed matching state are different statuses.
- Schedule reconciliation; recover interrupted jobs without duplicate effects.

Acceptance: detect missing, stale and orphaned managed accounts, ignore unrelated remote
accounts, repair safely, and never deactivate users from an incomplete listing.

Implementation: leased `sync_reconcile_jobs`, paginated Users/Groups listing that fails
closed on any inconsistency, per-user desired/queued/acknowledged/observed rows,
targeted retry, scheduled repair per connector; README.md "Reconciliation".

### PR 10 — Session inventory and scoped revocation

Depends on: 01, 04. Touch: session/token store, user/admin APIs and account security UI.

- Show current and other sessions, creation/activity/expiry, browser/device description
  and observed IP. Distinguish browser sessions, MFA devices and known app sessions.
- Revoke one session or all; revoke its codes, tokens and pending security flows. Include
  admin emergency revocation and app-specific grants. Do not present inferred app
  sessions as a complete live inventory before downstream adoption.
- Revoking access stays available without step-up as the existing incident-response
  invariant requires; enforce ownership and CSRF, and audit it.

Acceptance: one session's removal leaves another valid, self-revocation clears cookies,
cross-user IDs fail, and token-exchange races cannot escape revocation.

### PR 11 — Standard OIDC logout and durable downstream delivery

Depends on: 01, 10. Touch: OAuth discovery/handlers, client metadata, logout outbox.

- Add RP-initiated logout, exact registered post-logout redirect matching, appropriate
  confirmation and state handling. Advertise the endpoint only when implemented.
- Add client-scoped opaque `sid` tracking and back-channel logout registration. Issue
  correctly typed signed logout tokens and durable bounded retry jobs bound to the
  client and relevant subject/session. Reuse HTTP guards; callbacks cannot redirect.
- Document receiver checks, replay handling and subject-wide versus session-specific
  logout. Tokens for logout must never be accepted as login/access tokens or vice versa.
- Display pending, acknowledged, failed and unsupported delivery accurately.

Acceptance: fixture app loses its cookie session, duplicate logout is harmless, forged
or wrong-audience tokens fail, unsafe redirect/callback URLs fail, and offline receivers
receive retried logout after reconnecting.

### PR 12 — Complete offboarding workflow

Depends on: 08, 09, 10, 11. Touch: shared account lifecycle operations and admin user UI.

- Route disable/delete, upstream deactivation and later account expiration through the
  same transactional lifecycle operation. Revoke local access immediately and record
  downstream disable/logout tasks atomically, including systems with no current grant
  but a recorded provisioned account.
- Add a per-app completion view with timestamps, retries and explicit unsupported states.
  Preserve audit identity and remote mappings after directory deletion. Deactivation is
  the normal action; do not silently erase product data.
- Re-enablement creates new desired-state revisions; old completion tasks cannot disable
  or reactivate the wrong generation. Preserve final active administrator protection.

Acceptance: disable while one app is offline, verify local denial immediately and remote
convergence on return; prove no later stale work restores access; re-enable requires new
login. Never show globally complete while a required target is pending or unsupported.

### PRs D1–D4 — Downstream suite adoption, one PR per product

Repos: KyPost, KyBookmarks, KyNotes and KyPasswords (locate their actual repository paths
and read owning AGENTS.md before implementation). Depends on: 05, 08, 11, 12, 16 for
final role behavior. Each product may stage its adoption but must pass the same gate.

- Adopt released `oidcverify` where not already used. Validate nonce, issuer/audience,
  actual authentication time and required assurance; persist the issued `sid`.
- Add back-channel logout receiver with token-purpose checks and durable replay handling;
  invalidate local sessions and local derived API credentials as applicable.
- Apply versioned suite directory events idempotently and atomically with local access
  disablement. Reject stale reactivation. Provide authenticated observed-state checks
  needed for reconciliation; document exactly what acknowledgment guarantees.
- Map configured app roles without granting every KySignOn admin product administration.
  Sensitive app actions initiate fresh authorization and bind its result to that action.
- Preserve E2EE data. Specifically for KyPasswords, distinguish identity password reset
  from vault decryption/recovery: resetting SSO must not promise to unlock a vault.

Acceptance per product: real login, protected action re-auth, membership removal,
subject/session logout, offline delivery replay, restart, and proof that user data remains.
These are explicit cross-repository dependencies, not claims that those repos were
audited during planning. Add a primitives PR only if these consumers need a missing
shared verification primitive; do not create four new JWT implementations.

Release B gate: the offboarding demonstration passes against all four suite products.
Server-side feature availability may ship earlier, but suite-wide completion may not.

## Release C: onboarding and upstream identity

### PR 13 — Invitations, activation and password self-service

Depends on: 02, 06, 12. Touch: account/token store, auth routes, config, login/user/admin UI.

- Add expiring, revocable, single-use activation links; pending accounts cannot log in.
  Activation sets a password and enters required factor enrollment before app access.
- Provide manual link delivery and optional SMTP with protected credentials and a test
  action. Do not put raw activation/reset links in audit logs; store token hashes only.
- Add authenticated password change with step-up and full access revocation. Add reset
  initiation/consumption with generic responses and account/IP rate limits. Password
  reset does not remove MFA; lost-factor recovery is an audited restricted enrollment
  flow requiring an existing recovery code or authorized administrator intervention.
- Track actual email verification; stop unconditional `email_verified=true`. Existing
  addresses begin unverified unless trustworthy provenance exists. Inbound email fields
  alone will not prove ownership. Email changes revoke prior verification/reset tokens.
- Defaults: activation 24 hours, password reset 30 minutes; new issuance supersedes the
  previous link. Token consumption and credential mutation are atomic. A link GET only
  opens the form, so email scanners cannot consume it.

Acceptance: expired/replayed/cross-account links fail; a link cannot bypass MFA or
activation state; password change revokes other access; delivery failure is visible;
reset cannot enumerate users; no-email deployments can activate users manually.

### PR 14 — Inbound SCIM connector security and Users

Depends on: 07, 12, 13. Touch: new SCIM HTTP boundary, shared lifecycle/store, connector UI.

- Add `/scim/v2/Users`, discovery resources and a documented supported schema profile.
  Support create/get/list/filter/pagination/replace/PATCH/delete-to-deactivate with SCIM
  response/error formats. Implement and advertise only supported operations and filters.
  Use bounded parsing and parameterized filtering; reject unsupported expressions.
- Issue connector-scoped Bearer credentials shown once and hashed, with rotate/revoke,
  read/write scope and last-use metadata. Credentials never authorize browser admin APIs.
- Key identity by connector plus immutable external reference. Define uniqueness,
  stable server IDs and collision errors; never auto-link existing accounts by email.
  Source-owned fields are read-only locally; local security overrides may disable but
  upstream activation cannot undo that override. No upstream grant of global admin.
- Existing local users remain local. New upstream users receive activation/enrollment
  if local credentials are required; never generate a usable default password or send
  passwords downstream. Mark password provisioning unsupported in this profile.
- Protect designated local emergency administrators from upstream edits/deactivation;
  detach a connector only through an audited ownership-transfer/deactivation preview.

Acceptance: realistic SCIM client fixture completes lifecycle with stable IDs; conflicting
email does not take over an account; repeated creates resolve safely; stale conditional
writes fail; credential rotation rejects the old token; local disable overrides survive.

### PR 15 — Inbound SCIM Groups and operational setup

Depends on: 03, 08, 14. Touch: SCIM Groups, group/source metadata, connector admin UI.

- Implement Group create/get/list/filter/replace/PATCH/delete and member changes into the
  existing flat-group model. Group deletion removes grants, never deletes its users.
- Support atomic multi-operation PATCH and concurrency/version checks; enforce connector
  ownership on every referenced group/user. Reject nested groups explicitly.
- Treat missing referenced users as a clear retryable integration problem; never invent
  accounts from a group membership entry. Keep external and local group IDs distinct.
- Add setup instructions, field ownership display, credential rotation, redacted request
  logs and provisioning test results. Validate the supported profile against at least
  one actual upstream directory in a test tenant before claiming compatibility with it;
  recorded fixtures alone prove only protocol behavior.

Acceptance: upstream join/move/leave drives assignment and downstream convergence;
invalid PATCH rolls back fully; cross-connector membership is rejected; deleting an
external group cannot delete users or mutate local admin ownership.

Release C gate: upstream create → activation → MFA → group grant → app login → group
removal → downstream access removal, with a manual-only onboarding path also verified.

## Release D: roles, delegation and temporary access

### PR 16 — App roles and bounded claim mappings

Depends on: 04, 08. Touch: policy/claims/store, OAuth and sync, app administration.

- Add per-app role definitions and explicit group/direct-user mappings. Emit only that
  app's assigned roles and allowed groups; cap token size and return an actionable error
  rather than silently truncating permissions. Use fixed claim names/types, not scripts.
- Role changes revoke affected outstanding grants/tokens and enqueue desired-state
  changes. Enforce scopes/claim allowlists consistently in ID tokens and UserInfo.
- Keep legacy global `role` behavior in an explicit compatibility mode for existing
  clients until D1–D4 migrate; new clients use app roles. Never silently reinterpret the
  existing claim. Track and remove each compatibility exception after verification.

Acceptance: Finance maps to one app's billing role without privilege in another;
unassigned apps receive no claims; role removal blocks stale code exchange; unknown
scopes and large memberships cannot leak or silently broaden permissions.

### PR 17 — Delegated administration

Depends on: 02, 04, 12, 16. Touch: API permissions, store role bindings, admin navigation.

- Add fixed permissions for helpdesk, app owner and auditor alongside full administrator.
  App-owner bindings are app-scoped; helpdesk can manage ordinary account recovery but
  cannot reset administrators or assign administrative privileges. Auditors are read-only.
- Apply permissions at every API operation and object lookup; hide unavailable UI only
  as convenience. Ownership does not allow changing one's own scope or editing global
  policy, connector secrets, recovery configuration or app OAuth credentials.
- App owners may manage grants and app-role mappings only within their app, including
  explicitly documented ability to grant that app's roles. Global admin alone controls
  delegation. Mutations retain step-up and atomic audit.

Acceptance: a permission matrix covers every admin route; guessed IDs and direct calls
cannot cross scope; helpdesk cannot reset a global admin; demotion takes effect without
requiring the old session to expire; the final admin invariant still holds.

### PR 18 — Expiring access and account end dates

Depends on: 08, 12, 16, 17. Touch: membership/assignment/user schema, policy, worker and UI.

- Add UTC expiration to direct assignments and group memberships, and an account end
  date. UI displays the operator's timezone plus the exact effective instant.
- Evaluate expiry synchronously at authorization/token/UserInfo boundaries. A persisted
  due-job worker triggers revocation/logout/provisioning; delayed jobs never extend new
  access. On restart process overdue work; catch up using current desired state.
- Bound newly issued tokens to relevant account/grant expiry where possible. For union
  grants calculate when effective access ends rather than revoking on any one expiry.
  Cap downstream session access to communicated expiry or use logout/online checks.
- Scheduled removal of the last administrator must be rejected or require a verified
  successor before scheduling. Store changes and due work atomically.

Acceptance: expiry works with the worker stopped, alternate grants preserve access,
restart drains overdue removals, stale jobs cannot undo extensions, and timezone/DST
input resolves to the intended UTC instant.

### PR 19 — Access requests and approvals

Depends on: 17, 18. Touch: request store, user request view, app-owner/admin inbox.

- Let users request eligible apps with a reason and optional duration. App owner or
  administrator approves/denies; use pending/approved/denied/cancelled/expired states.
- Prevent self-approval, double approval and requests for global admin privileges. An
  approval creates an ordinary audited assignment with expiry, so no alternate access
  path exists. Recheck approver permission and requested app policy at approval time.
- Provide a browser inbox and optional existing SMTP delivery. Cap request volume and
  suppress duplicate pending requests. Only expose apps marked requestable.

Acceptance: approval grants exactly the requested app/duration once; revoked approver
authority blocks stale forms; cancellation/expiry cannot race into a grant; private apps
are not disclosed through search or IDs.

Release D gate: a delegated app owner approves temporary access, mapped roles reach
only the correct app, and expiry removes access without intervention.

## Release E: explanations, alerts and operational proof

### PR 20 — Explain effective access and authentication decisions

Depends on: 05, 06, 15, 16, 17, 18. Touch: shared decision output, admin user/app views.

- Show all contributing assignments, source group/connector, expiry, role mappings,
  effective factor/freshness policy and denial reason. Preview proposed policy changes
  against affected users without mutating access.
- Store the relevant decision reason and policy revision on authorization audit events
  so an old denial is not explained using today's policy. Avoid raw tokens and secrets.
- Scope explanations to viewer permissions; users see their own actionable denial,
  app owners see their app, auditors/full admins see their permitted organization data.

Acceptance: displayed decisions equal actual authorization for direct/group/expired/
disabled cases; historical reasons survive edits; unauthorized viewers cannot enumerate
groups, users or private apps via explanations.

### PR 21 — Audit search and export

Depends on: 17, 20. Touch: audit queries/indexes, admin audit UI/export endpoint.

- Add bounded filters by actor, target, app, action, outcome, connector and time range;
  stable pagination and indexes backed by query checks on representative data volumes.
- Export authorized filtered JSONL and CSV with size/time bounds, secret redaction,
  safe CSV cells and an audit event for the export. Reuse structured process logging for
  external log collection; no second audit delivery system.
- Preserve the existing audit retention behavior; separately document any proposed
  retention change rather than silently deleting history as part of this PR.

Acceptance: pagination has no duplicates under tied timestamps, scopes apply equally to
UI and export, malicious CSV values cannot execute formulas, and large exports remain
bounded without blocking authentication.

### PR 22 — Actionable security and provisioning alerts

Depends on: 09, 12, 13, 19, 21. Touch: persisted alert delivery, admin inbox/configuration.

- Add fixed rules for admin/delegation changes, recovery-code/reset use, connector
  credential changes, repeated login failures and overdue/failed access removal.
- In-app alerts are the baseline; use the existing optional SMTP transport for email.
  Deduplicate bursts, track acknowledgment, retry delivery and show failures. Use audit
  event IDs or transactional alert records so a crash cannot silently skip a trigger.
- Allow threshold and recipient configuration with permission checks; recipients cannot
  receive details they lack permission to view. Emit recovery/resolution events for
  outages so acknowledged stale alerts do not conceal new failures.

Acceptance: one prolonged outage produces a useful incident rather than mail floods;
restart cannot lose a critical alert; failed SMTP remains visible; privileged details do
not reach ordinary app owners; recovery use creates an alert without exposing the code.

### PR 23 — Upgrade, restore and end-to-end release verification

Depends on: 01–22 and D1–D4. Touch: migrations/tests, existing backup drill adapter, docs.

- Upgrade a pre-feature database with active sessions, clients, launcher apps and queued
  sync events; prove stable IDs, explicit legacy broad access and safe handling of old
  auth evidence. Run migration twice to verify idempotency.
- Extend backup/drill checks to cover policy, groups, app linkage, external identity/remote
  mappings, job state and encrypted connector/SMTP configuration. Reuse recoveryclient.
- Restoring an old snapshot must not silently revive old sessions/tokens/invitations or
  replay obsolete activation tasks. Invalidate ephemeral credentials at restore/startup
  through the established restore path and require reconciliation before enabling
  outbound provisioning from restored state. Review connector credentials for rotation.
- Publish setup/runbooks for app policy migration, SCIM setup, emergency admin recovery,
  offboarding failure, restore reconciliation and downstream capability limitations.
- Record suite versions and evidence for the release gates. No real custodian ceremony
  or third-party tenant test is claimed from synthetic fixtures; if unavailable, retain
  the named external verification gate as pending.

Acceptance: restored policy and ownership are intact; stale secrets/grants cannot log in;
restored queues cannot re-enable a departed user; all release scenarios pass through
real HTTP routes and all four adopted products.

## Dependency and delivery strategy

Recommended merge order within each release follows the sequence above, except PR 07
can land early as an interoperability fix, PR 03 can follow PR 01 independently of 02,
and PR 16 can land before downstream adoption to avoid repeating each product's PR.
Cross-release prerequisites take precedence over section order (notably D1–D4 use 16).
These are development lanes, not an instruction to spawn agents.

| Milestone | Required server PRs | External gate |
|---|---|---|
| A: app access and authentication | 01–06 | Two test relying parties |
| B: reliable suite offboarding | 07–12, 16 | D1–D4 deployed and verified |
| C: upstream lifecycle and onboarding | 13–15, prerequisite A/B server changes | One actual upstream test tenant |
| D: governed temporary access | 16–19 | Role-aware suite consumers |
| E: operations and release proof | 20–23 | All previous gates |

Each PR includes the relevant UI, API, migration, audit behavior and executable checks;
do not merge an exposed control whose enforcement is deferred. It may include additive
internal fields needed by its own behavior. Keep the existing global behavior explicit
until the corresponding feature is available and deliberately enabled.

## Verification and rollout rules

For every implementation PR, run focused checks for its acceptance cases and the current
CI requirements: Go formatting/build/vet/vulnerability scan/race tests; web build/audit/
tests with refreshed committed `web/dist`; both Workers' audit/typecheck/behavior tests;
production-image readiness and rejection of public HTTP issuers. Use current commands
from `.github/workflows/ci.yml`, not a frozen alternative pipeline. Read TypeScript and
owning subtree skills/contracts before modifying frontend or backup code.

Use deterministic time in expiry/freshness tests, real SQLite transactions for races,
and HTTP fixtures that assert actual requests, authentication headers and side effects.
Add browser coverage for redirect interactions, restricted enrollment, step-up overlays,
keyboard navigation and light/dark palette contrast. Never put accent fill colors into
text where existing palettes fail contrast. No tests that merely mirror implementation.

Before each rollout, take a verified sealed backup and record the schema/app version.
Use additive migrations and fail startup on unsupported schema versions. After policy
enforcement is enabled, rolling back to an older binary that ignores assignments is
unsafe: use a forward fix or a controlled restore with access contained and explicit
operator review. Disable new UI availability without disabling existing enforcement.
Dry-run and activate restrictive policy changes per app; record who enabled them.

Run a DOX pass in each PR and update owning AGENTS.md only for implemented contracts.
In particular, inbound ownership changes the current central-directory description and
standard logout changes today's claim that no browser logout endpoint exists. This plan
does not prematurely change those current-behavior statements. The existing separate
`docs/recovery-verification-plan.md` is unrelated work and must be preserved.

## Standards used

- Authentication request parameters and authentication claims follow [OpenID Connect
  Core](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest). The combination
  of app/group policies and reason codes above is KySignOn's proposed product behavior.
- Inbound/outbound resources and supported operations follow [SCIM schema RFC
  7643](https://www.rfc-editor.org/rfc/rfc7643.html) and [SCIM protocol RFC
  7644](https://www.rfc-editor.org/rfc/rfc7644.html). Publish an honest supported profile;
  successful interoperability with one directory is not universal compatibility.
- Browser logout follows [RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html);
  downstream session notification follows [Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html).

## Original planning handoff

Completed: repository-grounded plan covering every proposed feature, dependencies,
compatibility decisions, test gates and downstream responsibilities. No runtime code
changed and no implementation PR was opened. Next implementation task is PR 01; PR 07
is the independent provisioning prerequisite. Recheck worktree changes and live shared
package/product status before editing. The most sensitive invariants are true auth time,
authorization/revocation races, source ownership, stale provisioning replay, and preserving
user data during deactivation. Mirror this entire document to the
`kysignon-access-lifecycle-plan` myslop folder; the local copy is durable.
