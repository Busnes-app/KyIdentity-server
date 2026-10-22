# Provisioning

[Product overview](../README.md) · [Standalone installation](../INSTALL.md)

Commands and unlinked file paths below are relative to the repository root.

## Outbound provisioning

In **Suite sync**, choose **Generic SCIM 2.0** and enter the target's HTTPS SCIM
base URL and its provisioning Bearer token. KyIdentity encrypts the token at rest;
**Replace token** changes it without changing the connector or application identity.
The token is never returned in listings or copied into delivery errors. **Test
connection** performs a filtered Users read; success does not prove write permissions
or that an account has been provisioned.

The target must support `externalId eq "..."` filtering, standard ListResponse totals,
User creation, PUT updates, and PATCH of `active`. Lookup requests ask for the first
two matches: zero permits creation, one identifies the managed account, and more
than one requires intervention. Partial or inconsistent pages fail closed. Responses
are bounded to 1 MiB. KyIdentity sends its stable user ID as `externalId` and stores
the remote ID returned by create or lookup. URLs ending in `/Users` from the old
connection form are normalized to their base URL. Generic SCIM requires HTTPS even
with private callbacks enabled; the existing outbound dial restrictions still apply.

A source account deletion deactivates the remote account with `active=false`; it
never sends DELETE. Local MFA resets send no generic SCIM mutation. Suite products
retain their signed webhook events, including the existing deletion contract.

Per connector/user, only the earliest pending event can begin delivery. Backoff holds
later events for that user; other users and connectors continue. A durable attempt
survives process restart and local user deletion. Unsent claims may expire, but an
attempt whose request was written stays blocked after a lost response, HTTP 408 or
5xx other than 503, or asynchronous acceptance (202). A request that never left (DNS,
refused connection, TLS failure) and 429/503 refusals back off without blocking. A response acknowledging completion
and its event status are persisted atomically. These rules rely on the receiver honoring
its synchronous success/rejection responses; they cannot fence a nonconforming receiver.

Removals are the exception to both the attempt budget and the block. A removal is an
inactive update, a deletion or a group deletion; every receiver applies one
idempotently. It retries with the same backoff, at most 30 minutes apart, until the
receiver accepts it, for as long as it is current (a re-grant supersedes it). A removal
whose answer was lost is resent rather than blocked. Past its recovery time, an attempt
blocked ahead of a removal is dropped and the removal sent in its place; generic SCIM
keeps its create guard, so the removal still looks the account up by externalId. A
removal also supersedes an undelivered MFA reset for that connector.

In **Suite sync → Deliveries**, inspect in-flight/blocked attempts and read remote state.
**Failing deliveries** lists work given up after five attempts and removals still retrying
past five; the connector's provisioning alert stays open while any of these, or an expired
blocked attempt, remains.
Read-back only reports a matching externalId; it neither proves a request has finished
nor resumes delivery. Signed suite webhooks have no read-back contract.

To recover an expired attempt:

1. Stop **all** KyIdentity worker instances. Confirm at the receiving service that the
   old request has finished and cannot commit later. A timeout or empty lookup is
   insufficient. If this cannot be established, keep the attempt blocked.
2. Restart one instance, open **Deliveries**, and confirm these steps. **Resume delivery**
   requires fresh operation-bound step-up and records the recovery audit atomically.
3. For a lost create, keep the existing create guard unless the receiver explicitly
   confirms no account was created. The separate fresh-create checkbox additionally
   requires an empty externalId lookup before clearing that guard. Otherwise restore
   the account's correct externalId at the target and resume; lookup recovers its ID.
4. When a receiver outage blocked many users, **Resume all expired for this system**
   releases every expired attempt of that connector after the same confirmation, with one
   step-up and one audit (`admin.sync_deliveries_resumed`). It keeps every create guard;
   clearing one stays a per-attempt decision.

The oldest 100 attempts are shown; resolving them exposes the next page. A definitive
4xx rejection (except 408) or 503 uses ordinary backoff and the five-attempt budget
(removals have none); Retry-After extends backoff up to 30 minutes. Do not use resync or disconnect/reconnect
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
queues behind it, so an old create can never undo a later disable. An account removed
before its create was acknowledged (pending, retrying or failed) still receives the
inactive update in the create's place: the app may know the person another way, such as
its own setup or a sign-in. Only a never-acknowledged group is forgotten. Every event
carries a monotonic per-resource revision; suite receivers receive it as `meta.version`
(`W/"<n>"`) and should refuse writes older than one they applied. Conditional
`If-Match` writes to generic SCIM targets are not implemented.

Work that exhausts its attempt budget is not abandoned: each reconcile pass returns it
to the queue with a 30-minute backoff when it still describes current desired state,
and discards it when a newer state has overtaken it. This covers suite webhooks as well
as generic SCIM. Removals never exhaust; they keep retrying. A local deletion is sent to every
enabled connector; only a connector known to hold the account receives the profile,
the rest receive the identifier and `active=false`.

**Resync** re-sends every in-scope account (and assigned group) and never provisions a
user outside scope. It also replays every removal: each account the connector ever held
or was meant to hold (a state row, delivered or not, or a remote ID mapping) that is now
disabled, unassigned or deleted gets
an inactive update again, so a target restored from an older backup cannot readmit it.
Replays deactivate and never delete; repeating a resync queues nothing extra.
Installers run the same resync from inside the container with
`kyidentity resync-system --client <client id> [--wait <duration>]`; see
[Resyncing after a downstream restore](INSTALLER-SETUP.md#resyncing-after-a-downstream-restore).

For native KyPost recovery, `POST /api/admin/systems/{id}/recovery-evidence`
(global admin, operation-bound step-up) returns a nonce-bound complete signed
snapshot for 1–256 requested restored subjects, including explicit inactive
entries and known sync revisions. See the [wire and operator contract](KYPOST_RECOVERY_EVIDENCE.md).
This does not release either restore hold; a held identity connection refuses export.

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
disagrees with a stored mapping the target still lists is counted as a conflict and never
written through. A stored mapping to an ID a complete listing does not hold is dead (the
target was wiped or restored without it): repair replaces it with the listed resource that
carries the same `externalId`, or drops it so delivery looks the user or group up and
creates it again. A wiped target therefore gets its users and assigned groups back from
one repair. A complete run classifies each managed
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
