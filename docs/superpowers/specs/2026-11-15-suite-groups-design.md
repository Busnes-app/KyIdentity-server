# Suite groups: design

Status: approved scope 2026-11-15 (owner), design by worker `g-groups`.

A suite group is an ordinary KyIdentity directory group that an administrator marks
"Create shared resources for this group". Every installed app that supports suite groups
then gives that group one shared resource (a KyDrive workspace, a KyCalendar group
calendar, a KyMessages room, optionally a KyPost distribution list), and group membership
decides who uses it. This document covers KyIdentity's half and the wire every app reads.
Each app's PR documents its own half against this contract.

## How apps learn of suite groups

**Choice: a pull route in the existing suite directory**, `GET /api/suite/groups`, called
with the app's own OAuth client credentials exactly like `/api/suite/apps`, `/people` and
`/peer`, through a new `Groups` method on `ky-primitives/suitedir`.

Why this and not the alternatives:

- Every suite app already calls the suite directory with these credentials
  (`suite_apps.go` in each). No new secret, no new pairing, no token exchange.
- The response is the complete desired state for the calling app. An app reconciles
  against it, so running twice or after a crash halfway creates nothing twice: the app
  keys every resource on the group's stable ID and only ever moves it towards the listed
  state. The signed outbox (`account_sync_events`) would need new fence, revision and
  supersession rules for group events days before launch, for no gain over a snapshot.
- SCIM group delivery (`groups:true`) is a per-connector opt-in that carries no suite
  flag, slug or archive state, and its group `DELETE` is the opposite of the archive rule.
  A vendor extension would fork the apps into two code paths. One route serves all.
- Replay: the route is a read. A replayed request returns the current state to the holder
  of the client secret over TLS, which is what an honest request returns, so there is no
  replay to prevent. Wrong credentials are the same `401 invalid_client` as the rest of the
  directory.

Cost: membership changes reach an app at its next poll, not at once. Apps poll every 60 s
(the `suite_client` limiter allows 2 requests a second). **Removal delay: at most one poll
interval plus the app's reconcile time**; each app's PR measures and states its own figure.

## Threat model

- A compromised or curious suite app learns the names, slugs and member subjects of suite
  groups enabled for it. It already learns users by SCIM/OIDC and people by `/people`;
  it learns nothing about groups that were never suite groups, and an app outside the
  suite group set (any confidential client other than `kydrive`, `kycalendar`, `kymessage`
  and `kypost`) gets an empty list.
- A member list must never widen access. Members are only active, non-pending, unended
  everyday accounts (`role = 'user'`) whose membership is live and who already have
  effective access to the calling app (`effective_app_access`, the rule OAuth issuance
  uses). Marking a group a suite group grants no app access; assigning the group to the
  app (or the app's all-users mode) still does that.
- Administrator separation: dedicated administrator accounts (`role = 'admin'`) are never
  listed, even when they are explicit members. Delegated administrators are everyday
  accounts and are listed, as in `/people`.
- No role: the wire carries no role. Apps give members their ordinary member role and
  nothing higher; a suite group can never make anyone an app administrator.
- Guests: KyIdentity has no guest identity. Apps map members only to accounts signed in
  through KyIdentity, by `sub`; an app's own guest or external accounts are never members.
- Data loss: KyIdentity never tells an app to delete. Turning a group off, turning one app
  off for it, or deleting the group lists it as `archived`; apps then make the resource
  read-only, remove every member and keep it for administrators.
- Inheritance by name: a deleted group leaves a tombstone row holding its ID and slug. A
  recreated group with the same name has a new ID and gets a new slug (`sales-2`), so it
  can never be matched to the archived resource. Apps match on `id` only.
- Absence is not archive: an app archives only on an explicit `archived` entry, never
  because a group is missing from a response (a dropped malformed entry, a failed call).

## Data

Migration 3 (`suite_groups`), same SQL on SQLite and Postgres:

```sql
CREATE TABLE suite_groups (
  group_id TEXT PRIMARY KEY,          -- no foreign key: the row outlives the group
  slug TEXT NOT NULL UNIQUE,          -- set when first enabled, never changed or reused
  name TEXT NOT NULL,                 -- the group's name when it was deleted
  enabled BOOLEAN NOT NULL,
  deleted_at TIMESTAMP,               -- tombstone
  created_at, updated_at
);
CREATE TABLE suite_group_apps (       -- per-app overrides of the default
  group_id TEXT NOT NULL REFERENCES suite_groups(group_id) ON DELETE CASCADE,
  client_id TEXT NOT NULL, enabled BOOLEAN NOT NULL,
  PRIMARY KEY(group_id, client_id)
);
```

- The live name comes from `directory_groups`; `deleteGroupTx` copies it into the
  tombstone and sets `enabled = false, deleted_at = now` in the deletion transaction, so
  every deletion path (admin, upstream SCIM) leaves one.
- The slug is ASCII lowercase letters and digits with single hyphens, at most 48
  characters, from the group name (`group` when nothing is left), with `-2`, `-3`… on a
  collision with any row, tombstones included. Renaming keeps the slug: KyPost uses it as
  an address.
- Suite group apps and their defaults are code (`suiteGroupApps`): `kydrive`,
  `kycalendar`, `kymessage` on; `kypost` (distribution list) off. An override row records
  only an administrator's choice.
- `ponytail:` at most 200 enabled suite groups, so one response stays bounded (the client
  allows 8 MiB). Upgrade path: page the route by group.

## Routes

| Route | Auth | Notes |
|---|---|---|
| `GET /api/suite/groups` | suite directory client Basic auth, `suite_client` limiter, `no-store` | the wire below |
| `GET /api/admin/groups/{id}/suite` | `permDirectory` | `{enabled, slug, apps:[{id, enabled}]}`; a group never enabled is `enabled:false`, no slug |
| `PUT /api/admin/groups/{id}/suite` | `permAdmin` + operation-bound step-up, like every group mutation | `{enabled, apps:{"kypost":true}}`; omitted apps keep their setting; audit `admin.group_suite_updated` commits with the change |

Wire, for the calling client `c`:

```json
{"groups": [
  {"id": "…", "name": "Sales", "slug": "sales", "state": "active", "members": ["<sub>", "…"]},
  {"id": "…", "name": "Old team", "slug": "old-team", "state": "archived", "members": []}
]}
```

- Listed: every `suite_groups` row, when `c` is a suite group app. Others get `[]`.
- `active` when the row is enabled, not deleted and enabled for `c`; otherwise `archived`
  with no members. A group that was never active for an app is listed as archived too;
  the app has no resource for it and does nothing.
- Order by `id`. Members sorted. Not audited (like the rest of the directory).

## App contract (each app's PR)

1. Poll `Groups` every 60 s; on an error do nothing (never archive on failure).
2. For each `active` group: ensure exactly one resource keyed by `id` (create if absent,
   un-archive if archived), set its name from `name`, set members to exactly `members`
   mapped to local SSO accounts by `sub` (skip subs with no local account yet; they are
   added on a later poll after first sign-in), at the ordinary member role.
3. For each `archived` group with a resource: archive it (read-only, no members, kept,
   visible to administrators). Never delete.
4. Record the group ID on the resource (unique), so reconcile is idempotent and a crash
   between steps repeats safely.

## Defaults

The switch is off for every group. When turned on, Drive, Calendar and Messages are on and
KyPost's distribution list is off. Nothing reaches outsiders, so no extra switch is needed.

## Not built

- Nested groups (KyIdentity has none).
- Push notification of changes (apps poll; see delay above).
- A KyPost shared mailbox: out of scope by owner decision. Only a distribution list.
- Purging archived resources: an administrator does that in each app, by hand.
- A per-app member role choice: always the ordinary member role.
