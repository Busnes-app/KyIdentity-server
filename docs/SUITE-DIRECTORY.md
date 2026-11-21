# Suite directory

KyIdentity tells suite apps about each other, so cross-app features work without an
operator copying URLs or secrets between servers. Four read-only service endpoints, called
server to server by a registered app with its own OAuth client credentials. A multi-tenant
install adds a fifth, `/api/suite/orgs`, and scopes people and groups by organisation (see
Multi-tenant installs). The people route
is contract A2 of the wave-1 suite integrations (`ky-redesign/integrations/suite-integrations-contracts.md`);
this file is the durable copy.

## Authentication

HTTP Basic, `client_id:client_secret`, exactly as at the token endpoint
(`client_secret_basic`). Only enabled confidential clients. A wrong or missing credential is
`401 {"error":"invalid_client"}` with no hint which part failed. Rate limited per client.
Responses are `Cache-Control: no-store`.

## `GET /api/suite/apps`

The suite apps a person can open, for an app switcher.

- `sub` (optional): a KyIdentity user ID, the `sub` of that user's ID token. With it, the
  list holds only apps the user may open (the same access rules as the launcher and OAuth
  issuance), and only when the user may open the calling app too; otherwise the list is
  empty. Without it, every launchable app in the suite, for pages with no signed-in user
  (Element's home page).
- Lists OAuth clients only, enabled, with an HTTPS launch URL. Custom launcher cards are left
  out. Order is the launcher's (sort order, then name).
- The launcher's card settings apply: `name` is the client's launcher name when set, and a
  card shown to the app's administrators only is listed only for a `sub` who is one, never
  without `sub`. Like the launcher, this hides; it grants and removes no access.

```json
{"apps": [{"id": "kypost", "name": "KyPost", "url": "https://mail.example.com/api/auth/oidc/login"}]}
```

`id` is the client ID; apps pick the mark from it (ky-ui `appMarks`). `url` is the client's
launch URL, or its redirect origin plus its SSO start path, so following it signs the user
in through their KyIdentity session without a second login.

## `GET /api/suite/people`

The organisation's people the calling app may offer a signed-in user, for a people picker
or to resolve addresses. Same authentication, rate limit and `no-store` as the app list.

- `sub` (required): the signed-in user the calling app is acting for. If that user is not
  an active everyday account that may open the calling app, the answer is an empty list.
- Exactly one of:
  - `q`: 2 to 64 characters. Case-insensitive (ASCII) match: a word of the display name
    starts with `q`, or the username or email does. `limit` 1 to 20, default 10.
  - `email`: repeated, 1 to 100 exact addresses (each at most 254 bytes), case-insensitive.
    Unmatched addresses are simply absent. `limit` is refused here.
- Result set: active users who may open the calling app (the same access rule as OAuth
  issuance, `effective_app_access`), with an email address. Dedicated administrator
  accounts (role `admin`) are never listed and get an empty list as `sub`; delegated
  administrators are everyday accounts and are listed. Pending invitations are left out.
  Ordered by display name. `name` is the display name, or the username when it is empty.

```json
{"people": [{"sub": "…", "name": "Alice Example", "email": "alice@example.com"}]}
```

`400 {"error":"invalid_request"}` for a missing `sub`, both or neither of `q`/`email`, or
out-of-range values. No photo field exists yet. Lookups are not audited (like the app list);
nothing is logged about the query.

## `GET /api/suite/peer`

Connection details for a paired suite integration.

- `client` (required): the peer's client ID.
- Only for pairs KyIdentity knows: `kycalendar` and `kypost` (mail and calendar),
  `kycalendar` and `kymessage` (video meetings), `kydrive` and `kypost` (mail files),
  `kymessage` and `kypost` (chat from mail), `kypost` and `kypulse` (alert mail from
  a member's mailbox, KyPost `docs/KYPULSE.md`). Exact,
  case-sensitive client IDs, either side asking. Any other pair, a disabled or
  missing peer, or a peer with no HTTPS redirect origin is `404 {"error":"no_peer"}`.

```json
{"client": "kypost", "url": "https://mail.example.com", "secret": "<base64, 32 bytes>"}
```

- `url` is the peer's redirect origin.
- `secret` is the same for both sides of a pair and different for every pair:
  `DeriveKey(EncryptionKey, "kyidentity:suite-peer:v1:" + a + "|" + b)` with `a < b`. Both
  apps use it as their `ky-primitives/syncauth` shared secret. Nothing is stored; restoring
  KyIdentity's backup restores it, rotating the encryption key rotates it.
- Why this adds no trust: KyIdentity can already sign anyone into either app, so the peer
  secret gives it no power it lacks. Each app's own explicit configuration (its `*_URL` and
  `*_SECRET_FILE` variables) still wins when set.
- Each issue is audited (`suite.peer.issue`, caller and peer, never the secret).

## `GET /api/suite/groups`

The suite groups the calling app creates shared resources for. Same authentication, rate
limit and `no-store`. No parameters. Design and threat model:
`docs/superpowers/specs/2026-11-15-suite-groups-design.md`.

```json
{"groups": [
  {"id": "…", "name": "Sales", "slug": "sales", "state": "active", "members": ["<sub>"]},
  {"id": "…", "name": "Old team", "slug": "old-team", "state": "archived", "members": []}
]}
```

- Only the suite group apps get entries: `kycalendar`, `kydrive`, `kymessage` and `kypost`.
  Any other client gets `{"groups": []}`.
- Every group that was ever a suite group is listed, deleted ones included (a tombstone).
  `active` when the group is on and on for the caller (Drive, Calendar and Messages default
  on; KyPost's distribution list defaults off); otherwise `archived` with no members.
- `members`: subjects of live members who are active everyday accounts (`role = 'user'`)
  with access to the caller (`effective_app_access`). Dedicated administrators never.
  Sorted. The list carries no role: apps grant the ordinary member role only.
- `slug` is lowercase ASCII words joined by single hyphens, fixed when the group is first
  turned on and never reused, so a recreated namesake gets `sales-2`. `name` follows renames.
- At most 200 groups can be on at once. Ordered by `id`. Not audited.

In a multi-tenant install `org_id` (a UUID from `/api/suite/orgs`) is required, and the
list holds that organisation's groups only. Without it the answer is
`400 {"error":"invalid_request"}`; an organisation the caller is not told about by
`/api/suite/orgs` is `404 {"error":"unknown_org"}`. A single-tenant install ignores it.

Apps reconcile, keyed on `id` only: poll about every 60 s; on an error change nothing; for
an `active` group ensure one resource (create, or un-archive), set its name, and set its
members to exactly the listed subjects that have a local SSO account; for an `archived`
group with a resource, archive it (read-only, no members, kept for administrators). Never
delete, and never archive because a group is absent from a response. Client:
`ky-primitives/suitedir` `Groups`.

## Multi-tenant installs

A multi-tenant install (design `docs/superpowers/specs/2026-11-19-tenancy-design.md`) holds
many organisations under one issuer. The caller is a global client, so the organisation
always comes from KyIdentity's data, never from the calling app:

- `/api/suite/apps?sub=` and `/api/suite/people?sub=` answer for the `sub` user's
  organisation: people lists only its users, and apps only the apps its plan enables. `/apps`
  without `sub` stays global.
- `/api/suite/groups` requires `org_id` (above).
- Tokens and UserInfo carry `org_id`, and so does the body of every signed suite webhook,
  inside the `ky-primitives/syncauth` signature.
- While an organisation is `deletion_scheduled`, the people allowed to export sign in with
  tokens and UserInfo that carry `"export_only": true` (scope `openid email profile`, no
  refresh token). Admit only your export routes for such a sign-in, and refuse everything
  else. A token without the claim from an organisation that is not `active` is never issued.

### `GET /api/suite/orgs`

The organisations the calling app serves. Same authentication, rate limit and `no-store`.
`404 {"error":"not_found"}` in a single-tenant install.

- Listed: every organisation that has (or had) the calling app enabled, with `enabled`
  `false` once its plan turns the app off, and every deleted organisation (a tombstone, never
  reused). Others are absent.
- `revision` rises across the whole install with each change to an organisation or its
  apps, so a poll asks only for what changed: `since=<revision>` lists what changed after it.
- Ordered by `revision`, then `id`. `limit` 1 to 500, default 100. A full page carries
  `next`; pass it back as `cursor` (instead of `since`) for the next page.
- `enabled` and `quotas` (the plan's opaque object) are the calling app's only, read from
  the organisation's `org_apps` row. The platform API writes those rows in tenancy build plan
  PR 6; until then a multi-tenant install is refused at startup, so nothing serves this.

```json
{"orgs": [{"id": "…", "status": "active", "revision": 42, "enabled": true, "quotas": {"storage_gb": 5}}],
 "next": "42.…"}
```

`status` is `active`, `suspended`, `deletion_scheduled` or `deleted`. Apps poll about every
60 s. Remember the highest `revision` seen once a pass ends without `next`, and start the
next poll from it. An error changes nothing.

### `GET /api/suite/erased`

The people who used Delete everything (tenancy design, amendment 2026-11-21), and every
person of an organisation deleted after its account holder asked. Same authentication, rate
limit and `no-store`. `404 {"error":"not_found"}` in a single-tenant install.

- Listed: erased subjects of the organisations `/api/suite/orgs` tells the caller about.
  A subject is never reused, and the list never shrinks.
- `since=<revision>` lists what was erased after it, in `revision` order. `limit` 1 to 500,
  default 100. A full page carries `next`, the last revision, to pass back as `since`.

```json
{"subjects": [{"sub": "…", "org_id": "…", "revision": 7}], "next": "7"}
```

Delete the data of each listed subject. Re-read the list from `since=0`, with
`/api/suite/orgs`, after restoring a backup, before serving again.

### `user.erased`

A signed suite webhook, sent to every enabled suite app when a member deletes their own
account. The body is the bare inactive SCIM user (`id`, `externalId`, `active: false`) with
`org_id`, covered by the `ky-primitives/syncauth` signature with the event type. It means
"delete this person's data"; `user.deleted` keeps meaning "disable". Apply it idempotently
and answer `2xx` (or `404` for a person you never held); it is retried until then. Generic
SCIM and Active Directory targets get `user.deleted` instead.

Downstream contract, for every app run as a shared multi-tenant install: refuse a token
without `org_id`; key every row by `org_id`; bind a local account to `(sub, org_id)` and
refuse a known `sub` arriving with another `org_id`; take the org only from a verified token,
a signed webhook or a suite answer, never a URL, form or header; stop serving an
organisation whose status is not `active`, and drop its data only at `deleted`; enforce
your own quotas from this list. Client: `ky-primitives/suitedir` `Orgs`.
