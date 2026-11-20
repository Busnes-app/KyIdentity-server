# Suite directory

KyIdentity tells suite apps about each other, so cross-app features work without an
operator copying URLs or secrets between servers. Read-only service endpoints, called
server to server by a registered app with its own OAuth client credentials. The people route
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

Apps reconcile, keyed on `id` only: poll about every 60 s; on an error change nothing; for
an `active` group ensure one resource (create, or un-archive), set its name, and set its
members to exactly the listed subjects that have a local SSO account; for an `archived`
group with a resource, archive it (read-only, no members, kept for administrators). Never
delete, and never archive because a group is absent from a response. Client:
`ky-primitives/suitedir` `Groups`.

## `GET /api/suite/email-domains`

The suite's mail domains: the domains users' addresses use, set once by the KyIdentity
administrator (Administration → Suite settings). KyPost and the other apps read them here
instead of configuring their own. Same authentication, rate limit and `no-store`; any
enabled confidential client may read them. No parameters.

```json
{"domains": ["example.com", "xn--bcher-kva.example"]}
```

- Lowercase ASCII, IDNs in punycode, each a DNS name of at least two labels: no scheme,
  port, path, wildcard or address. No duplicates, at most 50, in the administrator's order.
  `[]` when none are set.
- Platform-wide: one list for the install (on the hosted platform, set by staff), never
  per org. These are mail domains, not app hostnames.
- Informational: KyIdentity does not refuse user addresses outside the list. Poll it
  (every few minutes is plenty); on an error keep the last list.

## Default theme: `GET /api/appearance`

The suite-wide default theme, set by the KyIdentity administrator. Unlike the routes above it
is **public** (no credential, `Cache-Control: no-cache`, rate limited per IP), because
KyIdentity's sign-in page applies it before anyone signs in and the value is not sensitive.

```json
{"defaultTheme": "ocean-pair"}
```

- `defaultTheme` is a ky-ui theme choice ID: `system` (Busnes following the OS; also the
  value when unset), a pair ID (`busnes-pair`, `matter-pair`, `ocean-pair`, `forest-pair`,
  `ky-pair`, `nord-pair`: that palette, following the OS) or a half ID (`busnes-light`,
  `busnes-dark`, `light-matter`, `dark-matter`, `white-cliffs`, `ocean`, `forest-light`,
  `forest`, `polished-ky`, `patina-ky`, `paper`, `nord`: a fixed palette and mode).
  KyIdentity accepts only these.
- A user's own saved choice always wins; the default applies only where the user has saved
  none. There is no lock. Platform-wide, never per org.
- Apps apply it with ky-ui 0.12.0 or later: the app's backend reads this route, hands the
  value to its pages (server-rendered for first paint, or from a same-origin route), and the
  page calls `setServerDefaultTheme(value)` then applies `chooseTheme(savedValue)`. Treat any
  value ky-ui does not know as `system`.
