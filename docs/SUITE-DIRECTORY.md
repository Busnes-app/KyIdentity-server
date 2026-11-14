# Suite directory

KyIdentity tells suite apps about each other, so cross-app features work without an
operator copying URLs or secrets between servers. Three read-only service endpoints, called
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
  `kycalendar` and `kymessage` (video meetings), `kydrive` and `kypost` (mail files). Exact,
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
