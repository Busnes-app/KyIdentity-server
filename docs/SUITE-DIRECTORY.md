# Suite directory

KyIdentity tells suite apps about each other, so cross-app features work without an
operator copying URLs or secrets between servers. Two read-only service endpoints, called
server to server by a registered app with its own OAuth client credentials.

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

## `GET /api/suite/peer`

Connection details for a paired suite integration.

- `client` (required): the peer's client ID.
- Only for pairs KyIdentity knows: `kycalendar` and `kypost`. Any other pair, a disabled or
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
