# Forward-auth (proxy apps), design

Date: 2026-11-15. Owner approval: 2026-11-15 suite feature list. Worker: f-fwdauth.

KyIdentity protects a web app that sits behind the edge nginx, including apps with no OIDC
support. nginx asks KyIdentity on every request (`auth_request`), and KyIdentity answers with
the signed-in user. There is no shared parent-domain cookie: each protected host gets its own
host-only cookie, minted through a one-time code.

## Threat model

Attackers considered, and what stops each one:

| Attacker | Goal | Defence |
|---|---|---|
| Internet client | Reach the app as someone else by sending `X-Ky-User`, `Remote-User` and similar | nginx overwrites every Ky header and the app's login header with the check's answer (`proxy_set_header`), so an empty answer removes them. The app must not be reachable except through the edge. |
| Internet client | Call `/api/forward/check` or the `/forward/*` edge routes directly and forge `X-Forwarded-Host` | Each proxy app has its own 256-bit edge secret. KyIdentity looks the app up by host and compares the secret's SHA-256 with the stored hash in constant time. Failures are rate limited per IP. |
| Phisher | Use `rd` to bounce a user off the sign-in origin | `rd` must be an absolute `https://` URL with no userinfo, port, fragment, backslash or control character, and its host must byte-equal a registered proxy app's host (lowercase ASCII). Anything else gets an error page and no redirect. |
| Login-CSRF attacker | Plant their own code in a victim's browser so the victim works in the app as the attacker | The flow starts on the app's own host (`/.ky/start`), which sets `__Host-ky_fwd_n`, a random nonce. The code is bound to its SHA-256. The callback refuses a code whose nonce cookie is missing or different. |
| Restored backup | Revive old forward sessions or codes | A restore clears `forward_codes` and `forward_sessions` with the other credentials (`restoredCleared`). |
| Code thief (logs, Referer) | Replay a code | Codes are 256-bit, stored hashed, single-use (consumed on first presentation, whatever the outcome), valid 60 s, and bound to one host. |
| Cookie thief on app A | Use A's cookie on app B | A forward session is bound to its host and app. The check refuses a session presented for another host. `__Host-` prevents a sibling subdomain from setting or overwriting the cookie. |
| Disabled or unassigned user with a live cookie | Keep using the app | The check re-reads the user's status, the app's assignments and the policy. A cached answer lives at most 30 s. Disable, "sign out everywhere", session revocation and password change delete forward sessions in the same transaction that deletes the login sessions. |
| Stale MFA | Keep a session past the app's factor age | The forward session snapshots the login's evidence, and the check evaluates the app's policy against it on every uncached request. |
| Path tricks on bypass prefixes | Reach a protected path through a bypass prefix (`/public/../admin`, `%2e%2e`, `//`, `;`) | A bypass applies only to a raw path with no `..`, no `%`, no `;`, no backslash and no `//`. Prefixes match whole segments only (`/public` matches `/public` and `/public/x`, not `/publicity`). Anything else is checked. nginx passes the raw URI to the app, so the raw path is what the app sees. |

Out of scope, accepted residual risks:

- An app that is reachable around the edge (a published port) trusts whatever header it is
  sent. KyIdentity cannot see this. The admin UI warns about it, and KyQuickStart refuses to
  deploy a `login: header` app with a published port.
- The protected app receives the `__Host-ky_fwd` cookie in the `Cookie` header, like any
  cookie on its host. The cookie only opens that same host, so the app gains nothing new.
- `/.ky/logout` is a GET, so a cross-site link can sign a user out of one app. It cannot sign
  anyone in. A POST form would need a CSRF exemption for the edge path, which is more risk than
  logout CSRF.

## Data

The migration (schema version 2, on SQLite and Postgres) adds three tables. Times are unix
seconds.

- `proxy_apps`: one row per protected host. A proxy app *is* a launcher application (an
  `applications` row, so it has an `app_registry` record) plus this row. It holds:
  - `application_id`, the primary key (FK `applications`, `ON DELETE CASCADE`)
  - `host` (unique, lowercase), `secret_hash` (SHA-256 hex) and `login_header`
  - `bypass_json`, a JSON array of prefixes
  - `session_seconds` (default 43200, between 300 and 604800) and `created_at`
- `forward_codes`: holds `hash`, `application_id`, `host`, `session_id` (FK `sessions`,
  cascade), `user_id`, `nonce_hash`, `path` and `expires_at` (now plus 60 s). A row is deleted
  when the code is redeemed. Expired rows go in the existing housekeeping sweep.
- `forward_sessions`: holds `hash`, `application_id` (FK, cascade), `host`, `user_id` (FK
  `users`, cascade), `session_id`, the evidence snapshot (`primary_at`, `factor_at`,
  `factor_method`), `created_at` and `expires_at`.
  - `session_id` has no FK, so the hourly sweep of idle-expired login sessions does not end a
    12-hour forward session.
  - `revokeSessionGrantsTx` deletes the forward sessions of every login session it revokes.
    That function is the single path for sign out everywhere, disable, password change, MFA
    reset, session limits and single-session revocation.
  - An authentication-policy edit deletes every forward session and code of that app in the
    policy transaction, as it revokes an OAuth app's tokens.

Nothing secret is stored in clear: the edge secret, codes, nonces and cookies are stored only
as SHA-256 hashes. They are 256-bit random values, so a fast hash is enough.

## Routes

The app-host routes are what nginx proxies from `https://<app host>/.ky/*` to KyIdentity's
upstream. Every one of them requires the edge secret, and is identified by the
`X-Forwarded-Host` the edge sets.

| Route | Called by | Auth | Result |
|---|---|---|---|
| `GET /api/forward/check` | nginx `auth_request` | Edge secret | 200 with `X-Ky-User`, the login header, `X-Ky-Email` and `X-Ky-Groups`, or 200 with none of them on a bypass path. 401 (nginx's `error_page 401` then runs `/forward/begin` with the original URI), or 403 for a signed-in user who is not assigned. A bad or missing secret gets 401. |
| `GET /forward/begin?rd=<path>` (`/.ky/start`, and nginx's 401 handler) | Browser, on the app host | Edge secret | Takes the path from `rd`, else from `X-Original-URI`. Sets `__Host-ky_fwd_n` (10 min) and sends a 302 to `<issuer>/forward/start?rd=https://<host><path>&n=<nonce hash>`. |
| `GET /forward/start?rd=<url>&n=<hash>` | Browser, on KyIdentity | Login session (`OptionalAuth`) | Validates `rd`. With no session, sends 302 to `/login?return_to=…`. Then checks the session is unrestricted and needs no password change, the account is active and assigned, and the session's evidence meets the policy. Any failure is an error page with no redirect; a signed-in user whose evidence is too weak is told to sign out and in again (no login loop). Mints a code and sends 302 to `https://<host>/.ky/callback?code=…`. With no `n`, sends 302 to `https://<host>/.ky/start?rd=<path>` (a registered host only). |
| `GET /forward/callback?code=` (`/.ky/callback`) | Browser, on the app host | Edge secret, code, nonce cookie | Consumes the code. Checks its host, its nonce, the login session, the user and their access, then creates the forward session. Sets `__Host-ky_fwd` (`Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, `Max-Age` the session length), clears the nonce and sends 302 to `https://<host><path>`. |
| `GET /forward/logout` (`/.ky/logout`) | Browser, on the app host | Edge secret | Deletes that host's forward session for the cookie, clears the cookie and sends 302 to the issuer. |
| `GET /api/admin/proxy-apps` | Admin UI | `permRead` | Lists the proxy apps. It never returns a secret or hash. |
| `POST /api/admin/proxy-apps` | Admin UI | `permAdmin`, step-up | Creates the launcher card, the proxy row and the secret. The secret is returned once. |
| `PUT /api/admin/proxy-apps/{id}` | Admin UI | `permAdmin`, step-up | Edits the host, login header, bypass list and session length. A host change ends that app's forward sessions. |
| `POST /api/admin/proxy-apps/{id}/secret` | Admin UI | `permAdmin`, step-up | Rotates the secret and returns the new one once. The old secret works for at most 30 s more (the cache). |

A proxy app is deleted by deleting its launcher card (`DELETE /api/admin/applications/{id}`);
the proxy row, codes and sessions cascade, and the edge then gets 401 for that host. Its name is
the card's name.

Rate limits:

- `forward_edge`: 30 burst, 1/s per IP, spent only by secret failures (429 past it, unaudited).
- `forward_begin`, `forward_start`, `forward_callback` and `forward_logout`: 30, 1/s each.

The check itself is not rate limited by IP, because the edge calls it on every request from
one address. An unauthenticated caller only reaches the secret comparison.

Audit events (`target_type` `application`):

- `forward.edge_rejected` (denied)
- `forward.start` (success, or denied with a reason)
- `forward.code_rejected` (denied: replay, host, nonce or expired)
- `forward.session_created`
- `forward.logout`
- `forward.check_denied` (once per cached decision, not per request)
- `admin.proxy_app_created`, `_updated` and `_secret_rotated`; deletion is the card's `admin.application_deleted`

No event carries the cookie, the code, the nonce, the secret, an email address or a user name.
Events carry the user ID and the app ID; like every audit row they record the client IP.

## Policy

Proxy apps use the app's existing authentication policy (`app_registry.auth_*`). The setter
currently refuses non-OAuth apps; it now also accepts proxy apps, with these limits:

- `fresh` mode is refused. It needs a per-authorization interaction, and the forward flow has
  none.
- Refresh settings must be zero.
- New proxy apps default to `factor=mfa`, `mode=reuse`. This is the safest default that still
  works for an ordinary user, because login always asks for the enrolled second factor.
- Access mode defaults to assigned-only, like every new app.

## Defaults

- Session length: 12 hours.
- Login header: `X-Ky-User`. The header name must be 1 to 64 characters of `A-Za-z0-9-`, and
  must not be a hop-by-hop or forwarding header (`Host`, `Cookie`, `Authorization`,
  `Connection`, `X-Forwarded-*`, `X-Real-IP`, `Forwarded`, `Content-*`, `Transfer-Encoding`,
  `Upgrade`, `X-Ky-Edge-Secret`).
- Bypass list: empty. At most 20 prefixes, each starting with `/`, with no `..`, `//`, `%`,
  backslash, `?`, `#`, whitespace or control character, and at most 128 characters. `/` is
  refused, because it would bypass everything.
- Groups header: the user's live groups that are assigned to this app (least disclosure). A
  group name containing a comma or a non-printable character is left out.
- Answer cache: 30 s, in process, keyed by the forward session's hash and the host. Only
  answers for a real forward session are cached. The cache is cleared when it holds 10,000
  entries.

## Suite pair pattern

This feature is not a pair of Ky apps exchanging data. The edge is not a suite peer and holds
no OAuth client, so no `suitePeers` entry, `syncauth` route or per-user switch is added.
Forward-auth is not outsider-facing: only KyIdentity users reach a protected app. So there is
no global administrator switch. A proxy app exists only when an administrator creates one,
and with none registered every forward route answers 401 or an error page.

## Not built

- Wildcard hosts, a parent-domain cookie, non-HTTP services and native-app token flows (out of
  scope).
- `fresh` per-request re-authentication.
- An idle timeout for forward sessions.
- POST logout.
- Stripping `__Host-ky_fwd` from the `Cookie` header sent to the app.
- Back-channel notification to the app when a forward session ends (header apps have no
  receiver).
- An HTTP API for KyQuickStart. Deliverable 2 adds a container-local CLI command in its own
  KyIdentity PR. The root AGENTS.md makes the container-local commands (`apply-setup`,
  `disable-user`) the installer channel, and a CLI needs no network listener, administrator
  session or step-up token held by the installer.
- A second app type in `app_registry`. A proxy app is a launcher card plus a `proxy_apps` row,
  so the launcher, access reviews, explanations and access requests need no change.
- Re-authentication from `/forward/start` when a signed-in session is too weak. The user signs
  out and back in; a stepped-up interaction like OAuth's is a later change.

## Owner questions (defaults chosen)

1. New proxy apps require MFA (`factor=mfa`). Is that the default you want, or password-only
   like OIDC apps? Default: MFA.
2. `X-Ky-Groups` lists only groups assigned to the app. Should it list all the user's groups?
   Default: assigned groups only.
3. `/.ky/logout` is a GET, which allows logout CSRF. Is that acceptable? Default: yes.
