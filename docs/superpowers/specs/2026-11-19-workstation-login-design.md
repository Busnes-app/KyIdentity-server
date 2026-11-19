# Workstation login (Linux, Himmelblau): design

Date: 2026-11-19. Worker `ws-linux`. Plan and owner decisions:
`ky-redesign/workstation-login/DESIGN.md` (approved 2026-11-19). This document does not
reopen those decisions. It records what Himmelblau actually does and how KyIdentity
meets it.

## What Himmelblau does (read from source)

Read at Himmelblau `4.0.8`, the newest release (tag, 2026-10-29), and at `main`
`b0b88b4e`. Paths are `src/common/src/idprovider/openidconnect.rs` (`oidc.rs` below)
unless named. Line numbers are 4.0.8 unless marked `main`.

| Question | Finding | Where |
|---|---|---|
| Discovery | Reads `/.well-known/openid-configuration`. `device_authorization_endpoint` is a **required** field of its metadata type, so discovery fails without it. `main` adds an `oidc_device_authorization_endpoint` fallback option. `issuer` must equal `oidc_issuer_url` exactly. | `oidc.rs:1463-1466`, `:1990-2011`; `main` docs `oidc_device_authorization_endpoint.xml` |
| Client | Public client. `CoreClient::from_provider_metadata(.., client_id, None)`, `AuthType::RequestBody`: `client_id` in the form body, **no client secret**. | `oidc.rs:2015-2019` |
| Grant | RFC 8628. Device authorization request with scopes `openid profile email offline_access`. Token poll is `grant_type=urn:ietf:params:oauth:grant-type:device_code`, `device_code`, `client_id`. No PKCE (RFC 8628 has none). | `oidc.rs:2024-2055`, `:2118-2160` |
| Poll errors | Needs a JSON body with `error`. `authorization_pending` and `slow_down` both mean "poll again" (it does **not** lengthen its interval on `slow_down`). `access_denied` and `expired_token` end the login. | `oidc.rs:2186-2235` |
| Polling rate | Polls every `interval` seconds, at most `expires_in / interval` times. | `oidc.rs:93-123` |
| Display | Shows `verification_uri_complete` (with a QR code) when present, else `verification_uri` and `user_code`. | `oidc.rs:96-111` |
| Host name | Sends **no** host name or device name. | `oidc.rs:2024-2055` |
| Password grant | Offers password-only (ROPC) login only when discovery advertises the `password` grant. KyIdentity does not advertise it. | `oidc.rs:1996-2000`, `:3055-3071` |
| Refresh tokens | Device-flow success **without** a refresh token still logs in, but skips Hello PIN enrolment (so every login is a new device flow). With one, it seals the refresh token to the TPM-backed Hello key and also keeps it in memory. | `oidc.rs:2723-2760`, `:1655-1662`, `:3318-3366` |
| Online PIN login | Every online Hello PIN login redeems the refresh token at the token endpoint, so **every online login contacts KyIdentity**. A network error falls back to the cached login. Any other error deletes the Hello key and sealed token and denies: the user must do a new device flow. | `oidc.rs:3231-3300` |
| Background refresh | When the cached NSS entry expires (`cache_timeout`, default 300 s) a lookup refreshes with the **in-memory** token. Only `invalid_grant` invalidates the cached user; any other error keeps it. | `oidc.rs:2876-2930`, `:1905-1912` |
| Rotation | 4.0.8 PIN login presents the **TPM-sealed** token first, and the background refresh does not re-seal. Under single-use rotation, a background refresh followed by a PIN login presents a spent token. `main` presents the in-memory token first and retries once with the other copy. | 4.0.8 `oidc.rs:3166-3230`; `main` `oidc.rs:3224-3245` |
| Username | `userinfo` (with the access token): `preferred_username`, then `email`, or `oidc_account_id_claims`. The ID token is decoded but not used for the name. | `oidc.rs:1697-1760`, `:2335-2357` |
| Groups | `userinfo` `groups` (string or array), `realm_access.roles`, `resource_access.*.roles`. A value containing `:` or a control character is dropped. | `oidc.rs:1792-1830`, `:1832-1876` |
| POSIX IDs | Derived locally: tenant = UUIDv5(fixed namespace, issuer URL); UID/GID = `idmap.gen_to_unix(tenant, name)`. Nothing is read from a claim. | `oidc.rs:1459`, `:2448-2460`, `:2366-2380`, `:1878-1903` |
| `pam_allow_groups` | Matched against the user's name and group names from the claims above (4.0+). Empty means everyone. Enforced in PAM account phase. | `resolver.rs:3280-3320`; docs `pam_allow_groups.xml` |
| Online probe | GETs the authorization endpoint; any non-2xx falls back to GET discovery. | `oidc.rs:2462-2552` |

Consequences for KyIdentity:

1. Advertise `device_authorization_endpoint` and the grant in discovery.
2. Workstation apps are public clients; the token endpoint takes `client_id` from the body.
3. Put the `groups` claim in **userinfo** for workstation apps.
4. **No `uidNumber`/`gidNumber` claims.** Himmelblau derives POSIX IDs from the issuer URL
   and names, so changing the issuer URL or renaming a user or group changes the IDs.
   This is documented, not built.
5. Every refusal of a revoked refresh token must be `invalid_grant`; anything else leaves
   the PC on its cache.
6. Group names with `:` never reach `pam_allow_groups`. Documented.
7. The rotation behaviour (row "Rotation") is a real interop problem with single-use
   tokens. Measured on nightly 5.0.0: a background refresh followed by a daemon restart
   presents the spent sealed token, reuse detection ends the family, and the person needs a
   new device code. Reported in `docs/WORKSTATION-LOGIN.md` as needing a Himmelblau change
   (re-seal after a background refresh); reuse detection is not loosened here.

## Threat model

| Attacker | Goal | Defence |
|---|---|---|
| Network or a malicious PC | Guess a user code and get a user to approve it, or approve one by brute force | User codes are 8 characters from the RFC 8628 20-letter consonant alphabet (`BCDFGHJKLMNPQRSTVWXZ`, about 34.6 bits), live 2-15 minutes, and entry is rate limited per account and per address. Each wrong code is audited. |
| Phisher | Start a device flow and talk a user into approving it | The approval screen names the app, its client ID and the requesting address, and has a Deny button. The grant only exists for workstation apps, is off by default, and the token only carries `openid profile email` and app-scoped groups. Accepted residual risk: a user who approves a phisher's code gives that machine a workstation session; it is audited, listed with the user's sessions and revocable. |
| Holder of a stolen device code | Redeem it | Device codes are 256-bit random. Each redeems once. A replay after redemption is refused and ends the workstation session it created. |
| Fast poller | Load the server or race approval | `slow_down` below the interval, per-address limits on the token and issue routes, and a cap of pending codes per app. |
| Database reader | Use stored codes | Device codes stored as SHA-256 (256-bit input). User codes stored as HMAC-SHA256 under a key derived from the server secret, so a dump cannot be brute forced offline without the key. Refresh tokens stay SHA-256 (existing). |
| Thief of a PC's refresh token | Keep access | Single-use rotation with family reuse detection (existing): a replay ends the family. Every refresh re-checks active account, app access, policy revision and the session. |
| Revoked user | Keep logging in | Disable, SCIM deprovision, unassign, session revoke, MFA reset and password change all end the workstation session (it is a `sessions` row, so the existing `revokeSessionsTx` paths reach it). Online, the PC learns at the next login. **Offline, it does not** (see below). |
| Framing site | Clickjack Approve | The page is the SPA, served with `frame-ancestors 'none'` and `X-Frame-Options: DENY` like every page; approval is a CSRF-protected POST. |
| Non-workstation client | Use the device grant, or public refresh | Both refused unless the client has a `workstation_apps` row; the device grant also needs that row's switch on. |

**Offline revocation trade-off.** KyIdentity can only refuse the next refresh. A PC that
cannot reach KyIdentity keeps accepting its cached Hello PIN login; Himmelblau does not
expire that cache on KyIdentity's schedule. The offline window bounds how long a
*refresh token* stays usable, so after the window an online PC needs a new device flow.
The window does not bound how long an offline PC accepts its cache. This is measured in
the end-to-end test and stated in `docs/WORKSTATION-LOGIN.md`.

## Data and protection at rest

New migration (`workstation_login`):

```
workstation_apps (client_id PK → oauth_clients ON DELETE CASCADE,
  device_grant_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  device_code_ttl INTEGER NOT NULL DEFAULT 300 CHECK 120..900,
  offline_window INTEGER NOT NULL DEFAULT 604800 CHECK 0..2592000)

device_codes (id PK, client_id → oauth_clients ON DELETE CASCADE,
  device_code_hash UNIQUE  -- SHA-256 of 32 random bytes
  user_code_hash UNIQUE    -- HMAC-SHA256(DeriveKey(secret,"kyidentity:device-user-code"), code)
  scope, ip_address, interval_seconds, status pending|approved|denied,
  user_id → users ON DELETE CASCADE NULL, evidence columns, auth_app_id/revisions,
  session_id NULL, last_polled_at, expires_at, created_at, redeemed_at)

sessions.workstation_client_id TEXT NULL  -- NULL: browser session
```

- A **workstation session** is a `sessions` row with `workstation_client_id` set. Its
  token hash is the hash of a random value that is never given to anyone, so it can never
  be a browser cookie; browser lookups also require the column to be NULL. It carries
  the approving login's evidence. Its `expires_at` is now + offline window and slides on
  each refresh. The browser idle/absolute limits do not apply to it; changing browser
  session limits does not end it.
- Raw codes, tokens, addresses and names are never logged. Audit rows carry the client
  ID, the device code row ID, and the outcome.
- Housekeeping deletes device codes an hour after they expire.

## Routes and their authentication

| Route | Auth | Notes |
|---|---|---|
| `POST /oauth/device_authorization` | `client_id` of an enabled workstation app with the grant on (public client, no secret) | Rate limit `device_authorization` per address (10, 0.2/s); at most 1,000 live pending codes per app. Returns `device_code`, `user_code` (`XXXX-XXXX`), `verification_uri` (`<issuer>/device`), `verification_uri_complete`, `expires_in`, `interval` (5). `no-store`. Audit `device_grant.issued`. |
| `POST /oauth/token` `grant_type=urn:ietf:params:oauth:grant-type:device_code` | `client_id` must match the code's client | `authorization_pending`, `slow_down` (poll sooner than interval − 1 s; the interval is not lengthened, because Himmelblau ignores it), `access_denied`, `expired_token`, `invalid_grant` (unknown, redeemed, wrong client). Redeems once. Audit `device_grant.redeemed` / `device_grant.replayed`. |
| `POST /oauth/token` `grant_type=refresh_token` | public workstation client by `client_id`, else confidential as today | Workstation families slide the session and family end by the offline window. |
| `GET /device` | none (SPA) | Signs in through the existing screens, then shows code entry and approval. |
| `POST /api/device/lookup` | session + CSRF | `{userCode}` → app name, client ID, address, created time. Rate limits `device_verify` per account (10, 0.1/s) and per address. Wrong codes audited `device_grant.code_rejected`. |
| `POST /api/device/decision` | session + CSRF | `{userCode, approve}`. Approve checks enabled app, grant on, app access, enrollment, password change, and the app's authentication policy against this session's evidence, binding the policy revision. Audit `device_grant.approved` / `device_grant.denied`. |
| `POST /api/admin/workstation-apps` | `permAdmin` + step-up | Creates the client (public, no redirect URIs, groups claim on, assigned-only) and its settings. |
| `PUT /api/admin/workstation-apps/{id}` | `permAdmin` + step-up | Grant switch, device-code lifetime, offline window. Shortening the window clamps the app's live workstation sessions in the same transaction; 0 ends them. |
| `GET /api/admin/workstation-apps` | `permRead` | Settings plus the issuer for the `himmelblau.conf` snippet. |

The grant also refuses non-workstation clients at both issue and redemption. A
workstation app's client type cannot be changed to confidential.

## Defaults

- Device grant **off** on a new workstation app.
- Device code 300 s (admin 120-900 s); poll interval 5 s.
- Offline window 7 days (admin 0-30 days). 0 issues no refresh token: each login is a
  new device flow and Hello PIN is not enrolled.
- Access: assigned only; groups claim on. The generated `himmelblau.conf` sets
  `pam_allow_groups` to the assigned groups.

## Choices made where the brief left them open

- **Sliding window, no absolute cap.** The window is "how long a PC that can't reach
  KyIdentity still works", so it is measured from the last refresh. Every refresh
  re-checks account, access, policy and session, so a long-lived session is re-checked
  continuously. (Owner question 1.)
- **Requesting address on the approval screen**, because Himmelblau sends no host name.
  Nothing new is added to the protocol for a host name.
- **Device-code replay ends the session** it created (RFC 6749 §4.1.2 spirit).
- **`slow_down` without lengthening the interval** so Himmelblau, which ignores it,
  is not locked out.
- **Workstation sessions in `sessions`** rather than a new table, so every existing
  revocation path reaches them without a second list to keep in step.

## Multi-tenant mode (not built)

Following PR #255's appendix: `workstation_apps` is platform-scoped like `oauth_clients`
(apps are global). `device_codes` has no user before approval; it becomes derived
(`user_id`) after. Multi-tenant mode would need: `org_apps` to gate the workstation app per
org at issue and approval; the device code bound to one org at issue (a per-org client or
an `org_id` on `device_codes`) so a user of org B cannot approve a code from org A's PC;
`org_id` in the device-grant tokens through `identityClaims`; and suspension ending
workstation sessions through the same `revokeSessionGrantsTx` path.

## Not built

- `uidNumber`/`gidNumber` claims (Himmelblau derives IDs).
- A host-name parameter on the device authorization request (nothing sends one).
- The `password` (ROPC) grant.
- Authorization-code refresh for workstation apps (XCreds is a later phase).
- Windows, macOS, KyQuickStart wiring, and Himmelblau changes.
