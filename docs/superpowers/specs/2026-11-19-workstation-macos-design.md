# Workstation login for macOS (XCreds): design

Date: 2026-11-19. Worker `ws-xcreds`. The plan and the owner's decisions are in
`ky-redesign/workstation-login/DESIGN.md` (approved 2026-11-19, section "macOS findings").
The Linux design this one extends is `2026-11-19-workstation-login-design.md`. Neither is
reopened here.

## What XCreds does (read from source)

Read at XCreds `tag-5.9(9148)` (release 5.9, 2026-04-08), the newest release.

| Question | Finding | Where |
|---|---|---|
| Preference keys | `discoveryURL`, `clientID`, `clientSecret` (optional), `redirectURI`, `scopes` (space separated), `passwordElementID`, `idpHostName`, `map_username`; payload type `com.twocanoes.xcreds` | `XCreds/PrefKeys.swift:11-13`, `Sample Profile/Auth0OIDC.mobileconfig` |
| Flow | Authorization code with PKCE S256 and a nonce, through OIDCLite. The verifier is two UUIDs (72 characters). | `XCreds/TokenManager.swift:86-112`; OIDCLite (design doc, "macOS findings") |
| Redirect | The web view matches the URL against `redirectURI` by prefix and takes `code=` out of the query. Nothing listens on the loopback address. | `XCreds/WebViewController.swift:415-445` |
| Password capture | `get_pw.js` collects every `type="password"` element it has seen (kept across DOM changes), on load, click and input. The value is read **only when the page's host is `idpHostName`** (or a built-in Microsoft, Google or Okta host). With `passwordElementID` set, it takes the password only from exactly one field with that id. | `Javascript/get_pw/get_pw.js`; `XCreds/WebViewController.swift:252-345` |
| Local user name | `map_username` names an ID-token claim, else the e-mail's local part, else `sub`. | `XCreds/TokenManager.swift:378-410` |
| Later checks | The refresh token, every `refreshRateHours`. ROPG only when `shouldUseROPG…` is set; KyIdentity has no password grant. | `XCreds/TokenManager.swift:240-262` |

Consequences for KyIdentity:

1. A workstation app must accept the authorization code flow with a registered
   `http://127.0.0.1/xcreds` redirect (allowed: http on loopback) and issue a refresh token
   to a public client there, under the workstation rules.
2. XCreds sets the Mac's password from what was typed on our page. A sign-in with no typed
   password (a passkey-only or push-only login, or an existing browser session) gives it
   nothing, so the app needs a rule that forces a password in this authorization.
3. The profile must set `idpHostName` to KyIdentity's host, or no password is captured.
   It sets `passwordElementID` to `password` (the id of the field in
   `web/src/components/LoginView.tsx`) and `map_username` to `preferred_username`, so the Mac
   account is named after the KyIdentity username, as on Linux.

## Threat model

| Attacker | Goal | Defence |
|---|---|---|
| Code interceptor on the Mac or the network | Redeem a stolen code | PKCE S256 for every client (existing). The code lives 60 s and redeems once. The redirect is exact match, and loopback http is the only http allowed. |
| Holder of a stolen refresh token | Keep access | Single-use rotation with family reuse detection (existing). Every refresh re-checks account, app access, policy revision and the workstation session. |
| Revoked user | Keep signing in | A code-flow workstation session is the same `sessions` row as a device-grant one, so every existing path ends it: disable, SCIM deprovision, unassign, session revoke, MFA reset, password change. Tested for both flows. |
| Someone at a Mac whose web view still holds a browser session | Sign in as the previous person without their password, or leave the Mac with no password to set | Require-password: an existing session never satisfies the app. The person must type a password in this authorization. |
| Passkey-only, push-only or phone sign-on | Sign in to a require-password app without typing a password | The password step marks the authorization interaction. A code for a require-password app needs that mark on the interaction its session completed. Device approvals and the KyAuth jwt-bearer sign-on are refused for such an app (and jwt-bearer for every workstation app). |
| Other public client | Get a refresh token | Refused unless the client has a `workstation_apps` row (existing rule, now tested on the code path too). |
| Database reader | Use stored values | Nothing new is secret. Codes and refresh tokens stay SHA-256 hashes (existing). `password_at` is a timestamp. |

**Offline.** As on Linux, KyIdentity can only refuse the next refresh. XCreds signs in with
the local password when it cannot reach KyIdentity. A revoked person's Mac account keeps
its local password until XCreds next reaches KyIdentity and its refresh fails.

## Data and protection at rest

Migration 9 `workstation_password`, on both backends:

```
workstation_apps.require_password BOOLEAN NOT NULL DEFAULT FALSE
authorization_interactions.password_at <timestamp> NULL  -- when this interaction's password step passed
```

- `password_at` is written only by the password handler, after the password verified,
  for an interaction that has no session yet and no other user. It holds no secret.
- No new secret is stored. A code-flow workstation session stores the same evidence,
  hashes and bindings as a device-grant one.
- Mac sign-in has no column. It is the app's redirect list: on means exactly
  `["http://127.0.0.1/xcreds"]`, off means `[]`.

## Routes and their authentication

No new route or listener.

| Route | Change |
|---|---|
| `GET /oauth/authorize` | For a require-password app an existing session is not enough: the person signs in again, as for `prompt=login`. The code is issued only if this interaction recorded a password, checked inside the code-insert transaction under the writer lock, so it cannot race the setting. |
| `POST /api/auth/login` | With an interaction, a verified password records `password_at` on it. |
| `POST /oauth/token` `authorization_code` | For a workstation app with an offline window above 0, the exchange creates a workstation session (as device redemption does), in one transaction that needs the browser session and the code's policy binding to still hold. It also binds the access token, the refresh family and its first token. `client_id` in the body, no secret, as before. |
| `POST /oauth/token` `refresh_token` | Unchanged: workstation families slide by the offline window. |
| `POST /oauth/token` jwt-bearer | Refused for a workstation app. |
| `POST /api/device/decision` | Approval refused for a require-password app (`sign_in_again`). |
| `PUT /api/admin/workstation-apps/{id}` | `permAdmin` + step-up (existing). Adds required `requirePassword` and `macSignIn`. Audited with the other settings. Changing `requirePassword` is a policy edit: the app's policy revision bumps, and its interactions, unused codes, unredeemed device codes, issued tokens and workstation sessions end in the same transaction. Every code, approval and refresh family binds that revision, so a grant racing the change fails at redemption. |
| `GET /api/admin/workstation-apps` | `permRead` (existing). Adds `requirePassword` and `macSignIn`. |

## Defaults

- Mac sign-in **off** on every app, new and existing, so no app gains a redirect URI by
  upgrading.
- Require password **off**. The Mac setup section tells the admin to turn it on, and says
  that XCreds cannot set the Mac password without it.
- Offline window: the app's existing value (default 7 days, sliding, no absolute cap:
  owner decision; every refresh re-checks access).
- Profile: `scopes` `openid profile email offline_access`, no `clientSecret`, no ROPG key.

## Choices made where the brief left them open

- **Device approval under require-password is refused, not allowed after a fresh login.**
  The `/device` screen has no interaction to carry the password mark. Allowing it on
  "signed in after the code was issued" would rest on the fact that every browser
  sign-in starts with a password today, and a later passwordless sign-in would
  silently pass. Himmelblau desktops do not need the rule. They keep their own app with
  it off. (Owner question 1.)
- **jwt-bearer refused for every workstation app.** KyAuth phone sign-on is a push-only
  login that creates no workstation session. It needs an https origin among the client's
  redirect URIs, so the loopback redirect never qualifies. An admin could still add an
  https redirect to a workstation app in the general client editor. Without this check
  that yields tokens (`TestDeviceSignOnRefusesWorkstationApp` fails with the check
  removed).
- **Mac sign-in is a switch, not free-form redirect editing**, so admins cannot mistype
  the URI. XCreds' own sample uses `https://127.0.0.1/xcreds`. The brief chose `http`,
  which is what KyIdentity's loopback rule allows.
- **Window 0 on the code flow:** no refresh token and no workstation session. The access
  token stays bound to the browser session, as for any public client. XCreds then needs
  KyIdentity at every sign-in.
- **The profile adds `idpHostName` and `map_username`** to the keys the brief listed. The
  first is required for password capture and the second for a predictable account name
  (table above).
- **Turning Mac sign-in off** stops new sign-ins; open sessions keep refreshing until
  revoked, like turning the device grant off.

## Multi-tenant mode (not built)

Both new columns are on platform tables (`workstation_apps`, `authorization_interactions`),
which stay platform-scoped under PR #255's rules. A code-flow workstation session is a
`sessions` row, already derived from `users`. Multi-tenant mode would need the same as
the device grant: `org_apps` gating the app at authorize (already in `app_access_facts`),
`org_id` in the tokens through `identityClaims`, and org suspension ending workstation
sessions through `revokeSessionGrantsTx`. Nothing here is org-specific.

## Not built

- A Ky Platform SSO extension, MDM delivery of the profile, and FileVault or
  Secure Token handling (XCreds' own options).
- A password grant (ROPG). XCreds' password-change checks fall back to the refresh token.
- A grace period for a reused refresh token.
- A Mac or Windows test in CI. The XCreds flow is tested in Go against the server
  (`TestXCredsFlow`). The live login-window test is manual, on the Mac Mini.
