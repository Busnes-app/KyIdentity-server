# Refresh tokens, re-authentication timers and step-up

Status: 2026-10-17. Covers Yoshi's requests 1–3; request 4 (issue #77) is fixed separately
by raising the session idle default (see "Issue #77" below). Delivered as stacked PRs:

1. #77: session idle default 30m → 8h.
2. Refresh tokens: everything below except the admin-adjustable session timers.
3. Session timers in the admin UI with the bounds below, and step-up verification.

## Why refresh tokens were left out, and what changed

`docs/access-lifecycle-plan.md` lists refresh tokens as out of scope without a stated
reason. The plan's actual concerns are visible elsewhere in it and in README:

1. **Revocation must reach every credential.** Access loss, disable, session revocation,
   policy and role changes all revoke tokens in the mutation transaction. A long-lived
   credential that one of those paths forgets is a standing bypass.
2. **Offline consumers cannot see revocation**, so access tokens are kept at 15 minutes.
   A refresh token is the opposite: long-lived, and only useful if it is checked online.
3. **Authentication evidence must never be invented.** Re-issuing tokens must not make a
   login look younger or stronger than it was.

The design answers each: the refresh-token family is itself an `issued_tokens` row, so
every existing revocation statement already reaches it (1); every refresh is an online
check against the same SQL guard that registers access tokens (2); and refreshed ID tokens
copy the original `auth_time`/`amr`/`acr` and are refused once the app's re-auth deadline
passes (3).

What refresh tokens are for here: letting an app keep its user signed in only as long as
KyIdentity still agrees. Today every Ky app keeps its own 7-day or 24-hour session after
one sign-in and never asks KyIdentity again, so disabling a user, removing access or
tightening an app's policy does not end an app session unless the app has a back-channel
receiver. An app that refreshes every 15 minutes learns of all of those within 15 minutes.

## Threat model

| Threat | Control |
|---|---|
| Refresh token stolen from an app's database or logs | Stored hashed here; usable only with the client secret (confidential clients only); rotates on every use, so the thief and the app race and the loser triggers reuse detection |
| Stolen token replayed after the app used it | Reuse of any spent token revokes the whole family and its access tokens, audited `oauth.refresh_reuse` |
| Token used by another client | Family bound to `client_id`; presented by a different client it is refused and the family revoked |
| User disabled, deprovisioned by SCIM, access removed, role or policy changed, client secret rotated, MFA policy applied, logout, session revoked | The family is an `issued_tokens` row bound to the session, so each existing `UPDATE issued_tokens SET revoked_at` and `revokeSessionsTx` revokes it; refresh also re-runs the `RecordIssuedToken` guard (session live, user active and not ended, enrollment not restricted, effective access, client enabled, policy and role revisions unchanged) |
| Token outlives the login | Family lives no longer than its browser session, the app's absolute refresh lifetime and the app's re-auth deadline (`max_age` policy, factor age, requested `max_age`) |
| Long-idle token revived | Each token expires after the app's refresh idle limit; the session's own idle limit also applies |
| Refresh makes a login look fresher or stronger | Refreshed ID tokens keep the original `auth_time`, `amr`, `acr`; no `nonce` (OIDC Core 12.2) |
| Public client (SPA, native) leaks a token with no secret to protect it | Public clients get no refresh tokens. DPoP (RFC 9449) is feasible with the Go standard library and is the upgrade path when a public client needs refresh; no Ky app is a public client today |
| Restore of an old capsule revives tokens | `issued_tokens` is already cleared by restore; refresh rows cascade and are listed in `restoredCleared` too |

Out of scope: an attacker who holds the app's client secret *and* its refresh token can
use it until the legitimate app's next refresh trips reuse detection. That is the limit
of sender-constraining by client secret.

## Defaults and bounds

| Timer | Default | Bounds | Set by |
|---|---|---|---|
| Session absolute | 24h | 1h – 7d | admin (global), `KYIDENTITY_SESSION_TTL` seeds it |
| Session idle | 8h | 5m – 24h, ≤ absolute | admin (global), `KYIDENTITY_SESSION_IDLE_TTL` seeds it |
| Refresh tokens for an app | off | on only for confidential clients | admin, per app |
| Refresh idle | 1h when enabled | 5m – 24h, ≤ refresh lifetime | admin, per app |
| Refresh lifetime (absolute) | 24h when enabled | 15m – 7d | admin, per app |
| Access token | 15m | fixed | — |
| App re-auth (`max_age` mode, factor age) | none (`reuse`) | existing policy bounds | admin, per app |

Refresh is opt-in per app: an app that never asks for it, and existing installations,
see no change. The global and per-app settings use the existing step-up, revision and
audit paths; any per-app change revokes that app's outstanding tokens, as policy edits
already do.

## How the timers interact

A refresh family is created at code exchange when the app has refresh enabled. It ends at
the earliest of:

- its browser session ending (logout, revocation, absolute or idle expiry, disable);
- the app's refresh lifetime, counted from the code exchange;
- the app's re-auth deadline: the policy's `max_age` and factor age measured from the
  recorded proof times, and any `max_age` the app requested at authorization;
- the end of the user's access (`AccessEndsAt`).

Each refresh must arrive within the app's refresh idle limit of the previous one, and
within the session's idle limit of the session's last activity. A successful refresh
counts as session activity: an app the user is working in keeps their single sign-on
alive for the other apps, so signing in to a second app later does not ask for the
password again, until the session's limits say otherwise.

Step-up is separate from all of this and never extended by refresh. An app needing a
fresh or stronger proof for a sensitive action sends a new authorization request with
`max_age` and/or `acr_values=urn:kysignon:acr:mfa` (or `prompt=login`), then checks
`auth_time` and `acr`/`amr` in the returned ID token against the action. `max_age=N` bounds
the password proof; because a second factor is always verified after the password in the
same login, `acr_values=urn:kysignon:acr:mfa` plus `max_age=N` means "MFA within N
seconds". An administrator can impose the same as an app policy (`max_age` mode, factor
`mfa` or `passkey`, factor age). Step-up results are ordinary new sessions and codes; a
refresh token from an older, weaker login keeps its weaker claims.

```
session  |--------------------- absolute 24h -----------------------|
         |-- idle 8h --|  (each KyIdentity request or refresh resets)
family       |------------ app refresh lifetime -------------| (or re-auth deadline)
refresh      |-1h-| |-1h-| |-1h-| ...  each use within app idle, rotates
access         15m   15m   15m
step-up                       ^ new authorize max_age/acr_values -> new session evidence
```

## Protocol

- Grant `refresh_token` on `POST /oauth/token` with client authentication
  (`client_secret_basic` or `client_secret_post`). `scope` may narrow, never widen.
- Response: new `access_token`, new `refresh_token`, ID token when `openid` was granted.
  The old refresh token is spent, even if the response is lost; the app must store the
  new one before using it. A retried spent token is reuse and ends the family.
- Errors are `invalid_grant` without saying which check failed; reasons go to audit.
- `POST /oauth/revoke` accepts a refresh token (RFC 7009) and revokes its family.
- Discovery adds `grant_types_supported`.
- `offline_access` is not supported: these tokens are bound to the browser session.

## What each Ky product must change

Server-side relying parties (KyPost, KyNotes, KyDrive, KyCalendar, KyMessage, kyPulse,
KyYard, kyrecovery, and `ky_server_base` for its copies):

1. Ask an administrator to enable refresh for the app (or, later, in the setup bundle).
2. Store the refresh token server-side with the app session, never in the browser.
3. Bound the local session by KyIdentity: when the stored access token has expired and
   the user makes a request, refresh. On `invalid_grant`, end the local session and send
   the user through sign-in. Do not refresh on a background timer; refresh is activity.
4. Persist the rotated token before using it; one refresh at a time per session.
5. Keep using the ID token's original `auth_time`/`acr` for step-up decisions; a refreshed
   ID token never satisfies a freshness check it did not satisfy before.
6. For sensitive actions use `max_age`/`acr_values` as above. KyPost and KyNotes already
   do. KyMessage does via `?fresh=1`. KyCalendar's step-up checks only its own session age and
   should send `max_age`. KyYard's step-up requires a local password an SSO-only user does
   not have and should use KyIdentity instead.
7. Back-channel logout remains the fastest signal; refresh bounds the worst case to the
   access-token lifetime for apps without a receiver.

A shared refresh helper belongs in `ky-primitives` beside `oidcverify`, so the products
do not each write their own.

## Issue #77

Root cause, reproduced in `internal/api/sso_bounce_test.go`: the session idle limit (30
minutes) counted only requests to KyIdentity. Apps keep their own sessions and come back
only when the user signs in to another app, by which time the KyIdentity session had
usually gone idle. The prompt was not caused by `prompt`/`max_age` (no app sends them on
ordinary sign-in), cookies or missing refresh tokens. Fix: default idle 8 hours, and
refreshes count as activity once apps adopt them.
