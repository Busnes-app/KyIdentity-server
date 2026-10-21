# Integrations

[Product overview](../README.md) · [Standalone installation](../INSTALL.md)

Commands and unlinked file paths below are relative to the repository root.

## Integration Requirements

These rules are enforced strictly. Each is a constraint on how a client integrates.

**Redirect URIs must match exactly.** There are no host aliases, port families, trailing
slash tolerance, or per-client fallbacks. A client that needs three callback ports
registers three URIs. This is the single control deciding who receives an authorization
code; anything looser makes registration advisory.

**PKCE (`S256`) is mandatory for every client**, public and confidential, and `plain` is
rejected everywhere. A public client presents no secret, so the verifier is the only thing
binding a code to the party that requested it; for a confidential client it stops an
injected authorization code (RFC 9700). A code stored without a challenge never redeems.

**Clients are confidential by default.** Registration issues a client secret unless
`"clientType":"public"` is passed explicitly. A suite server such as KyPost, KyDNS, KyNotes or KyCalendar can hold a secret, so it
should be confidential; `public` exists for SPAs and native apps that genuinely cannot.
A confidential client with an empty `client_secret_hash` is rejected rather than
authenticated by existing.

**Rotate or correct a client in place** with `PUT /api/admin/clients/{id}` —
`{"clientType":"confidential"}` promotes a public client and returns a fresh secret,
`{"rotateSecret":true}` rotates an existing one. The secret appears in that response only.
This exists so a misregistration is recoverable; delete-and-recreate would break the
integration it is meant to secure, which guarantees nobody ever does it.

**Access tokens live 15 minutes** and carry a `jti` recorded server-side.
`POST /oauth/revoke` (RFC 7009, client authentication required) invalidates one;
disabling a user, resetting their MFA, changing their password, or revoking their sessions
invalidates all of theirs. Services that validate tokens offline against JWKS cannot see a
revocation until expiry — call `/oauth/userinfo` where revocation must take effect at once.

**Refresh tokens** are off until an administrator turns them on for an app under
**Authentication** (confidential clients only; a public client has no secret to protect
them). The app then receives a `refresh_token` at code exchange and calls
`POST /oauth/token` with `grant_type=refresh_token` and its client credentials. Each token
works once: the response carries the next one, and presenting a spent token again ends the
whole family and every access token it minted (audited `oauth.refresh_reuse`). A family
lasts no longer than the browser session that signed in, the app's refresh lifetime
(15 minutes to 7 days), its re-authentication ages and the user's access; each token must
be used within the app's refresh idle limit (5 minutes to 24 hours). Logout, session
revocation, disabling the user, SCIM deprovisioning, access or role changes, policy edits
and client-secret rotation end it, as they end access tokens. A refresh counts as session
activity, so a user working in one app stays signed in for the others. Refreshed ID tokens
keep the original `auth_time`, `amr` and `acr` and carry no `nonce`; `scope` may narrow but
never widen. Tokens are stored hashed. `POST /oauth/revoke` accepts a refresh token and
ends its family. Design and threat model: `docs/refresh-tokens-and-reauth.md`.

**Sessions.** A browser session lasts 24 hours and ends after 8 hours with no request to
KyIdentity. Apps keep their own sessions and come back only to sign in or refresh, so that
is the activity that counts; a short idle limit asks for the password at nearly every app
sign-in. Administrators change both under **Sign-in policies → Sign-in sessions**
(`GET`/`PUT /api/admin/session-settings`, `{absolute, idle}` in seconds, step-up, audited
`admin.session_limits_configured`): lifetime 1 hour to 7 days, idle 5 minutes to 24 hours
and no longer than the lifetime. Saving ends, for good, every session beyond the stricter
of the old and new limits, with its tokens and refresh families, and queues back-channel
logout for them (`sessionsEnded` in the audit row), so relaxing the limits later revives
nothing; a longer limit never extends a session past the expiry it was given.
`KYIDENTITY_SESSION_TTL` and `KYIDENTITY_SESSION_IDLE_TTL` seed the values until an
administrator saves them, and startup refuses values outside the same bounds.

**Step-up for sensitive actions** is standard OIDC. The app sends a new authorization
request with `acr_values=urn:kysignon:acr:mfa` and `max_age=N` (or `prompt=login`), then
checks the ID token: `auth_time` within N seconds and `acr` `urn:kysignon:acr:mfa` means
the user proved their password and a second factor within N seconds, because the factor
is always verified after the password in the same sign-in. With `prompt=none` an
insufficient sign-in answers `login_required` instead of showing a page. Refresh never
updates `auth_time` or `acr`, so a refreshed ID token cannot pass a step-up check its
sign-in did not. An administrator can impose the same per app (Authentication: maximum
password age, required factor and its age). Security and devices lists where an account is signed in: each live browser
session with its address, browser, sign-in and last-activity times, expiry and the factor
used, plus the apps currently holding access tokens. `GET /api/user/sessions`,
`DELETE /api/user/sessions/{id}` and `POST /api/user/sessions/revoke-others` act on the
caller's own account; revoking the current session also clears its cookies. Administrators
use `GET /api/admin/users/{id}/sessions`, `DELETE /api/admin/users/{id}/sessions/{sid}` and
`POST /api/admin/users/{id}/apps/{clientId}/revoke` (revoke one app's tokens and pending
codes while the browser session survives). Revoking a session removes its authorization
codes, tokens, step-up grants and pending authorization interactions in the same
transaction as the audit event. These routes need CSRF but no step-up, like the emergency
button. The app list is derived from issued tokens: it shows which apps can still call
KyIdentity, not whether the app's own login is alive. The "Sign-out notifications" list
below it shows, per app, whether the back-channel logout for an ended login is pending,
acknowledged or failed; apps without a receiver never appear there.

**RP-initiated logout.** Discovery advertises `end_session_endpoint` at `/oauth/logout`
([OpenID Connect RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)).
Every ID token carries a `sid`: an opaque value minted per client and login, so two apps
cannot correlate a user's sessions through it and no app learns the internal session ID.
An app sends the browser to `/oauth/logout` with `id_token_hint`, optionally `client_id`,
`post_logout_redirect_uri` and `state` (GET or POST). A hint this server signed for that
client whose `sid` names the session held in this browser ends it at once. Without such a
hint, or with a hint for another user or another login of the same user, KyIdentity shows a
confirmation page whose form carries a session-bound token; a cross-site POST cannot
confirm on the user's behalf. A cross-site POST carries no session cookie (`SameSite=Lax`),
so it is answered with a 303 to the same request as a top-level GET on this origin rather
than reported as a sign-out.
`post_logout_redirect_uri` must match one of the client's registered post-logout URIs
exactly (register them on the client, https or loopback http only); anything else is a 400
page and nothing is changed, never a redirect. `state` is echoed on the redirect. Expired
hints are accepted, forged or foreign-issuer hints are not. Ending the session revokes its
codes, tokens, step-up grants and pending interactions in the same audited transaction as
the browser logout button.

**Back-channel logout.** Discovery advertises `backchannel_logout_supported` and
`backchannel_logout_session_supported`
([OpenID Connect Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html)).
A client may register one back-channel logout URI (public HTTPS, same guard as
provisioning callbacks). Whenever a login ends, whether by the logout button, RP-initiated
logout, "sign out other sessions", an administrator revoking a session or an app's tokens,
or an account being disabled, KyIdentity queues one delivery per client that saw that login
and has a receiver, in the same transaction as the revocation. A worker POSTs
`logout_token=<JWT>` as a form body with no redirects followed, a ten-second timeout and a
fresh token per attempt; 200 or 204 acknowledges, anything else retries with exponential
backoff (30 s doubling, 30 min cap) up to five attempts, then the delivery is marked failed.
Administrators see each delivery in the user's Sessions modal and can retry a stuck one,
which restores the attempt budget; the retry is audited as `admin.logout_retry`. Only
administrators see the transport error text, since it can name the receiver's host.
Deliveries run on four workers with at most one in flight per client, so a receiver that
never answers delays only its own queue. Delivered rows are pruned after seven days; a failed delivery stays until it succeeds
or an administrator retries it, because its absence would read as success.
A session that reaches its idle or absolute limit is dropped without a logout token:
expiry is not a sign-out action, and apps rely on their own session lifetimes for it.

The logout token is an RS256 JWT with header `typ: logout+jwt` and claims `iss`, `aud`
(the client ID), `sub`, `sid` (the client-scoped session ID from the ID token), `iat`,
`exp` (two minutes), `jti` and `events` containing
`http://schemas.openid.net/event/backchannel-logout`. It never carries `nonce` or
`token_use`, and this server rejects it as an ID token hint and as an access token. A
receiver must verify the signature against the JWKS, the issuer, that `aud` is its client
ID, that `typ` is `logout+jwt`, that the events claim is present and `nonce` absent, and
reject a `jti` it has already seen; it should then end every local session tied to that
`sid` (or to `sub` when it keys sessions by subject) and answer 200 with `Cache-Control:
no-store`. An acknowledgement means the receiver accepted the token, not that it proved it
ended a session; "Acknowledged" in the UI carries exactly that meaning. Subject-wide logout
(a token with `sub` and no `sid`) is not sent by this server today: every delivery names one
login.

**Authorization re-authentication (PR05a).** Ordinary requests reuse SSO. Following
[OpenID Connect authentication requests](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest),
`prompt=login` and `max_age=0` require a new password and any enrolled second factor
for each authorization request. A positive `max_age` (whole seconds, at most
2147483647) limits password age at authorization and again when the code is exchanged.
`prompt=none` never opens a login screen; missing or insufficient authentication returns
`login_required` to the validated redirect URI with the original state.

`acr_values` supports `urn:kysignon:acr:password` and `urn:kysignon:acr:mfa`.
The first value is the requested minimum; MFA can satisfy password assurance.
Recovery codes do not satisfy MFA. Unsupported values, unsupported prompt modes,
combined prompts, duplicate parameters, malformed ages, and alternate `request`,
`request_uri`, or `claims` inputs return `invalid_request`. Discovery advertises the
two supported request classes. Administrator passkey requirements strengthen either class
without changing the documented ID-token claim values.

Interactive login uses the existing password, TOTP, push, passkey and recovery screens.
A five-minute, single-use interaction binds the original validated request (including
client, redirect, scope, PKCE, nonce and state) to a signed HttpOnly browser cookie and the
resulting login session. A signed-in user must re-authenticate as that same account.
Up to ten interactions can be outstanding per browser and per account, with a server-wide
cap of 10000. Completing an anonymous login assigns its interaction to that account and
enforces the same bound. Upgrade and capacity recovery trim pre-existing account overages
to ten requests, preferring completed proofs; affected requests must restart authorization.
Expired interactions are cleaned on creation. At capacity, only the oldest anonymous,
unfinished interactions are evicted; account-bound requests and completed proofs are
preserved within the account bound. Every authorization request spends an IP allowance
of 300 requests with five requests/second refill. Browser identities never allocate
rate-limit buckets, so rotating cookies cannot reset the source allowance or fill the
shared limiter map. The separate interaction caps still apply per browser and account.
Throttling uses `temporarily_unavailable` after validating the redirect URI; database
failures use `server_error`. A different tab's login cannot satisfy
another interaction; if the browser's session changes, restart from the app. Cancel
sign-in burns the interaction and returns to the dashboard. If password/MFA verification
has already completed when its interaction expires or is cancelled, the valid login is
preserved and the UI asks the user to restart from the application. The new session
cannot resume the cancelled request; a spent recovery code still bought a valid login.
Concurrent completion and
cancellation serialize at the database; a code already issued cannot be recalled by
cancelling the former interaction. Administrative step-up grants are never accepted.

Choose **App connections → Authentication** on an OAuth app to configure:

- **Reuse SSO**, **Maximum password age**, or **Fresh sign-in every authorization**.
- Password with existing enrollment rules, mandatory ordinary MFA, or password plus
  passkey. Recovery never meets mandatory MFA; TOTP and push cannot meet passkey policy.
- An independent maximum second-factor age. Zero means no additional factor age limit;
  positive ages are whole seconds up to 2147483647. Expired evidence uses the existing
  full password/second-factor flow, with each proof retaining its actual verification time.

Client requests can strengthen these settings but cannot weaken them. Silent requests
with insufficient evidence return `login_required`. An account missing a required factor
receives an enrollment explanation after password verification; sign in normally to the
account dashboard to enroll before restarting from the app. A passkey here means a
verified WebAuthn second factor, not a guarantee about hardware or device-local storage.
Existing apps default to reuse SSO with existing enrollment rules; legacy unknown proof
can still reuse ordinary SSO but cannot satisfy freshness, mandatory MFA or passkey policy.

`PUT /api/admin/app-registry/{id}/authentication-policy` accepts `revision` (the app's
current revision) and `policy`: `mode` (`reuse`, `max_age`, `fresh`), `primaryMaxAge`,
`factor` (`password`, `mfa`, `passkey`), and `factorMaxAge`. Maximum-age mode requires a
positive primary age; other modes require zero. Password-only requirements require zero
factor age. The route requires an OAuth connection, administrator rights, CSRF and
operation-bound step-up. Lists expose `authentication` and `authenticationRevision`.

Every actual policy change increments its policy revision and atomically cancels that
client's pending/completed interactions, deletes pending/spent codes, revokes registered
tokens, and records the audit. Even a relaxation invalidates old grants; reverting a
policy never revives them. Code creation rechecks current policy in its transaction;
token registration checks the app identity, policy revision and the earliest password or
factor deadline atomically. Other apps and the central login session remain usable.
Offline JWT consumers may accept a token for up to 15 minutes, and destination app cookies
may last longer; these settings apply when an app initiates OAuth authorization.
Launcher visibility and provisioning scope remain governed by their existing controls.
On first upgrade, old pending codes and interactions restart without deleting existing
sessions or already-issued tokens. Subsequent startups preserve live requests.

**Required MFA enrollment.** Administrators can preview and apply organization
and administrator requirements under **Sign-in policies**, and each group's requirement
under **Groups → MFA policy**. Allowed TOTP, signed push and passkey methods intersect
across every applicable policy. Grace is 0–90 days; each user's scope
obligation stores an epoch-second deadline when it first applies, including account
creation, promotion and group membership. The earliest applicable deadline wins. Logins,
longer grace, disabling/re-enabling a policy and removing/re-adding membership never
extend an existing deadline. Deleting a group with an MFA requirement checks compliant
administrator login evidence as well as step-up, then deletes its policy and obligations;
a newly created group has a new identity and starts without an MFA requirement.

Unenrolled users may continue during grace, subject to stricter app policies. Users with
a permitted factor must sign in with it immediately. At the deadline, password-only
sign-in produces an enrollment-only session only for accounts with no enrolled factor.
An existing factor still has to be verified even when policy no longer permits it.
Pairing a new approver phone requires operation-bound step-up, including during enrollment. Recovery sign-in is also restricted when
MFA is required. Such sessions can inspect identity/factors, obtain operation-bound
factor-enrollment grants, enroll and sign out; they cannot access applications, admin
APIs, OAuth codes or online tokens. Completing enrollment does not upgrade that session:
sign out and sign in with password plus a permitted factor. There is no background
heartbeat keeping idle sessions alive; the server checks every authenticated request.

Applying policy requires operation-bound step-up and, whenever the administrator is
covered by the resulting policy, an actual permitted MFA login within five minutes.
Step-up cannot replace that login evidence. The preview and application use the same
transactional rules; revisions prevent stale writes. Applying cancels all outstanding
OAuth sign-ins and revokes registered tokens with its audit event. Online token checks
also enforce deadlines at use time; offline JWTs may remain valid for up to 15 minutes,
and destination app sessions can outlive them. Changing membership in an MFA-required group cancels that user's outstanding OAuth
interactions/codes and revokes registered tokens, even when the change relaxes policy.
An actual membership change requires a current administrator session; if that account
is subject to MFA, its permitted login proof must be within five minutes. Conflicting
factor intersections reject the entire membership or policy transaction. Promotion to
administrator also rejects conflicting requirements. Group previews summarize all applicable requirements for that group's members;
organization/admin previews summarize the directory.
Removing the last compliant factor is
rejected atomically, including concurrent device/passkey removals. Administrator MFA
reset remains available, revokes sessions and ends any remaining enrollment grace.

**Authentication claims describe the login that established the session.** `auth_time`
is the time the password was verified (for device sign-on, the time the device assertion
was verified), preserved across later SSO redirects. The second
factor's verification time is recorded separately; completing MFA or issuing a token
does not refresh the password's age. ID tokens expose these method/context values:

| Login | `amr` | `acr` |
|---|---|---|
| Password | `pwd` | `urn:kysignon:acr:password` |
| Password + TOTP | `pwd`, `otp`, `mfa` | `urn:kysignon:acr:mfa` |
| Password + signed push | `pwd`, `urn:kysignon:amr:push`, `mfa` | `urn:kysignon:acr:mfa` |
| Password + passkey | `pwd`, `urn:kysignon:amr:webauthn`, `mfa` | `urn:kysignon:acr:mfa` |
| Password + recovery code | `pwd`, `urn:kysignon:amr:recovery` | `urn:kysignon:acr:recovery` |
| Paired device key, unattested or App Attest (iOS) (device sign-on, single factor) | `pop` | `urn:kysignon:acr:device` |
| Paired device key, hardware-attested (TEE or StrongBox) | `hwk`, `user`, `mfa` | `urn:kysignon:acr:mfa` |

A device sign-on ID token also carries `signon_method: device`, `device_id`, and `origin`:
the `https://host[:port]` of the relay address the user typed into the consumer app (KyPost),
which the device signed and KyIdentity matched against the origins of the client's registered
redirect URIs. Register every public origin a consumer server is reached on (its browser SSO
redirect URI already does this); a relay on any other origin is refused. The binding is per
origin (scheme, host, port): relays sharing an origin with different paths are one trust
domain. Each consumer server accepts only its own configured base-URL origin, so registering
extra aliases at KyIdentity does not widen what a consumer accepts.

An attested device's ID token also carries `attested: tee|strongbox`. At pairing,
KyAuth Android uploads its Android Key Attestation chain; KyIdentity verifies it and grades the
device `none`, `tee` or `strongbox`. KyAuth iOS uploads an App Attest object instead, graded
`appattest` or `none` (below). Pairing never fails because of attestation, but only `tee` and
`strongbox` devices earn MFA-grade sign-on; `none` and `appattest` stay single factor. Configuration:

- `KYIDENTITY_ATTESTATION_STATUS_URL`: Google's revocation status list (default Google's; empty
  disables the check and logs a startup warning).
- `KYIDENTITY_ATTESTATION_EXTRA_ROOTS`: extra PEM trust roots, added to Google's.
- `KYIDENTITY_KYAUTH_CERT_SHA256`: comma-separated SHA-256 digests of accepted KyAuth signing
  certificates. The default accepts the release key (GitHub builds) and Play's three signing keys
  (`DefaultKyAuthCertSHA256` in `internal/config/config.go`). Setting it replaces the default, so
  repeat any default digest you still want; this is how to add an F-Droid build's key.
- Admin setting `attestation.requireLockedBootloader` (Enrollment policies, "Device sign-on";
  default off): refuse, and daily downgrade, devices whose bootloader is unlocked. The boot state
  is recorded either way.

iOS App Attest (`internal/appattest`, contract `2026-10-11-ios-app-attest.md` in [KyAuth-iOS specs](https://github.com/Busnes-app/KyAuth-iOS/tree/master/docs/specs)):
graded only for `platform: "ios"` with an `appAttest {keyId, attestation}` field; Android chains
are graded only for `platform: "android"`. The object must chain to the embedded, fingerprint-pinned
Apple App Attestation Root CA at the current time, carry the nonce
`SHA256(authData || SHA256("kyidentity-appattest-v1|" + credential + "|" + publicKey))`, match the
`keyId`, a configured App ID, sign count 0 and the accepted AAGUID. This proves a genuine KyAuth
build on a genuine Apple device, not that the signing key lives in the Secure Enclave or needs
user presence, so it is a level of its own and grades as one possession factor: an iOS device
signs on only to apps whose policy is `reuse` + `password` for users without mandatory MFA. A pass is `appattest` with boot state `unknown`; the daily sweep skips these devices
(no serials, no boot state). Failures grade `none` with the reason in the log and audit row only.

- `KYIDENTITY_APPATTEST_APP_IDS`: comma-separated `<TeamID>.<bundleID>`. Unset, it defaults to KyAuth
  iOS (`TATYN4X57D.org.kysecurity.authenticator`, `DefaultAppAttestAppIDs`); setting it replaces the
  default; set but empty disables grading and logs it at startup.
- `KYIDENTITY_APPATTEST_ALLOW_DEVELOPMENT`: `true` also accepts the development App Attest
  environment (debug and sandbox builds). Default `false`; anything but `true`/`false` refuses startup.

The roots and status list are refreshed whenever the list goes stale (a failed fetch retries within
15 minutes; redirects are refused, and a newly published root is logged), and a daily sweep
downgrades devices whose key was revoked.
Audit actions: `device.attestation_downgraded`, `admin.attestation_configured`; `device.registered`
records `attestedLevel`, `bootState` and `attestationReason`. Emulators ship software KeyMint and always grade `none`, so the `tee`/`strongbox` path has not
been verified on hardware yet; pair a physical phone to confirm. Likewise the `appattest` path is
tested only against a generated CA; the simulator has no App Attest.

These are KyIdentity context classes, not NIST assurance levels. Only `hwk` from a verified
attestation asserts a hardware-backed key. Recovery does not claim ordinary MFA. The standard method names
follow [RFC 8176](https://www.rfc-editor.org/rfc/rfc8176.html); the URNs are local contracts.
Administrator per-app freshness policies are implemented as described above; further work
is tracked in [the access lifecycle plan](access-lifecycle-plan.md).

Existing sessions survive the upgrade but omit `auth_time`, `amr` and `acr` until a new
login supplies evidence. Pending legacy authorization codes and MFA flows are invalidated;
users in those flows restart login. New codes and access tokens bind internally to the
originating session: removing it blocks exchange and online UserInfo access. Already-issued
legacy access tokens retain their previous expiry/revocation behavior. Internal session IDs
are listed to their owner and administrators for revocation; ID tokens publish a separate
per-client `sid` for RP-initiated and back-channel logout.

**System pairing requires the PIN** shown next to the token, and callback URLs must be
`https` and resolve off-network. `KYIDENTITY_ALLOW_PRIVATE_CALLBACKS=true` admits http and
private LAN ranges (RFC 1918, ULA, carrier-grade NAT), as services on `kypost-net` need; it is
off by default and never admits loopback, link-local or cloud metadata addresses.
Sync events are queued per paired system; a system only receives what was queued for it.

**Device pairing requires a P-256 public key.** A device without one can never approve a
push, and pairing it previously enrolled push MFA that no response could satisfy.
Five wrong pairing PINs for one account expire all of its live pairing tokens; generate a
new code to try again. A paired phone signs in to suite apps only when the pairing request
sent `signOn: true` (the web UI sends the checkbox value); an omitted field means no.
Removing a phone or changing whether it approves MFA or signs in spends a step-up grant.
Push stays offered at sign-in only while some approver phone with a key remains.

**`TRUSTED_PROXY_CIDRS` defaults to empty.** Forwarding headers are ignored unless the
immediate peer is a CIDR you named. Set it to your proxy's address and nothing wider: every
host inside a listed range can choose its own rate-limit bucket and its own entry in your
audit log.
IPv6 clients share one rate-limit bucket per /64, since one subscriber usually holds the
whole prefix; the audit log keeps the full address.

**`KYIDENTITY_FORWARDED_HEADER` names the one header that is believed, defaulting to
`X-Forwarded-For`.** Behind Cloudflare, set it to `CF-Connecting-IP`. Exactly one header is
honoured per deployment because trying several in turn means whichever one your edge does
*not* overwrite is the one an attacker gets to choose. The value must parse as an IP
address, and the chain is walked from the right past hops inside `TRUSTED_PROXY_CIDRS`, so a
client-supplied entry prepended to the list is never attributed.

**Backups are sealed to the suite recovery key and this server never holds what opens
them.** The key arrives by pairing with KyRecovery, or is pasted from the ceremony page on
the Disaster recovery screen for a server with no KyRecovery. Every capsule is sealed to it
and goes to each configured destination: KyRecovery when paired, and `KYIDENTITY_BACKUP_DIR`
when set. Files there are named `<KYIDENTITY_APP_NAME>-<capsule-id>.kycap`; the newest
`KYIDENTITY_BACKUP_KEEP` (default 7) with that prefix are kept and anything else in the
directory is never listed or deleted. The schedule is set on
the same screen; `KYIDENTITY_BACKUP_DEPOSIT_INTERVAL` (default 24h, 15m floor, `0` disables)
is only the default until an admin picks one. Custodian cards come from the KyRecovery
ceremony, and a restore is `kyidentity restore -capsule <file.kycap> -to <dir> -expect-digest
<sha256>` with k shares typed on stdin. The digest is required because the recovery key is
public: anyone who can write `KYIDENTITY_BACKUP_DIR` can seal a capsule the shares open, and
only the digest from KyRecovery's deposit record (or printed by `export-capsule`) tells this
server's capsules apart. A local-only deployment should keep those digests off the server.
A server with no key pinned can run drills but cannot make a capsule.

**KyRecovery must be reached over HTTPS, and by default at a public address.** TLS is not
for the capsule, which is sealed anyway; it protects the recovery public key that arrives at
pairing (trust on first use), the deposit token, and the receipts. For a KyRecovery on your
own network behind a TLS proxy, set `KYIDENTITY_BACKUP_ALLOW_PRIVATE_RECOVERY=true`; HTTPS is
still required, the choice is recorded on every pairing, and loopback stays refused. Either
way, pin the key by hand from the ceremony page before pairing, or compare the key ID the
screen shows with the fingerprint in the KyRecovery dashboard; a swapped key then fails
loudly. In Docker, a name that exists only on your LAN may not resolve inside the container when the
host uses a loopback stub resolver; append `docker-compose.lan-dns.yml` to `COMPOSE_FILE` in
`.env` (see the file's header) and recreate with `KYIDENTITY_DNS` set to your LAN's resolver. It replaces the host's resolvers for every lookup
the container makes, which is why it is an override and not the default.

**Passkeys are bound to the issuer's origin.** The relying party ID is the hostname of
`KYIDENTITY_ISSUER_URL` and the accepted origin is its scheme, host and port. Changing the
issuer URL invalidates every enrolled passkey, because the browser will not offer a
credential registered under a different RP ID. Browsers permit WebAuthn over plain HTTP only
on `localhost`, so a deployment reached by IP or by a name without TLS cannot enrol one.

**Enrolling or removing a passkey spends a step-up grant**, like every other change to an
account's factors. Resetting a user's MFA deletes their passkeys along with their TOTP
secret and recovery codes. Step-up requires your password plus an enrolled TOTP, push,
or passkey factor whenever any factor is enrolled. Recovery codes authorize only
enrolling a replacement TOTP or passkey; the recovery grant cannot directly authorize
administrative actions, factor deletion, or the standalone recovery-code regeneration
endpoint. TOTP enrollment itself reissues recovery codes and signs out other sessions.
A newly enrolled factor can authorize subsequent step-up operations.

Grants last at most five minutes, are single-use, and bind to the current session and
the exact HTTP method and target path. Enrollment preparation shares the grant with
its final enrollment request. Push and passkey step-up challenges are separate from
login challenges. Challenge issuance has a distinct `auth.step_up_challenge` audit event;
locked-account and missing-factor denials remain visible in `auth.step_up` events.
Dismissing the shared prompt aborts the action and cancels any pending challenge or late grant; it does not refresh the session's OIDC authentication evidence.
Upgrading invalidates old, unscoped step-up grants, so an open confirmation must restart.

**Destructive admin operations require step-up re-authentication.** Creating or editing an
account, resetting someone's MFA, deleting a user, registering or deleting an OAuth client,
connecting or removing a paired system, and exporting, pairing, unpairing, pinning a key,
running or rescheduling a backup each
spend a single-use grant that costs your password and an enrolled factor. A stolen session
cookie cannot produce one. Read-only views and the emergency "revoke sessions" button stay
on the session alone, so locking an account down during an incident is not slowed by a
second prompt.

**`KYIDENTITY_SECRET_KEY` and `KYIDENTITY_ENCRYPTION_KEY` must be exactly 64 hex characters.**
A malformed value is a startup error, never a silently weakened key. Generate with
`openssl rand -hex 32`. Left unset, they are generated into the data directory and reused.

---
