# Changelog

## 0.4.7 — 2026-10-22

### Upgrading

- `KYIDENTITY_APPATTEST_APP_IDS` now defaults to KyAuth iOS when unset, as the Android signing digests already did; set it empty to turn App Attest grading off.
- The first start marks pending outbox work that earlier versions left at its attempt budget as failed, so the reconcile pass re-queues it while it is current. Pending removals stay pending.

### Changes

- Security: removals to any connector are never given up. An inactive `user.updated`, `user.deleted` or `group.deleted` retries with backoff capped at 30 minutes between attempts until the receiver accepts it, so a receiver that was down for hours still gets the removal once it is back, with no administrator step. A re-grant still supersedes it. Creates and updates keep the five-attempt budget and are re-queued every 30 minutes while current, for suite webhooks as well as generic SCIM.
- Security: a removal whose answer was lost is resent rather than blocked. A removal queued behind a create or update with an unknown outcome still waits for the operator, even past its recovery time, because that write could land after the removal and restore access. A removal goes ahead of an undelivered MFA reset for that connector, and the reset is still sent after it.
- The provisioning alert now also opens while a removal is retrying past five attempts or an attempt is blocked past its recovery time, even if other deliveries to that connector succeed. **Suite sync → Deliveries** lists given-up work and retrying removals under **Failing deliveries** (`GET /api/admin/systems/{id}/deliveries/failing`).
- `resync-system --wait`: `failed` now means a create or update given up after five attempts, or a write blocked with an uncertain outcome. Removals never count as failed; one to a receiver that stays down ends in `timeout` and is delivered later on its own.
- A Retry-After from a SCIM target now delays the next attempt by at most 30 minutes.
- Repair re-provisions a SCIM target that was wiped behind KyIdentity's back: a stored remote ID that a complete listing does not hold is relinked by externalId or dropped, so the user or group is created again.
- The access-denied page tells a user without access to ask an administrator and names KyIdentity.
- Launcher tiles keep icon, name and arrow on one line with descriptions capped at two lines; paired phone rows are tidier.

## 0.4.6 — 2026-10-21

### Upgrading

- Removals that earlier versions dropped this way left no record, so a resync cannot replay them. If someone was disabled or unassigned right after being given access, check that app's account for them.
- The first start flags an existing bootstrap administrator still on its first password; its next sign-in must choose a new one (audit `system.password_change_required`). Nothing is reset and no one is locked out. See [Given passwords](docs/ACCOUNTS-AND-ACCESS.md#onboarding-and-passwords).

### Changes

- Security: the bootstrap administrator, and any account whose password an administrator set, must choose a new password at the next sign-in. Until then the session can only read itself, step up, change the password, enroll a replacement factor or sign out; other APIs answer `403 password_change_required`, `/oauth/authorize` returns `interaction_required` and no app token is issued. The web UI shows a **Choose a new password** screen. The change clears the flag, ends every other session and is audited as `user.password_changed` with `required: true`.
- Security: removing a person (disable, unassign, deletion) before KyIdentity has delivered their account to a directory connector now sends the removal instead of dropping it with the undelivered create. The downstream app may already know the person from its own setup or a sign-in, so it now hears the removal whether the create was pending, retrying or failed. Generic SCIM deactivates a matching account and creates nothing; suite webhooks receive the usual inactive `user.updated`. **Resync** and `resync-system` replay these removals too. A later re-assignment sends a fresh create. Accounts and content are never deleted.
- Audit: `auth.password_reset` and `auth.account_activated` rows now name the account; they were committed with an empty actor and target. `admin.user_updated` records `passwordSet`.

## 0.4.5 — 2026-10-20

### Changes

- `apply-setup` creates the setup's `admin` and `everyday` accounts with a verified email: the installer owns them and took the addresses from the owner's plan, so apps that require `email_verified=true` (Matrix MAS, Mealie) accept them without a mailed link. An ordinary rerun verifies an owned account still at its declared address, so accounts applied by 0.4.4 or earlier gain it (audit `installer.email_verified`). Changing an address still clears verification, and a rerun refuses the changed account. Advertised as capability `installer-verified-email`. See [Verified owner email](docs/INSTALLER-SETUP.md#verified-owner-email).
- A setup bundle can configure the SMTP relay with `mail` (`host`, `port`, `security` `starttls`/`tls`, `from`, optional `username` with `passwordFile`). The password comes from a destination-issued protected file, is sealed with the existing product key like the admin UI's; nothing derived from it enters arguments, reports or the preparation receipt. Setup refuses relay settings it does not own and later drift; UI changes still need step-up. With a relay, an unattended run can mail and redeem a verification link. Advertised as capability `mail-relay`. See [Mail relay](docs/INSTALLER-SETUP.md#mail-relay).

## 0.4.4 — 2026-10-19

### Changes

- Security: **Resync** now replays removals. It re-sends an inactive update for every account the connector held or holds through a remote ID mapping and has since been disabled, unassigned or deleted, so a downstream app restored from a backup taken before the removal loses the account again instead of readmitting it. Replays deactivate, never delete, and a repeated resync queues nothing extra. A later re-assignment is re-sent as active, as before.
- Add `kyidentity resync-system --client <client id> [--wait <duration>]` so an installer can replay a connector's directory state from inside the container after a downstream app restores a backup, without an admin session. It audits `admin.system_resynced` as `kyidentity-cli`; with `--wait` it exits 0 only once the connector's outbox is delivered, and prints one `kyidentity.resync-system/1` JSON result. Advertised as capability `resync-system`. See [Resyncing after a downstream restore](docs/INSTALLER-SETUP.md#resyncing-after-a-downstream-restore).

## 0.4.3 — 2026-10-18

### Upgrading from 0.4.2

- Browser sessions now end after 8 idle hours, not 30 minutes. A value in `.env` is kept; set `KYIDENTITY_SESSION_IDLE_TTL=30m` to keep the old limit.
- Startup refuses `KYIDENTITY_SESSION_TTL` outside 1 hour to 7 days and `KYIDENTITY_SESSION_IDLE_TTL` outside 5 minutes to 24 hours. Check `.env` before upgrading.
- `KYIDENTITY_SESSION_TTL` and `KYIDENTITY_SESSION_IDLE_TTL` now only seed the session limits. Once an administrator saves them under **Sign-in policies**, the environment is ignored.
- Refresh tokens stay off for every app until an administrator turns them on. Before turning them on, check the app stores the new `refresh_token` from every refresh response and never sends one twice: a reused token, including a concurrent refresh or a retry after a lost response, revokes the family and every access token it minted, and the user signs in again. Refresh also stops when the user's KyIdentity browser session ends.
- Installers: `apply-setup --export-client` refuses once the setup's administrator has been renamed, disabled or is no longer an administrator.
- The **MFA policies** page is now **Sign-in policies**.

### Changes

- `apply-setup` accepts setup amendments: a bundle with `"extends": "<parent setupId>"` and only `clients` adds OIDC clients to an applied setup without touching its accounts. The parent's owned accounts must pass inspection; existing client IDs are refused. Advertised as capability `setup-amendments`. See [Adding clients later](docs/INSTALLER-SETUP.md#adding-clients-later).
- Add `kyidentity disable-user --username U --require-active-admin G` to retire an account from inside the container without a step-up grant, such as the bootstrap administrator after setup. It runs the administrator disable transaction (sessions, tokens, app access, connector inactive state, `admin.user_updated` audit as `kyidentity-cli`) and refuses unless G is a different active administrator with no end date. An upstream-owned account gets the local override; a pending invitation's activation link is expired. Removes `first-run-password.txt` when it names U. Advertised as capability `disable-user`. See [Retiring the bootstrap administrator](docs/INSTALLER-SETUP.md#retiring-the-bootstrap-administrator).
- Security: an activation or reset link redeemed while a revocation of it was committing (a disable, a password or email change, a newer link) could pass the expiry that revocation set and reactivate the account. Redemption now checks expiry under the write lock.
- Security: `apply-setup --export-client` reads the setup's administrator by ID from its ownership record and refuses unless it keeps the owned username and is an active administrator. It looked the username up again, so a rename in between could bind the client to another account, and a deleted account crashed the export.
- Single sign-on across apps: the default session idle limit is 8 hours (was 30 minutes); the lifetime stays 24 hours. Apps return to KyIdentity only to sign in, so 30 minutes asked for the password at almost every sign-in to a second app (#77).
- Administrators set the browser session lifetime (1 hour to 7 days) and idle limit (5 minutes to 24 hours, no longer than the lifetime) under **Sign-in policies → Sign-in sessions** (`GET`/`PUT /api/admin/session-settings`), with step-up and audit `admin.session_limits_configured`. A shorter limit ends the sessions beyond it, with their tokens, refresh families and back-channel logouts, and relaxing it later revives none. A longer limit extends no existing session.
- Add rotating refresh tokens for confidential clients, turned on per app in its authentication policy (idle 5 minutes to 24 hours, lifetime 15 minutes to 7 days; off by default, refused for public clients). Each token works once; a reused token, or one presented by another client, revokes the family and every access token it minted (audit `oauth.refresh_reuse`). A family never outlives its browser session, the app's re-authentication ages or the user's access; logout, disable, SCIM deprovisioning, access, role and policy changes, secret rotation and restore end it. Each refresh counts as session activity. Refreshed ID tokens keep the original `auth_time`, `amr` and `acr`; scope may only narrow. `POST /oauth/revoke` accepts a refresh token. Discovery adds `grant_types_supported`. See [the design](docs/refresh-tokens-and-reauth.md).
- Document OIDC step-up for sensitive app actions: `acr_values=urn:kysignon:acr:mfa` with `max_age=N` admits only an MFA sign-in within N seconds, and `prompt=none` answers `login_required`. Now covered by a test.
- The documented image verification in `docker-compose.yml` and `docs/RESTORE.md` now accepts the `release-image.yml` signer at the version tag, so `:X.Y.Z` and `:stable` images verify. It accepted only the `ci.yml` signer.
- Dependencies: Go image 1.27.2, `golang.org/x/crypto` 0.58.0, React 19.3.1, lucide-react 1.57.0, vitest 5.0.4, wrangler 4.151.0, Scorecard action 2.5.0.

## 0.4.2 — 2026-10-16

### Upgrading from 0.4.x

- Pairing clients that call `POST /api/user/devices/pairing-token` directly: send `signOn: true` for phones that should sign in to apps. The web UI already does.
- If paired systems call back over `kypost-net`, a LAN or a tailnet, set `KYIDENTITY_ALLOW_PRIVATE_CALLBACKS=true` in `.env`; compose no longer turns it on. Callbacks to loopback, link-local or metadata addresses are refused regardless and must move.
- Inbound SCIM: a connector that renames or re-addresses a locally made administrator or delegated account now gets `409 mutability`. Change those accounts in KyIdentity instead.
- Push token refresh v1 is refused. Update authenticator apps that still send v1.
- Users with an unverified email no longer get forgot-password mail; an administrator sends them a reset link.

### Changes

- Five wrong pairing PINs for an account now expire all its live pairing tokens. IPv6 clients share one rate-limit bucket per /64.
- `POST /api/user/devices/pairing-token` without `signOn` now pairs a phone that cannot sign in to apps (was: can). Clients wanting sign-on must send `signOn: true`; the web UI already does.
- Removing a phone, and changing whether it approves MFA or signs in, now spend a step-up grant and are audited atomically. Deleting or changing an unknown device answers 404.
- Security: the compose file no longer turns on `KYIDENTITY_ALLOW_PRIVATE_CALLBACKS`. Set it to `true` if paired systems call back over `kypost-net`. It now opens only private LAN ranges (RFC 1918, ULA, carrier-grade NAT). Loopback, link-local and cloud metadata addresses are refused regardless. Device-supplied UnifiedPush endpoints never get it, so a self-hosted distributor has to be reachable at a public address.
- Security: forgot-password mails a reset only to a verified address. An address is verified when a link mailed to it is redeemed. For an account whose address was never verified, an administrator can send a reset link by email.
- Security: an inbound SCIM connector can no longer change the username or email of an account that was made an administrator or given a delegation locally (409 `mutability`).
- Pair Linux authenticators (`platform: "linux"`). A Linux device uses UnifiedPush or the new `ubuntupush` transport (Ubuntu Touch, via the UBports push service, `KYIDENTITY_UBUNTU_PUSH_URL`/`KYIDENTITY_UBUNTU_PUSH_APPID`); FCM is refused for it. `ubuntupush` payloads are RFC 8291 encrypted like UnifiedPush. Existing databases are migrated in place to accept the new platform and transport.
- Add UnifiedPush as a second push MFA transport: RFC 8291 encrypted, sent directly to the device's distributor, no relay needed. Push token refresh is now `kyidentity-push-token-v2`, which signs transport and keys; v1 is no longer accepted.
- Outbound requests to operator- and device-supplied URLs now also refuse carrier-grade NAT (including Tailscale `100.64.0.0/10`), NAT64 and other reserved ranges. A sync callback or back-channel logout URL on a tailnet now needs `KYIDENTITY_ALLOW_PRIVATE_CALLBACKS=true`, like a private-network one.
- Add administrator and step-up protected signed recovery evidence for paired KyPost systems, including current app scope, explicit inactive subjects and retained sync revisions. Refuse held authority and incomplete output; restore holds remain unchanged. See [the contract](docs/KYPOST_RECOVERY_EVIDENCE.md).
