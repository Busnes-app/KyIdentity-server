# Changelog

## 0.6.0 — 2026-11-01

### Changes

- Settings holds the personal pages: Account (passkeys, six-digit and recovery codes, password, where you are signed in), Phones & apps (phones that approve sign-ins) and Appearance are tabs of one **Settings** nav item, so Your account is Applications and Settings. Security and devices and Appearance are no longer nav items. Each view now has its own hash (`#/settings/devices`, `#/admin-users`), so links, reload and Back work; `#/devices` and `#/appearance` open their tab. The account footer's Sign out is an icon button (named "Sign out"), in the sidebar and the phone header. Vendored ky-ui 0.8.0 → 0.10.0. No API, auth or session change.
- Suite directory: `GET /api/suite/apps` lists the suite apps a user may open, for a cross-app switcher, and `GET /api/suite/peer` gives KyCalendar and KyPost each other's URL and a shared secret derived from the encryption key, so they pair without an operator copying secrets. Both take a registered app's confidential client credentials (HTTP Basic). See [the contract](docs/SUITE-DIRECTORY.md).
- A client's launcher card can carry its own name and be shown to the app's administrators only (**OAuth clients → ⋯ → Launcher card**, `PUT /api/admin/clients/{id}/launcher`, or `apply-setup --launcher-name`/`--launcher-audience`, capability `client-launcher-display`). Everyday users then see one "KyMessages" card opening Element, not the console. Hiding a card never removes access. The suite directory applies both.
- The launcher opens KyCalendar and KyDrive at `/api/sso/kysignon/login` and KyMessage at `/api/sso/kyidentity/login`, signing the user in instead of showing a login form.
- Launcher: suite apps show their own icons instead of the generic "B" their favicons serve. KyIdentity bundles the KyCalendar, KyDNS, KyDrive, KyMessages, KyNotes, KyPost, KyPulse, KyRecovery and KyYard icons (64 px, same origin, no CSP change). A card left on **Favicon** whose OAuth client ID or name is a suite app's, compared exactly and case-insensitively (`kymessage` and `kymessage-chat` count as KyMessages), shows its icon; stored rows are not rewritten, and an uploaded or chosen icon still wins. The icon picker offers them, and the API accepts `iconName` `suite:<app>` for those nine names only.
- Launcher: KyDash gets its new gauge icon as a bundled suite icon, so the API now accepts `suite:kydash` too. A card left on **Favicon** whose client ID or name is `kydash`, `ky-dashboard`, "KyDash" or "Ky Dashboard" (compared exactly and case-insensitively) shows it. Stored rows are not rewritten.
- `apply-setup --file <bundle> --launch-url <client>=<https URL>` gives a client an applied setup owns its launcher link, while it has none; a link an admin set stays. Without one, a card opens its first redirect URI's origin, which for KyMessages' chat client is MAS, not Element. Advertised as capability `client-launch-urls`. See [Launcher links](docs/INSTALLER-SETUP.md#launcher-links).
- The sidebar ends with a `© <year> · MIT License` line, as in KyPost. It opens an About dialog with the KyIdentity version, the copyright and the full MIT License text. `GET /api/auth/me` now returns `version` (signed-in users only).
- Push relays keep key records in their `RelayCoordinator` Durable Object instead of the `API_KEYS` KV namespace. Registering no longer writes KV, whose free-plan quota of 1,000 writes a day ran out on 2026-10-26 and stopped Android push. Each relay keeps its own keys, so the KyPost and KyIdentity Android relays no longer share one key per public IP. Existing keys keep working: a relay copies a key out of KV the first time it is used. Operators list and revoke keys with SQL in the dashboard's Durable Objects Data Studio (object `relay-keys`); see the relay READMEs. (#173)
- A self-registered server whose relay key the relay no longer knows now re-registers by itself: the relay answers `key_unknown` for a key it has no record of, and KyIdentity treats it like `key_superseded`. A key an operator revoked still gets a plain 401 and stays refused. (#165)
- **Choose a new password** no longer asks for the given password: the step-up dialog takes it, so a new account types it twice (sign-in and step-up), not three times. `POST /api/user/password` accepts a body without `currentPassword` when its step-up grant, bound to the caller's user, session and this route, is spent on that request; a `currentPassword` that is sent is still checked, and a missing one without a grant is refused. Step-up is unchanged. A password change, and any session or access revocation, now also cancels pending step-up challenges, so one begun under the old password cannot finish afterwards. (#136)
- Users: the account name opens **Edit user** for an administrator (named "Edit <name>", with a visible focus ring), and the row's other actions sit behind a quiet ⋯ button ("More actions for <account>"), as on OAuth clients and Groups, instead of six equally loud **Manage** buttons. A delegate sees the name as text and keeps the ⋯ menu. No API, permission or auth change. No "Last sign-in" column: `GET /api/admin/users` does not return a sign-in time.
- Status badges use the ky-ui 0.8.0 `.ky-status` pill (vendored ky-ui 0.7.0 → 0.8.0): a word with a dot or icon, in status colours that no longer resemble the accent. Disabled accounts, clients and connectors and Paused connectors are neutral rather than red; a Failing connector is red rather than amber; device attestation shows green. SCIM, Groups and This session are plain outlined tags, not states.
- OAuth clients and Groups follow the Users row: the client or group name opens **Manage** (named "Manage <name>", with the shared focus ring, underlined on row hover), and **Manage** is now the first item of the row's ⋯ menu instead of an outlined button beside it. A group's name stays text in one user's membership view, which offers no Manage. Group names take the same weight as account and client names. No API, permission or auth change.

## 0.5.0 — 2026-10-28

### Upgrading

- `PUSH_RELAY_URL` and `APNS_RELAY_URL` now default to the Busnes.app relays (`https://fcm.relay.kyauth.busnes.app` and `https://apn.relay.kyauth.busnes.app`) when unset, so push MFA on KyAuth for Android and iOS works with no setup. Set one empty to turn it off. If self-registration with a default relay fails, startup logs it and continues without that transport; a relay you set yourself still fails startup. (#153)
- The push relays moved to `https://fcm.relay.kyauth.busnes.app` (Android) and `https://apn.relay.kyauth.busnes.app` (iOS). KyIdentity's Android relay now runs on its own Worker: it shared KyPost's, whose one-key-per-public-IP rule let a KyPost server behind the same address revoke KyIdentity's key. Self-registered keys are now kept per relay host (`push-relay-<fcm|apns>-<host>.key` in the data directory), so an upgraded server registers with the new relay by itself; the old `push-relay-fcm.key` and `push-relay-apns.key` are ignored and can be deleted. Servers that set `PUSH_RELAY_URL`, `APNS_RELAY_URL` or a pinned key are unaffected.

### Changes

- Stopping KyIdentity no longer strands a connector delivery: shutdown waits for the sync worker (within the 5-second shutdown deadline) so a delivery it began records its outcome. A delivery left with no outcome, by a crash or an older version, now makes `resync-system --wait` report `failed` once its recovery time passes, instead of timing out with plain `pending`; recover it under the connector's Deliveries (**Resume delivery**).
- Appearance follows a theme chosen in another tab: the matching card is now checked without a reload. Match system is labelled "Follows device", as in the other Ky products.
- **Back up now** (`POST /api/admin/backup/deposit`) needs a signed-in administrator only, no longer a step-up re-authentication, as in the other Ky products. A deposit only seals the directory to the recovery key this server already pinned, so it cannot send data anywhere new or reveal it. Exporting the capsule, pairing, unpairing, pinning the key and changing the schedule still require step-up.
- Passkey ceremonies are verified by [go-webauthn](https://github.com/go-webauthn/webauthn) instead of a hand-rolled verifier. Enrolment now sends the authenticator's `attestationObject` to `POST /api/user/passkeys/register/finish` in place of `authenticatorData` and `publicKey`; the bundled web app does this. Enrolled passkeys keep working without re-registration. Still ES256 only. Newly refused: assertions with `crossOrigin: true`, a backup-eligible flag that differs from enrolment, or backup state without backup eligibility, and attestation statements that are present but invalid.
- Security: the image is built with Go 1.27.3 (was 1.27.2) for GO-2026-6809: `crypto/x509` now distrusts compromised intermediate certificates. `go.mod` sets `toolchain go1.27.3` so `go build` from source uses it too.

## 0.4.7 — 2026-10-23

### Upgrading

- `KYIDENTITY_APPATTEST_APP_IDS` now defaults to KyAuth iOS when unset, as the Android signing digests already did; set it empty to turn App Attest grading off.
- The first start marks pending outbox work that earlier versions left at its attempt budget as failed, so the reconcile pass re-queues it while it is current. Pending removals stay pending.

### Changes

- Serve the suite installer status endpoint `GET /api/installer/network` like the other Ky products, so `kyquickstart verify-edge` can check KyIdentity's route. It returns `{"clientIp","proxyHeadersTrusted","scheme"}` resolved by the existing `TRUSTED_PROXY_CIDRS` and `KYIDENTITY_FORWARDED_HEADER` rules; it used to fall through to the web app. See [Health & Status Verification](docs/RUNNING.md#health--status-verification).
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
