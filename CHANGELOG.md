# Changelog

## Unreleased

### Changes

- `apply-setup` accepts setup amendments: a bundle with `"extends": "<parent setupId>"` and only `clients` adds OIDC clients to an applied setup without touching its accounts. The parent's owned accounts must pass inspection; existing client IDs are refused. Advertised as capability `setup-amendments`. See [Adding clients later](docs/INSTALLER-SETUP.md#adding-clients-later).

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
