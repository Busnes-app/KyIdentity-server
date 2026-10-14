# Changelog

## Unreleased

- Five wrong pairing PINs for an account now expire all its live pairing tokens. IPv6 clients share one rate-limit bucket per /64.
- `POST /api/user/devices/pairing-token` without `signOn` now pairs a phone that cannot sign in to apps (was: can). Clients wanting sign-on must send `signOn: true`; the web UI already does.
- Removing a phone, and changing whether it approves MFA or signs in, now spend a step-up grant and are audited atomically. Deleting or changing an unknown device answers 404.
- Pair Linux authenticators (`platform: "linux"`). A Linux device uses UnifiedPush or the new `ubuntupush` transport (Ubuntu Touch, via the UBports push service, `KYIDENTITY_UBUNTU_PUSH_URL`/`KYIDENTITY_UBUNTU_PUSH_APPID`); FCM is refused for it. `ubuntupush` payloads are RFC 8291 encrypted like UnifiedPush. Existing databases are migrated in place to accept the new platform and transport.
- Add UnifiedPush as a second push MFA transport: RFC 8291 encrypted, sent directly to the device's distributor, no relay needed. Push token refresh is now `kyidentity-push-token-v2`, which signs transport and keys; v1 is no longer accepted.
- Outbound requests to operator- and device-supplied URLs now also refuse carrier-grade NAT (including Tailscale `100.64.0.0/10`), NAT64 and other reserved ranges. A sync callback or back-channel logout URL on a tailnet now needs `KYIDENTITY_ALLOW_PRIVATE_CALLBACKS=true`, like a private-network one.
- Add administrator and step-up protected signed recovery evidence for paired KyPost systems, including current app scope, explicit inactive subjects and retained sync revisions. Refuse held authority and incomplete output; restore holds remain unchanged. See [the contract](docs/KYPOST_RECOVERY_EVIDENCE.md).
