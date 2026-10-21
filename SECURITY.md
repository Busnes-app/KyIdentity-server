# Security Policy

KyIdentity is the single-organization OpenID Connect provider and user directory for the KySecurity suite. This document covers disclosure, known limitations and trust boundaries, deployment, and how the server protects accounts and data.

## Reporting Security Vulnerabilities

If you discover a security vulnerability in KyIdentity, please report it responsibly via GitHub Security Advisories rather than opening a public issue.

### How to Report

1. Go to the [Security Advisories](https://github.com/Busnes-app/kyidentity-server/security/advisories) page
2. Click "Report a vulnerability"
3. Provide a detailed description, affected versions, and reproduction steps if applicable
4. Do not disclose the vulnerability publicly until a patch is available

### Disclosure Timeline

The timeline for public disclosure depends on severity:

- **Critical** (e.g., unauthenticated data access, authentication bypass, remote code execution): 30 days
- **High** (e.g., privilege escalation, cryptographic weakness): 60 days
- **Moderate** (e.g., denial of service, information disclosure): 90 days

We will:
- Acknowledge receipt of your report within 2 business days
- Provide a timeline and severity assessment
- Develop and test a patch
- Coordinate a release that includes the fix before the deadline
- Credit you in the patch release notes (unless you prefer anonymity)

This timeline assumes good-faith coordination. Patches are publicly available before any advisory is published.

### Security Advisory Credits

We acknowledge security researchers and community members who help us improve. If you'd like credit in our release notes, please let us know your preferred name or handle when reporting.

## Known Limitations & Trust Boundaries

Read these before deploying or relying on specific features.

### Sessions

- Browser sessions are stored server-side; the cookie carries a random token and the database keeps only its SHA-256. The cookie is `HttpOnly` and `SameSite=Lax`.
- Defaults: 24 hours absolute, 8 hours idle (`KYIDENTITY_SESSION_TTL`, `KYIDENTITY_SESSION_IDLE_TTL`). Administrators can change both within fixed bounds: 1 hour to 7 days absolute, 5 minutes to 24 hours idle.
- Expired sessions are deleted by housekeeping every 15 minutes; a session past its idle limit is refused at once.
- Sign-out deletes the session, revokes the tokens and authorization codes issued under it, and queues back-channel logout to apps that registered a receiver. Apps without one keep their own sessions until they expire. See [Integration Requirements](docs/INTEGRATIONS.md#integration-requirements).

### Mobile Pairing

- A KyAuth device pairs from a QR code holding a pairing token and a 6-digit PIN, both stored only as hashes and valid for 90 seconds. The QR names the server by `KYIDENTITY_ISSUER_URL`, so the issuer must be the HTTPS address devices reach.
- Device registration is rate-limited per client address.
- Sign-in pushes name the account's username only inside an RFC 8291 sealed payload: the FCM and APNs relay body of a device that registered push keys, UnifiedPush and Ubuntu Touch push. A relay device paired without keys (an older KyAuth Android pairing) gets unsealed identifiers (user, device and challenge IDs, purpose, expiry), never the username, and the relay and Google can read them. A username too long for the fixed-size record is left out rather than enlarging it.
### UnifiedPush

- A device can register a UnifiedPush endpoint instead of an FCM token. KyIdentity then posts directly to the user's distributor (ntfy, NextPush, ...), and no relay or Google service is involved.
- The payload is RFC 8291 encrypted to keys the device holds; KyIdentity never sends a UnifiedPush payload in plaintext and refuses a registration without keys. The distributor sees **when** a sign-in request happens, the endpoint, and your server's address and origin (the VAPID subject). Bodies are padded to a fixed size, so it does not learn their length or content.
- The endpoint URL is chosen by the device, so KyIdentity treats it as untrusted: HTTPS only, no private or loopback addresses (checked at registration and again when connecting), no redirects. `KYIDENTITY_ALLOW_PRIVATE_CALLBACKS` does not apply to device-supplied endpoints, so a self-hosted distributor must be reachable at a public address.
- Endpoint URLs are capabilities and are never written to logs.

### Ubuntu Touch push

- A Linux device (`platform: "linux"`) uses UnifiedPush or `ubuntupush`; FCM is refused for it, and `ubuntupush` is refused for every other platform.
- `ubuntupush` posts to the UBports push service (`KYIDENTITY_UBUNTU_PUSH_URL`, HTTPS only, through the same no-redirect, no-private-address client). The body carries the same RFC 8291 ciphertext as UnifiedPush, padded to a fixed size, plus a fixed notification text with no user, server or challenge details. UBports sees the token, the app id (server configuration, never device input), the ciphertext and the timing.
- An `unknown-token` reply clears the device's push target, as a 404/410 does for UnifiedPush. Tokens are never logged.

### iOS Device Attestation (App Attest)

Android pairings are graded from a Keystore attestation chain that describes the signing key itself: hardware-resident, user authentication on every use. iOS has no attestation for arbitrary Secure Enclave keys. With `KYIDENTITY_APPATTEST_APP_IDS` set, an iOS pairing is graded `appattest` when Apple App Attest proves the request, including its public key, was built by a genuine, unmodified KyAuth on a genuine Apple device.

**The grade rests on app integrity, not on key attestation**, so it is not MFA-grade. App Attest does not prove the signing key lives in the Secure Enclave or that each use requires user presence. An `appattest` device signs on like an unattested one: single factor (`pop`, `urn:kysignon:acr:device`), refused by mandatory MFA and by `fresh`/`max_age` app policies. Push approvals from it are unaffected.

## Deployment Security

Your deployment choices determine the actual security of KyIdentity. This section covers the configuration decisions that matter most.

### TLS & Network Binding

**KyIdentity serves plain HTTP only; it does not terminate TLS.** Put a TLS proxy (Caddy, nginx, Cloudflare Tunnel) in front of it.

`KYIDENTITY_ISSUER_URL` must be `https://` unless its host is `localhost` or a loopback IP; startup refuses anything else. An `https` issuer marks session cookies `Secure` on every response. `KYIDENTITY_SECURE_COOKIES=true` forces the flag for a loopback issuer.

Whichever proxy you use, set `TRUSTED_PROXY_CIDRS` to its address as KyIdentity sees it (below), and set `KYIDENTITY_FORWARDED_HEADER=CF-Connecting-IP` behind Cloudflare.

### KYIDENTITY_BIND: Which Interface to Publish

`KYIDENTITY_BIND` chooses the host interface that publishes port 5867. It defaults to `127.0.0.1`.

- **`127.0.0.1`** (default): loopback only, for a proxy on this host and local health checks.
- **One LAN address** (e.g. `<host-lan-ip>`): only when a proxy on another machine must reach this host.
- **`0.0.0.0`**: every interface. Rarely right: anything that can reach the port talks plain HTTP to the server.

**Better practice:** run the proxy as a container on `kypost-net` and point it at `http://KyIdentity-Server:5867`. Nothing needs publishing for the proxy, and KyIdentity sees the proxy's own container address, so `TRUSTED_PROXY_CIDRS` can name exactly that one address. Pin the proxy to a fixed address on the network so the setting stays true.

### TRUSTED_PROXY_CIDRS: Client IP Trust

When a reverse proxy sits in front of KyIdentity, the server sees the proxy's address as the client IP. The client address keys the per-address rate limits (sign-in, MFA, recovery codes, password reset, device registration) and is recorded in every audit event.

**If `TRUSTED_PROXY_CIDRS` is empty, forwarded headers are discarded entirely.** Every caller is keyed as the proxy, so all users share one rate-limit bucket and the audit log shows the proxy's address instead of the user's.

**If `TRUSTED_PROXY_CIDRS` is set, KyIdentity trusts `X-Forwarded-Proto` and exactly one client-address header from that CIDR.** This marks cookies `Secure` and keys lockouts off the real caller.

The address header is named by `KYIDENTITY_FORWARDED_HEADER` and defaults to `X-Forwarded-For`. Behind Cloudflare, set `KYIDENTITY_FORWARDED_HEADER=CF-Connecting-IP`.

Only one header is consulted, on purpose. Trying several in turn (`CF-Connecting-IP`, then `X-Forwarded-For`, then `X-Real-IP`) means the one your edge does not overwrite is a free-form string the client controls, and that string becomes a rate-limit bucket key and an audit-log identity. Naming the contract removes the choice.

Two further rules apply to the value:

- It must parse as an IP address. An unparseable entry is discarded and the request is attributed to the peer, so a caller cannot mint a fresh rate-limit bucket per request by sending a new nonsense value each time.
- The chain is read right to left, skipping hops inside `TRUSTED_PROXY_CIDRS`, and the first address you did not write is the client. Reading the leftmost entry instead would attribute the request to whatever the client prepended to the list.

**Name the proxy's address specifically, not a wide range.** Any peer inside the range you name can forge their own client IP and bypass every rate limit and lockout. Example:

- Proxy on the same host, through the published port: the container does not see `127.0.0.1` but the address Docker forwards from, typically the `kypost-net` gateway (`TRUSTED_PROXY_CIDRS=10.89.0.1/32` with the default subnet). Confirm it with the check below.
- Proxy pinned on `kypost-net`: `TRUSTED_PROXY_CIDRS=10.89.0.10/32` (replace with your proxy's actual Docker network IP)
- Cloudflare Tunnel: `TRUSTED_PROXY_CIDRS=0.0.0.0/0` is unavoidable; Tunnel is the proxy and only Cloudflare can reach it. Pair it with `KYIDENTITY_FORWARDED_HEADER=CF-Connecting-IP`.

### Rate limiting under pressure

Rate-limit buckets live in this process's memory and are capped. When the cap is reached, **new** buckets are refused with `429` and existing ones are left alone.

The alternative — evicting buckets to make room — hands a fresh full allowance to precisely the clients currently being throttled, so a botnet large enough to fill the map can reset its own limits on demand. Shedding new arrivals is the failure mode that does not reward the attack.

This also means process-local rate limiting is a backstop, not a perimeter. A deployment expecting real volumetric abuse should throttle at the edge, where the state is shared across every instance.

This replaces the old `TRUST_PROXY_HEADERS=true`, which trusted forwarded headers on *every* connection from any peer and was only ever safe when nothing but the proxy could reach the port.

### Verification: Confirm Your Setup

**Verify rather than assume.** Sign in through the proxy from a machine whose address you know, then open the admin audit log and find your `auth.login_success` row. Its IP column is the client address KyIdentity resolved for you.

- Your own address: the proxy is trusted and forwards the header named by `KYIDENTITY_FORWARDED_HEADER`.
- The proxy's or a Docker gateway address (e.g. `10.89.0.1`): `TRUSTED_PROXY_CIDRS` does not match the proxy as KyIdentity sees it, or the proxy does not send that header. Every user then shares one rate-limit bucket.

### Secret Handling

Everything KyIdentity needs to keep secret lives in its data volume (`/data` in the container):

| File | Purpose |
|---|---|
| `kyidentity.db` (or legacy `kysignon.db`) | SQLite database |
| `encryption.key` | AES-256-GCM key for secrets at rest (`KYIDENTITY_ENCRYPTION_KEY`) |
| `secret.key` | HMAC key for CSRF tokens and signed browser cookies (`KYIDENTITY_SECRET_KEY`) |
| `jwt_rs256.key` | RSA signing key for ID and access tokens (`KYIDENTITY_RSA_KEY_PATH`) |
| `push-vapid-private.key` | VAPID key for UnifiedPush; startup refuses a mode looser than `0600` |
| `push-relay-fcm.key`, `push-relay-apns.key` | Keys returned by the push relays at registration |
| `first-run-password.txt` | Generated bootstrap password, until first sign-in |

- Keys not supplied through the environment are generated on first start, written `0600` in a `0700` directory, and reused.
- A key of the wrong length is a startup error, never a silently weakened key. There is no key rotation: losing or replacing `encryption.key` makes the data sealed under it unrecoverable.
- **Back up the whole volume and protect it like the keys it holds.** See [docs/RESTORE.md](docs/RESTORE.md).

### First Run & Bootstrap

- When no administrator exists, KyIdentity creates one named `BOOTSTRAP_ADMIN_USER` (default `admin`). Its password is `BOOTSTRAP_ADMIN_PASS` or, when unset, a random one written to `first-run-password.txt` (mode `0600`). Only the file's path is logged, never the password.
- The file is removed automatically after the first sign-in. If an administrator already exists, `BOOTSTRAP_ADMIN_PASS` is ignored.
- The bootstrap account must choose a new password at its first sign-in, MFA included. Until it does, every session it holds can only read its own identity (`GET /api/auth/me`), step up for the change, change the password, enroll a replacement factor, or sign out. Every other API, admin APIs included, answers `403 password_change_required`; `/oauth/authorize` sends the app `interaction_required`; no authorization code or token is issued, and tokens issued earlier stop validating. Enroll a second factor right after the change.
- The same applies to a password an administrator sets on someone else's account, at creation or later. Upgrading flags an existing bootstrap administrator that never replaced its first password (see [docs/ACCOUNTS-AND-ACCESS.md](docs/ACCOUNTS-AND-ACCESS.md#onboarding-and-passwords)).

## Authentication & Authorization

### Login Flow

- Username and password, sent to the server over the TLS proxy and checked against an Argon2id hash (64 MiB, 3 iterations, parallelism 4, 16-byte salt). Passwords are 12 to 1024 characters.
- 10 consecutive failures, wrong second factors included, lock the account for 15 minutes. A locked account gets the same answer as a wrong password.
- Per-address rate limits cover sign-in, every MFA step, recovery codes, password reset and account-link redemption.
- At most 8 password hashes run at once; a sign-in that waits more than 3 seconds for a slot gets `503`, which does not count as a failure.
- There is no CAPTCHA.

### Multi-Factor Authentication

- **TOTP** from an authenticator app.
- **Passkeys** (WebAuthn), bound to the issuer's origin.
- **Push approval** on a paired KyAuth device, with number matching. At most 5 sign-in pushes per user per hour.
- **Recovery codes:** 8 one-time codes, stored only as keyed hashes. With no other factor left, they are the only way back in. **Store them securely.**

Administrators can require enrollment for the whole organization, administrators only, or a group, with a grace period of up to 90 days.

### Roles & Authorization

- **Global roles:** `admin` (everything) and `user`.
- **Delegations** on top of `user`: `auditor` (read-only administration), `helpdesk` (recovery for ordinary users, never administrators), `app_owner` (grants and roles for the apps they own). See [Delegated administration](docs/ACCOUNTS-AND-ACCESS.md#delegated-administration).
- Permissions are computed on every request, never cached in the session. Disabling a user, demoting an administrator or changing a password revokes that user's sessions and tokens at once.
- KyIdentity refuses to disable, demote or delete the last active administrator.
- Destructive administrative operations require step-up re-authentication.

## Data Protection

### Encryption at Rest

Sealed with AES-256-GCM under a per-purpose key derived from `encryption.key`:

- TOTP secrets
- Connector credentials (suite signing secrets and SCIM bearer tokens)
- Mail (SMTP) settings
- The KyRecovery API token

Hashed, not stored: passwords (Argon2id), session tokens (SHA-256), recovery codes (keyed HMAC).

Not encrypted: account metadata (usernames, names, email addresses, roles, groups, status), client registrations, app assignments and the audit log. Anyone who can read the database file can read these.

### Encryption in Transit

- **Browsers and apps:** through your TLS proxy (see [Deployment Security](#deployment-security)).
- **Outbound calls** (SCIM and suite connectors, back-channel logout, UnifiedPush, UBports) go through one guarded client: HTTPS only, no embedded credentials, no redirects, and the destination is checked at connect time, so DNS rebinding cannot reach a refused address. Loopback, link-local and cloud-metadata addresses are always refused; private ranges are refused unless `KYIDENTITY_ALLOW_PRIVATE_CALLBACKS=true`.
- **`KYIDENTITY_ALLOW_PRIVATE_CALLBACKS=true` also allows plain `http`** for operator-supplied URLs. Use it only on a network you control, and prefer HTTPS anyway. It never applies to device-supplied push endpoints.
- **Push relays:** `PUSH_RELAY_URL` and `APNS_RELAY_URL` must be HTTPS.
- **Certificates:** outbound TLS is verified against the container's trust store; to add a private CA, see [README step 4](docs/RUNNING.md#4-private-certificate-authority-lan-installs).

### Sensitive Data in Logs

- Logs go to standard output and standard error only; [LOGGING.md](LOGGING.md) is the contract.
- Passwords, password-derived values, client secrets, tokens, signing keys, TOTP values, recovery codes, authorization codes and raw request bodies are never logged. UnifiedPush endpoint URLs are capabilities and are never logged either.
- Audit events are kept in the database for 180 days. Audit exports redact keys that look like credentials.

## Security Headers & Defense-in-Depth

Every response carries:

- **Content-Security-Policy:** `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';` HTTPS images are allowed for custom launcher icons. The logout confirmation page widens `form-action` to the registered post-logout origin.
- **X-Content-Type-Options:** `nosniff`
- **X-Frame-Options:** `DENY`
- **Referrer-Policy:** `strict-origin-when-cross-origin`
- **Permissions-Policy:** `camera=(), microphone=(), geolocation=(), payment=()`
- **Cache-Control:** `no-store` on `/api/` and `/oauth/`

KyIdentity does not send `Strict-Transport-Security`; it does not see TLS. Set HSTS at your proxy.

## Development & Security Testing

### Testing

- Each security-relevant package keeps a `security_test.go` (`internal/api`, `config`, `crypto`, `mfa`, `oauth`, `sync`).
- Authentication changes: test bypasses (missing credentials, modified or expired tokens, revoked sessions).
- Authorization changes: test escalation (users and delegates reaching admin routes, helpdesk reaching administrators).
- Cryptographic changes: test sealing, opening and refusal of wrong keys.
- Input validation: test injection and URL validation (redirect URIs, outbound targets).

### Code Review

Security-sensitive PRs should include:

- A description of the trust boundary or attack surface.
- Why the approach is secure, or why a known limitation is acceptable.
- Tests for both the happy path and attack scenarios.
- Any assumption about the deployment (for example, "assumes a TLS proxy in `TRUSTED_PROXY_CIDRS`").

### Security-Sensitive Code

- Sign-in, sessions and CSRF: `internal/api/auth_handlers.go`, `internal/api/middleware.go`, `internal/store/sessions.go`
- Authorization: `internal/api/permissions.go`, `internal/store/delegations.go`
- MFA and passkeys: `internal/mfa/mfa.go`, `internal/webauthn/`
- OAuth/OIDC: `internal/oauth/`
- Passwords and keys: `internal/auth/password.go`, `internal/crypto/`
- Outbound requests: `internal/netguard/netguard.go`
- Client IP trust: `internal/api/middleware.go`

## Security Contacts

- **Vulnerability reports:** [GitHub Security Advisories](https://github.com/Busnes-app/kyidentity-server/security/advisories)
- **Maintainer:** [Yoshiofthewire](https://github.com/Yoshiofthewire)

## Additional Resources

- [Quickstart with Docker Compose](docs/RUNNING.md#quickstart-with-docker-compose) — `kypost-net`, issuer, proxy trust and private CA
- [Onboarding and passwords](docs/ACCOUNTS-AND-ACCESS.md#onboarding-and-passwords) — activation, password reset, lockout
- [docs/RESTORE.md](docs/RESTORE.md) — backups and restore
- [LOGGING.md](LOGGING.md) — logging contract
- OWASP guidelines on secure development practices
