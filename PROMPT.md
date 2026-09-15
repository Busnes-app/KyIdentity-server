# KyIdentity Server

KyIdentity is the self-hosted, single-organization identity service and central identity authority for the KySecurity suite, including KyPost, KyBookmarks, KyNotes, and KyPasswords.

## Technical direction

- Implement the server in Go.
- Package and run it in a Docker container.
- Use SQLite for persistence (WAL mode, foreign keys).
- Configure the OIDC issuer URL during installation because deployments are self-hosted.
- Support deployment behind Nginx or Cloudflared.
- Use RS256 for OIDC ID-token signing and publish public keys through JWKS.
- Store signing and encryption secrets outside SQLite.

## Identity, SSO, and Suite Replication

- Implement OAuth 2.0 and OpenID Connect with PKCE.
- Central User Directory: When administrators create or modify user accounts in KyIdentity, changes automatically replicate to paired KySecurity products via signed sync webhooks.
- UI System Pairing: Connect downstream KySecurity servers to KyIdentity using short-lived (90s) pairing keys generated in the KyIdentity Admin UI.
- KyPost and all other KySecurity products integrate directly with KyIdentity through OIDC.
- KyIdentity owns authentication, identity, browser sessions, and MFA state.
- Support approved external OAuth/OIDC clients.
- Use exact redirect-URI matching and standard OIDC discovery/JWKS endpoints.

## Accounts and administration

- Single organization (multi-tenancy is out of scope for MVP).
- Administrators create and manage user accounts.
- Roles are `user` and `admin`.
- Required account fields: username, display name, email, password, role, and status.
- Passwords require at least 12 characters and use Argon2id.
- Create the first administrator with a one-time CLI command at installation.
- Administrators can pair KySecurity systems, trigger directory resyncs, manage OAuth clients, revoke sessions, and reset MFA.
- All security-sensitive administrator actions must be audited.

## MFA and Native Device Pairing

- Direct native implementation of device pairing (`/api/notifications/native/register`) using 90s PIN/QR codes.
- Support push MFA with 2-digit number matching and decoys.
- Support TOTP MFA with AES-GCM encrypted secrets at rest.
- Provide one-time recovery codes, stored only as hashes and invalidated after use.
- An administrator MFA reset revokes active sessions, invalidates enrollment/devices, and requires re-enrollment at next login.

## Dashboard & Visual Design

- Follow KyPost's frontend approach: React 19, TypeScript, Vite, React Router, bundled statically with the Go binary.
- Reuse the existing KySecurity CSS and fonts (`css/styles.css`, Space Grotesk, IBM Plex Mono, dark `#0d0f14`, cyan `#4deeea`).
- User dashboard: application cards (launcher), account settings, device pairing, and MFA configuration.
- Admin dashboard: user management, paired KySecurity systems & resync, OAuth clients, and audit logs.

## Security and operations

- Use secure, HttpOnly, SameSite cookies and CSRF protection.
- Rate-limit login, token, authorization-code, device pairing, and MFA endpoints.
- Do not log passwords, tokens, secrets, or TOTP values.
- Persist SQLite on a dedicated Docker volume and support backups of the database and signing/encryption keys together.

See `design.md` for the detailed architecture, data model, endpoint plan, authentication flows, verification requirements, and delivery phases.
