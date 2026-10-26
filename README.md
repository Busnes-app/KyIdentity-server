# KyIdentity Server

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15843/badge)](https://www.bestpractices.dev/projects/15843)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Busnes-app/KyIdentity-server/badge)](https://scorecard.dev/viewer/?uri=github.com/Busnes-app/KyIdentity-server)

**Start here:** [Standalone installation](INSTALL.md). Local accounts, groups, MFA and the identity provider run without other Ky servers. Configure an SMTP sender separately for activation and password-reset email; KyAuth is optional for push MFA and app sign-on.

KyIdentity is a self-hosted, single-organization identity provider and user directory for the Busnes.app Ky products. Manage people, groups, application access and MFA in one place; connected products use OpenID Connect for sign-in and configured connectors for provisioning and offboarding.

Built in Go with a focus on simplicity, minimal external dependencies, and native platform standards, KyIdentity serves as the authoritative source of truth for accounts and OpenID Connect authentication. Downstream synchronization is configured per product; it does not replicate every product’s database.

---

## Core Capabilities

1. **Authoritative User Directory & Real-Time Sync**: Create, manage, and deactivate accounts from a unified portal. Changes automatically propagate to paired KySecurity downstream products via HMAC-SHA256 signed sync webhooks. Administrators can export bounded signed [KyPost recovery evidence](docs/KYPOST_RECOVERY_EVIDENCE.md); this supplies current authority without releasing a restore hold.
2. **OpenID Connect & OAuth 2.0 Provider**: RFC-compliant authorization code flow with PKCE (`S256`), dynamic JWKS key discovery (`/.well-known/jwks.json`), and RS256 token signing.
3. **Multi-Factor Authentication (MFA)**:
   - **TOTP Authenticator Apps**: Standard RFC 6238 time-based one-time passwords with encrypted secrets at rest (AES-256-GCM).
   - **Push Authentication with Number Matching**: The sign-in screen shows a two-digit number; the user types it into KyAuth on a paired device to approve. Delivered through the FCM/APNs relay, directly over UnifiedPush, or through the UBports push service to Linux (Ubuntu Touch) devices; UnifiedPush distributors and UBports see when a sign-in happens but not its content (see SECURITY.md).
   - **Passkeys (WebAuthn)**: ES256 platform and roaming authenticators as a second factor, verified with [go-webauthn](https://github.com/go-webauthn/webauthn). Works with compatible platform passkey managers and roaming hardware keys; current KyAuth apps are authenticators rather than passkey managers.
   - **Emergency Recovery Codes**: Single-use recovery codes stored as HMAC-SHA256 under a key derived from the encryption key, bound to the user. Codes issued by older versions (bare SHA-256) still work until regenerated; `GET /api/auth/me` reports `recoveryCodesNeedRegeneration` while any remain.
4. **90-Second Ephemeral Pairing**: Frictionless UI-based pairing with QR codes and short PINs for native mobile devices and downstream server applications.
5. **Application Launcher**: Search and arrange the applications you can access, with saved groups, ordering and custom icons. The embedded React frontend follows system light/dark appearance with Busnes themes; older named presets remain available.

---

## License & Security

Refer to [SECURITY.md](SECURITY.md) for vulnerability disclosure procedures and [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

RSA token-signing keys must be at least 2048 bits. Existing smaller keys stop
startup without being overwritten; read the [signing-key upgrade guidance](docs/UPGRADES-AND-RECOVERY.md#rsa-signing-key-minimum) before upgrading such an installation.

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — Architecture & Standard Library Philosophy. <a id="architecture--standard-library-philosophy"></a><a id="standard-library-implementations"></a><a id="direct-dependencies"></a>
- [Running](docs/RUNNING.md) — Quickstart with Docker Compose, Health & Status Verification, Command Line Utilities. <a id="quickstart-with-docker-compose"></a><a id="1-configure-environment"></a><a id="2-start-the-server"></a><a id="3-retrieve-credentials--log-in"></a><a id="4-private-certificate-authority-lan-installs"></a><a id="health--status-verification"></a><a id="command-line-utilities"></a>
- [Accounts and access](docs/ACCOUNTS-AND-ACCESS.md) — Onboarding and passwords, Directory groups, Delegated administration, Expiring access and account end dates, and related procedures. <a id="onboarding-and-passwords"></a><a id="directory-groups"></a><a id="delegated-administration"></a><a id="expiring-access-and-account-end-dates"></a><a id="access-requests-and-approvals"></a><a id="explaining-access-decisions"></a>
- [Applications](docs/APPLICATIONS.md) — App connections, App roles and token claims. <a id="app-connections"></a><a id="app-roles-and-token-claims"></a>
- [Audit and alerts](docs/AUDIT-AND-ALERTS.md) — Audit search and export, Alerts. <a id="audit-search-and-export"></a><a id="alerts"></a>
- [Upgrades and recovery](docs/UPGRADES-AND-RECOVERY.md) — Upgrades and restores. <a id="upgrades-and-restores"></a>
- [Integrations](docs/INTEGRATIONS.md) — Integration Requirements. <a id="integration-requirements"></a>
- [Provisioning](docs/PROVISIONING.md) — Outbound provisioning, Inbound SCIM. <a id="outbound-provisioning"></a><a id="provisioning-scope"></a><a id="reconciliation"></a><a id="offboarding"></a><a id="scim-groups"></a><a id="inbound-scim"></a>
- [Verifying releases](docs/VERIFYING-RELEASES.md) — Check a release image's signature and source commit, and rebuild its binary to the same bytes.
- [Key strength and Go TLS profile](docs/STRONG-CRYPTO.md) — Key floors, safe migration, Compose configuration and independent Worker/edge limits.
- [Assurance case](docs/ASSURANCE-CASE.md) — Threat model, trust boundaries, and why the security requirements are met.
