# KyIdentity Server Design

## 1. Purpose

KyIdentity is the single-organization identity service and central identity authority for the KySecurity suite. It provides single sign-on (SSO) for KyPost, KyBookmarks, KyNotes, and KyPasswords, as well as OAuth 2.0 and OpenID Connect (OIDC) for approved non-KySecurity services.

KyIdentity acts as the authoritative user directory for the suite: when an administrator creates or updates an account in KyIdentity, the account automatically replicates across paired KySecurity products. Connecting downstream KySecurity systems to KyIdentity is performed securely through a UI-generated, short-lived pairing key.

The first release prioritizes secure authentication, automated suite-wide account syncing, native push/TOTP MFA, and an application launcher. KyIdentity MFA requires its own dedicated mobile authenticator app (or KyPost mobile during transition). It must not be folded into KyPassword or a single super app containing every KySecurity product.

## 2. MVP Scope

### Included

- **Core & Runtime**: Go HTTP server packaged as a non-root Docker container with SQLite persistence (WAL mode, foreign keys enabled).
- **Organization & Directory**: One organization with administrator-managed user accounts.
- **Cross-System Account Syncing**: Automatic replication of user accounts (create, update, status change, MFA reset) from KyIdentity to paired KySecurity products.
- **UI-Based System Pairing**: Administrator UI flow to generate short-lived (90s) pairing keys that securely register KySecurity services (KyPost, KyBookmarks, KyNotes, KyPasswords) and establish mutual HMAC sync credentials.
- **OAuth 2.0 & OpenID Connect**: Authorization-code flow with PKCE, RS256 ID-token signing, JWKS discovery, and userinfo endpoints.
- **Native Device Pairing & Push MFA**: Direct implementation in KyIdentity of device registration (`/api/notifications/native/register`) using 90-second ephemeral PIN/QR codes, push challenge dispatch with 2-digit number matching and decoys, and device pull-mode queue.
- **TOTP MFA & Recovery Codes**: Encrypted TOTP secret storage, time-step verification, and single-use hashed recovery backup codes.
- **Passkeys (WebAuthn Level 2)**: ES256 credentials as a second factor, with single-use server-issued challenges, signature-counter clone detection, and backup-eligibility recorded per credential. Attestation is not verified; passwordless sign-in is deferred.
- **Dedicated Authenticator Separation**: Support for KySecurity Authenticator mobile app as the long-term MFA client, maintaining strict separation from the password vault.
- **Web UI & Application Launcher**: KySecurity Patina themed web interface (React, TypeScript, Vite static bundle served by Go) with application cards, account settings, and device management.
- **Admin Dashboard**: Comprehensive management of users, paired KySecurity systems, manual directory resyncs, OAuth/OIDC clients, application links, MFA resets, session revocation, and audit logs.
- **Security & Logging**: Structured stdout/stderr logging without secrets, CSRF protection, HttpOnly SameSite cookies, rate limiting, and Argon2id password hashing.

### Deferred

- Self-service public registration.
- Multiple organizations or multi-tenancy.
- Social login and external identity providers (Google, GitHub, SAML).
- User-selected self-service password reset flows.
- Generic SCIM 2.0 protocol (replaced by native KySecurity pairing and sync engine in MVP).
- A general-purpose KySecurity super app that combines mail, passwords, bookmarks, notes, and MFA into a single binary.

## 3. Design Principles

- **Identity authority on the server**: KyIdentity is the source of truth for accounts and authentication across the KySecurity suite.
- **Standard protocols for SSO**: Use standard OAuth 2.0 and OpenID Connect with PKCE rather than custom SSO protocols.
- **Zero-knowledge separation**: Replicate user identity metadata (username, display name, email, role, status) to downstream systems, but never transmit or expose raw passwords or master vault keys.
- **MFA independent of password vault**: KyIdentity MFA must remain fully operational even if KyPassword is locked, compromised, or in recovery.
- **Simple, robust deployment**: Single statically-compiled Go binary, SQLite database on a persistent Docker volume, minimal runtime dependencies.
- **Secure system & device pairing**: All pairing actions (both admin system-pairing and user device-pairing) rely on short-lived (90s), cryptographically verified, single-use pairing keys generated in the UI.

## 4. High-Level Architecture

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                           KyIdentity Server                               │
│                                                                         │
│  ┌───────────────────────┐                 ┌─────────────────────────┐  │
│  │   Admin Web UI        │                 │    User Web UI          │  │
│  │  (System Pairing)     │                 │   (Device Pairing)      │  │
│  └──────────┬────────────┘                 └────────────┬────────────┘  │
│             │                                           │               │
│  ┌──────────▼────────────┐                 ┌────────────▼────────────┐  │
│  │  System Sync Engine   │                 │   Native Device Engine  │  │
│  │  (Event Dispatcher)   │                 │   (Push MFA & Pairing)  │  │
│  └──────────┬────────────┘                 └────────────┬────────────┘  │
│             │                                           │               │
│  ┌──────────▼───────────────────────────────────────────▼────────────┐  │
│  │                  OIDC / OAuth 2.0 / Auth Engine                   │  │
│  └──────────────────────────────────┬────────────────────────────────┘  │
│                                     │                                   │
│                        ┌────────────▼────────────┐                      │
│                        │   SQLite Data Store     │                      │
│                        └─────────────────────────┘                      │
└─────────────────────────────────────┼───────────────────────────────────┘
                                      │
              ┌───────────────────────┴───────────────────────┐
              │ (Outbound Webhooks / HMAC)                    │ (90s Ephemeral PIN / QR)
              ▼                                               ▼
┌───────────────────────────┐                       ┌───────────────────────────┐
│ Paired KySecurity Suite   │                       │ KySecurity Authenticator  │
│ (KyPost, KyPasswords,     │                       │ & Paired Mobile Devices   │
│  KyBookmarks, KyNotes)    │                       │                           │
└───────────────────────────┘                       └───────────────────────────┘
```

The Go server is structured around cohesive, testable modules:

- `http`: Routing, middleware (CORS, CSRF, rate limit, trusted reverse proxy IP detection), and HTTP responses.
- `identity`: User accounts, Argon2id hashing, session lifecycle, and authentication state.
- `sync`: UI system pairing tokens, downstream KySecurity product registration, and outbound account sync event dispatcher.
- `oauth`: Authorization-code flows, PKCE verification, RS256 token issuance, userinfo claims, and JWKS discovery.
- `mfa`: TOTP enrollment/verification, native device registration, push challenge state machine, and recovery codes.
- `admin`: User administration, system pairing management, manual directory resyncs, OAuth client registry, and audit logging.
- `dashboard`: User application launcher, device management, and account settings.
- `store`: SQLite migrations, queries, and transaction management.

## 5. System Pairing & Authentication Flows

### 5.1 System Pairing & Account Replication (Cross-System Sync)

KyIdentity is the central identity authority. When an administrator creates, modifies, or disables a user, the change automatically propagates to all paired KySecurity products.

#### System Pairing Handshake

```text
Admin (UI)                  KyIdentity Server               KySecurity Product (e.g. KyPost)
    │                              │                                     │
    │ 1. Request Pairing Key       │                                     │
    │─────────────────────────────>│                                     │
    │ 2. Display 90s Pairing Token │                                     │
    │<─────────────────────────────│                                     │
    │                              │                                     │
    │ 3. Enter Pairing Token in Product UI                               │
    │───────────────────────────────────────────────────────────────────>│
    │                              │                                     │
    │                              │ 4. POST /api/systems/register       │
    │                              │    (Pairing Token + Callback URL)   │
    │                              │<────────────────────────────────────│
    │                              │ 5. Validate & Issue System Secret   │
    │                              │────────────────────────────────────>│
    │                              │ (System Paired & Active)            │
```

1. **Token Generation**: In the KyIdentity Admin UI, the admin generates a 90-second single-use pairing token for a target KySecurity product.
2. **Registration**: The administrator copies/pastes the pairing token into the target product's configuration UI. The target product invokes `POST /api/systems/register` against KyIdentity.
3. **Mutual Trust**: KyIdentity verifies the token, records the system in SQLite (`paired_systems`), and generates a unique HMAC-SHA256 secret key and OIDC client credentials for that system.
4. **Replication**: When user changes occur:
   - KyIdentity writes a record to `account_sync_events`.
   - The background sync dispatcher sends an authenticated HTTPS webhook (`user.created`, `user.updated`, `user.status_changed`, `user.mfa_reset`) signed with the system's HMAC secret.
   - Downstream products update their local user tables immediately.
   - If a target system is offline, the dispatcher retries with exponential backoff and flags failures in the Admin Dashboard.

### 5.2 Native Device Pairing & Push MFA Flow

KyIdentity natively manages mobile push devices and pairing tokens.

#### Device Enrollment (90-second Ephemeral PIN/QR)

1. The user logs into the KyIdentity User Dashboard and navigates to **Security & Devices**.
2. The user clicks **Add Authenticator Device**. KyIdentity generates a 90-second single-use pairing token, displayed as both a scannable QR code and a 6-digit numeric PIN.
3. In the KySecurity Authenticator app (or KyPost mobile app), the user scans the QR code or enters the PIN.
4. The mobile app posts to `POST /api/notifications/native/register` with the pairing token, device ID, public key, and push push token.
5. KyIdentity validates the token, registers the device in `native_devices`, and activates it as an MFA approver.
6. When FCM rotates the delivery token, the paired device sends `PUT /api/notifications/native/devices/{deviceId}/push-token` with `pushToken`, Unix-millisecond `issuedAt`, and an ASN.1 ECDSA P-256/SHA-256 signature. The signed UTF-8 message is `kysignon-push-token-v1|<issuer-origin>|<deviceId>|<issuedAt>|<lowercase-hex-SHA256-of-trimmed-token>`. This prefix is a frozen wire constant and is not changed by the product rename. Requests must be within five minutes of server time and newer than the device's last accepted refresh; success returns `204`, replay returns `409`, and the client must sign a current request after a stale-window failure.

#### Push MFA Authentication

1. User submits valid username and password during OIDC authorization or web login.
2. KyIdentity detects push MFA enrollment and generates a challenge containing:
   - `challengeId` (UUID)
   - `matchDigits` (random 2-digit number, e.g., `42`)
   - `decoyDigits` (array of alternative numbers)
   - Expiration (5 minutes)
3. KyIdentity dispatches the push challenge to the user's paired device via push relay (or places it in `GET /api/notifications/native/pull` for pull-mode clients).
4. The browser displays the prompt: *"Select 42 on your authenticator device"* and begins polling `POST /api/auth/mfa/push/poll`.
5. The user opens the notification on their mobile device and taps the matching number `42`.
6. The mobile app sends `POST /api/mfa/push/respond` with the signed response.
7. Upon successful match, the polling browser receives confirmation and calls `POST /api/auth/mfa/push/finish` to complete authentication and receive the authorization code or session cookie.

### 5.3 OIDC Login Flow for KySecurity Suite Applications

1. KyPost (or another paired KySecurity app) redirects the browser to `GET /oauth/authorize` with `client_id`, `redirect_uri`, `response_type=code`, `scope=openid profile email`, `state`, and PKCE `code_challenge`.
2. KyIdentity validates the client and redirect URI against the `oauth_clients` table.
3. User signs in with username/password and completes MFA (Push or TOTP).
4. KyIdentity redirects the browser back to the registered `redirect_uri` with a short-lived authorization code and the caller's `state`.
5. KyPost exchanges the authorization code and `code_verifier` via `POST /oauth/token`.
6. KyIdentity verifies the PKCE verifier, invalidates the authorization code, and returns an RS256-signed ID Token and access token.
7. KyPost validates the ID token signature against `/.well-known/jwks.json`.

### 5.4 Administrator MFA Reset

1. An administrator opens the target user account in the Admin Dashboard and clicks **Reset MFA**.
2. KyIdentity prompts for explicit confirmation.
3. Upon confirmation, KyIdentity:
   - Revokes all active sessions for the user;
   - Deletes enrolled TOTP secrets, push devices, and recovery codes;
   - Records an immutable audit log entry (actor, target user, timestamp, reason);
   - Queues an account sync event (`user.mfa_reset`) to notify paired KySecurity products;
4. The user is forced to re-enroll MFA on their next login.

## 6. OAuth 2.0 and OpenID Connect Specification

### Endpoints

- `GET /oauth/authorize`: Interactive login, consent, and authorization-code issuance.
- `POST /oauth/authorize`: Form submission for authentication and MFA challenge verification.
- `POST /oauth/token`: Authorization-code exchange for ID token and access token (PKCE required for public clients).
- `GET /oauth/userinfo`: Authenticated endpoint returning user profile claims.
- `POST /oauth/revoke`: Token revocation endpoint.
- `GET /.well-known/openid-configuration`: Standard OIDC discovery metadata.
- `GET /.well-known/jwks.json`: Public RS256 key set for ID-token verification.

### Scopes & Claims

- `openid`: Standard subject identifier (`sub` - immutable UUID).
- `profile`: `preferred_username`, `name` (display name), `updated_at`.
- `email`: `email`, `email_verified` (boolean).

Subject identifiers (`sub`) are internal UUIDs; email addresses or usernames are never used as immutable primary keys.

## 7. Data Model (SQLite Schema)

All tables use standard SQLite data types with strict foreign key constraints.

```sql
-- Core Identity
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('user', 'admin')),
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token_hash TEXT NOT NULL UNIQUE,
    ip_address TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_active_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Cross-System Account Replication & System Pairing
CREATE TABLE paired_systems (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    system_type TEXT NOT NULL, -- 'kypost', 'kypasswords', 'kybookmarks', 'kynotes', 'custom'
    callback_url TEXT NOT NULL,
    hmac_secret_hash TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'failing', 'disabled')),
    last_synced_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE system_pairing_tokens (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    system_type TEXT NOT NULL,
    created_by_user_id TEXT NOT NULL REFERENCES users(id),
    expires_at DATETIME NOT NULL,
    used_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE account_sync_events (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL, -- 'created', 'updated', 'status_changed', 'mfa_reset'
    payload_json TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL CHECK (status IN ('pending', 'delivered', 'failed')),
    last_error TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Native Devices & Push MFA
CREATE TABLE native_devices (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_name TEXT NOT NULL,
    device_identifier TEXT NOT NULL,
    public_key TEXT,
    push_token TEXT,
    is_mfa_approver BOOLEAN NOT NULL DEFAULT 0,
    last_seen_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, device_identifier)
);

CREATE TABLE device_pairing_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    pin_code TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    used_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE mfa_methods (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    method_type TEXT NOT NULL CHECK (method_type IN ('totp', 'push')),
    encrypted_secret TEXT, -- AES-GCM encrypted TOTP secret
    is_primary BOOLEAN NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE mfa_challenges (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    method_type TEXT NOT NULL,
    match_digits TEXT NOT NULL,
    decoy_digits_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE recovery_codes (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- OIDC & OAuth Clients
CREATE TABLE oauth_clients (
    id TEXT PRIMARY KEY,
    client_name TEXT NOT NULL,
    client_type TEXT NOT NULL CHECK (client_type IN ('public', 'confidential')),
    client_secret_hash TEXT,
    redirect_uris_json TEXT NOT NULL,
    allowed_scopes_json TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE authorization_codes (
    id TEXT PRIMARY KEY,
    code_hash TEXT NOT NULL UNIQUE,
    client_id TEXT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    used_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Application Launcher
CREATE TABLE applications (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    icon_name TEXT NOT NULL,
    description TEXT,
    sort_order INTEGER NOT NULL DEFAULT 0,
    enabled BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Security Audit Events
CREATE TABLE audit_events (
    id TEXT PRIMARY KEY,
    actor_id TEXT,
    actor_username TEXT,
    action TEXT NOT NULL,
    target_id TEXT,
    target_type TEXT,
    ip_address TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
    details_json TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

## 8. Roles & Permissions

| Capability | Regular User | Administrator |
| :--- | :---: | :---: |
| Sign in / Sign out with SSO | Yes | Yes |
| Complete TOTP / Push MFA | Yes | Yes |
| View Application Launcher | Yes | Yes |
| Manage personal MFA & pair mobile devices | Yes | Yes |
| View / generate personal recovery codes | Yes | Yes |
| Enrol and remove personal passkeys | Yes | Yes |
| Create, disable, update, delete users | No | Yes |
| Pair downstream KySecurity products (generate pairing key) | No | Yes |
| Trigger manual account directory resyncs | No | Yes |
| Reset user MFA & revoke user sessions | No | Yes |
| Register & rotate OAuth/OIDC clients | No | Yes |
| Manage application launcher links | No | Yes |
| View security audit log stream | No | Yes |

## 9. Security & Cryptographic Requirements

- **Password Hashing**: Passwords are hashed using Argon2id with memory $\ge 64\,\text{MB}$, iterations $\ge 3$, parallelism $= 4$. Minimum password length is 12 characters.
- **MFA Secrets Encryption**: TOTP secrets are encrypted at rest using AES-GCM (256-bit). The master encryption key is loaded via environment variable or Docker secret, never stored in SQLite.
- **OIDC Token Signing**: ID tokens are signed with RS256. The private RSA key is stored in the Docker protected volume/secret, and the public key is exposed at `/.well-known/jwks.json`.
- **System Sync Authentication**: Webhook replication payloads are signed with HMAC-SHA256 using the mutual secret established during UI pairing.
- **Passkey Verification**: WebAuthn assertions are ES256 only, verified with `crypto/ecdsa` against an SPKI public key recorded at enrolment. Challenges are 256-bit, single-use, bound to one user and one ceremony purpose, and expire in three minutes. A signature counter that fails to advance rejects the assertion unless the authenticator reports zero throughout.
- **Rate Limiting**: IP-level and account-level rate limits are applied to `/oauth/authorize`, `/oauth/token`, `/api/notifications/native/register`, and MFA challenge endpoints.
- **Session Security**: Browser cookies are flagged `HttpOnly`, `Secure` (over TLS), and `SameSite=Lax` (or `Strict` for dashboard actions). CSRF tokens are enforced on all state-modifying requests.
- **Auditing & Logging**: Structured logs emitted to stdout/stderr. No passwords, tokens, client secrets, recovery codes, or TOTP secrets are ever logged.

## 10. Visual Design & Frontend Architecture

The frontend follows the existing KySecurity visual system and conventions:

- **Styling**: `css/styles.css` with dark `#0d0f14` background, `#161a22` panel containers, and `#4deeea` cyan accent.
- **Typography**: Space Grotesk for headings and display labels; IBM Plex Mono for technical metrics, codes, keys, and navigation.
- **Accessibility**: Strict keyboard focus indicators, ARIA attributes, and accessible contrast ratios.
- **Tech Stack**: React 19, TypeScript, Vite, React Router. Bundled into a static distribution and served directly by the Go HTTP server with single-binary deployment (`embed.FS`).

## 11. Operational & Deployment Architecture

- **Docker Container**: Multi-stage build producing a static Go binary running as a non-root user (`nobody` or `kyidentity:kyidentity`).
- **Network**: Defaults to attaching to the shared `kypost-net` Docker network so that KyIdentity and KyPost (and other KySecurity suite services) can communicate directly over internal Docker DNS (`http://kyidentity-server:5867`).
- **Data Persistence**: SQLite database and cryptographic keys stored on a dedicated Docker volume mounted at `/data`.
- **Configuration**: Fully configurable via environment variables:
  - `KYIDENTITY_BIND`: Interface address to bind container port publishing to (default `0.0.0.0` for network access, or `127.0.0.1` for loopback-only).
  - `KYIDENTITY_ISSUER_URL`: Public canonical base URL (e.g., `https://auth.example.com`).
  - `KYIDENTITY_DB_PATH`: Path to SQLite database file (default `/data/kyidentity.db`).
  - `KYIDENTITY_SECRET_KEY`: Master secret for session and cookie signing.
  - `KYIDENTITY_ENCRYPTION_KEY`: Master key for AES-GCM secret encryption at rest.
  - `KYIDENTITY_RSA_KEY_PATH`: Path to private RSA signing key for OIDC JWTs.
  - `KYIDENTITY_SESSION_TTL` / `KYIDENTITY_SESSION_IDLE_TTL`: Absolute and inactivity limits for browser sessions (defaults: `24h` / `30m`).
  - `TRUSTED_PROXY_CIDRS`: Trusted upstream reverse proxy CIDRs for real client IP extraction.
- **Bootstrap CLI**: Initial administrator account created via CLI flag (e.g., `kyidentity bootstrap-admin --username admin`) or environment variables on first start without logging credentials.

## 12. Verification & Automated Testing

The implementation must include runnable unit and integration checks verifying:

1. **Account Replication**: User creation/modification triggers signed outbound sync webhooks with proper retries.
2. **System Pairing**: 90s system pairing token validation, mutual registration, and replay rejection.
3. **Device Pairing**: 90s device pairing PIN/QR validation, native device registration, and single-use enforcement.
4. **Push MFA Engine**: 2-digit number match validation, decoy selection, and timeout expiration.
5. **OIDC & PKCE**: Authorization-code flow, PKCE code-challenge verification, RS256 JWT signature and claims validation.
6. **MFA Reset & Revocation**: Admin MFA reset revokes all active sessions and invalidates existing devices/secrets.
7. **Security Controls**: Argon2id password verification, brute-force rate limiting, and CSRF protection.

## 13. Delivery Phases

### Phase 1: Foundation, OIDC & System Replication Core
- Go HTTP server, SQLite migrations, Dockerfile.
- User management, Argon2id auth, session handling.
- OIDC authorization-code flow with PKCE and RS256 JWKS.
- UI system pairing key generator & downstream KySecurity product account sync dispatcher.
- Admin user management and paired systems UI.

### 2. Phase 2: Native MFA & Device Pairing
- Encrypted TOTP enrollment and time-step verification.
- Native device pairing (`/api/notifications/native/register`) with 90s PIN/QR codes.
- Push challenge engine with 2-digit number matching and mobile polling/respond endpoints.
- Admin MFA reset, session revocation, and audit logging.

### Phase 3: Application Launcher & Suite Polish
- User dashboard with application cards (KyPost, KyBookmarks, KyNotes, KyPasswords).
- Paired system health monitoring and manual resync tools.
- Complete visual styling integration with KySecurity CSS and fonts.
