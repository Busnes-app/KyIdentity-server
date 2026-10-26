# Assurance case

[Product overview](../README.md) · [Security](../SECURITY.md) · [Architecture](ARCHITECTURE.md)

This is the argument that KyIdentity meets its security requirements: what it protects, from whom,
where the trust boundaries are, and why the design and the code hold at each one. The detailed
behaviour lives in [SECURITY.md](../SECURITY.md); this page ties it together and points at the
evidence. Where a claim names code, the path is relative to the repository root.

## What KyIdentity must protect

KyIdentity is the OpenID Connect provider and user directory for one organisation. Its security
requirements:

1. **Only the right person signs in as an account.** Passwords, second factors, sessions and
   tokens cannot be guessed, replayed, stolen from storage or forged.
2. **Apps get only what was granted.** An authorization code or token reaches only the app and
   redirect URI it was issued for, with only the scopes, roles and claims assigned to that user.
3. **Access ends when it should.** Disabling a user, removing a grant, signing out or changing a
   password takes effect at once in KyIdentity and is pushed to connected apps.
4. **Secrets at rest stay secret** from anyone who copies the database without the key files.
5. **The server cannot be turned against the network it sits in** (no server-side request
   forgery through operator- or device-supplied URLs).
6. **What happened is recorded.** Security-relevant actions are in the audit log, and no secret
   ever reaches a log.

## Threat model

| Attacker | Can | Wants |
|---|---|---|
| Anonymous internet client | Send any request through the TLS proxy | Take over an account, guess passwords, exhaust resources |
| Signed-in ordinary user or delegate | Use their own session and APIs | Reach admin functions or other users' data |
| Malicious or compromised relying party | Register redirect URIs (if an admin lets it), receive codes and tokens | Get codes or tokens meant for another app, widen its scopes |
| Network attacker between browser and proxy | Read and alter traffic | Steal sessions or codes |
| Push relay, Google/Apple push, UnifiedPush distributor | See push traffic | Learn who signs in where, or forge an approval |
| Someone with a copy of the data volume or a backup | Read the database file | Recover passwords, TOTP secrets, connector credentials |
| Stolen or cloned phone | Hold a paired device | Approve sign-ins |

Out of scope: an attacker who already runs code on the host or holds the data volume **and** the
key files (they are the server), and a malicious administrator. Both are covered by deployment
guidance, not by the software. See [Known limitations](../SECURITY.md#known-limitations--trust-boundaries).

## Trust boundaries

1. **Browser and apps → TLS proxy → KyIdentity.** KyIdentity serves plain HTTP and trusts
   forwarded headers only from `TRUSTED_PROXY_CIDRS`, and only one named client-address header,
   read right to left (`internal/api/middleware.go`). Startup refuses a non-loopback `http://`
   issuer, and the `docker` CI job proves it.
2. **KyIdentity → outbound targets** (SCIM and suite connectors, back-channel logout, UnifiedPush,
   UBports, push relays). Calls use the guarded `internal/netguard` client: HTTPS by
   default, no redirects, and destination checks at connect time. Explicit private-callback
   compatibility may permit HTTP, outside the supported TLS configuration; loopback,
   link-local and metadata remain refused.
3. **KyIdentity ↔ paired devices.** Pairing needs a 90-second token and PIN, stored only as
   hashes. Approvals are signed by a device key; Android keys are graded from a Keystore
   attestation chain (`internal/attest`), iOS from App Attest (`internal/appattest`).
4. **KyIdentity → its data volume.** Secrets are sealed or hashed before they reach SQLite; the
   keys live in separate `0600` files.
5. **Administrator → KyIdentity.** Permissions are recomputed per request; destructive actions
   need step-up re-authentication.

## Secure design principles applied

- **Least privilege.** Delegated roles (`auditor`, `helpdesk`, `app_owner`) give narrow rights
  instead of full admin; `helpdesk` can never act on administrators. Apps receive only assigned
  scopes and roles (`internal/api/permissions.go`, `internal/store/delegations.go`).
- **Fail-safe defaults.** Forwarded headers are ignored until a proxy is named. Private outbound
  targets are refused unless explicitly allowed. A wrong-length key is a startup error, never a
  weaker key. A full rate-limit table refuses new buckets rather than evicting old ones.
- **Complete mediation.** Permissions are never cached in the session; every request recomputes
  them, so a demotion or disable takes effect on the next request.
- **Economy of mechanism.** Go’s standard library and established FLOSS libraries
  implement HTTP, JWT signing, TOTP and AES-GCM ([ARCHITECTURE.md](ARCHITECTURE.md)).
- **Separation of privilege.** Multi-factor sign-in, step-up for destructive admin actions, and
  KyIdentity refusing to remove the last active administrator.
- **Open design.** Only published algorithms (Argon2id, AES-256-GCM, HMAC-SHA-256, RSA and ECDSA
  signatures, RFC 8291 push encryption); the code and this argument are public.
- **Psychological acceptability.** Each place where security yields to convenience is
  documented where the operator reads it ([CONTRIBUTING.md, the user contract](../CONTRIBUTING.md#the-user-contract)).

## Common weaknesses and how they are countered

| Weakness | Counter | Where |
|---|---|---|
| Broken authentication, credential stuffing | Argon2id (64 MiB, 3 passes), 10-failure lockout, per-address rate limits on every auth step, bounded hashing concurrency | `internal/auth/password.go`, `internal/api` |
| Session theft or fixation | Random session token, only its SHA-256 stored; `HttpOnly`, `SameSite=Lax`, `Secure` behind HTTPS; idle and absolute expiry; revoked on sign-out and password change | `internal/store/sessions.go` |
| CSRF | Double-submit token signed with `secret.key` on every state-changing request | `internal/api/middleware.go` (`CSRFValidate`) |
| Authorization-code interception and injection | PKCE with S256 required for every client, confidential ones included; exact redirect-URI match | `internal/oauth/oauth.go`, `internal/api/oauth_handlers.go` |
| Token forgery and algorithm confusion | ID and access tokens are RS256 only; device assertions accept exactly `alg=ES256`, `typ=JWT` with a `kid` | `internal/oauth` |
| Broken access control and privilege escalation | Per-request permission computation; delegates cannot reach admin routes; tests for each escalation path | `internal/api/permissions.go`, `internal/api/security_test.go` |
| SQL injection | `database/sql` with `?` parameters throughout; the only dynamically built statements take table and column names from a fixed internal list | `internal/store` (`sealed.go`) |
| Cross-site scripting | React escaping (no `dangerouslySetInnerHTML`); a CSP with `script-src 'self'` and `frame-ancestors 'none'` | `web/`, security headers in `internal/api` |
| Server-side request forgery | One guarded outbound client, destination checked at connect time | `internal/netguard/netguard.go` |
| Secrets at rest | AES-256-GCM with a per-purpose derived key and the row identity as associated data, so a ciphertext copied to another row does not open | `internal/crypto`, `internal/store/sealed.go` |
| Secrets in logs | A logging contract that forbids passwords, tokens, keys, codes and push endpoints, plus audit-export redaction | [LOGGING.md](../LOGGING.md) |
| Vulnerable dependencies | Dependabot, `govulncheck` and `npm audit --audit-level=low` in CI; a dependency release ships updates daily | `.github/workflows/` |
| Supply-chain tampering | Actions pinned by commit; release images carry a build-provenance attestation checked before `:stable` moves; the binary rebuilds to the same bytes | [VERIFYING-RELEASES.md](VERIFYING-RELEASES.md) |

## Residual risk

Known limitations are listed, not hidden: the unsealed push identifiers for older Android
pairings, `appattest` not counting as MFA, process-local rate limits, no key rotation for
`encryption.key`, and account metadata stored unencrypted. Each is in
[SECURITY.md](../SECURITY.md#known-limitations--trust-boundaries) with what to do about it.

## Evidence

- **Tests:** each security-relevant package has a `security_test.go` (`internal/api`, `config`,
  `crypto`, `mfa`, `oauth`, `sync`); CONTRIBUTING requires attack-path tests for security changes.
  CI runs the whole suite under the race detector on every push and pull request.
- **Static analysis:** CodeQL on every push and pull request, `go vet`, and `govulncheck`.
- **Dynamic analysis:** the race detector on the full suite, a Go native fuzz target for the App
  Attest parser (its seed corpus runs with every test run), and container smoke tests that prove
  a public HTTP issuer is refused.
- **Review:** every change goes through a pull request with green CI and an adversarial review
  ([CONTRIBUTING.md](../CONTRIBUTING.md#every-pr-must-pass-hostile-ai-code-review)).
- **Releases:** attested images and a repeatable binary ([VERIFYING-RELEASES.md](VERIFYING-RELEASES.md)).

This case is updated when a trust boundary or a security requirement changes. A pull request that
moves one must update this page in the same change.

## Key-strength evidence and limits

[STRONG-CRYPTO.md](STRONG-CRYPTO.md) inventories every key boundary and the optional
Go TLS configuration. The source refuses short TOTP keys, attestation CA keys
(including omitted trust anchors), RSA token-signing keys and FCM signing keys;
regressions use real signatures and retained enrollment records.
The FCM regression also runs the actual provider function in the lockfile-native
workerd runtime: byte-rounded short keys are refused, RSA-2048/3072 signatures
verify and an already issued cached token remains usable. Its temporary JWK
inspection stays within the process already holding the private PEM; the signing
key is re-imported non-extractable. This checks signing keys, not TLS peers.

The process profile covers Go certificate policy, not the HTTPS edge or Cloudflare's Worker
TLS implementation. The latter remains a separate evidence gap; no complete
whole-repository key-length claim follows from these source checks alone.
