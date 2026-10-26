# Key strength and the Go TLS profile

[Installation](../INSTALL.md) · [Security policy](../SECURITY.md) · [Upgrades and recovery](UPGRADES-AND-RECOVERY.md)

This guide describes key-size enforcement and the optional Go process TLS
configuration. It does not certify a deployment, the external HTTPS proxy or
Cloudflare's Worker TLS implementation. Keep those boundaries separate when
assessing the whole repository; a successful Go configuration is not evidence
that a different runtime enforces the same certificate policy.

## Preserve existing identity and recovery material

Keep the database, `secret.key`, `encryption.key`, RSA signing key, VAPID key,
recovery public-key pin, sealed KyRecovery token, local capsules, existing
configuration and custodian cards. Retain the original data volume and Compose
network/image/build choices. Do not replace any key or regenerate enrollment
records merely because an endpoint no longer connects.

The root primitives module is pinned to merged source `bae5c14dba4c`
(`v0.10.2-0.20261026050236-bae5c14dba4c`). The old `v0.10.0` tag predates its
TOTP floor. This revision also includes capsule tar-budget and Shamir sampling
repairs; the container, key and share formats remain the same. Existing row
secrets remain sealed to their original purpose/identity. Verify backup and
restore compatibility when upgrading; a new default is not a reason to discard
an older archive or custody record.

## Key rules in every mode

| Boundary | Enforced policy |
| --- | --- |
| Deployment and row secrets | `secret.key` and `encryption.key`, or their hex environment forms, must decode to exactly 32 bytes. Existing wrong-length files are refused, never overwritten. AES-256-GCM row envelopes retain their keys and authenticated row/purpose binding. |
| OIDC token signing | RSA-2048+ PKCS#1/PKCS#8 keys; generated keys remain RSA-2048. The existing loader refuses smaller keys without rotating them. Device assertions and WebAuthn credentials use P-256/ES256. |
| Directory signatures | `ky-primitives/syncauth` refuses HMAC keys below 16 literal bytes. Generated suite secrets use 32 random bytes; prefer generated, independently scoped secrets. Length alone does not establish entropy. OAuth/SMTP/relay passwords and bearer tokens have their separate authentication rules. |
| TOTP | Generate 20 random decoded bytes. New enrollment and verification require at least 16 decoded bytes through the shared RFC 4226/6238 implementation. Rejected enrollment does not overwrite the current method. Existing weak records remain stored but cannot authenticate; use another enrolled factor, recovery or deliberate administrator reset to re-enroll. Recovery codes and other factors are retained. |
| Android attestation | The successfully verified certificate chain, including an omitted trust anchor selected from configured roots, must use RSA-2048+, EC-224+ or fixed Ed25519 keys. Device signing keys remain P-256. This is separate from TLS and applies to extra/fetched roots too. Failure grades the attestation `none`; it does not delete the device or grant hardware MFA. |
| Apple App Attest | At least one verified chain to the pinned Apple root must meet the same certificate-key floor, including every intermediate/root. The actual leaf key remains P-256. An App Attest grade proves app integrity, not hardware/user-presence MFA. |
| Push payloads and VAPID | RFC 8291 uses P-256, a 16-byte authentication secret, HKDF-SHA256 and AES-128-GCM; VAPID is P-256/ES256. Imported push points/auth bytes are checked at registration/refresh. Existing VAPID keys are retained. |
| Bundled FCM Worker | WebCrypto imports the service-account key as RS256, then checks the actual RSA modulus is at least 2048 bits before signing/contacting Google. Replace an undersized credential with a provider-issued strong one; do not alter device registrations. Already cached Google bearer tokens keep their existing expiration/revocation behavior. |
| Bundled APNs Worker | WebCrypto imports only P-256 ECDSA keys for ES256 provider tokens. Keep the provider key ID/team binding when rotating a credential. |
| Recovery | Products seal fixed-suite `kycap/3` containers to the pinned suite public key. KyIdentity's server does not open them. Restore is an explicit offline CLI action requiring the recorded digest and custodian shares. Transport changes never replace the pin or change historical decryptability. |

The attestation fixtures use generated CAs; they prove policy, not successful
real-hardware pairing. The embedded Google and Apple trust roots and all
production endpoint/custody choices need their own operational review.

## Enable the Go TLS profile

Use the Go toolchain selected by `go.mod` and the pinned Docker builder. Set
`GODEBUG=fips140=on` before starting the server and any remote Go CLI process.
Use `on`, not Go's diagnostic `only` mode: the suite's Argon2id and recovery
formats remain supported. This is not a FIPS certification claim.

For a process or systemd installation, retain its invocation/data paths and add
`GODEBUG=fips140=on` to its environment. Preserve other needed GODEBUG entries,
with the `fips140` entry set to `on`, then restart the process. A shell setting
does not reconfigure an already running service/container.

For Compose, append `docker-compose.strong-crypto.yml` to the existing
`COMPOSE_FILE` chain in the protected `.env`, retaining its original separator,
base, build and LAN-DNS overlays. The base file uses an explicit environment
map, so merely adding `GODEBUG` to `.env` does not forward it. The optional
overlay forwards the setting and changes nothing else. If another overlay
supplies other GODEBUG entries, preserve them deliberately together with
`fips140=on` in the final resolved setting.

Review resolved configuration privately because it includes secrets. Pull the
chosen verified image, or rebuild with the retained source-build overlay, and
recreate the service with the same chain. Existing published images must
contain these changes before this guide's key rules apply.

`python3 docs/check-strong-crypto-compose.py` uses synthetic inputs, starts no
containers and compares all resolved configuration in four chains: base,
source-build, LAN-DNS and source-build plus LAN-DNS. Removing its one added
GODEBUG entry must leave the entire configuration identical.

Go's selected TLS policy filters certificate chains, including explicitly
trusted roots/intermediates: RSA-2048+ and approved P-256/P-384/P-521/fixed
Ed25519 keys. Keep certificate/hostname verification enabled. This applies to
Go HTTPS clients (provisioning, logout, push, attestation refresh and recovery)
and SMTP's implicit TLS and STARTTLS. Private trust roots do not waive the
floor. A trusted-root regression exercises the real operator/device netguard
clients with a strong server leaf, so server-side key refusal cannot substitute
for checking the client's policy.

Choose HTTPS for every stored callback/SCIM, logout, relay, UnifiedPush,
attestation and recovery endpoint. Keep SMTP configured for verified implicit
TLS or required STARTTLS. `KYIDENTITY_ALLOW_PRIVATE_CALLBACKS` is a separate
legacy compatibility switch that can permit plain HTTP; such endpoints are
outside this TLS configuration. Go's setting does not upgrade an HTTP URL.
If private callbacks are needed, use verified HTTPS and review every stored
endpoint, not only the current environment default. Never disable verification
to bypass an incompatible certificate; replace the endpoint's chain instead.

## Configure the independent HTTPS edge

KyIdentity serves internal HTTP. Put it behind a trusted TLS proxy and restrict
backend reachability to that proxy. Use TLS 1.2/1.3 and a verified RSA-2048+ or
P-256+ certificate chain. For Nginx/OpenSSL the relevant policy includes:

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'DEFAULT@SECLEVEL=2';
```

Configure the actual certificate/key paths and routes, HTTPS issuer, secure
cookies and exact trusted proxy address as described in SECURITY.md. Verify
that edge before rollout; `GODEBUG` does not configure Nginx, browsers or native
clients.

## Worker and platform limits

Go's environment does not configure Cloudflare Workers. Their signing-key
checks above apply to the bundled Worker source; deployments need that source
revision. Worker `fetch` uses Cloudflare's TLS implementation against the fixed
Google/Apple HTTPS provider hosts. This guide does not establish that runtime's
minimum certificate-key policy, and a successful local Node/WebCrypto test
cannot establish it. Verify that platform boundary independently before using
this guide as whole-repository OpenSSF key-length evidence. No Worker secret,
provider deployment, device enrollment or production TLS edge is changed here.

## Verification and rollout

Run the complete ordinary and `GODEBUG=fips140=on` race suites, build/vet and
module/vulnerability checks, full web and Worker checks, Compose preservation,
repeatable binaries and Docker health/refusal smoke. Run `backup-drill` against
a throwaway instance; retain the expected missing-recovery-pin finding on an
unpaired fixture. Verify that retained secret/RSA/VAPID key bytes and original
MFA/connector credentials still work after restart.

Then check the actual TLS edge, normal sign-in, generated TOTP enrollment and
replay refusal, applicable hardware attestation, each connector and push path,
backup receipts and an offline restore using the proper custody procedure.
Local tests are evidence for the checked source, not proof of a live rollout.

Primary references: [RFC 4226 key requirements](https://www.rfc-editor.org/rfc/rfc4226#section-4),
[RFC 6238](https://www.rfc-editor.org/rfc/rfc6238),
[Go FIPS runtime policy and platform limits](https://go.dev/doc/security/fips140).
