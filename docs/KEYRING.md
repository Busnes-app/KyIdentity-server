# Suite keyring wire formats

KyIdentity stores encrypted key envelopes and authorizes access to them. A browser
generates the 32-byte Suite Root Key (SRK), device secrets and the Suite Recovery
Key. The server and applications never receive the SRK or its wrapping secrets.
The Emergency Kit is separate from MFA recovery codes and KyRecovery custodian
cards. A database backup preserves ciphertext and cannot replace either a working
unlock method or the Emergency Kit.

The threat model covers server-side data disclosure, account-only access to
encrypted data, cross-tenant/app access and a relay substituting transfer keys.
Trust the KyIdentity HTTPS origin and the client code it serves, the unlocked
devices and the channel used to convey the transfer code. An operator who can
change the served JavaScript or compromise an unlocked device can steal client
keys. A relay can deny service or replay old database state. Revocation stops
subsequent server fetches and does not recall locally copied keys or rotate the SRK.

## Encoding

Use unpadded, canonical base64url for binary fields. UUIDs are lowercase
RFC 4122 version 4. The first setup chooses a random `keyring_version` UUID,
which identifies the SRK generation for its lifetime. Keep the issuer stable
so clients can open previously saved envelopes. The session status supplies
the configured `issuer`, opaque `org_id` (including on single-tenant installs)
and immutable `user_id`. These fields come from authentication and configuration.
Setup echoes the organization and subject to bind the request to the account
that started setup.

Every durable wrapper and app envelope is `nonce[12] || AES-256-GCM ciphertext[32] || tag[16]`.
Generate a fresh nonce with the client CSPRNG for each seal. The AEAD additional
data is the UTF-8 encoding of the compact JSON array below (ECMAScript
`JSON.stringify`, no extra whitespace). HKDF means HKDF-SHA-256.

- Device, recovery and PRF AAD is
  `["ky-keyring/1","wrapper",issuer,org_id,user_id,keyring_version,wrapper_id,wrapper_kind]`.
  The HKDF input is the device secret, decoded recovery key or 32-byte WebAuthn PRF
  output, respectively. HKDF salt is 32 zero bytes and HKDF info is the AAD.
- App key AAD is
  `["ky-keyring/1","app",issuer,org_id,user_id,keyring_version,client_id,key_version]`.
  The HKDF input is the SRK, salt is 32 zero bytes and info is the AAD. Generate
  a fresh random 32-byte app subkey per version and encrypt it under the resulting
  KEK. Never give an application the SRK or the KEK for its wrapper.
- A device holds a non-extractable HKDF key in that browser's IndexedDB and an
  independent random 32-byte device access capability. Send the capability as
  `X-Ky-Keyring-Device` only for its own envelope fetch or transfer approval.
  Register SHA-256 of the UTF-8 encoded capability in lowercase hex as `device_hash`. A capability grants
  delivery of ciphertext only, in combination with the correct user session.
- The printable recovery key is `KYR1-` followed by 64 uppercase hex digits
  grouped in eight groups of eight. The browser requires confirmation of the
  key before initialization or rotation. Rotation changes only this wrapper.
- PRF is optional. The browser creates a separate keyring passkey at the
  KyIdentity origin with user verification and requests the `prf` extension.
  Evaluate it at `SHA-256(UTF-8("ky-keyring/1:webauthn-prf"))`. Register a
  wrapper only when a 32-byte result is returned. KyIdentity login factors are
  managed separately. The stored credential ID is public and selects the
  credential for unlock.

## Approve a new device

Both browsers must have independent live sessions for the same account. New transfers
use **KYT2**, HPKE base X-Wing (KEM `0x647A`, HKDF-SHA256, AES-256-GCM) from
`ky-primitives/xwing`, compiled through `cmd/pqwasm`. There is no classical fallback
for a KYT2 transfer. Reload both browsers after upgrading. Migration 19 drops the
five-minute pending/approved P-256 transfers and replaces only that temporary table;
existing SRK wrappers, app envelopes, device capabilities and Emergency Kits stay valid.

The recipient generates an ephemeral X-Wing pair (32-byte private seed, 1216-byte
public key), a random request UUID and a 256-bit random approval secret. Define `T`
as the UTF-8 compact JSON array:
`["ky-keyring/1","transfer-xwing/2",issuer,org_id,user_id,keyring_version,transfer_id,recipient_key]`.
Send the canonical base64url public key and `HMAC-SHA256(approval_secret, T)`.
Convey `KYT2.<transfer_id>.<approval_secret>` over an independent trusted channel.
Neither the secret nor the private seed goes to the server.

The trusted browser verifies the MAC before sealing the 32-byte SRK to that public
key. HPKE info is `UTF8("kyidentity/keyring-transfer/2") || 0x00 || T || 0x00 || approval_secret`
(the final secret is **32 raw bytes**); HPKE AAD is `T`. Including the secret in the
HPKE key schedule retains the out-of-band protection even if the KEM secret were
exposed. The issuer, tenant, subject, ring and transfer ID prevent cross-context replay.
The response is `{sender_key: "xwing:1", sealed: base64url(packet)}`; `sender_key`
is a format marker, not a key. `packet` is the shared helper's versioned format:
`0x01 || enc[1120] || ciphertext[32] || tag[16]` (1169 bytes, 1559 base64url characters).
The requester validates the marker, consumes the response once, opens it, and
registers its locally wrapped SRK. Cancel, expiry, lost claim, reload or failed
opening requires a fresh transfer. Ephemeral seeds and approval secrets stay in
memory and are wiped on completion/cancel/unmount; Go/browser memory reclamation
cannot promise erasure of every copy.

## HTTP

Account routes have prefix `/api/user/keyring` and require the normal session
cookie and KyIdentity CSRF protection. Sensitive mutations (marked *) require a
fresh grant for the exact method and path in `X-KyIdentity-StepUp`. Successful
writes and their audit, including grant consumption where applicable, commit
together. API responses have `Cache-Control: no-store`. JSON mutations reject
unknown fields, trailing documents and bodies over 4 KiB.

| Method and path below the prefix | Request and success |
| --- | --- |
| GET (prefix alone) | Account binding and keyring version, empty version before setup, plus wrapper metadata |
| POST (prefix alone) | * `keyring_version`, echoed `org_id` and `user_id`, `device`, `recovery`. Returns 204. |
| POST /wrappers | * `keyring_version`, `wrapper` of kind device or prf. Returns 204. |
| GET /wrappers/{id} | `id`, `kind`, optional `credential_id`, `sealed`. Device fetch requires its capability |
| DELETE /wrappers/{id} | * Revoke a device or PRF wrapper. Returns 204. |
| PUT /recovery | * `keyring_version`, `previous_id`, replacement recovery `wrapper` with a fresh ID. Returns 204. |
| GET /apps/{client} | Current `key_version` and `sealed` for an app the account can access |
| PUT /apps/{client} | * `keyring_version`, next `key_version`, `sealed`. Creation starts at 1. An empty string revokes an existing key. Returns 204. |
| POST /transfers | `keyring_version`, `id`, `recipient_key`, `request_mac`. Returns `expires_at` (Unix seconds) |
| GET /transfers/{id} | On a different session, the pending `recipient_key`, `request_mac` and the requesting session's `user_agent`, `ip_address` and `signed_in_at`, shown before approval |
| PUT /transfers/{id}/approve | * `sender_key`, `sealed`, `device_id` plus that device's capability. Returns 204. |
| POST /transfers/{id}/claim | The original session consumes approval and receives `sender_key`, `sealed` |
| DELETE /transfers/{id} | The original session cancels the transfer and receives 204 |
| GET /handoff/{id} | Browser-bound completed authorization interaction details, keyring metadata and current app envelope |
| POST /handoff/{id}/complete | Atomically consumes the handoff interaction and mints a fresh OAuth `code`, `redirect_uri` and `state` |
| DELETE /handoff/{id} | Cancels the handoff interaction and returns `redirect_uri` and `state` |

Wrapper upload fields are `id`, `kind`, `sealed`, plus `device_hash` for a device
or `credential_id` for PRF. The account's app routes resolve the OAuth client ID
through `app_registry` and check `effective_app_access` on every call.
`GET /api/keyring/app` accepts a signed, live KyIdentity OAuth **access token**
in `Authorization: Bearer`. It reads only that token's own client and subject
and verifies its registered token/session and current effective app access.
Apps cannot read SRK wrappers or write app envelopes with their tokens.
App keys are never placed in OIDC tokens or claims; cross-origin apps obtain
their plaintext subkey through the OIDC key handoff below. Rotating a subkey
replaces the prior envelope. Coordinate re-encryption or retention of the old
key in the app before rotation.

## Cross-origin OIDC key handoff

An OIDC client on another origin can receive its own 32-byte plaintext app
subkey during authorization code sign-in without exposing the Suite Root Key
to the app or plaintext keys to the server.

1. Before redirecting the browser to `GET /oauth/authorize`, the app generates
   an ephemeral X-Wing key pair (32-byte seed, 1216-byte public key) in memory,
   encodes the public key in canonical unpadded base64url (1622 characters), and passes it as a single `keyring_pk` query parameter alongside
   PKCE (`S256`), `state` and its OIDC `nonce`. An omitted nonce binds as the empty string.
   Legacy RPs may still send their 65-byte P-256 SEC1 public point (87 characters).
   The key length selects the suite; invalid X-Wing keys fail without a downgrade. `keyring_pk` with `prompt=none` returns
   `interaction_required`; duplicate or invalid values return `invalid_request`.
2. After normal authentication, MFA enrollment, password-change and
   `effective_app_access` checks succeed, KyIdentity checks whether the account
   is eligible for a suite keyring. Administrators, staff, export-only and
   workstation sessions bypass the handoff silently and receive a normal OAuth
   code redirect. Eligible member sessions are redirected (`302`,
   `Cache-Control: no-store`) to `/keyring-handoff?interaction=<raw>` bound to
   the `kyidentity_authorization_browser` cookie and the active session
   (ten-minute TTL).
3. On a trusted browser whose local device wrapper and active app subkey exist,
   `/keyring-handoff` unwraps the SRK and target app subkey automatically with
   no extra click. Otherwise it offers inline unlock (passkey PRF, `KYT2`
   approval from another browser, or `KYR1` Emergency Kit), first-time keyring
   setup, first-time app key provisioning, or continuing without an encryption
   key.
4. Once the plaintext app subkey is ready, the KyIdentity page calls
   `POST /api/user/keyring/handoff/{id}/complete`, which rechecks app access
   and atomically deletes the interaction while inserting a fresh single-use
   authorization `code`. For an X-Wing recipient, the page seals through `pqwasm` with AAD `H`:
   `["ky-keyring/1","handoff-xwing/2",issuer,org_id,user_id,keyring_version,client_id,key_version,code,redirect_uri,recipient_key,nonce]`.
   HPKE info is `UTF8("kyidentity/keyring-handoff/2") || 0x00 || H`. The nonce is
   supplied from the original authorization interaction, not browser input. Output
   uses the same 1169-byte helper packet as transfer, with `sender_key: "xwing:1"`.
   Domain labels separate handoff from transfer; all account and authorization
   coordinates are authenticated. No zero-salt classical KDF runs on this path.

   **Only for a legacy P-256 recipient**, generate an ephemeral P-256 sender pair,
   derive ECDH and use HKDF-SHA256 with 32 zero salt bytes, AES-256-GCM and the
   unchanged legacy AAD:
   `["ky-keyring/1","handoff",issuer,org_id,user_id,keyring_version,client_id,key_version,code,redirect_uri,recipient_key,sender_key]`.
   Its `sender_key` remains the sender's 65-byte SEC1 point and `sealed` remains
   the 60-byte nonce/ciphertext/tag envelope. This compatibility path cannot be
   selected by a failed X-Wing seal/open.
5. The page zeroes all local key material and redirects via
   `window.location.replace` to
   `<redirect_uri>?code=<code>&state=<state>#kh=<sealed>&kh_pk=<sender_key>&kh_kv=<key_version>&kh_rv=<keyring_version>`.
   Because the sealed subkey lives strictly in the URL fragment, it is never
   sent to any HTTP server or access log. The app clears `window.location.hash`
   immediately, exchanges `code` via PKCE, confirms `issuer`, `org_id`, `sub`
   (`user_id`), `client_id` and `redirect_uri`, opens `kh` with its ephemeral
   private seed (or legacy private key) using the same info/AAD, and discards the ephemeral key pair.

`kh_pk=xwing%3A1` explicitly identifies the new fragment format. Upgraded RPs
must validate that marker and the helper packet version, confirm the original
nonce and authorization coordinates after PKCE exchange, and refuse downgrade.
Existing RPs keep their P-256 fragment byte format until their own JS upgrades.
This repository changes no RP deployment. URL regression tests exercise a full
OIDC authorize/login/complete/exchange flow for both key sizes, and require the
representative authorize and callback URLs to fit 2048 characters. Longer RP
redirect URIs, state or scopes can exceed that budget; verify the actual deployment's
browser/proxy request-line limits (use at least 8 KiB) before rollout.

## Browser build

`web/build-pq.mjs` builds the **go.mod-pinned** `ky-primitives/cmd/pqwasm` with
`-trimpath`, uses the image's exact Go 1.27.4 toolchain, and copies its matching
`wasm_exec.js`. Keep that script toolchain in step with the Docker Go stage. `npm run dev`, `npm test`
and `npm run build` run this first and require Go as well as Node. Docker builds
the same helper in its pinned Go stage before Vite; CI installs that Go version
for the web job. Vite emits content-addressed assets. WASM and `.pq/` are ignored,
never committed; always build the frontend before building a shipping Go binary.
The browser lazily loads same-origin runtime/WASM assets only when X-Wing is used.
CSP allows `wasm-unsafe-eval` for compilation, with JavaScript `unsafe-eval` still
refused. The WASM is about 4.2 MB raw / 1.2 MB gzip; configure proxy compression
for `application/wasm`. The runtime does not use a CDN or fetch third-party code.
Vitest executes the actual WASM against upstream vectors and committed Go/browser
keyring packets; Go independently reconstructs and authenticates the same transcripts.

If `complete` fails, the interaction is still live: the page wipes all key
material and offers **Try again** (reloads the interaction and unlocks again)
and **Cancel sign-in**. If sealing or redirecting fails after `complete`
succeeded, the interaction and its code are spent: the page wipes key material,
drops the code and offers **Restart sign-in**, an OAuth error redirect
(`error=server_error`, `state`, no `code`) so the app starts a fresh
authorization with a new `keyring_pk`.

Missing, unreleased or expired items return 404. Denied access and missing or
spent grants return 403. Conflicts and count limits return 409. Excessive
request rates return 429. The limits are 16 device/PRF wrappers,
one recovery wrapper, 128 app slots (including revoked versions), and four
pending or approved transfers per account with at most one per requesting
session. Transfers expire after five minutes. Revoking an approving device
also cancels its unclaimed approvals. KyIdentity administrators and staff
accounts have no keyring access, including when they hold a bearer token.

Disablement ends access and drops transfers. Permanent deletion or erasure purges
that subject's encrypted keyring through scoped deletion and foreign keys. The
restore marker drops transfers and login grants and preserves durable envelopes
from the snapshot. Restoring a snapshot can bring back earlier recovery and
revocation state. An Emergency Kit must match the restored recovery wrapper.
