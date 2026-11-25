# Suite keyring, wire version 1

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

Every envelope is `nonce[12] || AES-256-GCM ciphertext[32] || tag[16]`.
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

Both browsers must have independent live sessions for the same account. The
recipient generates an ephemeral P-256 key pair, a random request UUID and a
256-bit random approval secret. Its public key is an uncompressed SEC1 point.
Define the transcript prefix as
`["ky-keyring/1","transfer",issuer,org_id,user_id,keyring_version,transfer_id,recipient_key]`.
Send the point and HMAC-SHA-256 of the UTF-8 compact JSON prefix keyed by the
approval secret. Convey the code `KYT1.<transfer_id>.<approval_secret>` over
an independent trusted channel to the existing trusted browser. The code and
private keys stay off the server.

The trusted browser fetches the public request and verifies the MAC against the
received code before it generates its own ephemeral P-256 key pair. Append the
sender's public point to the prefix to obtain the transfer AAD. Both browsers
derive the AES key by HKDF over the 32-byte ECDH result, with the approval
secret as salt and the transfer AAD as info. The sender seals the SRK. The
recipient claims the response once, validates and opens it, and registers its
own locally wrapped SRK. A lost claim response, page reload or expiry requires
a fresh transfer. Cancel from the requesting browser before leaving it.

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

Wrapper upload fields are `id`, `kind`, `sealed`, plus `device_hash` for a device
or `credential_id` for PRF. The account's app routes resolve the OAuth client ID
through `app_registry` and check `effective_app_access` on every call.
`GET /api/keyring/app` accepts a signed, live KyIdentity OAuth **access token**
in `Authorization: Bearer`. It reads only that token's own client and subject
and verifies its registered token/session and current effective app access.
Apps cannot read SRK wrappers or write app envelopes with their tokens.
An integrating app needs its own client-side handoff for its plaintext subkey.
App keys are not placed in OIDC claims, and no cross-origin handoff is defined
by these endpoints. Rotating a subkey replaces the prior envelope. Coordinate
re-encryption or retention of the old key in the app before rotation.

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
