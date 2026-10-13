# Paired KyPost recovery evidence (version 1)

This export reports current KyIdentity authority for an exact requested set of
restored subjects. Ordinary resync only re-sends current in-scope accounts; absence
from resync cannot prove that a restored account lost access or was deleted.
The export does not release either product's restore hold. KyPost admission and
restore-release consumers are separate work and are not implemented by this API.

## Request and operator boundary

`POST /api/admin/systems/{id}/recovery-evidence` requires a global administrator,
a live session, CSRF protection, and a single-use operation-bound step-up grant.
The grant binds the HTTP method and path, **not the request body**. Existing
`X-KyIdentity-StepUp` authentication applies. This is an API export; there is no
new UI, scheduled delivery, or outgoing callback.

```json
{"nonce":"64 lowercase hexadecimal characters","subjects":["restored-subject-id"]}
```

The future KyPost consumer must generate a cryptographically random 32-byte nonce
and retain its exact expected subject set. The exporter validates the canonical
encoding; it cannot prove that the requester generated random bytes. Subject IDs
are case-sensitive, 1–128 ASCII letters, digits, hyphens or underscores. Include
1–256 unique subjects; empty lists, duplicates, unknown request fields, trailing
JSON and bodies exceeding 64 KiB are rejected with 400. The whole set is one
snapshot: do not split a larger recovery into independently trusted pages.

The connection must have type `kypost`, status `active`, no provisioning hold and
a decryptable pairing secret accepted by syncauth. Disabled/failing, restored/held,
generic SCIM and other connection types are refused with 409. A missing connection
returns 404. Missing linkage, storage or audit failures fail without evidence.
A missing linkage currently returns 404 too. Complete output over 256 KiB returns
413 without a signature; keep restore held. Profiles are never truncated.

Do not use the existing manual provisioning-resume override as evidence that a
restored KyIdentity database is current. Operators must establish which identity
instance and live directory are authoritative before consuming any recovery export.

## Exact signed response

Success returns `application/json`, `Cache-Control: no-store`, the exact signed
JSON bytes, and these existing syncauth headers:

- `X-KySignOn-Signature`: existing `v1=` HMAC-SHA256 signature.
- `X-KySignOn-Timestamp`: issuance time, UTC RFC3339.
- `X-KySignOn-Event-Type`: `recovery.evidence` (distinct from directory events).
- `X-KySignOn-Event-ID`: the request nonce.

Preserve response headers and bytes together; parsing and reserializing the body
invalidates its signature. The secret never travels in either headers or body.
HMAC proves possession of the shared pairing secret, **not independent asymmetric
issuer authorship**: the paired KyPost server also holds that secret.

The body contains `version:1`, configured `issuer` (never derived from Host or
forwarded headers), `systemId`, `nonce`, `issuedAt`, `expiresAt` (five minutes after
issuance), and `subjects` in request order. There is exactly one entry per requested
ID, with `id`, `revision`, and `profile`:

- Current effective access to this connection's linked app produces the existing
  active SCIM profile and app-specific roles. Existing global-role compatibility
  applies when the app has no role definitions. Administrators have no scope bypass.
- Deleted, disabled, expired, unknown or unassigned subjects produce only
  `{"id":"…","externalId":"…","active":false,"roles":[]}`. Their identity,
  address, global role and other app roles are not disclosed.
- `revision` is the existing user resource ledger revision for this connection,
  including retained acknowledged offboarding/deletion. An absent ledger is
  explicitly `null`; it is not revision zero or proof that no older event exists.
  This is an observed ledger revision, not a newly allocated recovery fence or proof
  that the profile was queued at that revision. Live expiry can change access
  without advancing the ledger. Completeness covers the requested set only.

System state, encrypted credential, app linkage, database access/role state and
ledger revisions are read in one immediate SQLite transaction. Local signing
and the `admin.recovery_evidence_exported` audit must both succeed before bytes or
signature headers are published. The audit records actor, system and subject
count, not the challenge, profiles or credentials. No queue, hold, assignment or
revision is changed. The transaction prevents concurrent authority mutations
from interleaving with the snapshot; live expiry predicates still apply during
its reads. Authority can change immediately after commit, so this is bounded
point-in-time evidence, never a durable permission grant.

## Required consumer rules (not yet shipped)

Verify exact bytes using the configured pairing key and require the distinct event
type, matching nonce/event ID, version, configured issuer and connection identity,
complete exact subject set, valid issuance/expiry and an unspent fresh challenge.
Consume the challenge durably once. Enforce an admission barrier against concurrent
directory changes and use per-subject revision fences: an older signed active
webhook must not undo an inactive recovery result. A `null` revision needs an
explicit ordering policy; do not invent a floor or silently accept stale events.
Do not pass this artifact to ordinary user-update handlers.

Even verified evidence cannot release KyPost without the other native restore
gates: domain/account ownership, retained storage and namespace safety, credential
revocation, outbox quarantine and receiving state. Incomplete or disputed authority
keeps the whole restore held. Live provider delivery and physical clients require
separate operator qualification.

## Verification

`go test -race ./internal/store ./internal/api -run 'TestRecoveryEvidence|TestPermissionMatrixCoversEveryAdminRoute'`
checks acknowledged loss/deletion, unknown revisions and no profile disclosure,
scoped direct/group roles, expiry, held/unsupported authority, bounded input/output,
audit/signing failure, real route step-up/permissions, exact-byte tampering and event
purpose substitution, and serialization with a concurrent assignment mutation.
