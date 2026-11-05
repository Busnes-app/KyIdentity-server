# Upgrades and recovery

[Product overview](../README.md) · [Standalone installation](../INSTALL.md)

Commands and unlinked file paths below are relative to the repository root.

## Proxy trust configuration

Before upgrading, inspect `TRUSTED_PROXY_CIDRS` and `KYIDENTITY_FORWARDED_HEADER`.
Startup now refuses a range wider than its private block with `X-Forwarded-For`
(the default) or `Forwarded`. IPv4-mapped ranges and header-name case variants
receive the same check. The refusal names the offending range and header.

Prefer the exact proxy peer as KyIdentity sees it (`<proxy-ip>/32` or `/128`),
keeping the existing multi-hop header. If a tunnel needs catch-all trust, use its
overwritten single-IP header (Cloudflare: `KYIDENTITY_FORWARDED_HEADER=CF-Connecting-IP`)
and ensure only the tunnel can reach the port. The edge must replace client input,
not append or forward it; direct access to the port remains unsafe with broad trust.
Verify the resolved address through the existing `/api/installer/network` response
and sign-in audit, following [Security](../SECURITY.md#verification-confirm-your-setup).
No client-IP parser or installer-network response change accompanies this check.

## Explicit application administrators

Before upgrading KyIdentity and the KyMessages, KyPulse or ky-server-base receivers:

1. In **App connections**, use the same application identity for the product's OAuth
   client and provisioning connection. Define its exact `admin` role and assign it
   explicitly to the dedicated application administrator (directly or through a group).
   Verify that administrator also has access to the app. Global KyIdentity `admin`
   alone is insufficient; keep everyday identities outside these administrator grants.
2. Verify those assignments before upgrading receivers that require per-app `admin`.
   After this KyIdentity update, app-backed SCIM and signed webhooks send `roles: []`
   if the app has no roles or the user has none. Deleting the final role also clears
   downstream roles; it never restores global administrator status.
3. Upgrade the source and receivers together as a coordinated rollout. On each
   connector use **Resync** (or `kyidentity resync-system --client <client-id> --wait 2m`)
   after the source upgrade to replace retained and queued old profiles; check delivery
   success. Before any new delivery attempt, the source refreshes only the role array
   of unfenced app-backed user events (including old queued profiles and MFA resets)
   from current explicit app assignments. Event ID, type, revision and other profile
   fields stay intact. Held uncertain attempts are never rewritten or retried by this
   refresh; establish remote quiescence and use the existing attempt-recovery action
   before they can be claimed again. Resync and verify delivery after recovery.
   Startup alone cannot undo an old write that already reached a receiver or stop
   an in-flight request from an older process; stop the old source before upgrading.
4. Sign in afresh to each product as its dedicated administrator and verify an
   administrator action. Verify an unassigned global administrator and an everyday
   account have no product administrator access. Confirm existing content is retained.
   Receiver updates must treat empty `roles` as ordinary user, clear previously cached
   grants, and never fall back to the separate legacy `role` claim.

ID-token and UserInfo `roles` remain per-app. **Legacy global role claim** still emits
singular `role` for clients deliberately retaining that compatibility switch; it is
not an application administrator grant. Truly unmapped legacy provisioning systems
retain their historical global-role payload. This change does not migrate mixed-use
accounts or end sessions already held by a receiver; verify the receiver's revocation
and role-refresh behavior during rollout.

## Upgrades and restores

Upgrading is starting the new image on the existing data directory: migrations run at
startup, identifiers are stable, and an app that existed before per-app access modes is
marked `all_active_users` rather than quietly locked down, because that is what the old
server did. Running the migrations again changes nothing, which is checked by comparing
the schema of a twice-upgraded database with a fresh one.

Restoring is two commands and one deliberate consequence. `kyidentity restore -capsule
<file> -to <dir> -expect-digest <sha256>` checks the capsule against the digest KyRecovery
recorded at deposit, unpacks it (custodian shares on stdin, never argv) and marks
the directory as restored. The next start reads that marker once and invalidates what
the capsule carried: sessions, issued tokens, authorization codes and interactions,
MFA and step-up challenges and grants, invitation and reset links, device pairing
tokens and in-flight delivery fences. Back-channel logouts go the other way: a restore
ends every login here, so before the sessions go it queues a logout for each one to the
relying parties that saw it, and keeps the logouts it already owed rather than deleting
them. Nothing else would re-derive that work, and a receiver told nothing keeps its own
session until its own timeout. Queued outbound
deliveries are closed out with a reason rather than sent, except queued removals
(disables and deletions), which keep waiting behind the hold, and outbound provisioning is
held on every connector that is not disabled. Scheduled backup deposits are turned off;
set the schedule again once the restored server is the one in service. A `system.restored` audit row records the
counts, and the marker is removed only after that has committed, so an interrupted
start repeats the work rather than skipping it.

A held connector delivers nothing until a repair reconciliation has compared this
directory with what is really on the far side and written the difference through; the
Suite sync page shows the hold. Nothing else releases it: not a preview, not a failed
run, not a listing that was refused or truncated, and not a connector whose kind cannot
be listed at all. This is what stops a restored outbox from recreating accounts that
have since left. A connector that cannot be listed — a suite webhook has no directory to
read back — would otherwise stay held forever, so `POST
/api/admin/systems/{id}/provisioning/resume` (administrators, step-up) lifts the hold on
the operator's word instead, recorded as `admin.provisioning_resumed`. Connectors that
were disabled at snapshot time are held too, so re-enabling one later does not deliver
what was queued before it was disabled.

The capsule's own outbox never delivers, on any of those paths. Closing a row out is not
enough by itself: the worker re-pends exhausted work that still matches a connector's
desired state, and a restore leaves every row eligible for that. So the closed-out rows
are marked with a revision no connector can carry, which the re-pending cannot match and
the next pass deletes. Deletions and MFA resets carry no desired state and do still
retry, which only ever removes access. What reaches a resumed connector is what this
directory wants now, not what the capsule was in the middle of. Passwords, enrolled
factors and recovery codes are in the capsule and keep working, so the restore runbook
asks for connector credentials to be reviewed for rotation before delivery resumes.
Procedures are in [docs/RUNBOOKS.md](RUNBOOKS.md) and
[docs/RESTORE.md](RESTORE.md); what has and has not been verified for a release is
in [docs/RELEASE-EVIDENCE.md](RELEASE-EVIDENCE.md). Device attestation checks that need a
physical phone are in [docs/attestation-verification-plan.md](attestation-verification-plan.md).

## RSA signing-key minimum

KyIdentity loads only RSA signing keys with a modulus of at least 2048 bits,
in either PKCS#1 or PKCS#8 PEM format. First start still generates a 2048-bit
key when the configured key file does not exist. Larger existing keys are
retained. There is no opt-out for undersized keys.

An installation using a smaller key now stops with a size error. Its existing
key file is preserved; it is not automatically replaced or upgraded. Before
upgrading such an installation, back up the existing state and arrange a
deliberate signing-key rotation with the administrators of dependent clients.
Replacing the signing key changes its JWKS key ID and makes tokens signed by
the old key fail verification against the new key. Do not delete the key file
as a troubleshooting shortcut. Recovery from an older backup with an
undersized key also requires this planned rotation before the server can start.
