# Encryption-key rotation and bootstrap password change

Research against upstream worktree commit `0060ca2e9134a3555e911624982974bfd6786566`,
2026-10-19. The selected offline implementation and operating contract are in [KEY-ROTATION.md](KEY-ROTATION.md); this note preserves the source investigation.
No builds, tests, live requests or production mutations were performed for this research.

## Findings

Both issues are present. There is no encryption-key rotation command, and the restore
runbook explicitly says never to rotate that key. Bootstrap creates an ordinary active
administrator without a password-change requirement. Simply replacing the key or adding
a UI warning would leave correctness or authorization gaps.

Sources: [restore prohibition](RESTORE.md#L304),
[command dispatch](../cmd/kyidentity/main.go#L55),
[bootstrap creation](../cmd/kyidentity/main.go#L412).

## Rotation: every dependency on the encryption master

| Data | Current protection | Required handling |
| --- | --- | --- |
| TOTP secrets | Row-bound `v2:` AEAD, purpose `mfa_totp`, row=user ID | Open with old master and reseal with new master |
| SCIM/suite connector credentials | Row-bound AEAD, purpose `paired_system`, row=connector ID | Reseal; preserve plaintext credentials and connector ownership |
| SMTP settings | Row-bound AEAD, purpose `mail_settings`, row=`mail_settings_enc` | Reseal the whole JSON value |
| KyRecovery token | Legacy-compatible AES-GCM with derived key label `kysignon:setting:kyrecovery_token`, setting `kyrecovery_token_enc` | Open/reseal through backup adapter using its fixed label |
| Unused recovery codes | `hmac:` + HMAC of `userID|normalizedCode`, pepper derived from encryption master | Preserve the original HMAC pepper independently; hashes cannot be converted without users' plaintext codes |
| Prepared installer credentials | `credentials.json` hashes `product-encryption-key`; native preparation receipt hashes the exact JSON | Validate and migrate filesystem receipt and native preparation contract together in the output copy |
| Capsule payload | Contains effective encryption master beside a database snapshot | Future backups must contain new master and rotated DB together; existing capsules stay self-contained |

Sources: [sealed column inventory](../internal/store/sealed.go#L11),
[row AEAD](../internal/crypto/crypto.go#L128),
[mail settings](../internal/mail/mail.go#L73),
[recovery token sealer](../internal/backup/adapter.go#L91),
[recovery-code hashing](../internal/mfa/mfa.go#L249),
[master digest](../cmd/kyidentity/setup_stage.go#L192),
[filesystem and native receipt](../cmd/kyidentity/setup_stage.go#L324),
[native receipt ownership](../internal/store/installer_setup.go#L87),
[capsule key material](../internal/backup/payload.go#L94).

The encryption master does not protect password hashes, OAuth client-secret hashes,
refresh-token hashes or session-token hashes. `secret.key` supplies CSRF/browser binding;
RSA signing, VAPID and generated relay keys are separate files. Copy those unchanged.
Recovery public-key pin, topology, deposit receipts, connector delivery fences and restore
holds also stay unchanged. A rotation must never call `ApplyRestoredState` or reconcile
connectors as a side effect.

Sources: [password creation](../cmd/kyidentity/main.go#L424),
[client hash](../cmd/kyidentity/setup.go#L287),
[session hash](../internal/api/auth_handlers.go#L288),
[secret-key middleware](../internal/api/server.go#L49),
[configuration keys](../internal/config/config.go#L148),
[backup adapter contract](../internal/backup/AGENTS.md),
[restore effects](../internal/store/restore.go).

## Minimal safe rotation implementation

Recommend an offline `rotate-encryption-key --out <new-data-directory>` command producing
a verified replacement directory. Do not modify the source DB, source key or live process.
The owner selected offline copying into a verified separate directory. Online rotation
would require a larger key-versioning and concurrent-writer design.

1. Require the service and mutating CLI commands to be stopped. Add a common, nonblocking
   data-directory process lock to the server and native mutating commands if enforcing this
   mechanically. A SQLite snapshot alone does not prove the source is quiescent: the
   original server can keep committing after the snapshot. No existing process-lock code
   was found in `cmd/` or `internal/`. An older running binary cannot honor a newly added
   lock, so an explicit offline operator acknowledgement is still needed for that upgrade.
2. Resolve source and output as protected, distinct clean absolute directories. Refuse
   output inside source, source inside output, existing output, symlinked ancestors and
   unsafe ownership/permissions. Read the existing key with the protected-file reader;
   never call normal configuration loading to generate missing keys on this path.
3. Initially refuse `KYIDENTITY_ENCRYPTION_KEY` and a database outside the source data
   directory with an explicit explanation. An environment key shadows the output key on
   restart. Supporting it needs an explicit new protected key destination and a verified
   deployment-configuration switch. Also refuse unexpected external RSA-key placement
   unless the runbook explicitly preserves that dependency. Accept the historical
   in-directory `kysignon.db` name when that is the configured source; do not silently
   select or generate another database.
4. Copy every source regular file and directory into a private staging directory, preserving
   mode and relative names; refuse unsupported entries rather than silently losing them.
   Replace only the selected database with `Store.SnapshotTo` output, excluding its WAL/SHM
   sidecars. Never copy only `kyidentity.db` from a WAL deployment. Keep signing keys,
   secret key, VAPID, relay keys, recovery pin, installer tree, local backups and unrelated
   operator files. External references remain external and must be listed as such.
5. Open and migrate only the staged DB. Run `SealLegacySecrets(oldMaster)` there before
   rotation to handle pre-v2 inputs with the established migration policy. In one audited
   SQLite transaction reseal every nonempty sealed-column value, reseal the KyRecovery
   token, wrap the recovery-code pepper, and replace validated preparation receipt
   contracts. Any unreadable row or audit failure aborts the entire DB change.
6. Write the new 32-byte file key only into staging. Verify DB integrity, every resealed
   secret under the new key, recovery-token plaintext equality, preserved recovery-code
   verification key and every migrated preparation receipt. Close SQLite so no committed
   output is left only in a WAL. Fsync files and containing directories; publish without
   clobbering an existing destination. A partial staging directory must never be reported
   as usable or auto-started.
7. Print paths, old/new key fingerprints, counts and verification result, never key bytes,
   plaintexts or credential values. Source remains rollback material. Activation mounts or
   renames the verified output at the original runtime data path while the service is down.
   Do not activate by pointing `KYIDENTITY_DATA_DIR` at a new path: installer bundles use
   absolute container-local credential paths.

Existing building blocks: [protected path traversal](../cmd/kyidentity/setup_stage.go#L25),
[protected key load](../cmd/kyidentity/setup.go#L333),
[snapshot semantics](../internal/store/store.go#L2749),
[transaction writer lock](../internal/store/store.go#L32),
[legacy reseal transaction](../internal/store/sealed.go#L37),
[effective key override](../internal/config/config.go#L418),
[data and external RSA paths](../internal/config/config.go#L148),
[absolute preparation paths](../cmd/kyidentity/setup_stage.go#L144).

### Recovery-code preservation without retaining the old master

Introduce one row-bound encrypted setting, for example `recovery_code_key_enc` with
purpose `recovery_code_key` and row equal to the setting name. When absent, the effective
pepper remains `DeriveKey(master, "kyidentity:recovery-code")`. At first rotation wrap that
derived 32-byte pepper under the new master. At later rotations unwrap it with the old
master and rewrap it unchanged. Do not store the old master itself or change existing
`hmac:` rows. Bare legacy SHA-256 rows keep their existing redemption/regeneration behavior.

Load the pepper once per recovery-code generation or verification operation, returning an
error for a present but invalid setting. This avoids changing every `NewEngine` caller:
`GenerateRecoveryCodes` resolves it before its loop; `VerifyAndConsumeRecoveryCode`
resolves it before the atomic consume call. Startup and the restore drill should also
validate any present wrapped pepper. Add the setting to the rotation inventory. A future
recovery-code regeneration can retain the stable pepper; retiring a suspected compromised
pepper needs its own deliberate code-regeneration operation.

Sources: [generation and verification](../internal/mfa/mfa.go#L218),
[atomic code consumption](../internal/store/store.go#L2200),
[setting missing versus invalid](../internal/store/store.go#L2681),
[restore decryption verification](../internal/backup/drill.go#L264).

### Prepared installer receipt migration

For each `installer_setup_resources` row with `kind='preparation'`:

- Read its owned `installer/<setup UUID>/credentials.json`, require protected files,
  expected schema, canonical bounded JSON, and its SHA-256 equal to `contract`; require
  `setup_id=name=object_id`. Validate retained intent/bundle and credential digests using
  the existing preparation checks before migration.
- When the credentials map contains `product-encryption-key`, require its value to be
  SHA-256 of the old master, replace only that value with the new-master hash, marshal in
  the same struct/map shape as `stageSetup`, hash those exact bytes, and update the native
  contract conditionally on its old value in the rotation transaction.
- Write only the staged `credentials.json`. Preserve `intent.json`, `setup.json`, all
  generated credentials, absolute path map keys, bundle digest, other native ownership
  contracts and account passwords byte for byte. Preparations without a key digest remain
  untouched. Include parent setups and amendments independently.
- Refuse missing receipts, damaged preparation directories, unexpected stray receipt
  ownership and interrupted preparations rather than manufacturing replacement ownership.
  Verify generated-file hashes against the staged equivalent of each original absolute
  path, while leaving JSON paths unchanged for activation at the original mount path.

Sources: [canonical credential receipt](../cmd/kyidentity/setup_stage.go#L324),
[immutable native contract](../internal/store/installer_setup.go#L90),
[path binding and intent](../cmd/kyidentity/setup_stage.go#L148),
[connector credential contract](../internal/store/installer_scim.go#L25).

## Bootstrap forced password change

Add `users.password_change_required BOOLEAN NOT NULL DEFAULT 0`; set it only on accounts
newly created by `ensureBootstrapAdmin`, including configured startup passwords and the
`bootstrap-admin` CLI. Persist it through the existing user/audit creation transaction and
read it through `userColumns`/`scanUser`. Do not mark installer-created owner/everyday
accounts: those are separate provisioning paths whose existing resume and password
preservation contracts must stay intact. Existing active administrators remain unchanged
on repeated bootstrap. Username `admin` and an old first-run file are not reliable proof
that an existing password remains a bootstrap credential.

Sources: [startup bootstrap](../cmd/kyidentity/main.go#L283),
[existing-account preservation](../cmd/kyidentity/main.go#L407),
[creation/audit transaction](../internal/store/store.go#L835),
[shared user reader](../internal/store/provisioning.go#L105),
[installer account contract](../internal/store/installer_setup.go#L16).

Enforce the restriction at all authority boundaries:

- `RequireAuth`: permit only profile, logout, password change and operation-bound password
  step-up routes while the flag is set. Reject other API/admin routes with a fixed
  `password_change_required` response. Step-up issuance must itself restrict the requested
  operation to `POST /api/user/password`; allowing its route alone grants unrelated authority.
- `/oauth/authorize` uses `OptionalAuth`, so add a separate refusal/interaction path there.
  In SQL reject flagged users in code creation, `recordIssuedTokenTx` and token liveness.
  The common token writer covers refresh and device assertions as well as code exchange.
- Keep this requirement separate from `mfa_session_access`. Reusing `enrollment_only`
  would report the wrong recovery action and the current enrollment allowlist excludes
  password changes. Permit password-change step-up/change through MFA restriction when
  bootstrap rotation is required, while preserving enrollment/factor checks for all other
  operations; explicitly test accounts requiring both actions.
- Password change rejects the current password as the new password, sets the new hash,
  clears the flag and revokes grants/other sessions in one audited transaction. Use a
  conditional old-password-hash match under the writer lock to reject a password-reset
  race between Argon2 verification and the update. Account-link password reset must clear
  the flag after setting a verified new password too. Do not clear it during an unrelated
  profile update, role change, repeat bootstrap, MFA enrollment or merely logging in.
- Expose the boolean in login/profile responses. Render a dedicated forced-change form
  before dashboard/admin/authorization continuation using existing password/step-up UI
  primitives. A CSRF-valid direct API caller must face the same restrictions.

Sources: [authenticated route gate](../internal/api/middleware.go#L323),
[optional auth](../internal/api/middleware.go#L344),
[password and step-up routes](../internal/api/server.go#L151),
[step-up operation checks](../internal/api/stepup_handlers.go#L81),
[MFA enrollment allowlist](../internal/api/enrollment_policy_handlers.go#L123),
[authorize gate](../internal/api/oauth_handlers.go#L177),
[code insertion guard](../internal/store/store.go#L2375),
[token insertion/liveness](../internal/store/store.go#L2454),
[device token path](../internal/oauth/device_assertion.go#L321),
[password handler](../internal/api/onboarding_handlers.go#L239),
[password mutation](../internal/store/onboarding.go#L138),
[link redemption](../internal/store/onboarding.go#L87),
[profile response](../internal/api/auth_handlers.go#L711),
[current UI gate order](../web/src/App.tsx#L76),
[existing password form](../web/src/components/DeviceSettings.tsx#L88).

## Implementation gates and decisions

Selected: offline verified replacement, preserving the original for rollback; require
password replacement only for newly created bootstrap accounts. Existing accounts stay
unchanged. The initial command refuses environment/external master deployments and
preserves recovery codes and installer receipts.

Runnable acceptance must cover two consecutive rotations; all encrypted data; recovery
codes before/after restart and restore; setup parent/amendment inspect/export/resume at the
original runtime mount path; source equality after success and every refusal; corrupt-row,
wrong-key, audit-failure and partial-publication rollback; WAL-only committed data; unsafe
paths; environment override refusal; online-source refusal; and independent old/new capsule
drills. Bootstrap acceptance must exercise actual password/CSRF/step-up, admin and ordinary
API denial, code/refresh/device token denial, password reset, unchanged existing users,
setup-owned owner access, same-password refusal and simultaneous MFA enrollment policy.

The implemented runtime contracts are recorded in root `AGENTS.md`, `KEY-ROTATION.md`,
`RESTORE.md` and installer setup guidance. The backup adapter contract stays unchanged:
capsules contain the effective master key and the matching database snapshot.
