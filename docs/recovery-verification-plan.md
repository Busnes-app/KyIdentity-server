**Repo:** kyidentity-server
**PR:** #21 — https://github.com/Busnes-app/kyidentity-server/pull/21
**PR:** #22 — https://github.com/Busnes-app/kyidentity-server/pull/22
**PR:** #23 — https://github.com/Busnes-app/kyidentity-server/pull/23
**Worktree:** /home/yoshi/busness.app/kyidentity-server (master, a2d5dbc)

# Recovery verification plan

Date: 2026-09-05. Owner: marigold. Continues myslop post 295 in
`kyidentity-kyrecovery-verification`. Scope: plan the remaining compatibility and
real-card scratch restore verification. Local checks completed; the operator
real-card drill is pending the machine/capsule details and custodians.

## Evidence already available

- Post 295 reports the adapter and hardening merged, v0.5.1 published, and prior CI
  and local backup/API race tests passing. These historical checks were not rerun
  while preparing this plan.
- Yoshi reported a successful 109 KiB deposit of an unverified
  `cap-KySignOn-…` capsule on September 5 at 09:13:49 AM. Its deployed
  revision, key continuity and re-pairing history remain unverified.
- This session fetched origin and confirmed clean master matched origin/master at
  `a2d5dbc` before adding this document. Read `docs/RESTORE.md` and the root and
  backup AGENTS.md contracts.

## Execution sequence

1. **Establish compatibility evidence.** Record the deployed revision, whether the
   successful deposit followed the upgrade without re-pairing, and the before/after
   recovery key IDs if available. Use existing operator evidence; do not request
   SSH just to repeat the deposit. If historical evidence is absent, mark continuity
   unknown. If local copies are configured, verify the exact legacy
  `KySignOn-cap-KySignOn-<unix-nanos>.kycap` migration to the library prefix and
   that unrelated files remain untouched. Otherwise mark this check not applicable.
2. **Prepare the operator drill.** Choose a trusted scratch machine, a binary built
   from a recorded revision, and an empty task-specific directory at mode 0700.
   Arrange the ceremony's threshold number of custodians. An operator downloads
   the chosen non-corrupt KySignOn capsule through their KyRecovery session and
   records its ID, creation time with timezone, digest and expected recovery key ID.
   Prefer the latest capsule per the runbook; if using the reported capsule to
   investigate that particular deposit, record that choice explicitly.
3. **Open with the real cards.** Follow only Steps 1 and 2 and “Drill it” in
   `docs/RESTORE.md`. Custodians enter shares directly into the local restore
   process on stdin, outside agent tools and session recording. Never put shares
   in chat, argv, logs, a shared file or the evidence record. Record command exit
   status and the non-secret authenticated manifest output.
4. **Verify the restored contents.** Match authenticated capsule ID, service,
   creation time and recovery key ID to the selected record. Check the downloaded
   capsule's digest using KyRecovery's digest definition; do not equate the outer
   capsule digest with the manifest's payload hash. Check the expected five or six
   files, each mode 0600: database, RSA key, encryption key, session secret, config,
   and recovery public key when paired. Run SQLite integrity checking read-only;
   compare non-sensitive record counts against an available backup-time baseline.
   Without that baseline, record readability and counts only, not full equivalence.
   Validate key lengths and RSA parsing without printing private material. Any
   further secret-decryption or signing self-check must operate only on scratch
   data and emit pass/fail. Existing in-app drill results remain separate evidence:
   they use disposable keys and cannot prove real-card recovery.
5. **Clean up and report.** After recording results, confirm the exact task-specific
   scratch path and remove its plaintext output. Record cleanup success. Save a
   sanitized local result and mirror it to the existing myslop folder, distinguishing
   independently verified results, operator reports, unknowns and exact failures.
   Mark done only when the real-card drill and cleanup pass and each compatibility
   check is resolved or explicitly recorded as unavailable/not applicable.

## Boundaries and dependencies

The next execution dependency is an operator-controlled scratch environment, access
to the selected capsule, and the actual custodians. No credentials or shares are
needed to complete this plan. A local automated regression run can supplement the
drill (`go test -race ./internal/backup/... ./internal/api/...`) but cannot replace it.

Do not run the runbook's production cutover steps, replace/delete the live volume,
launch a restored server with live integrations, or rotate production keys during
this drill. Preserve `encryption.key` and the sealer label
`kysignon:setting:kyrecovery_token` (a frozen pairing-compatibility label). On failure, retain only sanitized diagnostics
and clean up plaintext scratch material; investigate before retrying.

DOX pass: this document applies existing responsibilities and verification rules;
it changes no application behavior or owning AGENTS.md contract.

**Local copy:** /home/yoshi/busness.app/kyidentity-server/docs/recovery-verification-plan.md

## Execution results — 2026-09-05

Independently checked this session:

- `go test -race ./internal/backup/... ./internal/api/...` passed. This covers the
  pre-library pairing sealer and exact legacy local-copy migration in automated
  fixtures; it does not establish the live deployment's history.
- `go test -race ./cmd/kyidentity/...` passed.
- `go test -race github.com/Busnes-app/ky-primitives/recoveryclient -run
  'Restore|ReadShares' -count=1` passed with synthetic test material.
- Built `/home/yoshi/.local/state/kyidentity-verification-295/kyidentity`. Go build
  metadata records revision `a2d5dbc59c0724fd96dc21a861f1e6ba33b38711`, dependency
  v0.5.1, and `vcs.modified=true` because the local plan is untracked. Application
  source was not edited. PR #23 is confirmed merged through GitHub.
- No KyIdentity container is running locally, and no capsule was found in the
  checkout. A KyRecovery container exists; no operator credentials were accessed.
- Confirmed from recoveryclient v0.5.1 source that the receipt digest is lowercase
  hex SHA-256 of the entire capsule container, distinct from payload hash.
- Prepared `/home/yoshi/.local/state/kyidentity-verification-295/real-card-drill.sh`.
  It uses the existing restore binary, disables terminal echo during share entry,
  checks the receipt digest, asks the operator to compare authenticated manifest
  fields, checks six paired-capsule files/permissions/key lengths/config, reads
  SQLite integrity and application counts, checks for an active administrator,
  validates RSA consistency with OpenSSL, and removes its own scratch directory
  on exit. It never starts the restored server. Receipt metadata and manifest
  output stay beside the wizard; shares are not persisted.
- Wizard passes `bash -n` and `shellcheck`. Its embedded content check passed a
  synthetic valid fixture and rejected bad permissions, incorrect key length and
  missing administrator. Rerun:
  `python3 /home/yoshi/.local/state/kyidentity-verification-295/check-wizard.py`.
  The interactive wizard has not been run end-to-end, and these fixtures do not
  prove real-card restoration or usability of real encrypted MFA/pairing records.

Remaining input: the trusted machine and capsule path (or run the prepared kit
locally there), non-secret capsule receipt/key ID, the ceremony's custodians,
and whether the reported deposit followed the upgrade without re-pairing. Before
and after key IDs and deployed revision remain unknown. Local-copy configuration
and live migration remain unknown. No real capsule has been opened; no live volume
or key has been changed. No plaintext production scratch output exists to clean up.

Next action for the operator, in a private unrecorded terminal on this machine:

```bash
bash /home/yoshi/.local/state/kyidentity-verification-295/real-card-drill.sh
```

For another machine, use a binary built for that machine at the recorded revision
beside the wizard; it requires Bash, Python 3, OpenSSL, sha256sum and stty. Send only
sanitized results, never cards, private keys, database contents or session tokens.
The board is blocked on this operator step, with ownership retained by marigold.
