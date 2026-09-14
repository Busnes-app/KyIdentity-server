# Release evidence

What has been verified for this release, how, and what is still open. A gate is only
closed by evidence from the thing itself: a passing test against the real artifact, or a
named person's run against a real tenant. Nothing here is closed by a synthetic fixture
standing in for a third party.

## Versions in this release

| Component | Version |
|---|---|
| Server (`appVersion`) | 1.0.0 |
| Go toolchain (`go.mod`, CI) | 1.26.6 |
| `ky-primitives` | v0.6.0 |
| Node (web and relay CI jobs) | 22 |

## Automated evidence

Every item below runs in CI on each push and pull request (`go test -race ./...`, the
web and relay suites, and a Docker build whose image is smoke-tested and, on master,
attested and promoted).

| Claim | Evidence |
|---|---|
| A pre-feature database upgrades with stable identifiers, states its legacy broad access, invents no authentication evidence, and lands on the schema of a fresh install | `TestUpgradeFromPreFeatureDatabase` (store) |
| Running the migrations twice changes nothing, including the indexes | same test: schema fingerprints after each run, and a group and a user sharing a remote id still insert |
| A restore invalidates the sessions, tokens, links and queued work a capsule carries | `TestRestoreInvalidatesEphemeralCredentialsAndHoldsProvisioning` (store) |
| Outbound provisioning stays held after a restore until a repair reconciliation that actually compared the far side | `TestProvisioningHoldIsReleasedByReconciliation` (store), `TestReleaseRestoreScenario` (api, real HTTP routes) |
| A connector that cannot be listed is resumed only by a deliberate, audited operator act | `TestProvisioningHoldCanBeResumedDeliberately` (store) |
| A connector disabled at snapshot time is held too, so re-enabling it delivers nothing | `TestRestoreHoldsAConnectorThatWasDisabled` (store) |
| The restore marker is applied once, audited, and then gone | `TestRestoreMarkerAppliesOnceAndIsThenGone` (cmd) |
| A restore drill checks policy, groups, app linkage, remote mappings, job state and the encrypted relay configuration, not just that somebody can log in | `TestDrillCoversLifecycleStateAndEncryptedConfiguration` (backup) |
| A capsule carries everything a restore needs and the restored bytes are usable | `TestCollectSealableCarriesEverythingARestoreNeeds`, `TestDrillProvesARestoreIsUsable` (backup) |
| Only the restore command combines custodian shares | `TestNothingInTheServerDecrypts` (backup) |

`kysignon backup-drill` is the operator-facing form of the same recipe. It requires a
pinned recovery key, so it is run against a deployment rather than in CI.

## Gates still open

These need a real counterparty and cannot be closed from this repository.

| Gate | What would close it | Status |
|---|---|---|
| A: two test relying parties | Two real OIDC clients completing login, refresh and logout | Open |
| B: suite offboarding end to end | D1–D4 deployed against this server and verified | Open — D1–D4 not deployed; `ky-primitives` v0.6.0 has no logout-token verification path |
| C: one actual upstream test tenant | A real SCIM upstream provisioning and deactivating an account | Open — exercised only against the fake connector in tests |
| D: role-aware suite consumers | Each product reading the `roles` claim, then its per-app legacy claim turned off | Open |
| E: combined live run | A restore drill, a restore, and a reconciliation on a deployment, with the custodian ceremony | Open — no custodian ceremony is claimed from test fixtures |

## What this release does not claim

- No third-party tenant, custodian ceremony or downstream product has been exercised.
  The suite-facing behaviour is proven against this server's own routes and fakes.
- Spreadsheet handling of exported CSV is neutralised at the cell level and tested as
  text; it has not been opened in a spreadsheet application.
- The alerts feature has no per-app scope: app owners see no alerts at all.
