# Backup

## Purpose
KyIdentity's adapter over `github.com/Busness-app/ky-primitives/recoveryclient`, the suite's product-side backup package. The lib decides everything about keys, pairing, destinations, schedule, sealing, drilling and restoring; this package says what KyIdentity seals, what its drill checks, and how the store, the deployment key and the config map onto the lib's interfaces.

## Ownership
- `payload.go`: `CollectSealable` (database snapshot through the live handle, RSA signing key, encryption and secret keys, `recovery.pub` when present, config manifest), `Members`, the capsule paths, the verification recipe.
- `drill.go`: `RunRestoreDrill` runs `recoveryclient.Drill` with `DataDir` as the scratch root and adds KyIdentity's checks from the authenticated, reopened manifest recipe: required files, SQLite integrity and application records, MFA secrets decrypt, paired-system tokens decrypt, the signing key issues a verifiable token. A "Recovery Key" check reports pin status; the drill never touches the suite key.
- `adapter.go`: type and error aliases under the names the handlers use; `settings` maps `*store.Store` onto `recoveryclient.Settings` (`store.ErrNotFound` → `recoveryclient.ErrNotFound`); `sealer` wraps `crypto.EncryptAESGCM(crypto.DeriveKey(EncryptionKey, "kysignon:setting:kyrecovery_token"))` so pairings sealed before the lib keep opening (`TestAPairingSealedBeforeTheLibStillOpens`); `RunBackup` builds `RunConfig` from `config.Config` and passes `CollectSealable` as the collect func.

## Local Contracts
- Do not reimplement anything the lib provides. If a behaviour is missing, add it to `recoveryclient` and bump the dependency.
- The sealer label is fixed forever; changing it orphans every live pairing.
- `ListLocalCopies` and `RunBackup` migrate only the exact legacy `KyIdentity-cap-KyIdentity-<unix-nanos>.kycap` shape to the library prefix before listing or retention; unrelated files are never renamed or pruned.
- Settings keys are the lib's (`kyrecovery_*`, `backup_*`); the store just holds rows.
- `TestNothingInTheServerDecrypts` runs `guardtest.NoDecryptOutside` on the repository with `cmd/kyidentity/main.go` `restore` as the only allowed caller. It was proven by planting `capsule.Open` in a handler and watching it fail.

## Verification
- `go test ./internal/backup/...`
- `kyidentity backup-drill` against a throwaway data dir: every check but "Recovery Key" passes on an unpaired instance.

## Child DOX Index
None.
