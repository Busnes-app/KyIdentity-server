# KyIdentity fleet Appearance — 2026-10-26

Applies the approved Busnes look to KyIdentity's web shell and gives it the shared ky-ui 0.4.0 Appearance theme-preview cards (native radios) over the suite catalog: Match system plus every catalog theme, read dynamically from `web/src/ky-ui/themes.js`. Shared files come from ky-ui `4f83f34` and pass `sync-consumers --check`; they are generated, never hand-edited. No score is claimed here: the council rates these captures.

## Stages

- **00 before**: base commit, current theme control and main view.
- **01 after**: suite shell scale (240px sidebar, 24px title, 40px controls and nav rows, shared field border and type) and the Appearance cards.
- **02 after**: owner correction — shared description class and copy, consistent wrapping, preview hairline, no theme selector in the shell navigation. Only affected Appearance/shell views were recaptured.
- **02 confirm**: one confirmation recapture after the single stage 02 fix batch, where a fix was needed.

Surfaces: Applications (main view), Users (administration task view) and Appearance.

## Catalog and saved choice

- Storage key `kyidentity-theme`; theme names saved by earlier versions (the 17 suite names) still select their theme; new choices are saved by catalog name, and Match system as `system`.
- Match system follows the device until a choice is saved; that default is unchanged.

## Product notes

- Appearance is in the sidebar under Your account, so every signed-in role reaches it. No selector sits in the navigation.
- Fixed in passing: on phones the shell grid stretched the header rows when a page was short (visible in the stage 00 users capture).

## Capture batches

Every manifest in `screenshots/` lists the source commit, a hash of any uncommitted diff, OS, driver, viewport, theme source, fixture and the SHA-256 of every PNG. `results.csv` pairs each after image with its stage 00 before; `checks.csv` holds the in-app checks. `source.patch` is the source-only diff (no vendored or built files) for independent review.

| Batch | Source commit | Uncommitted diff | Images | Surfaces | Captured |
| --- | --- | --- | --- | --- | --- |
| `kyidentity-00-before` | `ba43fbe982` | none | 12 | appearance, applications, users | 2026-10-26T10:55Z |
| `kyidentity-01-after` | `e7a40de3ed` | `6c39307a0aaa…` | 12 | appearance, applications, users | 2026-10-26T11:20Z |
| `kyidentity-02-after` | `70c147d6d8` | none | 4 | appearance | 2026-10-26T11:36Z |

Conditions: linux 7.2.10-1-cachyos, playwright chromium 156.0.8078.4 (headless), device scale 1, 1280×900 and 390×844, light/dark by OS emulation with no saved choice, America/Chicago, en-US. Fixture: fresh data dir with generated secret/encryption keys; bootstrap-admin "admin" (generated password on stdin, replaced through the required password-change screen at first sign-in); no applications, groups, users or mail; KYIDENTITY_ISSUER_URL on loopback http.

## In-app theme check

`node docs/ui-fleet-2026-10-26/capture.mjs --verify <prefix>`: Sky and Sun (light named themes), Busnes Dark, Busnes Light and Match system, asserting the page background, the hovered idle navigation row and the selected row at 4.5:1 or better from computed colours in the running product, then arrow-key selection with a visible focus ring.

| Run | Source commit | Passed |
| --- | --- | --- |
| `kyidentity-01-after` | `e7a40de3ed` | 16/16 |
| `kyidentity-02-after` | `70c147d6d8` | 16/16 |

## Checks

| Check | Result |
| --- | --- |
| Web unit tests (vitest) | 194/194 pass |
| Web build (`tsc` + Vite) and committed `web/dist` equals a fresh build | pass |
| `npm audit` (all and `--omit=dev`) | 0 vulnerabilities |
| Vendored ky-ui check (`check-vendor.mjs`, `sync-consumers --check`) | pass at 4f83f34 |
| `docs/check-strong-crypto-compose.py` | pass |
| Push relay workers typecheck/tests | not run: untouched by this change; CI runs them |

Go: `go build ./...`, `go vet ./...`, gofmt and the full `go test -race -count=1 ./...` passed locally on this machine (CachyOS, Go 1.27.1); Go code is unchanged by this work. Docker image, publish and attestation jobs were not run locally: CI runs them on this PR.

## Reproduce

```sh
cd web && npm ci && npm run build   # then any product-specific bundle step in AGENTS.md
cd .. && KY_PLAYWRIGHT=<path to @playwright/test/index.mjs, if web/ has none> \
  node docs/ui-fleet-2026-10-26/capture.mjs <prefix> [surface,...]
node docs/ui-fleet-2026-10-26/capture.mjs --verify <prefix>
node docs/ui-fleet-2026-10-26/results.mjs
```

Each run starts a disposable loopback server on its own port with generated secrets and removes its data directory afterwards. No live service, personal data or authentication bypass is used.
