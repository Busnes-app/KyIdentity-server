# Shared UI verification

> Evidence scope: this document records the revision, environment and capture conditions below. Screenshots and generated fixtures demonstrate appearance; they do not qualify live email delivery, push delivery, recovery custody or every product feature. Test counts describe that recorded run, not the current suite.

## Change

Generate Busnes palettes and share safe storage/cross-tab theme updates without changing named presets. Shared assets are pinned to ky-ui 0.2.0 with content hashes. Product layouts, saved theme keys and named presets remain local.

## Capture conditions

Captured 2026-09-25 from this branch, using the application UI (not a design mockup). Applications page in a real scratch server, signed in as the local preview administrator. No applications assigned.

OS-following Busnes Light and Dark were captured at 1280×900 and 390×844 CSS pixels. Browser device scaling may make PNG dimensions larger. Document width stayed within the viewport in these captured states; local navigation/table scrolling is intentional. Screenshots show the selected-page accent, not a complete accessibility audit.

No complete end-to-end product workflow or exhaustive named-theme audit is claimed.

## Checks

162 frontend tests and production build passed. Central ky-ui sync --check verified all ten consumers. Screenshot coverage is Busnes Light/Dark; existing named choices are retained, but not every named palette/page combination was visually exercised.

## Screenshots

| Light | Dark |
| --- | --- |
| ![Desktop light](docs/ky-ui-light-desktop.png) | ![Desktop dark](docs/ky-ui-dark-desktop.png) |
| ![Mobile light](docs/ky-ui-light-mobile.png) | ![Mobile dark](docs/ky-ui-dark-mobile.png) |

## Reproduce

Run npm ci, npm test (where configured), and npm run build in web/, then start the product with isolated local preview data following its README. Use System theme, emulate OS light/dark, and inspect both viewport sizes. Do not point preview instances at production data. For KyVault, use a configured development KyIdentity or explicitly labeled read-only browser fixtures; never bypass backend authentication.


## Approved interface polish — 2026-10-19

See [UI-POLISH.md](UI-POLISH.md) for the implemented changes, preservation scope, checks, actual before/after screenshots and disposable capture conditions. Earlier captures above remain historical evidence.

## Fleet Appearance — 2026-10-26

Shared ky-ui 0.4 Appearance radio cards over the suite catalog, plus the suite shell scale. Staged before/after captures (light/dark × 1280×900/390×844, synthetic fixture), manifests with revisions and hashes, in-app theme transition checks, CSV results and the recorded check runs are in [docs/ui-fleet-2026-10-26](docs/ui-fleet-2026-10-26/README.md). Scores are not self-assigned; the council rates the captures separately.

## Upstream merge verification — 2026-10-26

Merged `master` at `f5c3ff2` into the fleet branch after PR #166 changed the
administrator backup action. Source files merged cleanly; conflicting generated
JavaScript and `dist/index.html` were rebuilt from the combined source.

`npm run build --prefix web` (including TypeScript), all 194 web tests, the vendor
check and the race-enabled API tests `TestAdminBackupEndpoints` and
`TestDepositNeedsAdminButNotStepUp` passed. Appearance/sidebar/theme styles and
frontend dependency inputs are unchanged by this merge, so the earlier staged
Appearance captures retain their recorded source revisions. Full current-head CI
and autonomous clearance are still required.

Two pre-existing Vite notices remain: `/css/styles.css` is served by Go outside
the Vite source tree, and the generated application bundle exceeds Vite's default
500 kB advisory threshold. Both parent bundles already exceeded that threshold
(536,717 and 537,697 bytes); this merge does not introduce that warning.

## Visual refinement — 2026-10-26

Round-3 release review, gap 2: shell and Users hierarchy, with no route, role, copy or Go change. Evidence, stages, fixture and limits are in [docs/ui-visual-refinement-2026-10-26](docs/ui-visual-refinement-2026-10-26/README.md).

- **Font:** round 3's Arial-like face was a capture-fixture artifact. The server serves `./css` and `./fonts` from its working directory, and the old driver ran from a bare scratch directory, so both returned 404. With the corrected fixture, every capture (BEFORE included) loads Space Grotesk and IBM Plex Mono. The real defect it uncovered, a mono wordmark leaking in from `/css/styles.css`, is fixed in `index.css`.
- **Users:** the nine icon actions are one labelled "Manage" disclosure, with delete set apart; on phones rows stack as labelled blocks. `table-roles.mjs` measured DOM roles through Playwright on synthetic HTML, not the accessibility tree; the independent review later confirmed the real app's Chromium accessibility tree at 390px (CDP `Accessibility.getFullAXTree`). Firefox and WebKit are untested. In-app `--verify`: 23/23 before, after and at the confirm recapture.
- **Checks** at `f36ea7d` plus this change:
  - `node web/src/ky-ui/check-vendor.mjs` and `npm run build` pass; the committed `web/dist` equals a fresh build.
  - `npm test` (vitest) and `npm audit --omit=dev` pass (0 vulnerabilities).
  - `go build ./...`, `go vet ./...`, gofmt, and `go test -p 2 -race -count=1 ./...` (18 packages) pass.
  - Push relay workers are untouched and were not run; CI runs them.
- Ratings belong to the independent reviewer; no 9/10 is claimed.

## Review follow-up R1 — 2026-10-26

From the independent refinement review. Evidence, stages and limits are in [docs/ui-review-followups-2026-10-26](docs/ui-review-followups-2026-10-26/README.md).

- **R1:** a delegate no longer sees an empty "Manage" menu on an Administrator row. `UserRowActions` renders nothing when no action applies; the nine handlers, guards and role conditions are unchanged. On phones that row's empty Actions cell is hidden.
- **Test:** `web/src/components/AdminUsers.test.tsx` covers a full administrator (nine actions), a delegate on an administrator row (nothing) and a delegate on an ordinary row (five). Removing the guard fails it.
- **Real app:** a real Helpdesk delegate, created and delegated through the UI. Before, the Administrator row's Manage opened with 0 actions; after, there is no Manage, while ordinary rows keep 5 and a full administrator keeps 9 on every row. This holds at 1280×900 and 390×844, light and dark. The full administrator's `--verify` passes 23/23 before, after and on the committed build.
- **Checks** at `858eb70` plus this change:
  - `check-vendor` and `npm run build` pass; the committed `web/dist` equals a fresh build.
  - vitest passes 198/198, and `npm audit --omit=dev` finds 0 vulnerabilities.
  - `go build`, `go vet`, gofmt and `go test -p 2 -race -count=1 ./...` pass; Go code is unchanged.
- **Limits:** N2 (Escape does not close the menu) and N3 (phone cell names repeat their label) are left as recorded.

## Suite design pass — 2026-10-31

ky-ui 0.6.0 shell and palette pairs: every pre-dashboard screen (sign-in, MFA, reset and
activation links, forced password change) in the shared `ky-auth` frame with the theme
switcher; administration grouped into folding Directory, Applications, Security and System
sections; the shared user block and About dialog; Users gains a search, role and status
toolbar with compact rows; OAuth clients show name, ID, redirect count and real status with
"Manage" plus a ⋯ menu. No authentication, session, OAuth/OIDC or CSRF code changed.
Before/after captures (1440×900 light/dark, 390×844 light, synthetic fixture created in the
UI) are in `docs/ui-suite-2026-10-31/screenshots/`.
