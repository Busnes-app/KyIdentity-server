# KyIdentity review follow-up R1 (2026-10-26)

Implementation follow-up to the independent refinement review (`ky-ui` `reviews/2026-10-26-fleet/refinement-runtime-review.md`, finding R1 and nit N1). This is not a review and claims no score.

## R1: no empty Manage menu for a delegate on an administrator row

A delegated helpdesk viewer saw a "Manage" disclosure on Administrator rows that opened an empty menu, because every action there is gated by `full` or `full || u.role !== 'admin'`. The row's actions are now their own component, `UserRowActions`, which renders nothing when `!full && u.role === 'admin'`. The nine handlers, their `disabled` guards, labels, names and role conditions are unchanged; `AdminUsers` passes the same functions through. No new copy was added.

On phones the Administrator row's now-empty Actions cell is hidden (`.users-table td:empty`), so no bare "Actions" label is left. On desktop the column stays and the cell is blank.

- `web/src/components/AdminUsers.test.tsx` renders the three cases. A full administrator gets all nine actions, with delete last. A delegate on an administrator row gets no markup. A delegate on an ordinary row gets the five recovery actions. Removing the guard fails the second case.
- A real delegate account, not a simulation: the capture fixture's administrator creates `helpdesk` and `member` through the Create User form, then grants `helpdesk` the Helpdesk delegation in the delegation editor, answering step-up in the UI. `CAPTURE_AS=delegate` signs in as `helpdesk`, so the server's own delegated access applies. The reviewer's harness rewrote `/api/auth/me` client-side; that was not needed here.

## N1: what `table-roles.mjs` measured

The visual-refinement batch said Chromium keeps the table roles under the phone CSS. Its `table-roles.mjs` measured roles with Playwright `getByRole`/`ariaSnapshot` on synthetic HTML: DOM role computation, not the browser's accessibility tree. The independent reviewer has since verified the real app at 390px with CDP `Accessibility.getFullAXTree` (table 1, rowgroup 1, row 2, columnheader 6, cell 6, no LayoutTable fallback). Firefox and WebKit are unknown. The earlier evidence files are left as recorded; `UI-VERIFICATION.md` now states this correctly.

## Stages

Same driver and fixture throughout. Each manifest in `screenshots/` records the source commit, a hash of the uncommitted diff (this directory excluded), the embedded `web/dist/index.html` hash, OS, driver, fixture, the loaded fonts and each PNG's SHA-256. Each `*-rows.jsonl` records, per capture, which row was opened and, for every row, whether it offered Manage, whether it was open, and its actions. `SHA256SUMS` covers every file in `screenshots/`.

| Prefix | Build (embedded index) | Viewer | Result |
|---|---|---|---|
| `kyidentity-00-before-delegate` | committed `858eb70` (`22ea47e7846d`) | helpdesk delegate | Administrator row: Manage opens with 0 actions; ordinary rows 5 |
| `kyidentity-00-before-admin` | same | full administrator | every row 9 |
| `kyidentity-01-after-delegate` | fix, first build (`a01f5e4c2421`) | helpdesk delegate | Administrator row: no Manage; ordinary rows 5. On phone a bare "Actions" label is left |
| `kyidentity-01-after-admin` | same | full administrator | every row 9 |
| `kyidentity-01-confirm-delegate` | final build with the empty phone cell hidden (`7ff014818e3f`, committed) | helpdesk delegate | as `01-after`, without the bare label: the one confirm recapture |

Surfaces: `users`, `manage-admin-row` (opens the Administrator row's Manage if there is one) and `manage-member-row`. The page does not remount between surfaces, so in `manage-member-row` an earlier-opened Administrator menu stays open. Each batch is OS light and dark × 1280×900 and 390×844, device scale 1, Playwright 1.63 with Chromium 153.0.8010.12 via `KY_PLAYWRIGHT`, synthetic accounts only. The full administrator's in-app `--verify` passes 23/23 at `00-before`, `01-after` and `01-confirm`, the last on the committed build. Identity's own web package has no Playwright, so the CI regression is the vitest test above.

## Remaining limits

- On phones an Administrator row seen by a delegate exposes five cells, not six, because its empty Actions cell is hidden.
- N2: Escape, an outside click or a chosen action does not close the native `<details>` menu; Enter or Space on the summary does. Not changed here.
- N3: on phones each cell's name repeats its generated label ("Account admin"). Not changed here.
- Firefox and WebKit table semantics under the phone CSS are untested.

## Reproduce

From the repository root: `KY_PLAYWRIGHT=<ky-ui>/node_modules/@playwright/test/index.mjs [CAPTURE_AS=delegate] node docs/ui-review-followups-2026-10-26/capture.mjs <prefix> [surface,...]`, or `... capture.mjs --verify <prefix>`. The driver builds the server into a temporary directory on loopback port 5871 and removes it afterwards.
