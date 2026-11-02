# Admin table layout — 2026-11-02

The owner flagged OAuth clients, Inbound SCIM and Suite sync at desktop width. Changes are in the CHANGELOG (Unreleased).

## Captures

`screenshots/kyidentity-30-{before,after}-{oauth,scim,suitesync}-{1440,1280}-{light,dark}.png`: 1440×900 and 1280×800, Busnes Light and Busnes Dark. "Before" is `master` at `639b4c9` (0.6.0); "after" is this branch. Driver: `kyidentity-30-admin-tables.mjs` in the ky-redesign capture tooling. It runs the real server on a scratch data directory and seeds the rows straight into SQLite with the server stopped. The seed has eleven suite clients, among them `hermes-chat` with a UUID ID and clients with two and three redirect URIs. It also has eight Suite sync targets (Active, Failing, Disabled, two SCIM rows, URLs with ports and long paths) and one inbound connector with a live and a revoked token.

## Overflow measurement

For every shot, the driver records the document's `scrollWidth - innerWidth`, `.ky-content`'s overflow, and `scrollWidth - clientWidth` for each `.table-card` and table. It fails when any after shot is above 0.

- Before: Suite sync overflowed by 738 px at 1440 and by 898 px at 1280.
- After: every value is 0 on all three pages, at both sizes, in both themes.

The repository has no browser test runner, so this check lives in the capture driver. Vitest covers the new pieces instead: `listCell` (`web/src/listCell.test.ts`), and the Suite sync ⋯ menu and URL cell (`web/src/components/AdminSystems.test.tsx`).

## Limits

- Chromium only.
- The ⋯ menu was not opened in a capture. Its content is checked by the render test.
- The expanded setup disclosure and phone widths were not captured.
