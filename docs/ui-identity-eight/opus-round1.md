# KyIdentity stage 00 — Opus round 1 (baseline)

Reviewer: Claude Opus 5.5 (`claude-opus-5-5`), independent and read-only. Rubric `ky-suite-v2` from
ky-ui@639e588. Machine record: `opus-round1.json` (`ky-ui-council-scores/2`). Frozen score vectors
sha256 `8aabb7e60c63ce2a9d3983f9139b63983c6e9b224127706e949301a64e497253`, fixed before the live
supplement and copied verbatim into `files[]`. Scored blind: no prior Identity rating exists, and peer reports were not opened.

## Verdict

**Not satisfied** (`satisfied: false`, `genuinely_satisfied: false`).

| Cohort | n | Quality sum | Quality mean (exact) | Min | Max | Files ≥ 8 | Ky fit mean (exact) |
|---|---|---|---|---|---|---|---|
| admin-console | 20 | 137.2 | 6.86 | 5.7 | 8.0 | 2 | 7.8 |
| auth | 4 | 31.2 | 7.8 | 7.8 | 7.8 | 0 | 8.4 |
| member-home | 4 | 29.0 | 7.25 | 7.0 | 7.5 | 0 | 8.1 |
| settings | 8 | 59.8 | 7.475 | 6.7 | 8.2 | 2 | 8.1 |

Capture-set summary (not a ranking): quality 257.2 / 36 = 643/90 = **7.1444…** (half-up 7.1);
Ky fit 286.8 / 36 = 239/30 = **7.9667** (half-up 8.0). No cohort reaches 8.0. The parent computes
the combined Claude/Sol progression score.

## Inputs and checks

- Source `95799c4`, evidence `f27d56b`, worktree HEAD `f16a734` (guidance only; images unchanged).
- Inventory recomputed before viewing: 36 PNGs, hashes, bytes and dimensions match `inventory-v1.json`
  and `manifest-00-before.json`; 0 exact duplicates; 306 same-size pairs, 0 near duplicates (closest:
  users-manage-mobile-dark vs users-mobile-dark, 4.36% pixels changed, max delta 211).
- Vendored `web/src/ky-ui/tokens.css` equals ky-ui@639e588 `src/tokens.css` (`639f8e73…`).
- Brand references: four KyRecovery stage-05 desktop originals at `247c10ee`, extracted by `git show`,
  hashes match `brand-references.json`. Used for `ky_fit` only.
- All 36 originals opened one at a time at native resolution. Confidence high for every file.
- Totals: per-file `Decimal` half-up; cohort means exact over rounded totals; recomputed by script and
  checked against the inventory.

## Per-surface scores (light and dark scored identically on every surface)

H/T/D/C/A/Co = hierarchy, typography, density_layout, color, visible_affordances, coherence.

| Surface | Viewport | H | T | D | C | A | Co | Total | Ky fit |
|---|---|---|---|---|---|---|---|---|---|
| login | desktop | 8 | 8 | 7 | 8 | 8 | 8 | 7.8 | 8.4 |
| login | mobile | 8 | 8 | 7 | 8 | 8 | 8 | 7.8 | 8.4 |
| applications | desktop | 7 | 8 | 7 | 8 | 7 | 8 | 7.5 | 8.2 |
| applications | mobile | 7 | 7 | 6 | 8 | 7 | 7 | 7.0 | 8.0 |
| security | desktop | 7 | 8 | 7 | 7 | 7 | 7 | 7.2 | 7.6 |
| security | mobile | 7 | 7 | 6 | 7 | 7 | 6 | 6.7 | 7.4 |
| appearance | desktop | 8 | 8 | 8 | 8 | 8 | 9 | 8.2 | 8.8 |
| appearance | mobile | 8 | 8 | 7 | 8 | 8 | 8 | 7.8 | 8.6 |
| users | desktop | 8 | 8 | 8 | 8 | 8 | 8 | 8.0 | 8.0 |
| users | mobile | 7 | 7 | 6 | 8 | 7 | 7 | 7.0 | 7.8 |
| users-manage | desktop | 6 | 8 | 5 | 8 | 7 | 6 | 6.6 | 7.8 |
| users-manage | mobile | 7 | 7 | 6 | 8 | 7 | 7 | 7.0 | 7.6 |
| create-user | desktop | 8 | 7 | 8 | 8 | 8 | 8 | 7.9 | 8.2 |
| create-user | mobile | 8 | 7 | 7 | 8 | 7 | 8 | 7.5 | 8.0 |
| groups | desktop | 7 | 7 | 6 | 8 | 6 | 5 | 6.5 | 7.8 |
| groups | mobile | 7 | 7 | 6 | 8 | 6 | 5 | 6.5 | 7.6 |
| app-connections | desktop | 5 | 7 | 5 | 8 | 6 | 5 | 5.9 | 7.8 |
| app-connections | mobile | 5 | 7 | 4 | 8 | 6 | 5 | 5.7 | 7.4 |

Each file's dimension observations, brand observations, artifacts and caveat are in the JSON.

## What is good

- Desktop shell is one 240px left sidebar with wordmark, stamp, two titled groups, the shared accent
  rail and a bottom account region. It reads as the same suite as KyRecovery.
- Appearance uses the shared `ky-appearance` cards and matches the Recovery reference almost exactly.
- Users desktop is a clean table with one filled primary, aligned Manage column and semantic status.
- Palette and accent discipline hold: orange marks the primary, the selected nav item and focus.

## Major findings (visible evidence)

1. **Users Manage disclosure breaks the table (severity: high for this workflow).** Opening Manage on
   the administrator row grows it from 62px to ~460px, re-flows every column and moves that row's
   trigger ~150px left. The menu is table content, not an overlay. This is the lowest desktop score
   outside App connections, and it is the main per-user admin path.
2. **Empty list views look assembled (high).** Groups and App connections show a header-only table
   card, a dashed rule, a floating "No matching…" message (no search entered) and a disabled pager.
   App connections has no primary, and its only button touches the title. On phones its table is
   clipped at "Acc", hiding Actions. Applications' empty message names App connections without a link.
3. **Security and the phone shell (medium).** The native checkbox is Chromium blue in both themes,
   buttons are ~34px, every section is its own card with dashed inner rules, and section headers wrap
   differently at 390px. Phone navigation is two unlabelled scrolling rows, and Applications repeats
   the signed-in identity right under the header. Users phone records have no heading.

Phone navigation is two stacked scroll groups, not adjacent sidebars, so it is not a one-left-region
violation. It loses points for unlabelled groups and the space it takes.

## Priority batches (at most three)

1. **Row-actions overlay.** Render the Manage menu as an anchored overlay: out of flow, overlay shadow,
   one open at a time, Escape and outside click close it and return focus to the trigger. Row height and
   column widths must not change. On phones, span the full record or use a sheet. Keep `UserRowActions`
   per-row authorization, the separated delete action and operation-bound step-up unchanged.
2. **List-view header and empty state.** Use one page-header pattern: h1 left, the view's single
   primary right, sized like Users' Create User. At zero items, show what belongs here plus the existing
   action, and hide the table header and pager. Say "No groups yet" unless a search is active. Stack App
   connections rows on phones like Users. Cut the policy paragraphs to one quiet line. Link only to
   existing views. No new features.
3. **Security and phone polish.** Put the accent token on native checkbox/radio `accent-color`, bring
   buttons to `--ky-control-size`, and flatten Security into divided sections like KyRecovery with one
   header layout. Show the two phone nav group labels (or use one row with a divider), drop the
   duplicate "Signed in as" line, and make the account name each Users phone record's heading.

Minor, not blocking: login reset link offset and tight; dark stamp tile blends into its panel; Create
User password helper sits inside the label, its placeholder clips at 390px, and required/optional is
not marked; mono is used in status pills and pagers.

## What each picture cannot prove

- **Login:** keyboard order, validation/errors, MFA step, password managers, real contrast.
- **Applications:** a populated launcher, ordinary-user view, what "Set one up" opens.
- **Security:** pairing, passkey, TOTP and recovery flows, step-up prompts, content below the fold.
- **Appearance:** applying a theme, saved choice, cross-tab sync. Phone shows six cards only.
- **Users:** scale, search, sort, delegate or ordinary-user views.
- **Users Manage:** keyboard/Escape, focus return, the action dialogs, a delegate's reduced menu.
- **Create User:** validation, step-up, submission, focus trap, on-screen keyboard overlap.
- **Groups / App connections:** populated rows, row actions, create dialogs, membership step-up.

## Gates

All `untested`. Screenshots cannot pass a gate. Not measured: keyboard, focus, contrast, states,
responsive, required labels.

## Live supplement (after freeze; does not change vectors)

Own incognito tab, Chrome154/DPR2, `http://127.0.0.1:51489`, ordinary admin login. I only opened and
closed existing controls and read computed styles. Nothing was created, submitted or changed, and the
tab was closed afterwards.

- Manage open: row 62→460px, menu `position: static`, `box-shadow: none`, Email column x 550→506,
  trigger x 1144→997.
- Escape leaves the disclosure open (focus stays on its summary). Opening a second row leaves the first
  open: two 460px rows, document 1308px. This raises the Manage finding beyond what the stills show.
- Phone App connections: the title's bottom equals the button's top (235px); the table is 576px wide
  inside a 348px `overflow-x: auto` card.
- Phone nav groups have aria-labels "Your account" and "Administration" but no visible headings.
- Security checkbox `accent-color: auto`; content buttons are 34px and 31px.

## Product `design.md` conflicts (reported, not repaired)

- `design.md:24` says "KySecurity Patina themed". `:425` gives a #0d0f14/#161a22 palette with a
  #4deeea cyan accent. `:476` says "KySecurity CSS and fonts". All three conflict with the current
  Busnes cream/charcoal/orange requirement and the tokens.
- `:426` puts IBM Plex Mono on navigation; the contract limits mono to code, keys and fixed-width data.
- `:34` says generic SCIM 2.0 was replaced by native pairing in the MVP; AGENTS.md documents generic
  `scim` connectors as current. This one is non-visual.

## Missing coverage

Keyboard, focus-visible, measured contrast, loading/error/validation states, configured
apps/groups/connections/devices, delegate and ordinary-user roles, remaining admin pages (Sign-in
policies, Access requests, Suite sync, Inbound SCIM, OAuth clients, Audit log, Alerts, Disaster
recovery, Mail delivery), competitors. No competitive gap and no full-product acceptance is claimed.
