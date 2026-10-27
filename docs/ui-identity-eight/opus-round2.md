# KyIdentity stage 02 — Opus round 2 (bounded confirmation)

Reviewer: Claude Opus 5.5 (`claude-opus-5-5`), independent and read-only. Rubric `ky-suite-v2` from
ky-ui@639e588. Machine record: `opus-round2.json` (`ky-ui-council-scores/2`). Frozen score vectors
sha256 `565dcda0c6ed894728e217251a50e1d4c540256f57d60106ad0fb3b3ea385482` (2026-10-27T15:22:30Z),
fixed before `opus-round1.*` and the live supplement were opened, and copied by script into `files[]`.
Peer reports, COUNCIL/CSV/XLSX, round1-audit, verification and checks files were not opened.

## Verdict

**Not satisfied on my own numbers** (`satisfied: false`, `genuinely_satisfied: false`).

| Cohort | n | Quality sum | Quality mean (exact) | Min | Max | Files ≥ 8 | Ky fit mean (exact) |
|---|---|---|---|---|---|---|---|
| admin-console | 20 | 155.8 | 779/100 = 7.79 | 7.7 | 8.0 | 4 | 43/5 = 8.6 |
| auth | 4 | 30.2 | 151/20 = 7.55 | 7.3 | 7.8 | 0 | 17/2 = 8.5 |
| member-home | 4 | 29.6 | 37/5 = 7.4 | 7.3 | 7.5 | 0 | 43/5 = 8.6 |
| settings | 8 | 62.8 | 157/20 = 7.85 | 7.5 | 8.0 | 4 | 43/5 = 8.6 |

Capture-set summary (not a ranking): quality 278.4 / 36 = 116/15 = **7.7333…** (half-up 7.7).
Ky fit, scored separately: 309.2 / 36 = 773/90 = **8.5889…** (half-up 8.6). No cohort reaches 8.0
exactly or half-up.

Every round-1 major finding is fixed, both on screen and in the live check. What remains is one
bounded phone row-action finding and optional polish. I do not ask for another round just to chase
points. Progression is the parent's combined Claude/Sol decision, and this 0.27 individual shortfall
is not a veto.

## Inputs and checks

- Source `df8daef`, evidence `41982e9`. `df8daef..41982e9` touches only `docs/ui-identity-eight/`.
  All 11 `source_files` hashes in the manifest match `git show df8daef:<path>`.
- Inventory recomputed before viewing. 36 PNGs; sha256, bytes and dimensions match `inventory-v2.json`
  and `manifest-02-after.json`, and the stage-02 files on disk are exactly that set. 36 unique hashes.
  306 same-size pairs (153 + 153), 0 near duplicates. Closest pair: app-connections-desktop-dark vs
  groups-desktop-dark, 4.21% of pixels changed, max delta 221.
- Vendored `tokens.css` equals ky-ui@639e588 (`639f8e73…`).
- Brand references: four KyRecovery stage-05 desktop originals at `247c10ee`, extracted with
  `git show`. Their hashes match `brand-references.json`. Used for `ky_fit` only.
- All 36 originals opened one at a time at native resolution, with high confidence on each. I read one
  4× crop and some pixels to confirm the phone invoker overlap and the login x=389 rule.
- Totals: exact `Fraction` weights, per-file `Decimal` half-up, cohort means exact over the rounded
  totals. A second script recomputed every total against the inventory: 0 mismatches.

## Per-surface scores (light and dark scored identically)

H/T/D/C/A/Co = hierarchy, typography, density_layout, color, visible_affordances, coherence.

| Surface | Viewport | H | T | D | C | A | Co | Total | R1 | Δ | Ky fit |
|---|---|---|---|---|---|---|---|---|---|---|---|
| login | desktop | 8 | 8 | 7 | 8 | 8 | 8 | 7.8 | 7.8 | 0.0* | 8.5 |
| login | mobile | 7 | 8 | 6 | 8 | 8 | 7 | 7.3 | 7.8 | −0.5* | 8.5 |
| applications | desktop | 7 | 8 | 7 | 8 | 7 | 8 | 7.5 | 7.5 | 0.0 | 8.8 |
| applications | mobile | 7 | 7 | 7 | 8 | 7 | 8 | 7.3 | 7.0 | +0.3 | 8.4 |
| security | desktop | 8 | 8 | 8 | 8 | 7 | 8 | 7.9 | 7.2 | +0.7 | 8.8 |
| security | mobile | 8 | 8 | 7 | 8 | 7 | 7 | 7.5 | 6.7 | +0.8 | 8.4 |
| appearance | desktop | 8 | 8 | 8 | 8 | 8 | 8 | 8.0 | 8.2 | −0.2* | 8.8 |
| appearance | mobile | 8 | 8 | 8 | 8 | 8 | 8 | 8.0 | 7.8 | +0.2 | 8.4 |
| users | desktop | 8 | 8 | 8 | 8 | 8 | 8 | 8.0 | 8.0 | 0.0 | 8.8 |
| users | mobile | 8 | 8 | 7 | 8 | 8 | 8 | 7.8 | 7.0 | +0.8 | 8.4 |
| users-manage | desktop | 8 | 8 | 8 | 8 | 8 | 8 | 8.0 | 6.6 | +1.4 | 8.8 |
| users-manage | mobile | 8 | 8 | 7 | 8 | 7 | 8 | 7.7 | 7.0 | +0.7 | 8.4 |
| create-user | desktop | 8 | 8 | 8 | 8 | 7 | 8 | 7.9 | 7.9 | 0.0 | 8.8 |
| create-user | mobile | 8 | 7 | 8 | 8 | 7 | 8 | 7.7 | 7.5 | +0.2 | 8.4 |
| groups | desktop | 8 | 8 | 7 | 8 | 7 | 8 | 7.7 | 6.5 | +1.2 | 8.8 |
| groups | mobile | 8 | 8 | 7 | 8 | 7 | 8 | 7.7 | 6.5 | +1.2 | 8.4 |
| app-connections | desktop | 8 | 8 | 7 | 8 | 7 | 8 | 7.7 | 5.9 | +1.8 | 8.8 |
| app-connections | mobile | 8 | 8 | 7 | 8 | 7 | 8 | 7.7 | 5.7 | +2.0 | 8.4 |

\* Near-unchanged image versus stage 00: only a button region changed (login desktop 0.006%, login
mobile 0.022%, appearance desktop 0.035% of pixels). These deltas are reviewer variance, not product
progress or regression. Login mobile −0.5 is a correction: round 1 under-weighted things that were
already in stage 00. The hero band is ~340px and pushes the form into the lower half. The headline
sits at x=25 while the stamp and form sit at x=32. A 1px rule at x=389 is left over from the desktop
split.

Drift: mean Δ over all 36 files is +0.589. Over the 30 changed images it is +0.753; over the 6
near-unchanged images it is −0.233. Each file's observations, brand observations, caveat and drift
cause are in the JSON.

Ky fit per file: desktop 9/8/9/9/9 = 8.8; phone 9/8/8/9/8 = 8.4; login 9/8/N/A/9/8 = 8.5, where
`shell` is N/A because the sign-in screen has no navigation shell. `type_geometry` stays at 8 because
of Title Case dialog titles and 13px button labels. Phone `shell` and `suite_cohesion` are 8: nav
labels clip mid-word at both edges, and there is no Recovery phone reference to compare against.

## Resolved since round 1 (visible and live)

- **Desktop Manage:** rows stay 68px whether the menu is open or closed. The menu floats 8px under the
  invoker with an overlay shadow and nine 40px items. Only one menu opens at a time. A real Escape
  closes it and returns focus to the invoker.
- **Empty Groups / App connections:** the header-only table, dashed rule, floating message and pager
  are gone. Both show a headed empty state. App connections has a right-aligned primary.
- **Security:** flat ruled sections, 40px outline actions, and a native checkbox in the accent colour.
- **Phone shell:** one scrolling nav row with inline group labels. Applications no longer repeats the
  signed-in identity. Each Users phone record is headed by its account name.

## Remaining findings

1. **Phone row-action sheet covers its own invoker (medium, bounded, phone only).** In
   `users-manage-mobile-*`, the sheet's top edge (y=430) cuts ~7px off the first record's Manage button
   (y=397–437). Live at 390×844, `.row-actions-menu` is `position: fixed` with inset 430/16/16/16 and a
   transparent `::backdrop`. For the second record the whole 40px invoker is hidden. The sheet has no
   scrim and no account name, so the user can only remember which record it acts on. Smallest fix:
   put the row's account name as the sheet's first line and give the open popover a `::backdrop`
   scrim. The alternative is to anchor it under the invoker, as on desktop. Keep native popover,
   one-open, dismissal, authorization and step-up unchanged.
2. **Groups search takes focus on arrival (minor, optional).** The search field shows the accent
   border at load, and live `activeElement` is `#group-search`. The cause is `autoFocus` at
   `AdminGroups.tsx:128`, which predates this batch. App connections leaves focus on body. On a list
   with zero groups the focused search pulls attention from Create group, and on phones it can raise
   the keyboard. The view already focuses its heading at line 21.
3. **Phone polish (minor, optional, mostly unchanged since stage 00):**
   - Login hero band and alignment, as described under the drift note.
   - The Create User placeholder clips at 390px.
   - "Set one up" wraps onto two lines.
   - Security's Phones heading wraps and stacks its button, while Passkeys keeps its button inline.

   Also minor: App connections empty copy names three sources but offers only the launcher action.
   The Passkey name field sits between its Add button and the empty text. Recovery codes has no
   status line. None of these is a reason for another round on its own.

## What each picture cannot prove

- Login: validation, MFA step, password managers, real contrast.
- Applications: populated launcher, ordinary user, what "Set one up" opens.
- Security: pairing/passkey/TOTP/recovery flows, step-up, the Password section below the fold.
- Appearance: applying a theme, saved choice, cross-tab sync.
- Users / Manage: scale, search, the action dialogs, a delegate's reduced menu.
- Create User: validation, step-up, submission, focus trap, on-screen keyboard.
- Groups / App connections: populated rows, row actions, the open disclosure, create dialogs.

## Gates

All `untested`; screenshots cannot pass a gate. The live Escape/focus-return observation covers
desktop only. I did not reopen the parent-reported checks: 198 unit tests, the build, r2-browser.json
and the Impeccable scan. I make no claim that the full required suite passed on final source.

## Live supplement (after freeze; vectors unchanged)

I used my own new incognito tab (Chrome154/DPR2, `http://127.0.0.1:45905`), passed my tabId on every
call, and closed the tab afterwards. I logged in as an ordinary admin. I did nothing beyond
opening/closing Manage menus, navigating, and reading computed styles. Nothing was created,
submitted, selected or changed.

- Desktop: rows were 68px both closed and open. The menu sat at x967–1223, y206–604, 8px below the
  invoker, with shadow `rgba(0,0,0,.18) 0 8px 24px`. Items were 40px. Opening a second menu left only
  one open. A real Escape closed it and moved focus to "Manage alex".
- Phone: the menu is fixed with a transparent backdrop. It overlapped the first invoker by 7.4px and
  covered the second completely.
- Groups focuses `#group-search` on entry. The phone nav is one 366px scroller (scrollWidth 2238)
  with no edge mask. Page overflow is 0.

## Missing coverage

Not covered:
- keyboard, focus-visible and measured contrast
- loading, error and validation states
- configured apps, groups, connections and devices
- delegate and ordinary-user roles
- the remaining admin pages
- competitors

I claim no competitive gap and no whole-product acceptance.
