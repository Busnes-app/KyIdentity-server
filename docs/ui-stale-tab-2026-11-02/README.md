# Stale tab after an upgrade — 2026-11-02

A tab opened before an upgrade kept running the old app while reading the new server's data
(0.6.0's About box inside the 0.5 UI). Two changes: `index.html` and the SPA fallback are sent
with `Cache-Control: no-cache` (assets unchanged), and ky-ui's update notice offers a reload
when the server serves a different build. It never reloads by itself.

## Captures

`screenshots/kyidentity-stale-tab-{before,after}-1440-{light,dark}.png`, 1440×900, Busnes Light
and Dark. Driver: `kyidentity-40-stale-tab.mjs` in the ky-redesign capture tooling. It signs in on
one build, then stops the server and starts the next build on the same data and port under the
open tab, advances the page clock five minutes and focuses the window.

- Before: the tab is opened on `master` (`9456f75`) and the server is upgraded to this branch.
  No notice; the tab keeps running the old bundle.
- After: the tab is opened on this branch and the server is upgraded to this branch with its
  main bundle renamed, standing in for the next release. "KyIdentity was updated. Reload to use
  the new version." with Reload and Dismiss.

## Limits

- Chromium only. The "next release" is this branch with a renamed bundle, not a real later release.
