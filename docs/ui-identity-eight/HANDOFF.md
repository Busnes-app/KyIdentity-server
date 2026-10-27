# KyIdentity UI checkpoint — 2026-10-27

**Repo:** Busnes-app/KyIdentity-server
**PR:** #174 — https://github.com/Busnes-app/KyIdentity-server/pull/174
**Worktree:** /home/yoshi/git/busnes.app/KyIdentity-server/.claude/worktrees/ui-identity-eight (`ui/identity-eight`)

## Current rule and state

Owner progression rule: arithmetic mean of Claude/Sol quality over the same reviewed set, half-up to one decimal;8.0 or higher accepts (7.98 counts as8). Keep exact raw/cohort scores and satisfaction; individual/category deficits are not vetoes. No extra rounds for tiny differences. Gemini only after both genuinely satisfied,advisory,never delaying accepted progression. Root AGENTS.md records it.

KyRecovery is owner-accepted and PR#81 is green at48389ec3a2a319ecbf24e6a267fe0eb03dd277b5,security verdict=cleared. Reviewer input was truncated,so omitted changes were not reviewed. Watcher stopped; no merge/deploy was authorized. Recovery fixtures were retired. Next app is Identity,not another Recovery pass.

## Done

- Baseline source95799c4,evidencef27d56b:36 originals across9surfaces,desktop1280×900/phone390×844,OSlight/dark,Chromium153/Playwright1.63,DPR1,normal serviceworkers,en-US,America/New_York. Administrator+4ordinary synthetic accounts; other setup empty/unconfigured. Open Create User unsubmitted.
- R1 raw reviews frozen and audited:Claude643/90=7.1444,Sol118/15=7.8667;combined1351/180 rounds7.5. Parent viewed all8 originals with20dimension spreads>=2. Keep raw scores. Workbook/CSV/COUNCIL have completed R1.
- UI0e5cee3: native auto popover preserves table geometry/permissions and existing step-up handlers; phone bottom menu,truthful empty Group/App connections views,complete MFA policy in disclosure,labelled phone connection rows,flat Security sections,40px controls,native theme accents,one phone navigation strip,existing permitted launcher management links.
- Stage01 desktop menu anchor was off-screen; explicit position-anchor:auto corrected in UI df8daef1cc7c2c11eccab288334ef0ee20f6634b. Stage01 preserved as superseded. Stage02 is the single bounded confirmation,not another design review round.
- Frozen confirmation41982e901a817ad602fc50f73a3e4a50ac74bb04:manifest-02-after.json,inventory-v2.json,duplicate-audit-v2.json.36 originals,306 same-size comparisons,no duplicates/overflow. Parent individually inspected all36.
-198web tests and final build passed. Browser regression check-ui.mjs passes4size/theme cases:stable row geometry,menu within viewport,one open,keyboard/outside dismissal,Escape/Edit-dialog focus return,empty/search states,full membership policy retained,40pxSecurity targets. Impeccable final source scan0findings. Vite has a >500kB uncompressed-bundle advisory (~151kB gzip),not a compiler/typecheck failure.
- Full local verifier /tmp/kyidentity-r2-verify.py is running,log /tmp/kyidentity-r2-full.log;ordinary race passed. It started at0e5cee3 before CSS cleanup,so results are not a fresh all-final-source run. Do not mislabel freshness; final-head hosted CI must qualify current source. Do not stage partial check logs/results while runner writes them.
- Offline gallery /home/yoshi/Pictures/KyPost-UI-Councel/exports/2026-10-27-changes-gallery/KyIdentity-Round2-Changes.html has36 matched comparisons,R1scores/R2pending. Checker:self-contained,contrast passes.

## Pending

- R2 Opus: node:delegated-task:command%3Amcp%3A27617469-e7a2-4680-8e45-a055c47cd9fd%3Adelegate-task%3Akyidentity-refined-opus-r2-20261027
- R2 Sol: node:delegated-task:command%3Amcp%3A27617469-e7a2-4680-8e45-a055c47cd9fd%3Adelegate-task%3Akyidentity-refined-sol-r2-20261027
- Each writes only its own round2 report pair. Wait for both terminal tasks before raw/report validation,spread audit and shared export regeneration. No partial report commits. Apply combined rule,not individual vetoes; no fresh full review through child-thread sends.
- Handle current PR#174 CI/security at current head. Link/watch event-driven; unwatch at final hand-back. No merge/deploy authorization. Keep old source checks explicit if later fields differ.

## Fixtures and limits

- FINAL fixture http://127.0.0.1:45905,private disposable credential /tmp/kyidentity-council-s4gj_vja/fixture.json. Retain until reviews finish. Do not publish password or filled-password snapshot trees. Delegates use their own incognito tabs and pass tabId every call.
- Completed baseline51489 and superseded39373 fixtures can be retired only through their owned Python wrapper's SIGTERM/finally handler. Their stdout files distinguish wrappers: /tmp/kyidentity-ui-fixture.log and /tmp/kyidentity-r2-fixture.log. Final wrapper stdout /tmp/kyidentity-r2-final-fixture.log must stay. Never kill unrelated processes.
- Owned full verifier uses GOMAXPROCS2 and default caches. Let it finish; no broad process kills or duplicate heavy suite.
- Other roles,remaining admin workflows,populated groups/connections,full keyboard/focus/state/all-theme contrast and competitive coverage remain unproven. No whole-product acceptance claim. Existing authorization/CSP/custody/saved themes unchanged.
- Old design.md cyan/MVP prose was reported,not repaired as an unrequested side task. No code changes are requested solely for that stale context.
- MySlop credential already returns401;no shared-board post succeeded,no retry with unchanged credential. This checkpoint is committed and pushed with the PR so other machines can fetch it.
