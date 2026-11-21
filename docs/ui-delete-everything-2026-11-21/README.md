# Delete everything captures (tenancy build plan 8 (c))

2026-11-20. Driver: [`capture.mjs`](capture.mjs), using the suite capture library in
`~/git/ky-redesign/captures/drivers/lib.mjs`. "before" is `origin/master` at `49e8aa6`; "after"
is this branch. Each server is a fresh, real install with a real sign-in, and every shot is
1440x900 and 390x844 in Busnes Light and Dark. No shot overflows horizontally.

**Fixtures.** This release refuses to start in multi-tenant mode, where the button applies. So
the shots marked *fixture* replace three answers in the browser and nothing else:
- `GET /api/user/erase` returns `{holder: true, otherMembers: 2}`;
- the application list holds KyPost, KyCalendar and KyDrive;
- the `export-only` view adds `exportOnly: true` to the session's `enrollment`.

Nothing is submitted. The server side is covered by the Go tests.

| View | What it shows |
| --- | --- |
| `account` | Settings › Account, single-tenant. Before and after are the same: the server answers `404`, so there is no section. |
| `account-hosted` (fixture) | The Delete everything section at the end of Account, for a household's account holder. |
| `dialog` (fixture) | The dialog: exports first, then the typed address. The address has been typed, so the button is enabled. |
| `export-only` (fixture) | What a member sees during the 7-day window. |
