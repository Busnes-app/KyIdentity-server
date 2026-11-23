# Plans and orgs captures (tenancy build plan 9 (b))

2026-11-23. Driver: [`capture.mjs`](capture.mjs), using the suite capture library in
`~/git/ky-redesign/captures/drivers/lib.mjs`. "before" is `origin/master` at `5604cd9`; "after"
is this branch. Each server is a fresh, real single-tenant install with a real sign-in, and every
shot is 1440x900 and 390x844 in Busnes Light and Dark. No shot overflows horizontally.

Two changes. The Delete everything copy says "organisation", not "household", because every
paid plan is now one customer org, and the copy is plainer. Each dialog now has one way out: the
header's Close, so the confirm form drops its Cancel and the confirmation drops its second Close.
Shots marked *fixture* replace three browser answers, as in
[`../ui-delete-everything-2026-11-21`](../ui-delete-everything-2026-11-21/README.md): `GET
/api/user/erase` (`{holder: true, otherMembers: 2}`), the application list, and `exportOnly` in
the session's `enrollment`. Nothing is submitted. Every shot shares one sign-in, so each Account view lists one session. Full-page shots grow the viewport to the page
height, so the fixed sidebar spans the whole page.

| View | What changes |
| --- | --- |
| `account` | Nothing: single-tenant has no Delete everything section. |
| `account-hosted` (fixture) | The section's summary: "Deletes your organisation. You lose access straight away. The other 2 members have 7 days to export their own data before everything is deleted. This cannot be undone." |
| `dialog` (fixture) | The same summary, word for word; no Cancel beside the header Close. |
| `done` (fixture) | Titled "Deletion scheduled": "You have been signed out. The other members have 7 days to export their own data."; one Close. |
| `export-only` (fixture) | The heading "Your organisation is being deleted" and the lede "Export your own data from each app below before your organisation and its data are permanently deleted." |
