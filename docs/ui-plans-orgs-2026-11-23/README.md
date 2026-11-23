# Plans and orgs captures (tenancy build plan 9 (b))

2026-11-23. Driver: [`capture.mjs`](capture.mjs), using the suite capture library in
`~/git/ky-redesign/captures/drivers/lib.mjs`. "before" is `origin/master` at `5604cd9`; "after"
is this branch. Each server is a fresh, real single-tenant install with a real sign-in, and every
shot is 1440x900 and 390x844 in Busnes Light and Dark. No shot overflows horizontally.

The only change is copy: Delete everything says "organisation", not "household", because every
paid plan is now one customer org. Shots marked *fixture* replace three browser answers, as in
[`../ui-delete-everything-2026-11-21`](../ui-delete-everything-2026-11-21/README.md): `GET
/api/user/erase` (`{holder: true, otherMembers: 2}`), the application list, and `exportOnly` in
the session's `enrollment`. Nothing is submitted.

| View | What changes |
| --- | --- |
| `account` | Nothing: single-tenant has no Delete everything section. |
| `account-hosted` (fixture) | The section's summary: "Deletes your organisation". |
| `dialog` (fixture) | The dialog's summary. |
| `done` (fixture) | The confirmation: "Your organisation will be deleted". |
| `export-only` (fixture) | The heading: "Your organisation is being deleted". |
