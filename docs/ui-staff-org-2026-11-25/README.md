# Staff org selection captures (tenancy build plan 5)

2026-11-25. Driver: [`capture.mjs`](capture.mjs), using the suite capture library in
`~/git/ky-redesign/captures/drivers/lib.mjs`, from branch `feat/staff-org-selection`. A fresh,
real single-tenant install with a real sign-in; every shot is 1440x900 and 390x844 in Busnes
Light and Dark. No shot overflows horizontally.

**Fixtures.** This release refuses to start in multi-tenant mode, where the picker shows. So the
finder's answers (`GET /api/admin/orgs`) are replaced in the browser: an empty search is a staff
org, any other the customer org "The Rivera family". Nothing else is replaced and nothing is
submitted. The Users list below the picker is the single-tenant install's own, because a
single-tenant server ignores `X-Ky-Org`; the driver records the header each Users load sent
(the staff org, then the customer org). The server side is covered by the Go tests.

| View | What it shows |
| --- | --- |
| `picker` | Users, starting in the staff org. |
| `found` | A search by a member's exact email, with its one result. |
| `selected` | After "Work in this org": the picker names the customer org and the pages reloaded with it. |
