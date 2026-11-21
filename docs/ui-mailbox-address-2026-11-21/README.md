# Mailbox address captures (2026-11-21)

Driver: `capture.mjs` in this folder (uses `$KY_REDESIGN/captures/drivers/lib.mjs` and Playwright's
Chromium), run against a fresh bootstrap of each binary: `before` is `origin/master` at `49e8aa6`,
`after` is this branch. Both are single-tenant servers with the push relays empty. 1440×900 and
390×844, OS light and dark.

| Shot | Shows | Source |
| --- | --- | --- |
| `users-before-*` / `users-after-*` | Administration › Users on a single-tenant install | real server. Before and after are **byte-identical** PNGs (`cmp`), all four sizes and schemes. The driver also checks that the after server's `GET /api/admin/users` contains no `mailbox`. |
| `hosted-menu-*` | a hosted household org's users: the holder's mailbox address under their sign-in email, and the ⋯ menu with **Mailbox address** | list fixture-injected |
| `hosted-set-*` | the dialog for a member without an address, with one typed in | list fixture-injected |
| `hosted-change-*` | the dialog for the holder, prefilled with the current address, noting audit and no clearing | list fixture-injected |

**Fixture:** this release refuses a multi-tenant server at startup, and staff can't select a
customer org until tenancy build plan PR 5. So for the `hosted-*` shots the browser rewrites
only the `GET /api/admin/users` answer. It adds two customer rows and `mailboxDomains`, the shape
a household org's list has (`TestMailboxAddressRouteInACustomerOrg`). Nothing is saved, and every
other request goes to the real server.

All shots: no horizontal overflow; `<html data-theme>` is `busnes-light` or `busnes-dark` as
expected.
