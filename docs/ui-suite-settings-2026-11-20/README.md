# Suite settings captures (2026-11-20)

Driver: `capture.mjs` in this folder (uses `$KY_REDESIGN/captures/drivers/lib.mjs`, default `~/git/ky-redesign`, and
Playwright's Chromium), run against a fresh bootstrap of this branch's binary at
1440x900, OS light scheme, nothing saved in the browser. Every action goes through the real UI
and API, including step-up for the mail domains.

| Shot | Shows | `<html data-theme>` |
| --- | --- | --- |
| `signin-before` | sign-in page with no default set | `busnes-light` |
| `admin-empty` | Administration › Suite settings on a fresh install | `busnes-light` |
| `admin-refused` | `https://example.com` refused with the server's reason; nothing stored | `busnes-light` |
| `admin-saved` | `example.com` and `Bücher.example` saved (stored as punycode), default set to Ocean, follows device; the admin's own page switches at once | `white-cliffs` |
| `signin-default` | a new browser with nothing saved: the sign-in page applies the default (Ocean Light under a light OS) | `white-cliffs` |
| `signin-user-choice` | the same browser after saving Busnes Light: the user's choice wins | `busnes-light` |

The driver also checks that saving one form keeps an unsaved edit in the other (it fails
against the first version of the page). Run log: `/api/appearance` answered `{"defaultTheme":"ocean-pair"}`, an anonymous
`/api/suite/email-domains` answered 401, and no shot overflows horizontally.
Not captured: dark scheme, phones, and other apps (none applies the default yet).
