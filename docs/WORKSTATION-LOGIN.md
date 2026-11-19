# Workstation login (Linux desktops)

People sign in to Linux desktops with their KyIdentity account through
[Himmelblau](https://github.com/himmelblau-idm/himmelblau)'s generic OIDC mode. The desktop
shows a short code. The person opens `<issuer>/device` on a phone or another computer, signs
in as usual (password, MFA, push or passkey), checks what is asking, and approves. The
desktop then signs in and, by default, sets up a Hello PIN for later sign-ins.

Design and the Himmelblau source review: `docs/superpowers/specs/2026-11-19-workstation-login-design.md`.

## Set up

1. **App connections → Workstation login → Add.** This creates a workstation app: a public
   OAuth client with no secret and no redirect URIs. Device sign-in is **off** until you
   turn it on.
2. **Manage access.** Assign the groups whose members may sign in to desktops. The app is
   assigned-only, so nobody else can approve a code for it. The same group names go into
   `pam_allow_groups`, so a desktop also refuses everyone else.
3. **Edit settings.** Turn on **Allow device sign-in**. Choose the code lifetime (2-15 minutes,
   default 5) and the offline window (0-30 days, default 7).
4. **On each desktop**, install Himmelblau 4.0 or later (`himmelblau`, `nss-himmelblau`,
   `pam-himmelblau`) and copy the generated file to `/etc/himmelblau/himmelblau.conf`:

   ```ini
   [global]
   oidc_issuer_url = https://id.example.com
   app_id = <the workstation app's client ID>
   pam_allow_groups = linux-users
   ```

   Then run `sudo aad-tool configure-pam` and restart `himmelblaud`.

Requirements Himmelblau imposes:

- `oidc_issuer_url` must be `https://` and equal KyIdentity's issuer exactly.
- A group name containing `:` is dropped by Himmelblau and a `,` would split the list, so
  such groups never match `pam_allow_groups`. The admin screen warns about them.
- Himmelblau derives POSIX UIDs and GIDs itself, from the issuer URL and the user or group
  name. KyIdentity sends no `uidNumber` or `gidNumber`. Changing the issuer URL, or renaming a
  user or group, gives that account or group new IDs on every desktop; file ownership on
  disk does not follow.
- The username on the desktop is the KyIdentity username (`preferred_username`).

## Break-glass

Keep local accounts working. `aad-tool configure-pam` keeps `pam_unix` in the stack; leave
it there, and keep one local administrator account with a password on every desktop. That
account signs in when KyIdentity, the network or Himmelblau is down, and it is the way back
in after a broken configuration. Never point `pam_allow_groups` at an empty list on
purpose: Himmelblau treats an empty list as "everyone KyIdentity lets in".

## Sessions, refresh and the offline window

An approved code creates a **workstation session** for that person and app. It is listed
with their sessions ("Workstation login: <app>") and can be revoked there like any other.

- With an offline window above 0, the desktop gets a refresh token. Each refresh is
  single-use: the desktop gets a new one, and presenting a spent one ends the whole family.
  The session lasts the window from its **last** refresh, so a desktop that reaches
  KyIdentity at least once a window keeps working.
- With a window of 0 there is no refresh token. Every sign-in is a new code on the desktop,
  and Himmelblau does not offer a PIN.
- Shortening the window shortens open sessions at once; 0 ends them.

What ends a workstation session at once: disabling the account, SCIM deprovisioning,
removing the person's access to the app, revoking their sessions (theirs or an
administrator's), an MFA reset and a password change. Each is tested
(`TestWorkstationSessionsEndWithAccess`, `TestWorkstationSessionEndsOnSCIMDeprovision`).
Turning the device grant off stops new sign-ins; open sessions keep refreshing until one of
the above, or until the app's client is disabled.

## The offline trade-off

KyIdentity can only refuse the desktop's next refresh. Online, Himmelblau redeems its
refresh token on every PIN sign-in, so a revoked person is refused at their next sign-in
(and Himmelblau then deletes their PIN). **Offline, it cannot ask.** A desktop that cannot
reach KyIdentity keeps accepting the cached PIN; disabling someone takes effect on that
desktop only when it is next online. The offline window limits how long the refresh token
works, not how long an offline desktop trusts its cache. Measured behaviour is below.

## Measured with Himmelblau (end-to-end)

`scripts/e2e-himmelblau.sh` runs a throwaway KyIdentity from the checkout behind a
throwaway TLS terminator and Himmelblau (Community Nightly packages, Debian 13, systemd) in
a podman container, and authenticates with `pamtester`. It needs podman, network access
for the image and a few minutes, so it is a manual check, not a CI job.

Results are recorded in the PR that introduced this feature and summarised here once
measured.

## Endpoints

| Route | Who |
|---|---|
| `POST /oauth/device_authorization` | the desktop (`client_id` of a workstation app; no secret) |
| `POST /oauth/token`, `grant_type=urn:ietf:params:oauth:grant-type:device_code` | the desktop |
| `POST /oauth/token`, `grant_type=refresh_token` | the desktop (workstation apps are the only public clients that may refresh) |
| `GET /device`, `POST /api/device/lookup`, `POST /api/device/decision` | the signed-in person |
| `GET/POST /api/admin/workstation-apps`, `PUT /api/admin/workstation-apps/{id}` | administrators (changes need step-up) |

Audit actions: `device_grant.issued`, `.code_rejected`, `.approved`, `.denied`,
`.redeemed`, `.replayed`, `admin.workstation_app_created`, `admin.workstation_app_updated`.
No code, token or address is written to the audit details.
