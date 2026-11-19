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
throwaway TLS terminator and Himmelblau (Community Nightly packages, Debian 13) in a podman
container, and authenticates with `pamtester` through `pam_himmelblau`. It needs podman,
socat, openssl, jq, network access for the image and about ten minutes, so it is a manual
check, not a CI job. In the container `himmelblaud` runs directly as its own user: a
rootless container cannot give the systemd units the namespaces they ask for.

Measured on 2026-11-19 against Himmelblau `5.0.0-debian13~20261119` (nightly, built from
`main`). The 4.0.8 release was read, not run (no free 4.x packages).

| Case | Result |
|---|---|
| Assigned user: device code, approval, PIN enrolment; PAM `authenticate` and `acct_mgmt` | succeeds |
| Assigned user: later online PIN sign-in | succeeds; **one refresh at KyIdentity per sign-in** |
| Unassigned user | KyIdentity refuses the approval (`no_access`); the code expires; no PAM success |
| Denied code | Himmelblau reports "User denied authorization" and shows a new code; no PAM success |
| User KyIdentity admits but outside `pam_allow_groups` | PAM account management refuses |
| Disabled after enrolment | next online PIN sign-in refused ("Your session has expired"), new code shown |
| Sessions revoked, online | same: refused at the next PIN sign-in |
| Offline (KyIdentity unreachable) | cached PIN sign-in succeeds |
| Revoked while the desktop is offline | PIN keeps working offline; refused at the first PIN sign-in once Himmelblau sees KyIdentity again (it re-probes after 15 s) |
| Background user refresh, then PIN sign-in | succeeds |
| Background user refresh, then a daemon restart (or reboot), then PIN sign-in | **refused: a new device code is needed** (below) |

A denied or expired code does not end the PAM conversation: Himmelblau reports it and
starts a new code, so a greeter keeps offering sign-in.

### Known issue: Himmelblau and single-use refresh tokens

Himmelblau keeps two copies of the refresh token: one in memory and one sealed to the PIN
key. A background user refresh (every `cache_timeout`, 300 s by default, while the account is
looked up) rotates only the in-memory copy. After `himmelblaud` restarts, which includes
every reboot, only the sealed copy is left, and it has already been spent. KyIdentity treats
a spent refresh token as a replay and ends the family, so the next PIN sign-in fails and the
person must approve a new code. Nothing is exposed; the cost is a device-code sign-in after
a restart that follows a background refresh.

Fixing it needs a Himmelblau change: re-seal the refresh token after a background refresh
(or persist the latest copy). KyIdentity keeps strict reuse detection; a grace period for
the previous token would weaken replay detection for every workstation.

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
