# Accounts and access

[Product overview](../README.md) · [Standalone installation](../INSTALL.md)

Commands and unlinked file paths below are relative to the repository root.

## Onboarding and passwords

**Inviting.** Creating a user without a password invites them: the account is pending
and disabled, holds no credential at all, and cannot sign in, be provisioned or hold app
access until an activation link sets a password. Users → the link button issues the
link (step-up required); it is shown once for hand-over, or mailed when mail delivery is
configured. Activation links last 24 hours, reset links 30 minutes, and a new link of
the same kind retires the previous one. Only the token's hash is stored, and the raw
link never appears in the audit log. A link is only redeemable while the account is
still in the state it was issued for, and every link dies when access is revoked: to
cancel an invitation, use the account's Revoke Sessions action (or delete it); setting a
password on a pending account also retires its activation link. Opening a link only shows the form; submitting it
spends the token and sets the password in one transaction, so a mail scanner that
follows the link changes nothing. Activation makes the account active and, when the link
was mailed, records the address as verified; the first sign-in then goes through any
required factor enrollment before app access. An administrator setting a password on a
pending account is the manual activation; flipping its status alone is refused.

**Given passwords.** A password the account's owner did not choose must be replaced at the
next sign-in: the bootstrap administrator's (generated, or `BOOTSTRAP_ADMIN_PASS`, or
`bootstrap-admin`), and any password an administrator sets on someone else's account when
creating it or later. Sign-in, MFA included, succeeds but opens only **Choose a new
password**. Until the change, the session can read `GET /api/auth/me` (which reports
`passwordChangeRequired: true`), step up for the change, call `POST /api/user/password`,
enroll a replacement factor (for a sign-in with a recovery code, whose step-up cannot
authorize the change), and sign out. Every other API answers `403
password_change_required`, `/oauth/authorize` returns `interaction_required` to the app, no
code or token is issued, and the account's earlier tokens stop validating. The given
password is entered once more, in the step-up dialog; the form itself asks only for the new
one, which must differ from the given one. The change clears the flag, ends every other session, token
and app grant, and is audited as `user.password_changed` with `required: true`; a reset link
also clears it. Invitations, setup-created accounts (`apply-setup`) and an administrator
setting their own password are not flagged.

**Upgrading.** The first start of this version flags, once, an existing bootstrap
administrator still on its first password, audited as `system.password_change_required`. It
is identified by its `admin.user_created` audit row from the `bootstrap` actor with no later
`user.password_changed`, `auth.password_reset` or password-setting `admin.user_updated` row;
or, once retention has pruned its creation row, as an administrator whose row was never
modified. Nothing is reset: the account still signs in with its current password, then
chooses a new one. Setup-owned and SCIM-owned accounts are never flagged.

**Passwords.** Security and devices → Password changes your own password after a
step-up; every other session, token and app grant ends, this browser stays signed in.
Changing it clears a required password change.
"Forgot your password?" on the sign-in page always answers the same way whether or not
the account exists or mail is configured, is limited per address and per account, and
mails a 30-minute reset link when it can. Redeeming a reset link signs the account out
everywhere and clears the lockout counter; it never removes a second factor. Losing a
factor is a recovery-code sign-in or an administrator MFA reset, not a password reset.

**Lockout.** Ten consecutive failures lock an account for 15 minutes. Wrong passwords,
wrong second factors at sign-in and failed step-ups all count; the counter clears only
when a sign-in fully succeeds, so a known password does not buy fresh TOTP guesses.
Each sign-in allows five second-factor attempts. A locked, disabled, pending or unknown
account gets the same `401 invalid_credentials` as a wrong password, at the same hashing
cost, even with the right password; only the audit row says which. A locked account that
already passed its password learns it is locked at the second factor (`429
account_locked`). Password hashing runs at most eight
at a time; past that, requests wait up to three seconds, then get `503` with
`Retry-After`, which never counts as a failure.

**Push sign-in limits.** A user has at most one pending login push; a second sign-in
while it is live sends none (the browser falls back to the other factors) until it is
answered or expires. Login pushes are capped at five per user per hour. Three login
pushes denied or left to expire within an hour record `auth.mfa_push_fatigue`, which
raises the `push_fatigue` alert: someone else may know the password.

**Email verification.** `email_verified` in ID tokens and userinfo is true only after a
link mailed to the address was redeemed; existing addresses start unverified. Changing
an address clears verification and retires every outstanding link.

**Mail delivery.** Administration → Mail delivery holds one SMTP relay (host, port,
STARTTLS or implicit TLS, sender, optional credentials). The password is stored
encrypted with the deployment key and is never returned; a blank password keeps the
stored one only while host, port, username and transport are unchanged, so the stored
credential can never be pointed at a different relay, and a blank host turns delivery
off. "Send test to me" mails the signed-in
administrator and audits the outcome. Cleartext SMTP is not offered: a relay without
STARTTLS is refused before any credential is sent. Without mail delivery every link is
handed over by an administrator and self-service reset is unavailable.

## Directory groups

Administrators can create, rename and delete groups under **Groups**, manage each group's
members, or open membership controls from a row in **Users**. Names are trimmed and unique
under the directory's SQLite `NOCASE` collation; renaming preserves the group's stable ID.
Membership does not change the user's global role. Group assignments grant app access;
SCIM Groups delivery is available per generic SCIM connector; see Outbound provisioning.

Group and membership mutations require a single-use step-up grant for their exact method
and path and commit with their audit event. Repeated add/remove requests are idempotent;
each accepted request is audited. Deleting a group or user removes its membership rows.

| Method and path | Purpose |
| --- | --- |
| `GET /api/admin/groups` | List groups; optional `userId` annotates each group's `member` flag for that user. |
| `POST /api/admin/groups` | Create a group from `name` and `description`. |
| `PUT /api/admin/groups/{id}` | Replace the name and description. |
| `DELETE /api/admin/groups/{id}` | Delete the group and its memberships. |
| `GET /api/admin/groups/{id}/members` | List members; `includeNonMembers=true` includes candidates to add. |
| `PUT /api/admin/groups/{id}/members/{userId}` | Ensure the user is a member. |
| `DELETE /api/admin/groups/{id}/members/{userId}` | Ensure the user is not a member. |

Both list endpoints accept `limit` (1–100, default 25), `offset` (0–1,000,000, default 0),
and `q` (up to 200 characters). Group search matches names; member search matches username,
display name or email. Responses include `total`, `limit`, and `offset`, with results under
`groups` or `users`. Counts and results share a database snapshot. Membership and deletion
audits retain the group name and, for membership changes, the username captured in the
mutation transaction. Names allow 1–128 characters, rejecting control/format marks,
private-use characters, and whitespace other than ordinary spaces. Descriptions allow up
to 2048 characters without Unicode format marks. All routes require an active administrator;
member lists expose only public directory fields.

## Delegated administration

Global administrators (`role: admin`) hold every permission and are the only ones who
can delegate. Users → the delegation button on a user sets fixed, narrow permissions
for an ordinary account; each is read on every request, so removing one takes effect
on that user's next call without waiting for their session to end.

| Delegation | May | May not |
|---|---|---|
| Helpdesk | List users and groups; view a user's sessions and offboarding status; reset MFA, revoke sessions and app grants, retry logouts, issue activation and reset links, for ordinary users | Touch an administrator's or another delegate's account in any of those ways; create, edit or delete users; assign privileges |
| Auditor | Read every administration page: users, groups, app connections, provisioning, connectors, clients, policies, mail settings, backup status, audit log | Change anything, including step-up protected writes and the recovery capsule export |
| App owner (per app) | List users and groups to pick principals; see the owned app's access, roles and access explanations; assign users and groups to the app; create and delete its roles and map principals to them; decide access requests for the app | See or touch any other app; change the app's access mode, authentication policy, claim switches, links, OAuth credentials or provisioning connection |

Everyone holding a delegation falls under the *administrators* MFA enrollment policy
from the moment it is granted: a required policy restricts their session until they
enrol, and a user who cannot satisfy it cannot be delegated to. Nobody but a global
administrator can change delegations, global MFA policy, connector secrets, mail
settings, recovery material or OAuth credentials. Writes keep their step-up
requirement and audit row (`admin.delegations_updated` records each change). Ownership
names an app record; unlinking a connection into a new record ends ownership of it, so
re-delegate after an unlink. The `GET /api/auth/me` answer carries an `access` block
the SPA uses to show the pages a delegate can use; the server enforces every route.

## Expiring access and account end dates

A direct user assignment on an app connection and a membership in a group can each
carry an expiry instant; an account can carry an end date. The operator enters a
wall-clock time in their own zone and the page shows the exact UTC instant beside it,
so a DST edge or a wrong zone is visible before it bites. Instants must lie in the
future; repeating the grant moves or clears its instant.

Expiry is decided where access is decided: the access views exclude an expired grant
and an ended account on every authorize, token exchange, UserInfo and provisioning
decision, so it holds even with no background work running. Access is a union, so an
expired grant changes nothing while another live grant remains, and a token issued on
bounded access ends with that access (`expires_in` and the ID token `exp` stop at the
latest live grant, capped by the account end date).

The expiry follow-up runs at start and once a minute: it removes expired assignments and
memberships (roles mapped through the group end, MFA policy requirements lift), revokes
the tokens and codes that depended on them, sends back-channel logout to the apps that
saw those logins, deactivates the downstream accounts, and ends accounts past their end
date (disabled, not deleted; sessions and grants revoked; profile deprovisioned). Every
removal writes an audit row with actor `expiry`. Each item commits on its own: one row
the follow-up cannot process is audited as a `*_failed` row with outcome `failure`,
returned to the log, and retried next minute, while everything else due still lands.
The rows themselves are the persisted due work, so a restart drains overdue expiries
first and an instant extended before the follow-up runs is simply not due. The last
active administrator, counted as an administrator whose end date has not passed, can
neither be scheduled to end nor ended by the follow-up: the schedule is refused with
`cannot_remove_last_admin`, and an end date that would remove the last administrator is
cleared and audited as `account.end_refused`. Over the API, omitting `endsAt` keeps the
current schedule; an empty string clears it.

## Access requests and approvals

An administrator opens an assigned-only app to requests with *Users may request access*
on its access page. A user who lacks access then sees the app under *Request access* on
their dashboard, states a reason and picks a duration (none, 1, 7, 30 or 90 days);
apps that are not open to requests are never named, whether by listing or by guessed
ID. One pending request per app, at most five pending per user, ten filings per
minute, and a request nobody answers expires after fourteen days.

Owners of the app and global administrators see the request in *Access requests*; a
delegate's inbox holds only their apps. Approving or denying spends a step-up grant and
writes an audit row. An approval is an ordinary direct assignment with the requested
expiry, written through the same path a manual grant takes, so there is no second way
to hold access and everything in "Expiring access" applies to it. The decision re-reads
the approver's current authority, the app's policy and the request's state under the
write lock: a requester cannot approve their own request, a request is decided once,
an owner whose delegation was withdrawn cannot approve from a stale form, an app closed
to requests in the meantime cannot be approved, and a request withdrawn or expired
before the click grants nothing. The requester is told by mail when delivery is
configured.

## Explaining access decisions

*Explain* on a user's row of an app's access page shows why that user can or cannot
open the app, read from the same rows that decide it: the verdict and reason, every
direct and group grant with its expiry and whether it is still live (an upstream-managed
membership is marked), the app roles held and through which group, when access ends,
the account's status and end date, the app's authentication policy, and the access,
authentication and role revisions. The reason words are the ones the listing uses
(`user_disabled`, `account_ended`, `app_disabled`, `client_disabled`,
`all_active_users`, `direct_assignment`, `group_assignment`, `not_assigned`,
`grants_expired`), so the two never disagree. The access page's policy preview still
shows who would lose or gain access under a proposed policy without changing it.

Explanations follow viewer permissions: administrators and auditors may explain any app,
an app owner only their apps, and the answer names only groups assigned to that app,
which the same viewers already see. A user can ask `GET
/api/user/access-explanation?clientId=…` about themselves, ten times a minute, and gets
the verdict and whether the app is requestable; every denial reads the same
(`no_access`) whatever its cause, a client that does not exist reads like a denial,
and the app is named only when they have access or may request it, so the answer
discloses nothing an authorize attempt would not. A denied
authorization is audited with the reason and the access, authentication and role
revisions of that moment, so an old denial is never explained with today's policy, and
the redirect tells a user of a requestable app to ask from their dashboard.
