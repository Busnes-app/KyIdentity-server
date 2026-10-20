# Applications

[Product overview](../README.md) · [Standalone installation](../INSTALL.md)

Commands and unlinked file paths below are relative to the repository root.

## App connections

Administrators can use **App connections** to associate an OAuth client, launcher card,
and provisioning system that belong to the same application. Review the connection names
and IDs, then confirm the link with step-up authentication. **Unlink** separates one
connection again. Each app has at most one connection of each type; overlapping types and
stale selections are rejected. Linking/unlinking commits with its audit record. Linking requires matching access and authentication settings
and no assignments on either app; unlinking copies both policies and assignments.

Existing connections initially receive separate stable app IDs, even when their names or
URLs match. Linking retains the selected app ID and all original connection IDs, client
secrets, callback URLs, launcher cards and sync settings. New connections automatically
receive their own app ID. Deleting a connection removes its reference; the app ID survives
while another connection remains. Connection settings stay in their existing admin views.

Use **Manage access** to assign users or groups and preview effective access. Existing
apps migrate to explicit **All active users** access. New apps default to **Assigned users
only**, with no grants. Direct and group assignments combine by union; removing one grant
preserves access while another applies. Administrators need assignments too. Disabled
users, disabled apps, and disabled linked OAuth clients cannot sign in. Use **Manage
launcher cards** to edit cards independently of your own app entitlements.

Policy changes show how many users would lose access across the directory, even when the
list is filtered. The preview reflects current membership; edits use app revisions to
reject stale settings. Mutations require operation-bound step-up and atomic audit records.
Launcher-only access controls visibility, not authorization at the destination website.
Provisioning follows effective access; see Outbound provisioning, Provisioning scope.

Each user arranges their own **Applications** page under **Customize**. They can make,
name and order groups, hide apps, and choose **Tiles** or **Dock + list**, where the first
group is shown as large icons. The layout is stored per account
(`PUT`/`DELETE /api/user/launcher-preferences`), and `GET /api/user/applications` returns
it as `preferences`. It only arranges apps the user can already reach. Hiding an app does
not remove access, and a hidden app stays one click away at the bottom of the page. Apps
granted after the last save appear in a **New** group.

OAuth authorization and token exchange both enforce current access. Losing effective
access revokes online tokens and invalidates authorization codes in the same transaction.
Token registration rechecks access and the originating code atomically, including during
membership-removal races. Re-granting access cannot revive invalidated codes or tokens.
Offline JWT consumers may accept old access tokens for up to 15 minutes, and an app's own
session lasts until it asks KyIdentity to sign out or receives the back-channel logout
described below; an app with no back-channel receiver is never told.

Admin API: `GET /api/admin/app-registry` accepts the same pagination bounds as group lists
and searches connection names and IDs. `POST /api/admin/app-registry/{id}/link` accepts
`sourceId`, `targetRevision`, and `sourceRevision`; the target app ID is retained.
`POST /api/admin/app-registry/{id}/unlink` accepts `kind` (`client`, `launcher`, or `system`)
and `revision`, returning the new app ID. Both mutations require operation-bound step-up.
A `409` means the selection is stale or its access settings/assignments prevent linking.
Reload before choosing again.

Access API: `GET /api/admin/app-registry/{id}/access-users` returns paginated users,
current/preview access, the current app revision and an unfiltered `losingAccess` count.
Optional `mode` (`assigned_only` or `all_active_users`) and `enabled` preview policy changes.
`GET /api/admin/app-registry/{id}/access-groups` lists groups and assignment state.
Both accept the same pagination bounds as group lists. `PUT .../{id}/access-policy`
requires `mode`, `enabled`, and `revision`. `PUT`/`DELETE
/api/admin/app-registry/{id}/assignments/{kind}/{principal}` adds/removes an individual
assignment (`kind` is `users` or `groups`). Duplicate assignments are idempotent.

## App roles and token claims

**Roles.** App connections → Roles defines the fixed role names an app understands
(letters, digits, `_`, `.`, `:`, `-`) and maps groups or users to them. A token for the
app carries exactly the roles the user holds there, sorted, under the `roles` claim,
and nothing about any other app; an app with no roles gets an empty list. Unassigned
apps issue no token at all, so they receive no claims. Any role, mapping or claim
setting change revokes the affected users' live tokens and pending codes for that app,
bumps the app's role revision so a code issued before the change cannot be exchanged
after it, and re-sends the users' profiles to the app's provisioning connection with
the new roles (a connection whose app defines roles receives those instead of the
global directory role).

**Claims by scope.** `profile` grants `preferred_username`, `username` and `name`;
`email` grants `email` and `email_verified`; `openid` always grants `sub`, `sid`, the
authentication claims and `roles`. The ID token and UserInfo apply the same rules to the
same granted scope, so neither can widen the other. Allowed scopes on a client are drawn
from `openid`, `profile` and `email`; an unknown scope is refused at registration, not
silently accepted. If the roles and groups mapped for a user do not fit in a token
(4 KiB of identity claims), the token request fails with `invalid_request` naming the
counts rather than truncating a permission set.

**Upgrade note.** Before this release every ID token and UserInfo answer carried the
name and email claims regardless of scope. A relying party that requests only `openid`
must now also request `profile` and `email` to keep receiving them; there is no switch
for this, because emitting claims a client did not ask for is the defect being fixed.
Group membership changes, including deletion of a mapped group and changes arriving
over inbound SCIM, count as role changes for every app that maps the group, and a
provisioned account whose roles are revoked receives an explicit empty `roles` list. An
app's first role, and its last one going, re-send every account provisioned through its
connection, since the whole role set changes shape at that point.

**Per-app switches.** *Legacy global role claim* keeps the directory-wide `role`
(`user` or `admin`) in the app's tokens; apps that existed before app roles keep it on,
new apps start with it off, and it should be turned off for each app once that app reads
`roles`. *Groups claim* adds a `groups` claim listing the app's assigned or role-mapped
groups the user belongs to, never the user's other groups. Both are per app; flipping
either revokes every live grant for the app so the token shape changes cleanly.
