# KySignOn runbooks

Six procedures an operator runs rarely and under pressure. Each says what to do, what
it changes, and what it does not fix. Restoring from a capsule has its own document,
[RESTORE.md](RESTORE.md); the reconciliation half of it is below.

## Moving an app from broad access to assignments

An app upgraded from a pre-access-lifecycle server carries `all_active_users`: the old
server let every active account reach every client, and the upgrade states that rather
than silently locking the app down. Narrowing it is a two-step move, in this order.

1. Grant first. Assign the users and groups that should keep access on the app's page,
   or open the app to requests and let owners approve. `GET
   /api/admin/app-registry/{id}/access-users` lists who is reaching it today, which is
   the list you are trying to reproduce.
2. Then switch the mode to `assigned_only`. Anyone not covered loses access at the next
   token issue, and any connector linked to the app deprovisions them.

Switching first and granting afterwards is an outage plus a round of deprovisioning and
reprovisioning at the far end. Check one account either way with
`GET /api/admin/app-registry/{id}/access-users/{userId}/explain`, which names the grant
that allows it or the reason it does not.

## Setting up an inbound SCIM connector

The upstream directory pushes accounts to KySignOn. Create the connector, issue a token,
hand the token over once, and watch the first sync. The full route list and payload
shapes are in the README under "Inbound SCIM"; what matters operationally:

- The token is shown once, at issue. There is no way to read it back; reissue instead.
- A connector owns the accounts it creates. Local administrators cannot lift an
  upstream deactivation, only add one, so an account disabled upstream stays disabled.
- Deleting a connector does not delete its accounts. Decide deliberately whether the
  people it brought in should be offboarded first.

## Emergency administrator recovery

Nobody can log in as an administrator.

1. Stop the server. A second administrator being created while the first is being reset
   is how two half-configured accounts appear.
2. `kysignon bootstrap-admin -username <name> -password <password> -email <address>`
   against the same data directory. It creates an administrator, or resets the password
   of the named one.
3. Start the server and sign in. If mail is configured, prefer a password reset link to
   a password typed on a command line, which lands in shell history.

If the first-run password was never used, it is at `<data>/first-run-password.txt`,
mode 0600, and the server deletes it once that account has a password of its own.
Enrollment policy still applies: an administrator who owes a second factor is restricted
to enrolling one until they do, which is deliberate and not a lockout.

## An offboarding that did not reach a connector

Access was removed here but the far end still has the account.

1. Read the alert. A connector whose deliveries are failing or given up raises one, and
   the alert names the connector rather than the account.
2. `GET /api/admin/systems/{id}/provisioning` shows what this connector still believes.
   `GET /api/admin/systems/{id}/deliveries` shows the attempts, their errors, and any
   attempt whose outcome is unknown.
3. An attempt recorded as uncertain is a write that may have landed. Read the far end
   yourself, then resolve it with the read-back and resume routes; do not simply retry,
   which is how a second account appears upstream.
4. If the connector is broken rather than slow, disable it. Delivery stops, the
   directory keeps recording what should happen, and a repair reconciliation catches up
   when it is fixed.

Removing the user here is not enough on its own: the far end is only converged by a
delivery or a reconciliation.

## Reconciling after a restore

`kysignon restore` unpacks a capsule and marks the directory as restored. The next start
invalidates the credentials the capsule carried (sessions, tokens, authorization codes,
step-up and MFA challenges, invitation and reset links, device pairing tokens), closes
out the queued outbound deliveries with a reason, and holds outbound provisioning on
every connector. It records `system.restored` with the counts, naming the connectors you
have to act on now.

Ending every login here is not something the relying parties can see, so the restore
queues a back-channel logout for each login it ends, to the clients that registered a
receiver, and keeps any logout it already owed. Expect those deliveries to go out
shortly after the start; a client that is down raises the usual failed-delivery alert.

Two things the capsule brings back that are not credentials of the operator's: an
inbound SCIM token revoked after the snapshot is live again, and so is any connector
credential rotated after it. Clearing the inbound tokens would break every upstream
sync, so they are kept; if a token was revoked because it leaked, revoke it again as
the first thing you do after the restore.

While a connector is held, nothing is delivered to it. The console shows the hold on the
Suite sync page. To resume:

1. Review the connector's stored credentials. They are in the capsule; treat a bearer
   token or signing secret that has been in a capsule handled by custodians as due for
   rotation, and rotate it before you resume delivery, not after.
2. Run a preview reconciliation to see the drift between this directory and the far end.
3. Run a repair reconciliation. Only a repair that listed the far side completely and
   wrote the difference through releases the hold. A preview does not, a failed run
   does not, and a listing that was refused or truncated does not.

A connector whose remote cannot be listed at all — a suite webhook has nothing to read
back — can never produce that evidence. Rather than stay held forever, it is resumed
deliberately: `POST /api/admin/systems/{id}/provisioning/resume`, administrators with
step-up, recorded as `admin.provisioning_resumed`. That is you accepting the capsule's
view of that connector. The capsule's outbox still does not deliver: those rows are
marked so the worker cannot re-pend them, and what reaches the connector is what this
directory wants now. The exception is deletions and MFA resets, which carry no desired
state and retry, and only ever remove access. A connector that was disabled when the
snapshot was taken is held as well, so re-enabling it later does not quietly deliver
work queued before it was disabled.

The hold exists because a restored outbox is a list of decisions made before the
snapshot. Replaying it would recreate accounts that have since left and miss the ones
that arrived. Reconciliation derives the work from what is actually there instead.

Everyone's session ended. Users log in again with the passwords and factors they had;
those are in the capsule too. Recovery codes issued before the snapshot still work, so
rotate them for anyone whose account matters if the capsule's handling was not clean.
Invitations and reset links sent before the snapshot are dead: reissue them.

## What the downstream products do not do yet

KySignOn can express more than the four suite products currently act on. Adopters
should not read a feature's presence here as coverage end to end.

- Back-channel logout is delivered and retried by this server, but the suite consumers
  (D1–D4 in the plan) are not deployed against it yet, and the released
  `ky-primitives` `oidcverify` has no logout-token path and does not check `typ`. A
  receiver needs a dedicated verification primitive before it consumes logout tokens.
- App roles are pushed in the `roles` claim and over SCIM. Until each product reads
  them, the per-app legacy role claim stays on; turning it off is a per-app decision
  once its consumer reads `roles`.
- Expiring access, access requests and alerts are enforced and recorded here. A product
  that caches authorization decisions locally will lag by its own cache, not by this
  server's revision.

The release gates that depend on those products stay open until they are deployed and
verified; see [RELEASE-EVIDENCE.md](RELEASE-EVIDENCE.md).
