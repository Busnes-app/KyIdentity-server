# HR provisioning

The generic JSON API stages an employee and immutable source UID, calls KyPost to
reserve an email address, then creates the KyIdentity account with that email as
both its login and email address. Only after that commit does it write the email
back to HR. KyIdentity's UUID remains the immutable SSO subject; email is mutable
identity metadata, never an account-matching key.

This is an inbound integration API, not a scheduled HR-directory reader. Workday
SOAP/XML, Workday tenant credentials and other vendor adapters are not included.
An HR integration translates its source records to this contract. No HR tenant
was used for qualification; tests use synthetic workers and local HTTPS services.

The HR tables are installed by schema migration 3 on SQLite and Postgres.

## Configure

1. Enable KyPost's opt-in native mail runtime and configure the organization's
   mail domain using its existing native-domain setup. Configure KyPost SSO against
   this KyIdentity issuer. This feature does not configure DNS or mail delivery.
2. Pair KyPost in KyIdentity as type `kypost`, with its callback exactly
   `https://<post-host>/api/sync/webhook`. Install the pairing signing secret in
   KyPost. Both products must include HR address reservation support.
3. In Administration → Inbound SCIM, create a **new** source connector and issue
   a write-scoped Bearer token. Existing source-owned users cannot be adopted by
   enabling HR on their connector. Give the write token only to the HR integration.
4. Using an administrator session, CSRF token and operation-bound step-up grant,
   `PUT /api/admin/scim-connectors/<connector-id>/hr`:

   ```json
   {
     "systemId": "<paired-kypost-system-id>",
     "domain": "example.com",
     "writebackUrl": "https://hr-bridge.example.com/kyidentity/work-email",
     "writebackToken": "<separate-token-issued-by-the-HR-integration>"
   }
   ```

   Configuration currently uses the admin API; there is no HR configuration form.
   The domain and paired KyPost system cannot change once workers exist.
   Reconfiguration requires the writeback token again and refuses live job leases.
   Writeback credentials are encrypted with the existing KyIdentity encryption key and bound to the connector row
   and never returned by status APIs. Endpoints require HTTPS, refuse redirects and
   use the existing network guard at connection time. The existing explicit
   `KYIDENTITY_ALLOW_PRIVATE_CALLBACKS` setting controls private-network dialing;
   it does not permit cleartext HR requests.
5. Assign the KyPost application to these employees through the existing
   KyIdentity application-access policy. A mailbox reservation grants no app access.
   In installations with separately registered OIDC and provisioning applications,
   verify both access scopes or link their app records through the existing admin flow.

## Import and query

Send `POST /hr/v1/workers` with `Content-Type: application/json` and
`Authorization: Bearer <source-connector-write-token>`:

```json
{
  "sourceUid": "employee-0042",
  "sourceVersion": 1,
  "preferredName": "alice.adams",
  "displayName": "Alice Adams",
  "active": true
}
```

- `sourceUid` is opaque, case-sensitive and immutable within this source connector,
  at most 256 bytes. Never derive it from an email address or display name.
- `sourceVersion` is an integer from 1 to 9007199254740991 and must increase for
  each employee change. Repeating an identical version is idempotent. Stale versions
  or different facts under the same version return 409.
- `preferredName` is a stable ASCII mailbox-name request, 1–48 letters, digits,
  dots, underscores or hyphens; no leading/trailing/consecutive dots. It cannot
  change on later imports. Legal/display-name changes use `displayName`.
- `active` must be explicitly true or false. Unknown fields, including email,
  passwords and administrator roles, are rejected. Missing workers are never
  interpreted as departures. This version does not schedule future employment dates.

The response is a durable job, initially `mailbox_pending` with an empty email and
a reserved `userId`. At this point there is no KyIdentity account for that UUID.
Query `GET /hr/v1/workers?sourceUid=employee-0042` with the same source's read or write
token. Tokens from another source cannot read that employee. Source tokens do not
authenticate to the administrator API. HR-enabled connectors cannot perform SCIM
writes that would bypass source versions or overwrite assigned emails.

The background worker runs independently of directory delivery, claiming one job
per three-second tick. It uses bounded 20-second network passes and persistent
leases. Failures retain the stage, expose a fixed safe `lastError` and retry with
exponential delays capped at 1024 seconds. KyPost addresses remain reserved across
lost responses, departures and retries. Exact same-name collisions receive suffixes
`.2` through `.1000`; exhaustion needs an operator-chosen different preferred name
before importing a new worker. Existing identities and address owners are never adopted.

States are `mailbox_pending`, `writeback_pending`, `complete`, and `inactive`.
`GET /api/admin/scim-connectors/<id>/hr` returns redacted configuration and up to
100 workers; `?offset=100` reads the next page. Attempts count consecutive failures
in the current stage and reset on success or a newer import. A completed job means
the HR endpoint acknowledged email writeback; it does not prove employee activation,
SSO authorization or inbound/outbound mail delivery.

## Email writeback contract

After KyPost confirms its reservation and the identity commits, KyIdentity sends
an authenticated **PUT** to the exact configured writeback URL:

```json
{
  "sourceUid": "employee-0042",
  "sourceVersion": 1,
  "userId": "<immutable-KyIdentity-UUID>",
  "email": "alice.adams@example.com"
}
```

`Authorization` contains the separate writeback Bearer token. `Idempotency-Key` is
`<userId>:<sourceVersion>`. The receiver must implement an idempotent assignment to
that exact source UID, reject stale source versions, and return 200, 201 or 204 only
after applying the email. A 202 is pending, not completion. Return no body or a
small response (at most 4096 bytes). Errors, throttling and lost responses retry
the same assignment without reallocating mail or creating another identity.
KyIdentity does not interpret a writeback email as a new source-owned email field.

## Activation, departures and recovery

The new identity is an ordinary pending, disabled account with no password.
Use the existing administrator **manual activation link**, handed to the employee
through an established secure channel. Do not send the initial link only to their
new mailbox: they cannot sign in to it yet. Activation and app assignment permit
normal signed directory provisioning to prepare and publish the reserved mailbox.
Before that, KyPost's reservation has no live receiving route, usable local account
or mailbox storage. An assigned address alone does not prove domain deliverability.

A newer `active:false` import disables an existing identity through the normal
offboarding transaction, revoking access and queuing downstream deactivation. It
does not delete retained content or release the address. Rehire uses the same UID,
UUID and email; local disable overrides and ordinary access policy still apply.
Read normal provisioning/offboarding status to verify downstream acknowledgments.
The final-active-administrator invariant remains enforced if an operator promoted
an HR-owned identity; dedicated administration should use separate local identities.

Restoring KyIdentity holds all HR connections and clears stale job leases. Review
and resume the paired KyPost provisioning connector first, check the source's current
worker versions and credentials, then deliberately reconfigure the HR connection
with step-up. A disabled source connector pauses new work. Disconnecting it follows
the existing explicit keep/disable account choice and removes the HR integration
and its jobs; KyPost address reservations stay retained. Do not disconnect/reimport
as a retry strategy: stable source connection ownership is part of the identity.
