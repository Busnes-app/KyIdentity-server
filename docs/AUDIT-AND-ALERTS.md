# Audit and alerts

[Product overview](../README.md) · [Standalone installation](../INSTALL.md)

Commands and unlinked file paths below are relative to the repository root.

## Audit search and export

The audit log page filters by actor (id or username), target id, action prefix (for
example `oauth.` covers every OAuth event), outcome and a time range entered in the
operator's zone. Filters are bounded, indexed, and paged in a total order (time, then
id), so paging never repeats or skips a row under tied timestamps. *Export CSV* and
*Export JSONL* carry the same filter as the page, over `GET
/api/admin/audit-events/export?format=csv|jsonl&…`, at most 50,000 rows and 30 seconds
per export (response headers `X-KyIdentity-Export-Total`, `-Limit` and `-Truncated` say
when a filter exceeded the bound), with a burst of five exports refilling at about six a
minute per address and sixty listing calls a minute. An export that stopped short of the
filtered set, whether by the row bound, the deadline or a failed write, ends with an
in-band marker (`_export: incomplete` with the reason and row counts) so a downloaded
file is never mistaken for a complete one. Each export is recorded before the first
byte leaves (`admin.audit_export_started`; if that row cannot be written the export is
refused) and again when it ends (`admin.audit_exported` with the outcome and row count). Details whose keys look like
credential material (`secret`, `token`, `password`, `hash`, `credential`, `private`) are
redacted at any depth, CSV cells that start with `=`, `+`, `-`, `@`, tab or carriage
return are prefixed with a quote so no spreadsheet treats them as formulas, and the
recorded rows carry the filter and row count. Administrators
and auditors may search and export; nobody else. Retention is unchanged: rows older
than the configured cutoff are trimmed by the existing housekeeping, and any change to
that period is a separate decision, not part of search or export. For external log
collection use the structured process log; there is no second audit delivery path.

## Alerts

The alerts page turns the audit trail and connector state into a short list an
administrator or auditor can act on: privilege changes (an account made or unmade an
administrator, delegations changed), recovery use (a recovery code consumed, a second
factor reset by an administrator, a password reset link redeemed), connector credential
changes (inbound SCIM tokens issued or revoked, an outbound connector created or its
bearer token rotated, the mail relay changed), repeated login failures for one account
or, when the name matches no account, from one address (threshold and window
configurable, default ten in ten minutes; a submitted name never becomes an alert of
its own, past ten live login alerts further sources share a single "many sources"
alert, a login alert whose source has been quiet for a whole window resolves itself
without mail, and login-failure mail is one mailing per four hours however many
sources appear, so an attacker cycling names or addresses cannot flood the inbox, the
mail or the table), push fatigue (three denied or unanswered sign-in pushes for one
account within an hour),
failed or refused scheduled access removal, and outages (a connector whose deliveries are failing
or given up, a client whose back-channel logouts were given up). Every audit insert
queues its id through a trigger, the evaluator writes alerts and drains the queue in one
transaction, and a worker goroutine of its own runs it every few seconds with a bounded
pass, so a crash can repeat work but never skip a trigger, a stuck relay never delays
provisioning or expiry follow-up, and history recorded before this version is not
re-alerted.
Repeats fold into one open alert per rule and subject with a count; an acknowledged
alert reopens on the next occurrence rather than hiding it; an outage stays one alert
for its whole duration, resolves itself when deliveries succeed again, and a later
failure opens a fresh one. Alert text names the account, connector or app and nothing
else: the audit details behind it, and any recovery code or credential, never reach the
alert, the mail or the page. Recipients (`PUT /api/admin/alerts/settings`, administrators
with step-up, usernames on the wire) must be administrators or auditors when configured
and are checked again before each message; anyone who has since lost that access is
skipped and the skip is shown. Mail goes through the existing relay when one is
configured, with growing retry delays and a visible failure after eight attempts, so a
broken relay or a missing configuration shows on the alert rather than silently
dropping it. Administrators and auditors read the inbox (`GET /api/admin/alerts`), only
administrators acknowledge (`POST /api/admin/alerts/{id}/acknowledge`), and both
settings changes and acknowledgements are audited. Resolved alerts and finished
deliveries are trimmed with the audit retention period; live alerts are kept whatever
their age. There is no second alert transport and no per-rule switch; the process log
remains the place for external collection.
