# Active Directory sync and password queue: design

Date: 2026-11-19. Worker `ws-windows`. Plan and owner decisions:
`ky-redesign/workstation-login/DESIGN.md` (approved 2026-11-19); this document does not
reopen them. Windows PCs joined to a Samba or Windows AD domain log in with KyIdentity
accounts: KyIdentity writes users and groups into one OU, and a DC-side agent sets their
passwords from ciphertext KyIdentity cannot read.

## Pieces

1. **Connector** `active_directory`, a `paired_systems` kind next to `scim`
   (`internal/sync/ad.go`). It reuses the outbox (`delivery.go`, `reconcile.go`): per-user
   FIFO, removals always win and retry, and an LDAP write whose request went out with no
   answer is an uncertain outcome that fences later writes, exactly like a SCIM write after
   `WroteHeaders`.
2. **Password queue** (`internal/store/ad.go`): at every password set, for each AD
   connector that holds the user, the plaintext is sealed with HPKE to that connector's
   agent public key. Only ciphertext is stored.
3. **DC agent** `cmd/kyidentity-dc-agent`: holds the X25519 private key, pulls its
   connector's queue, sets `unicodePwd` over LDAPS and reports the result.
4. **Admin UI** in Suite sync, and `docs/ACTIVE-DIRECTORY.md`.

## Threat model

| Attacker | Wants | Defence |
|---|---|---|
| Database or backup thief (capsule, dump, replica) | Plaintext passwords, the bind password, agent access | Queue holds HPKE ciphertext to a key KyIdentity never has. Bind password sealed with the encryption key (`crypto.Seal`, `SealConnector`, bound to the connector ID), as the SCIM token is. The agent token is stored as SHA-256 only. A test dumps the database and greps for the test password. |
| Network attacker between KyIdentity and the DC | Read or alter directory writes, steal the bind password | `ldaps://` only (no `ldap://`, no StartTLS). TLS 1.2+, verified against the pinned CA or certificate only (system roots are never used), host name checked. A mismatched pin is a test. |
| Network attacker between the agent and KyIdentity | Read or forge queue entries | HTTPS (system roots, or a CA file the operator names); plain `http` only to loopback. Entries are opaque ciphertext; a forged entry fails HPKE open. |
| Holder of one connector's agent token | Another connector's queue, or plaintext | The endpoint answers only the token's own connector. Ciphertext needs the agent private key. Worst case: false acknowledgements, which mark passwords delivered that are not (visible as a mismatch the next time the user signs in to a PC). Tests: wrong, missing and other-connector tokens. |
| Someone who can write the database | Swap in their own agent key, or forge an entry that sets a password they chose | The agent key is stored with an HMAC under a key derived from the encryption key (not in the database), checked before sealing. Every entry is signed with Ed25519 (seed derived the same way) over connector, user, seq, expiry and ciphertext; the agent pins the public key and verifies before decrypting. Tests: tampered key queues nothing; unsigned, wrongly signed, re-dated and expired entries leave AD unchanged. |
| Someone who can write the database | Replay an old ciphertext onto another user, or an old password onto the same user | HPKE `info` binds connector ID, user ID and sequence number, so a moved row fails to open. The agent keeps the highest sequence it applied per user (0600 state file) and refuses anything not newer. Sequence numbers are `max(last+1, unix ms)`, so a database restored from backup still issues increasing numbers. Tests: cross-user replay and out-of-order replay. |
| Stolen admin session | Redirect future passwords to their own key, or the connector to their own LDAP server | Every connector change (URL, CA, bind DN or password, OU, agent public key, agent token) spends a step-up grant and is audited. An administrator with step-up can also reset any password, so this is not a new power; it is recorded. |
| Malicious or compromised directory content | Make KyIdentity overwrite objects it does not own | Writes only touch objects under the chosen OU whose `adminDescription` carries this connector's marker. Others are left alone; a name collision is a delivery error naming the conflict. A test proves an object outside the OU is unchanged. |
| A live, compromised KyIdentity process | Plaintext at login and password set | Accepted risk (owner decision 5): it already sees the password at sign-in. |
| A compromised DC or agent host | Everything in the domain | Out of scope; the agent key and the DC are domain tier-0. |

Accepted, documented risks (owner decision 5): the NT hash exists in AD; plaintext passes
through a live KyIdentity; existing users need one password set or change before they can
log into a PC.

## Data stored and protection at rest

Migration `active_directory` (one entry, SQLite and Postgres bodies):

```
ad_connectors(system_id PK → paired_systems ON DELETE CASCADE,
  bind_dn, base_dn, ca_pem, agent_public_key, agent_token_hash,
  password_ttl_minutes CHECK 10..1440 DEFAULT 1440)
ad_passwords(system_id → paired_systems ON DELETE CASCADE,
  user_id → users ON DELETE CASCADE, PRIMARY KEY(system_id,user_id),
  seq, ciphertext, expires_at, attempts, last_error,
  password_tag, delivered_seq, delivered_at)
```

- The LDAPS URL is `paired_systems.callback_url`; the bind password is
  `paired_systems.hmac_secret_encrypted` (sealed). It is never returned by any API; the
  admin replaces it.
- `ad_passwords` holds at most one undelivered ciphertext per connector and user, so a
  newer password supersedes an older one by overwriting it. On acknowledgement or expiry
  the ciphertext is cleared (`''`); the row keeps only sequence numbers, times and a fixed
  error code. `password_tag` is SHA-256 of the user's `password_hash` at queue time, so
  the admin view can say "the directory has an older password" without storing anything
  password-derived beyond what `users` already holds.
- HPKE: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM (Go standard library
  `crypto/hpke`). `info` = `kyidentity-ad-password/1` NUL connector ID NUL user ID NUL
  decimal seq. Stored as base64 of the single-shot `hpke.Seal` output (enc ‖ ciphertext).
- The agent token is 32 random bytes, shown once, stored as hex SHA-256 (unique).
- `ad_connectors.agent_key_mac` = HMAC-SHA256(DeriveKey(encryption key, `kyidentity:ad-agent-key-mac`), connector ID NUL public key); `ad_passwords.signature` = Ed25519 with the seed DeriveKey(encryption key, `kyidentity:ad-entry-signing`). The public signing key is shown on the connector panel for the agent's `kyidentitySigningKey`.
- The agent's private key lives only on the agent host, mode 0600, created on first run.

Plaintext lifetime: the request that sets the password holds it, seals it after the
password commit, and drops it. It is never written to a log, an audit row or the database.

## Ordering and atomicity of capture

Capture runs after the password commit, in its own transaction, and queues only if
`users.password_hash` still equals the hash this request wrote. Writes are serialised, so
of two racing changes only the one that is current can queue, and its sequence number is
higher. If the process dies between the two commits, nothing is queued: the admin view then
shows the user's directory password as stale (tag mismatch), and a password-change request
fixes it. Chosen over threading plaintext through five store mutations.

Capture points: `POST /api/admin/users` (with a password), `PUT /api/admin/users/{id}`
(with a password), activation and reset links (`Redeem`), and the signed-in change
(`POST /api/user/password`). Not the CLI bootstrap admin or installer accounts: both
create accounts before any connector can hold them, and both force a password change,
which is captured.

"Users the connector manages" means a `sync_resource_state` row for that connector that is
active, which is what assignment to the connector's app produces.

## Directory writes

- Users: `CN=<username>,<OU>`, `sAMAccountName` = username, `userPrincipalName` =
  username@ the OU's DNS domain (its `DC=` parts), `displayName`, `mail` (when set),
  `adminDescription` = `kyidentity:<connector ID>:user:<user ID>`. A username AD cannot
  hold (over 20 characters, or `"/\[]:;|=,+*?<>@`) is a delivery error, never truncated.
- A new user is created with a random 32-byte password nobody knows, so it can be enabled
  at once; the agent later sets the real one. Active is `userAccountControl` 512;
  disabled, unassigned and deleted are 514. Nothing is ever deleted.
- Groups (always on for this kind): `CN=<name>,<OU>`, global security group, same marker
  kind `group`. `member` is replaced with the DNs of managed users in the OU whose marker
  names a current in-scope member, read in one search. Members added in AD by hand to a
  managed group are removed; KyIdentity is the source of truth. An unassigned or deleted
  group is emptied and kept.
- Every write first finds its object by marker under the OU (size limit 2; two is an
  error). An object holding the name without the marker is reported as a conflict.
- Dial: `netguard`'s dialer (DCs on a LAN need `KYIDENTITY_ALLOW_PRIVATE_CALLBACKS=true`,
  as private SCIM targets do), 5 s connect, 20 s per delivery.
- Reconciliation listing and SCIM read-back are refused for this kind (unsupported).

## Routes and listeners

| Route | Auth |
|---|---|
| `POST /api/admin/systems` with `systemType: active_directory` and an `activeDirectory` object | admin + step-up (existing route) |
| `GET /api/admin/systems/{id}/active-directory` (config without secrets, password status per managed user) | `permRead` |
| `PUT /api/admin/systems/{id}/active-directory` (URL, CA, bind DN, OU, public key, TTL; `bindPassword` replaces) | admin + step-up |
| `POST /api/admin/systems/{id}/active-directory/agent-token` (issue or replace, shown once) | admin + step-up |
| `POST /api/admin/systems/{id}/test` (bind, then a base search of the OU) | admin (existing route) |
| `GET /api/ad-agent/v1/passwords` | agent Bearer token, rate limited |
| `POST /api/ad-agent/v1/passwords/{userId}/{seq}` (result: `applied`, `rejected` with a fixed reason, or `retry`) | agent Bearer token, rate limited |

The password-change request reuses `POST /api/admin/users/{id}/reset-link` (recovery
permission + step-up). No new listener. The agent opens no port.

Audit actions: `admin.system_created/configured` (existing), `admin.ad_agent_token_issued`,
`directory.password_queued`, `directory.password_delivered`, `directory.password_rejected`,
`directory.password_expired`. Details hold the connector ID and sequence number, never the
password, the user name or the address.

## Defaults

- Password TTL 24 h; admin range 10 min to 24 h (the plan's "admin can lower").
- No agent token and no public key until the admin sets them; with no public key, nothing
  is queued and the user shows as "password not yet in directory".
- Agent: polls every 30 s, backoff doubling to 5 min on failure; refuses `http` except to
  loopback.
- Least privilege documented: the sync account gets create/write on the OU; the agent's
  account gets Reset Password on the OU only.

## Multi-tenant mode (PR #255)

Not built. `ad_connectors` and `ad_passwords` are derived tables (parents
`paired_systems` and `users`); no `org_id` of their own. Customer AD targets are like
generic SCIM targets, which the spec disables in multi-tenant v1. Enabling them would need
a nullable `paired_systems.org_id` naming the owning org, `(org_id, user_id)` composite
keys on `ad_passwords`, the agent endpoint binding the org through its connector, and the
connector refusing users outside that org.

## Not built

- Sync back from AD, password writeback from AD, Ctrl-Alt-Del changes flowing back (the
  GPO blocks them).
- Pushing NT hashes or Kerberos keys (rejected in the plan).
- StartTLS or plain LDAP; skipping verification.
- Nested groups, several OUs, a configurable UPN suffix or attribute mapping.
- Deleting AD objects; reconciliation listing of the OU.
- AD's password-history check on reset (needs the policy-hints control); AD still applies
  length and complexity, and KyIdentity applies its own policy first.
- Deploying a DC through KyQuickStart; Linux and macOS.
- A Windows client join: proven only against Samba with `kinit` and NTLM; a real Windows
  login is unproven.
