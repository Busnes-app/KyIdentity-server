# Active Directory: Windows PC sign-in

KyIdentity can be the source of truth for an Active Directory domain (a Samba AD DC, or an
existing Windows AD), so Windows PCs joined to that domain sign in with KyIdentity
accounts. Design and threat model:
[`superpowers/specs/2026-11-19-active-directory-design.md`](superpowers/specs/2026-11-19-active-directory-design.md).

Two parts work together:

- **The connector** (in KyIdentity, Suite sync → Connect service → Active Directory) writes
  users and groups into one OU over LDAPS.
- **The DC agent** (`kyidentity-dc-agent`, on the DC or a domain member) sets passwords.
  KyIdentity encrypts each new password to the agent's public key and keeps only the
  ciphertext; it cannot read its own queue.

## Accepted risks

Read these before you turn it on.

1. **The NT hash exists in AD.** AD derives its own keys from the password the agent sets,
   including the NT hash, which is password-equivalent for NTLM. Protect the DC and its
   backups as tier 0, and restrict NTLM (below).
2. **Plaintext passes through a live KyIdentity.** When a password is set or changed, the
   running KyIdentity process holds the plaintext for that one request, seals it and drops
   it. It already sees passwords at sign-in. A compromised running KyIdentity can read
   passwords; a stolen database or backup cannot.
3. **Existing users need one password change.** KyIdentity stores only a password hash, so
   it has nothing to send for passwords set before a user was assigned to the connector.
   Those users show as "Password not yet in directory" until their next password set or
   change. Use "Send password-change request" to mail them a reset link.

## What the connector does

- Users and groups are created in the OU you choose and nowhere else. Each carries
  `adminDescription` = `kyidentity:<connector ID>:user:<user ID>` (or `:group:`). The
  connector only ever changes objects with its own marker; anything else in the OU is left
  alone, and a name clash with such an object is shown as a delivery error.
- Users: `sAMAccountName` = KyIdentity username (at most 20 characters, no
  `"/\[]:;|=,+*?<>@`; longer names are refused, never truncated), `userPrincipalName` =
  username@ the OU's DNS domain, `displayName`, `mail`. A new account gets a random
  password nobody knows until the agent sets the real one.
- A rename in KyIdentity renames the AD account (`sAMAccountName`, `userPrincipalName` and
  CN) or group (`sAMAccountName` and CN) with the same name rules. A new name another
  object holds is a delivery error, and the account keeps its old name until it is fixed.
- Who is synced: users with access to the connector's app (App access), and groups assigned
  to that app with their in-scope members. A managed group's `member` list is replaced by
  KyIdentity's; members added by hand in AD are removed.
- Disabled, deleted or unassigned users get the ACCOUNTDISABLE bit (0x2) of
  `userAccountControl` set, and enabling clears only that bit: other flags an AD operator
  set are kept. Nothing is deleted. An unassigned group is emptied and kept.
- LDAPS only. The certificate you paste (the DC's CA, or the DC's own certificate) is the
  only trust anchor; system roots are never used and verification cannot be skipped. A DC
  on a private network needs `KYIDENTITY_ALLOW_PRIVATE_CALLBACKS=true`, as private SCIM
  targets do. Loopback and link-local addresses stay refused.
- The bind password is encrypted at rest, never shown again, and replaced by typing a new
  one. "Test connection" binds and reads the OU.

## Set up

### 1. Directory accounts (least privilege)

Create two service accounts and delegate on the OU only:

- `kyidentity-sync` (the connector): create and delete user and group objects, read and
  write all properties of users and groups, and Reset Password.
- `kyidentity-agent` (the agent): Reset Password on user objects, write `pwdLastSet`.

On Samba, `scripts/e2e-samba-ad.sh` (`_dc_delegate`) shows the exact `samba-tool dsacl`
ACEs; on Windows use the Delegation of Control wizard on the OU.

### 2. The agent key

On the agent host:

```sh
kyidentity-dc-agent init -key /var/lib/kyidentity-dc-agent/agent.key
```

It creates the X25519 private key with mode 0600 (and refuses to use one readable by group
or others) and prints only the public key, `x25519:…`.

### 3. The connector

In Suite sync, Connect service → Active Directory: the LDAPS URL, the CA or DC certificate,
the sync account's bind DN and password, the OU, the agent public key and the password
lifetime (default 24 hours; 10 minutes to 24 hours). Then Test connection, and Issue agent
token: it is shown once. Assign users or groups to the connector's app under App access.

Every change here needs a step-up and is audited. Changing the agent public key drops queued
passwords the old key sealed.

### 4. Run the agent

`/etc/kyidentity-dc-agent.json`:

```json
{
  "kyidentityUrl": "https://id.example.org",
  "kyidentitySigningKey": "ed25519:<KyIdentity signing key from the connector panel>",
  "connectorId": "<connector ID from Suite sync>",
  "tokenFile": "/etc/kyidentity-dc-agent/token",
  "keyFile": "/var/lib/kyidentity-dc-agent/agent.key",
  "stateFile": "/var/lib/kyidentity-dc-agent/state.json",
  "ldapsUrl": "ldaps://dc1.example.org",
  "caFile": "/etc/kyidentity-dc-agent/dc-ca.pem",
  "bindDn": "CN=kyidentity-agent,CN=Users,DC=example,DC=org",
  "bindPasswordFile": "/etc/kyidentity-dc-agent/bind-password",
  "baseDn": "OU=KyIdentity,DC=example,DC=org"
}
```

The token and bind password files must be mode 0600. `kyidentityCaFile` is optional, for a
KyIdentity behind a private CA. Plain `http` is accepted only to loopback.

```sh
kyidentity-dc-agent run -config /etc/kyidentity-dc-agent.json
```

The agent checks KyIdentity's signature on every entry before decrypting it. Encrypting to
the agent key needs only the public key, so the signature (made with a key derived from the
deployment encryption key, never stored in the database) is what proves KyIdentity queued
it. It polls every 30 seconds (backing off to 5 minutes while KyIdentity or the DC is down),
decrypts each entry, finds the account by its marker in the OU, sets `unicodePwd` and
reports the result. It logs user IDs, sequence numbers and outcomes, never a password. It
keeps the highest sequence number it applied per user in `stateFile` and refuses anything
older, so an old ciphertext cannot be replayed. Build it with
`go build ./cmd/kyidentity-dc-agent`.

## Password queue

- Captured when an admin creates a user with a password or sets one, when an activation or
  reset link is redeemed, and when a user changes their own password. Only users the
  connector currently holds are queued.
- Each entry is HPKE (X25519, HKDF-SHA256, AES-256-GCM) sealed to the agent key, bound to
  the connector, the user and a sequence number, and signed (Ed25519) over all of these and
  its expiry. The stored agent public key carries an HMAC under a key derived from the
  encryption key, so a key swapped in the database is refused before anything is sealed. A newer password replaces an older one
  that has not been delivered.
- Entries are cleared when the agent acknowledges them and expire after the password
  lifetime.
- Audit: `directory.password_queued`, `directory.password_delivered`,
  `directory.password_rejected` (with a reason code), `directory.password_expired`. They
  never hold the password.
- The agent endpoint is `GET /api/ad-agent/v1/passwords` and
  `POST /api/ad-agent/v1/passwords/{userId}/{seq}`, with the agent token as a Bearer
  token. The token is stored hashed and answers only its own connector's queue.

The connector view lists every managed user's directory password: In directory, Waiting for
agent, Locked until the user sets a password, Older password in directory, Rejected by directory (with the reason, for example AD's
complexity policy), or Password not yet in directory.

AD checks length and complexity on the agent's reset. It does not check password history on
an administrative reset; KyIdentity applies its own password policy first.

## Baseline GPO

Apply to the computers that sign in with KyIdentity accounts:

- **Block password changes on the PC.** A change made with Ctrl-Alt-Del would never reach
  KyIdentity, and the next KyIdentity change would overwrite it. User Configuration →
  Administrative Templates → System → Ctrl+Alt+Del Options → **Remove
  Change Password** = Enabled. Users change their password in KyIdentity.
- **Restrict NTLM.** Security Settings → Local Policies → Security Options: **Network
  security: LAN Manager authentication level** = Send NTLMv2 response only. Refuse LM &
  NTLM; **Network security: Restrict NTLM** audit first, then deny where nothing breaks.
  Kerberos is what a domain sign-in uses.
- **Keep a local administrator as break-glass.** If the DC, the agent or KyIdentity is
  unreachable, cached logons still work for a while, but keep one local administrator
  whose password is managed by Windows LAPS, so you can always get in.

## Limits

- One OU per connector, no nested groups, no configurable UPN suffix or attribute mapping.
- Nothing flows back from AD: no password writeback, no user import.
- Reconciliation listing of the OU and read-back diagnostics are not available for this
  connector type.
- Proven against Samba AD with `kinit`, NTLM (`smbclient`) and `ldapsearch`
  (`scripts/e2e-samba-ad-kyidentity.sh`, CI job `samba-ad`). A real Windows client join and
  sign-in has not been tested.
- Multi-tenant mode is not supported; see the design document.
