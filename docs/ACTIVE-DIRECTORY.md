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
4. **An account is live from creation.** The connector creates each AD account
   **enabled**, with a random password that nobody knows; KyIdentity does not store
   it. The account stays enabled until the user's real password arrives (owner
   decision, 2026-11-19). The risk is small: an enabled account exists whose password
   nobody can type. It matters only if AD itself is compromised, or if AD has an open
   password-reset path (a help-desk reset, self-service reset or delegated Reset Password
   right beyond the two service accounts below) that lets someone set a password KyIdentity
   did not. Keep Reset Password on the OU limited to `kyidentity-sync` and
   `kyidentity-agent`.

## What the connector does

- Users and groups are created in the OU you choose and nowhere else. Each carries
  `adminDescription` = `kyidentity:<connector ID>:user:<user ID>` (or `:group:`). The
  connector only ever changes objects with its own marker; anything else in the OU is left
  alone, and a name clash with such an object is shown as a delivery error.
- Users: `sAMAccountName` = KyIdentity username (at most 20 characters, no
  `"/\[]:;|=,+*?<>@`; longer names are refused, never truncated), `userPrincipalName` =
  username@ the OU's DNS domain, `displayName`, `mail`. A new account is created enabled,
  with a random password nobody knows, until the agent sets the real one (accepted risk 4).
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

It creates an X-Wing private seed with mode 0600 (and refuses to use a key readable by
group or others) and prints only the public key, `xwing:…`. The public key is 1216 bytes
(1630 characters including prefix and base64); the private file is
`xwing-private:` plus the base64 32-byte seed. `init` reloads an existing file without
replacing it, including an existing `x25519-private:` key. `run` never creates a key.

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
  "kyidentitySigningKey": "hybridsig:<KyIdentity signing key from the connector panel>",
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

## Upgrade an existing agent to X-Wing

A server upgrade leaves existing X25519 agents and their `ed25519:` pins working.
The connector panel chooses its signing pin from the registered agent key. Existing
agents remain classical until deliberately re-keyed; changing only the binary does not
upgrade their stored key.

1. Upgrade KyIdentity and the agent binary, then stop the agent.
2. Keep the existing private key and configuration securely for rollback. Generate a
   new key at a **new path** with `init -key /var/lib/kyidentity-dc-agent/agent-xwing.key`.
   Re-running `init` on the old path only prints the old public key.
3. Paste the new `xwing:` public key into the connector and save with step-up. This clears
   undelivered ciphertext for the old key; it cannot be re-encrypted because KyIdentity
   has no copy of those passwords.
4. Copy the panel's new `hybridsig:` signing pin into `kyidentitySigningKey`, and point
   `keyFile` at the new private file. Keep `stateFile` and `connectorId` unchanged to
   retain replay protection. The token and directory credentials are unchanged.
5. Restart the agent and have an assigned user change their password. Check the connector
   reports In directory and verify directory sign-in. Other users' delivered passwords
   continue working; users whose queued passwords were cleared must set them again.

The server derives separate ML-DSA-65 and Ed25519 seeds from `encryption.key` using
`kyidentity:ad-entry-signing:mldsa65` and `kyidentity:ad-entry-signing` respectively.
The latter is the original Ed25519 derivation, so legacy pins survive restarts and
upgrades. Do not replace `encryption.key`. The hybrid public encoding is `hybridsig:`
plus standard base64 of the tagged primitive public key (2678 characters in total).
The admin inputs have no HTML length cap, the API accepts 64 KiB of connector settings,
and the agent configuration loader accepts the complete pin. No schema migration is
needed: queue ciphertext and signature columns are TEXT.

Hybrid signatures authenticate **KyIdentity to the agent**. Poll requests and applied,
rejected or retry results continue using the connector-scoped Bearer token over verified
HTTPS; there was no Ed25519 agent request/result signature to migrate. Protect that token
as before. X-Wing protects queued passwords, not the separate LDAPS hop to Windows or
Samba, which can negotiate classical TLS.

## Password queue

- Captured when an admin creates a user with a password or sets one, when an activation or
  reset link is redeemed, and when a user changes their own password. Only users the
  connector currently holds are queued.
- New `xwing:` entries use HPKE X-Wing (KEM `0x647A`, ML-KEM-768 + X25519),
  HKDF-SHA256 and AES-256-GCM through `ky-primitives/xwing`, with info domain
  `kyidentity-ad-password/2`. Legacy `x25519:` keys retain their exact HPKE wire format
  and `kyidentity-ad-password/1` info. Both bind the connector ID, user ID and sequence;
  these IDs are globally unique, and the current queue callers carry no separate org
  context. The agent selects the suite from its local key, with no ciphertext fallback.
- X-Wing queue entries are signed with `ky-primitives/hybridsig` (ML-DSA-65 + Ed25519,
  **both required**) under label `kyidentity-ad-entry/2`. The signed message is the
  existing `kyidentity-ad-entry/1` field encoding: connector, user, sequence, expiry and
  ciphertext separated by NUL bytes. Legacy X25519 connectors keep Ed25519 signatures
  and their existing verification pin. A `hybridsig:` pin never accepts Ed25519 alone.
- The stored agent public key carries an HMAC under a key derived from the
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

**Expect the real password within 7 days** of an account being created. Find accounts
still waiting in Suite sync → the Active Directory connector's panel, in the directory
password table. A waiting account's row reads one of:

- **Password not yet in directory**: no password captured yet. After 7 days, use **Send
  password-change request** on the row.
- **Locked until the user sets a password**: the user has a temporary password and must
  choose their own at their next KyIdentity sign-in.
- **Waiting for agent**: captured but not yet applied. Check that the agent is running.

Until the real password arrives, the user cannot sign in to a PC: nobody knows the
account's password.

AD checks length and complexity on the agent's reset. It does not check password history on
an administrative reset; KyIdentity applies its own password policy first.

## Baseline GPO

Apply to the computers that sign in with KyIdentity accounts:

- **Check the DC before a cached logon.** Computer Configuration → Administrative Templates →
  System → Logon → **Always wait for the network at computer startup and logon** = Enabled.
  Without it Windows 11 signs a user in from cached credentials at boot and checks the DC
  afterwards: in the release check a user disabled in KyIdentity, with the DC reachable,
  still got a desktop (the check failed with "account disabled" and the session stayed).
  With it the same logon is refused with "Your account has been disabled".
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

### What disabling does not reach

A PC that cannot reach a DC signs users in from cached credentials, even with the baseline.
In the release check a user disabled in KyIdentity after their last online logon still
signed in while the PC was cut off from the DC. Disabling takes effect on a PC the next time
it reaches a DC. To shorten that window, lower **Interactive logon: Number of previous logons
to cache** (0 turns cached logon off, and with it any sign-in away from the network); the
check has not exercised that setting.

## Windows 11 release check

`scripts/e2e-win11-domain.sh` is a manual release check, not CI: it needs `/dev/kvm`,
docker, about 30 GB of disk and up to an hour. It runs a throwaway Samba AD DC, this branch's
KyIdentity (in `go test`) and the DC agent, and a fresh, unactivated Windows 11 Pro VM
(`dockurr/windows`, pinned by digest, which downloads the ISO from Microsoft). Every docker
object is `kyws-win11-*` and is removed at the end; `E2E_WIN11_KEEP=1` keeps them.

```sh
E2E_WIN11_EVIDENCE=docs/ui-active-directory-win11-<date> scripts/e2e-win11-domain.sh
```

It takes `/tmp/ky-integ-test.lock` itself for its builds, so do not run it under that lock;
`scripts/e2e-samba-ad-kyidentity.sh` does the same when it has to build the DC image.

The script drives Windows through its own shared folder: a SYSTEM task runs the commands it
drops there. A logon counts only from the Security log (4624 logon type 2 online, 11 cached;
4625 with its status) and the console session, read after each reboot.

Results of 2026-11-20 (Windows 11 Pro 10.0.26200, Samba 4.23.8; screenshots in
[`ui-active-directory-win11-2026-11-20/`](ui-active-directory-win11-2026-11-20/)):

| Step | Result | Evidence |
|---|---|---|
| 1. Join (`Add-Computer`, reboot) | Joined; secure channel true; `nltest /dsgetdc` finds the DC by DNS | [run log](ui-active-directory-win11-2026-11-20/run-log.txt) |
| 2. Logon as the KyIdentity user (password the user set) | Online logon (4624 type 2) 4 s after boot; `whoami /upn` = `winuser@kyws.test`; `klist` holds `krbtgt/KYWS.TEST` (AES-256) | [desktop](ui-active-directory-win11-2026-11-20/02-logon-desktop.png) |
| 3. Password changed in KyIdentity, agent delivers | Old password refused (4625 `0xC000006A`); new password logs on online | [refused](ui-active-directory-win11-2026-11-20/03-old-password-refused.png), [desktop](ui-active-directory-win11-2026-11-20/03-new-password-desktop.png) |
| 4. Disabled in KyIdentity, DC reachable, Windows default policy | **Not refused**: desktop from cached credentials (4624 type 11), then a background 4625 `0xC0000072` that leaves the session up | [desktop](ui-active-directory-win11-2026-11-20/04-disabled-default-policy.png) |
| 4. The same, with the baseline GPO | Refused (4625 type 2 `0xC0000072`), no logon of any type | ["Your account has been disabled"](ui-active-directory-win11-2026-11-20/04-disabled-refused.png) |
| 5. DC unreachable, active user (baseline applied) | Cached logon (4624 type 11) 27 s after boot; no Kerberos tickets | [desktop](ui-active-directory-win11-2026-11-20/05-cached-logon-dc-down.png) |
| 5. DC unreachable, user disabled after their last online logon | **Cached logon** (4624 type 11) 33 s after boot | [desktop](ui-active-directory-win11-2026-11-20/05-cached-logon-disabled-dc-down.png) |
| 6. Baseline GPO from Samba (`samba-tool gpo create`/`load`/`setlink`) | Applied: `DisableChangePassword=1` in the user hive, `SyncForegroundPolicy=1`; Ctrl-Alt-Del has no "Change a password" | [before](ui-active-directory-win11-2026-11-20/06-ctrl-alt-del-before-baseline.png), [after](ui-active-directory-win11-2026-11-20/06-ctrl-alt-del-with-baseline.png) |

The run took about 30 minutes on Major: ISO download and unattended install about 10, the
logon steps 19 (`TestWin11DomainEndToEnd`, 1130 s). Cleanup removed every object it created.

The Windows VM differs from a managed PC in ways that do not change how a domain logon is
checked: `dockurr/windows` turns UAC and the firewall off and allows guest SMB for its shared
folder.

## Limits

- One OU per connector, no nested groups, no configurable UPN suffix or attribute mapping.
- Nothing flows back from AD: no password writeback, no user import.
- Reconciliation listing of the OU and read-back diagnostics are not available for this
  connector type.
- Proven against Samba AD with `kinit`, NTLM (`smbclient`) and `ldapsearch`
  (`scripts/e2e-samba-ad-kyidentity.sh`, CI job `samba-ad`), and at a real Windows 11 Pro
  logon by the manual release check above. Windows AD as the DC is untested.
- Multi-tenant mode is not supported; see the design document.
