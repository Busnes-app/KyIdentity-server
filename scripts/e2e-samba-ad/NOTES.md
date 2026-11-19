# Samba AD DC test notes

Observed on Samba 4.23.8 (alpine:3.24 `samba-dc`), freshly provisioned by
`scripts/e2e-samba-ad.sh`.

## Container

- Provisioning needs `--cap-add SYS_ADMIN`: it writes NT ACLs to `security.*`
  xattrs on sysvol and fails with a Python traceback in `setntacl` without it.
- The generated `/var/lib/samba/private/krb5.conf` relies on DNS SRV lookup,
  which the docker resolver cannot answer. The script writes a krb5.conf with
  `kdc = <container IP>` instead.

## Default password policy (`samba-tool domain passwordsettings show`)

```
Password complexity: on
Password history length: 24
Minimum password length: 7
Minimum password age (days): 1
Maximum password age (days): 42
Account lockout threshold (attempts): 0
```

## How Samba rejects a `unicodePwd` write

Every policy rejection is LDAP result **19 constraintViolation**. The
diagnostic message reads `<8-hex WERROR>: Constraint violation - check_password_restrictions: <reason>`:

| Case | Diagnostic message |
|---|---|
| too short (reset or change) | `0000052D: Constraint violation - check_password_restrictions: the password is too short. It should be equal to or longer than 7 characters!` |
| not complex (reset or change) | `0000052D: Constraint violation - check_password_restrictions: the password does not meet the complexity criteria!` |
| in history (user change only) | `0000052D: Constraint violation - check_password_restrictions: the password was already used (in history)!` |
| younger than min age (user change only) | `0000052D: Constraint violation - check_password_restrictions: password is too young to change!` |
| wrong old password (user change) | `00000056: Constraint violation - check_password_restrictions: The old password specified doesn't match!` |

`0000052D` is ERROR_PASSWORD_RESTRICTION; `00000056` is ERROR_INVALID_PASSWORD.

- A **reset** (`replace: unicodePwd`, needs the Reset Password right) checks
  length and complexity but **not history or minimum age**. Reusing the current
  or a recent password succeeds. That stays true when the LDAP_SERVER_POLICY_HINTS
  control is sent (`1.2.840.113556.1.4.2239`, and the deprecated `.2066`, value
  `30 03 02 01 01`). Samba ignores it, although Windows AD would enforce history.
- A **user change** (`delete:` old value plus `add:` new value, bound as the
  user) checks all of the rules. Minimum age (1 day) fires before history, so a
  history test needs `samba-tool domain passwordsettings set --min-pwd-age=0`.
- Other result codes the self-test asserts: 50 insufficientAccessRights when a
  delegated account writes outside its rights or outside the OU, and 68
  entryAlreadyExists (`00002071: samldb: sAMAccountName 'squatter' already in use!`)
  when an add reuses a sAMAccountName.

## dc_attrs_hash exclusions

`uSNChanged whenChanged lastLogon lastLogonTimestamp logonCount badPwdCount
badPasswordTime lastLogoff dSCorePropagationData` (`$E2E_DC_VOLATILE_ATTRS`).
Logons and failed binds change these without anything writing the object.
Only `*` (user attributes) is hashed. Operational attributes are not.
