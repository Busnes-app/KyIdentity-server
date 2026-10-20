# Offline encryption-key rotation

Stop KyIdentity **and every administrative CLI process**. New servers hold a data
lock that refuses rotation while running; older binaries do not know that lock.
`--confirm-stopped` explicitly confirms that the operator stopped those too.
This command changes no running installation and never replaces source data.

```sh
kyidentity rotate-encryption-key --confirm-stopped --out /private/new-identity-data
```

Run as the data-directory owner with the existing `KYIDENTITY_DATA_DIR` and
`KYIDENTITY_DB_PATH`, if configured. Source data must be private, with protected
ancestry. Output must be a new, separate absolute directory under a protected
parent, on a filesystem supporting no-clobber rename and durable fsync. File-backed
32-byte `encryption.key` is required. Environment master-key overrides, external
databases/signing keys, symlinks, sockets, special files, incomplete preparation
and credentials outside the data directory are refused. Remove a stale setup
socket only after verifying the old server has stopped.

The command snapshots SQLite including its WAL, copies regular data privately,
reseals TOTP, connector, SMTP and recovery-token secrets, preserves recovery-code
verification, and validates/updates both native and filesystem setup receipts.
It verifies each new ciphertext and SQLite integrity before publishing. Reports
contain only paths and SHA-256 key fingerprints. Output is published only after
verification; activation requires a successful report and durable parent-directory sync. Do not delete the original directory or its backups.

Activate the new directory at the **original runtime data path**, preserving the
in-container path (normally `/data`). Prepared bundles contain absolute credential
paths. Pointing `KYIDENTITY_DATA_DIR` at a new path breaks those references. Keep
the original directory securely as rollback material; never start two copies.

After activation, verify `/readyz`, sign-in and bootstrap password enforcement,
MFA/recovery-code redemption, existing pairing and `apply-setup --check`. Generate
and drill a fresh sealed backup: its database and new key must travel together.
Old sealed capsules remain self-contained with their old key. Rollback means stop
every process and restore the complete original directory; do not combine its
key with the new database. Rotation preserves old recovery-code verification
pepper under the new master; it does not change their 40-bit code format. Regenerate
codes if the old key may have been compromised. Rotation does not revoke tokens,
rotate upstream credentials, reset setup ownership or clear delivery fences.
