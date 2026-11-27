package store

import (
	"database/sql"
	"strings"
)

// Transfers are five-minute, one-shot messages, not durable key wrappers. Upgrade
// drops pending classical transfers; both browsers must reload and request KYT2.
// Keep migration 18 unchanged so upgrades exercise the actual shipped schema.
const keyringXwingTransferSchema = `
DROP TABLE keyring_transfers;
CREATE TABLE keyring_transfers (
 org_id TEXT NOT NULL REFERENCES orgs(id), user_id TEXT NOT NULL, id TEXT NOT NULL,
 request_session TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
 expires_at BIGINT NOT NULL,
 recipient_key TEXT NOT NULL CHECK (length(recipient_key)=1622),
 request_mac TEXT NOT NULL CHECK (length(request_mac)=43),
 approved_device TEXT, sender_key TEXT NOT NULL DEFAULT '', sealed TEXT NOT NULL DEFAULT '',
 CHECK ((approved_device IS NULL AND sender_key='' AND sealed='')
     OR (approved_device IS NOT NULL AND sender_key='xwing:1' AND length(sealed)=1559)),
 PRIMARY KEY (org_id, user_id, id), UNIQUE (org_id, user_id, request_session),
 FOREIGN KEY (org_id, user_id) REFERENCES keyrings(org_id, user_id) ON DELETE CASCADE,
 FOREIGN KEY (org_id, user_id, approved_device) REFERENCES keyring_wrappers(org_id, user_id, id) ON DELETE CASCADE
);
CREATE INDEX keyring_transfer_expiry ON keyring_transfers(expires_at);
CREATE INDEX keyring_transfer_session ON keyring_transfers(request_session);
`

func migrateKeyringXwing(tx *sql.Tx) error {
	return migrateKeyringXwingWithTriggers(tx, sqliteTriggerSQL)
}
func migrateKeyringXwingPostgres(tx *sql.Tx) error {
	return migrateKeyringXwingWithTriggers(tx, func(t tenancyTrigger, cond string) string {
		return strings.ReplaceAll(pgTriggerSQL(t, cond), "CREATE FUNCTION ", "CREATE OR REPLACE FUNCTION ")
	})
}

func migrateKeyringXwingWithTriggers(tx *sql.Tx, triggerSQL func(tenancyTrigger, string) string) error {
	if _, err := tx.Exec(keyringXwingTransferSchema); err != nil {
		return err
	}
	refusals := tenancyRefusals("unixepoch()")
	for _, t := range []tenancyTrigger{
		{"keyring_transfers_org_exists", "BEFORE INSERT", "keyring_transfers", "org_missing", msgOrgMissing},
		{"keyring_transfers_org_immutable", "BEFORE UPDATE OF org_id", "keyring_transfers", "org_changed", msgOrgChanged},
	} {
		if _, err := tx.Exec(triggerSQL(t, refusals[t.refusal])); err != nil {
			return err
		}
	}
	return nil
}
