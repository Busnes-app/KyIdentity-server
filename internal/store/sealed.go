package store

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
)

// Row secrets are sealed with crypto.Seal under one of these purposes, bound to the row
// identity named beside it.
const (
	// User ID: mfa_methods is unique per (user, type), and re-enrolment keeps the old row
	// ID, so the method ID is not known when the secret is sealed.
	SealTOTP = "mfa_totp"
	// Paired system ID; it is assigned before the credential is sealed and never changes.
	SealConnector = "paired_system"
	// Settings key.
	SealMail = "mail_settings"
)

// MailSettingKey is the system_settings row holding the sealed relay configuration.
const MailSettingKey = "mail_settings_enc"

// SealedSecretsSetting marks a database whose legacy row secrets have all been sealed.
// From then on legacy ciphertext is never migrated, so a blob planted later stays refused.
const SealedSecretsSetting = "sealed_secrets_version"

// sealedColumns is every sealed row secret: table, ciphertext column, row identity, purpose, filter.
var sealedColumns = []struct{ table, column, row, purpose, where string }{
	{"mfa_methods", "encrypted_secret", "user_id", SealTOTP, "method_type = 'totp'"},
	{"paired_systems", "hmac_secret_encrypted", "id", SealConnector, "1"},
	{"system_settings", "value", "key", SealMail, "key = '" + MailSettingKey + "'"},
}

// SealLegacySecrets re-seals every legacy row secret in one transaction and records
// that it did; a rerun is a no-op and a crash commits nothing. A legacy secret that does
// not decrypt aborts it: that is a wrong key or a damaged row, and both need an operator.
func (s *Store) SealLegacySecrets(key []byte) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var done string
	err = tx.QueryRow(`SELECT value FROM system_settings WHERE key = ?`, SealedSecretsSetting).Scan(&done)
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	for _, c := range sealedColumns {
		rows, err := tx.Query(fmt.Sprintf(`SELECT %s, %s FROM %s WHERE %s AND COALESCE(%s, '') != ''`, c.row, c.column, c.table, c.where, c.column))
		if err != nil {
			return err
		}
		legacy := map[string]string{}
		for rows.Next() {
			var row, value string
			if err := rows.Scan(&row, &value); err != nil {
				_ = rows.Close()
				return err
			}
			if !crypto.IsSealed(value) {
				legacy[row] = value
			}
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return err
		}
		for row, value := range legacy {
			plain, err := crypto.DecryptAESGCM(key, value)
			if err != nil {
				return fmt.Errorf("%s row %s: legacy secret does not decrypt under the encryption key: %w", c.table, row, err)
			}
			sealed, err := crypto.Seal(key, c.purpose, row, plain)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(fmt.Sprintf(`UPDATE %s SET %s = ? WHERE %s AND %s = ? AND %s = ?`, c.table, c.column, c.where, c.row, c.column), sealed, row, value); err != nil {
				return err
			}
		}
	}
	if _, err := tx.Exec(`INSERT INTO system_settings (key, value) VALUES (?, '2')`, SealedSecretsSetting); err != nil {
		return err
	}
	return tx.Commit()
}
