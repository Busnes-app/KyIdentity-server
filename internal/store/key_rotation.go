package store

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/google/uuid"
)

const recoveryCodeKeySetting = "recovery_code_key_enc"

// RecoveryCodeKey preserves existing one-time codes across master-key rotations.
func (s *Store) RecoveryCodeKey(master []byte) ([]byte, error) {
	value, err := s.GetSetting(recoveryCodeKeySetting)
	if errors.Is(err, ErrNotFound) {
		return crypto.DeriveKey(master, "kyidentity:recovery-code"), nil
	}
	if err != nil {
		return nil, err
	}
	key, err := crypto.Open(master, "recovery_code_key", recoveryCodeKeySetting, value)
	if err != nil || len(key) != 32 {
		return nil, errors.New("recovery-code verification key is unreadable")
	}
	return key, nil
}

// RotateEncryptionKey operates on an offline copy. Receipts map setup IDs to
// verified old/new preparation digests; filesystem publication belongs to the CLI.
func (s *Store) RotateEncryptionKey(oldKey, newKey []byte, receipts map[string][2]string) error {
	if len(oldKey) != 32 || len(newKey) != 32 || bytes.Equal(oldKey, newKey) {
		return errors.New("rotation requires distinct 32-byte keys")
	}
	pepper, err := s.RecoveryCodeKey(oldKey)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	seal := func(purpose, row string, plain []byte) (string, error) {
		value, err := crypto.Seal(newKey, purpose, row, plain)
		if err != nil {
			return "", err
		}
		check, err := crypto.Open(newKey, purpose, row, value)
		if err != nil || !bytes.Equal(check, plain) {
			return "", errors.New("rotated secret verification failed")
		}
		return value, nil
	}
	for _, c := range sealedColumns {
		rows, err := tx.Query(fmt.Sprintf(`SELECT %s,%s FROM %s WHERE %s AND COALESCE(%s,'')<>''`, c.row, c.column, c.table, c.where, c.column))
		if err != nil {
			return err
		}
		values := map[string]string{}
		for rows.Next() {
			var row, value string
			if err := rows.Scan(&row, &value); err != nil {
				rows.Close()
				return err
			}
			values[row] = value
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return err
		}
		for row, value := range values {
			plain, err := crypto.Open(oldKey, c.purpose, row, value)
			if err != nil {
				return errors.New("rotation refused an unreadable sealed secret")
			}
			resealed, err := seal(c.purpose, row, plain)
			if err != nil {
				return err
			}
			if _, err = tx.Exec(fmt.Sprintf(`UPDATE %s SET %s=? WHERE %s=? AND %s`, c.table, c.column, c.row, c.where), resealed, row); err != nil {
				return err
			}
		}
	}
	var token string
	err = tx.QueryRow(`SELECT value FROM system_settings WHERE key='kyrecovery_token_enc'`).Scan(&token)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if token != "" {
		const label = "kysignon:setting:kyrecovery_token"
		plain, err := crypto.DecryptAESGCM(crypto.DeriveKey(oldKey, label), token)
		if err != nil {
			return errors.New("rotation refused an unreadable recovery token")
		}
		value, err := crypto.EncryptAESGCM(crypto.DeriveKey(newKey, label), plain)
		if err != nil {
			return err
		}
		check, err := crypto.DecryptAESGCM(crypto.DeriveKey(newKey, label), value)
		if err != nil || !bytes.Equal(check, plain) {
			return errors.New("rotated recovery token verification failed")
		}
		if _, err = tx.Exec(`UPDATE system_settings SET value=? WHERE key='kyrecovery_token_enc'`, value); err != nil {
			return err
		}
	}
	wrapped, err := seal("recovery_code_key", recoveryCodeKeySetting, pepper)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO system_settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, recoveryCodeKeySetting, wrapped); err != nil {
		return err
	}
	var count int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM installer_setup_resources WHERE kind='preparation'`).Scan(&count); err != nil {
		return err
	}
	if count != len(receipts) {
		return errors.New("rotation requires every native preparation receipt")
	}
	for id, digests := range receipts {
		res, err := tx.Exec(`UPDATE installer_setup_resources SET contract=? WHERE kind='preparation' AND name=? AND setup_id=? AND object_id=? AND contract=?`, digests[1], id, id, id, digests[0])
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return errors.New("rotation refused changed preparation ownership")
		}
	}
	if err := recordAuditTx(tx, &AuditEvent{ID: uuid.NewString(), ActorUsername: "kyidentity-cli", Action: "system.encryption_key_rotated", TargetType: "system", Outcome: "success", DetailsJSON: `{"offline":true}`, CreatedAt: time.Now().UTC()}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CheckIntegrity() error {
	var result string
	if err := s.db.QueryRow(`PRAGMA integrity_check`).Scan(&result); err != nil {
		return err
	}
	if result != "ok" {
		return errors.New("database integrity check failed")
	}
	return nil
}
