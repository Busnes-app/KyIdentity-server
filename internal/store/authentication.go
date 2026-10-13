package store

import (
	"database/sql"
	"strings"
	"time"
)

// migrateAuthenticationEvidence preserves legacy sessions as unknown evidence and
// expires their outstanding codes. All columns and invalidations commit together.
func (s *Store) migrateAuthenticationEvidence() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, table := range []struct {
		name    string
		columns []string
	}{
		{"sessions", []string{"primary_authenticated_at DATETIME", "factor_authenticated_at DATETIME", "factor_method TEXT NOT NULL DEFAULT ''"}},
		{"authorization_codes", []string{"session_id TEXT NOT NULL DEFAULT ''", "primary_authenticated_at DATETIME", "factor_authenticated_at DATETIME", "factor_method TEXT NOT NULL DEFAULT ''", "authentication_expires_at DATETIME"}},
		{"issued_tokens", []string{"session_id TEXT"}},
		{"mfa_tokens", []string{"primary_authenticated_at DATETIME", "interaction_hash TEXT NOT NULL DEFAULT ''"}},
		{"mfa_challenges", []string{"verified_at DATETIME", "purpose TEXT NOT NULL DEFAULT 'login'"}},
	} {
		rows, err := tx.Query("PRAGMA table_info(" + table.name + ")")
		if err != nil {
			return err
		}
		existing := map[string]bool{}
		for rows.Next() {
			var cid, notNull, pk int
			var name, kind string
			var defaultValue sql.NullString
			if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &pk); err != nil {
				rows.Close()
				return err
			}
			existing[name] = true
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, column := range table.columns {
			name := column[:strings.IndexByte(column, ' ')]
			if !existing[name] {
				// Identifiers above are fixed schema literals, never external input.
				if _, err := tx.Exec("ALTER TABLE " + table.name + " ADD COLUMN " + column); err != nil {
					return err
				}
			}
		}
	}
	if _, err := tx.Exec(`DELETE FROM authorization_codes WHERE session_id = ''`); err != nil {
		return err
	}
	// An in-progress legacy login cannot prove when its password was verified.
	if _, err := tx.Exec(`DELETE FROM mfa_tokens WHERE primary_authenticated_at IS NULL`); err != nil {
		return err
	}
	return tx.Commit()
}

// GetSessionByID resolves server-side authorization context, never a browser credential.
func (s *Store) GetSessionByID(id string) (*Session, error) {
	sess := &Session{}
	err := s.db.QueryRow(`SELECT id, user_id, primary_authenticated_at, factor_authenticated_at, factor_method
 FROM sessions WHERE id = ? AND expires_at > ?`, id, time.Now().UTC()).Scan(
		&sess.ID, &sess.UserID, &sess.PrimaryAuthenticatedAt, &sess.FactorAuthenticatedAt, &sess.FactorMethod)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return sess, err
}
