package store

import (
	"database/sql"
	"errors"
	"time"

	"github.com/Busness-app/kysignon-server/internal/crypto"
	"github.com/google/uuid"
)

// Account links (activation and password reset) are single-use, expiring, and stored
// only as hashes: the raw token exists in the link handed or mailed to the owner and
// nowhere else. A new link of the same kind retires the previous one.
func (s *Store) migrateOnboarding() error {
	for _, c := range []struct{ probe, ddl string }{
		{`SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='pending'`, `ALTER TABLE users ADD COLUMN pending BOOLEAN NOT NULL DEFAULT 0`},
		{`SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='email_verified_at'`, `ALTER TABLE users ADD COLUMN email_verified_at DATETIME`},
	} {
		var n int
		if err := s.db.QueryRow(c.probe).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			if _, err := s.db.Exec(c.ddl); err != nil {
				return err
			}
		}
	}
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS account_tokens (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 kind TEXT NOT NULL CHECK (kind IN ('activation','reset')), token_hash TEXT NOT NULL UNIQUE,
 delivery TEXT NOT NULL CHECK (delivery IN ('manual','email')),
 expires_at DATETIME NOT NULL, used_at DATETIME, created_at DATETIME NOT NULL);
 CREATE INDEX IF NOT EXISTS idx_account_tokens_user ON account_tokens(user_id, kind)`)
	return err
}

// IssueAccountToken mints a link token for userID and retires any earlier link of the
// same kind. Activation needs a pending account; reset needs an active one. The raw
// token is returned once and never stored.
func (s *Store) IssueAccountToken(userID, kind, delivery string, ttl time.Duration, audit *AuditEvent) (string, error) {
	eligible := `SELECT EXISTS(SELECT 1 FROM users WHERE id=? AND pending)`
	if kind == "reset" {
		eligible = `SELECT EXISTS(SELECT 1 FROM users WHERE id=? AND status='active' AND NOT pending)`
	}
	raw, err := crypto.GenerateRandomHex(32)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	err = s.auditedTx(audit, func(tx *sql.Tx) error {
		var ok bool
		if err := tx.QueryRow(eligible, userID).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return ErrNotFound
		}
		if err := expireAccountTokensTx(tx, now, `user_id=? AND kind=?`, userID, kind); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO account_tokens (id, user_id, kind, token_hash, delivery, expires_at, created_at) VALUES (?,?,?,?,?,?,?)`,
			uuid.NewString(), userID, kind, crypto.HashSHA256(raw), delivery, now.Add(ttl), now)
		return err
	})
	if err != nil {
		return "", err
	}
	return raw, nil
}

func expireAccountTokensTx(tx *sql.Tx, now time.Time, where string, args ...any) error {
	_, err := tx.Exec(`UPDATE account_tokens SET expires_at=? WHERE used_at IS NULL AND expires_at>? AND `+where, append([]any{now, now}, args...)...)
	return err
}

// RedeemAccountToken spends a live link of the given kind and sets the password in the
// same transaction. The account must still be in the state the link was issued for
// (pending for activation, active for reset): a link outlives neither a cancelled
// invitation nor a password an administrator set meanwhile. Activation makes the
// account active; a link that was mailed proves the address. Every session, grant and
// remaining link ends, so a reset also evicts whoever held the old password. Anything
// but a live link for an eligible account is ErrNotFound.
func (s *Store) RedeemAccountToken(raw, kind, passwordHash string, audit *AuditEvent) (*User, error) {
	now := time.Now().UTC()
	var user *User
	err := s.auditedTx(audit, func(tx *sql.Tx) error {
		var id, userID, delivery string
		err := tx.QueryRow(`SELECT id, user_id, delivery FROM account_tokens WHERE token_hash=? AND kind=? AND used_at IS NULL AND expires_at>?`, crypto.HashSHA256(raw), kind, now).Scan(&id, &userID, &delivery)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		res, err := tx.Exec(`UPDATE account_tokens SET used_at=? WHERE id=? AND used_at IS NULL`, now, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrNotFound
		}
		res, err = tx.Exec(`UPDATE users SET password_hash=?, pending=0, status=CASE WHEN ?='activation' THEN 'active' ELSE status END,
 email_verified_at=COALESCE(email_verified_at, CASE WHEN ?='email' THEN ? END), updated_at=?
 WHERE id=? AND ((?='activation' AND pending) OR (?='reset' AND status='active' AND NOT pending))`, passwordHash, kind, delivery, now, now, userID, kind, kind)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrNotFound
		}
		if err := revokeUserAccessTx(tx, userID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM login_failures WHERE user_id=?`, userID); err != nil {
			return err
		}
		if err := reconcileProvisioningTx(tx, now); err != nil {
			return err
		}
		user, err = scanUser(tx.QueryRow(`SELECT `+userColumns+` FROM users WHERE id=?`, userID))
		return err
	})
	if err != nil {
		return nil, err
	}
	return user, nil
}

// ChangePassword sets a new password for a signed-in owner: the session that proved
// itself stays, every other session, token, code and outstanding link ends.
func (s *Store) ChangePassword(userID, keepSessionID, passwordHash string, audit *AuditEvent) error {
	now := time.Now().UTC()
	return s.auditedTx(audit, func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE users SET password_hash=?, updated_at=? WHERE id=? AND status='active' AND NOT pending`, passwordHash, now, userID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrNotFound
		}
		if _, err := revokeSessionsTx(tx, now, `user_id=? AND id<>?`, userID, keepSessionID); err != nil {
			return err
		}
		if err := revokeSessionGrantsTx(tx, `user_id=?`, now, userID); err != nil {
			return err
		}
		return expireAccountTokensTx(tx, now, `user_id=?`, userID)
	})
}

func (s *Store) DeleteExpiredAccountTokens() error {
	_, err := s.db.Exec(`DELETE FROM account_tokens WHERE expires_at<? OR used_at IS NOT NULL`, time.Now().UTC())
	return err
}
