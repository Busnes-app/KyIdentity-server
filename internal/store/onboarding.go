package store

import (
	"database/sql"
	"errors"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
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
// Another org's user is ErrNotFound, as an ineligible one is.
func (o *OrgStore) IssueAccountToken(userID, kind, delivery string, ttl time.Duration, audit *AuditEvent) (string, error) {
	raw, _, err := o.issueAccountToken(userID, kind, delivery, ttl, audit)
	return raw, err
}

// IssueAccountTokenToEmail returns an email-delivered token and the recorded address
// read in the issuing transaction. Callers do not choose the recipient.
func (o *OrgStore) IssueAccountTokenToEmail(userID, kind string, ttl time.Duration, audit *AuditEvent) (string, string, error) {
	return o.issueAccountToken(userID, kind, "email", ttl, audit)
}

func (o *OrgStore) issueAccountToken(userID, kind, delivery string, ttl time.Duration, audit *AuditEvent) (string, string, error) {
	// An owned account the upstream marks inactive, or a local override holds down, gets
	// no activation link: redeeming it could only produce a disabled account.
	eligible := `SELECT email FROM users WHERE org_id=? AND id=? AND pending AND (source_connector_id IS NULL OR (source_active AND NOT locally_disabled)) AND ` + orgActiveSQL("users")
	if kind == "reset" {
		eligible = `SELECT email FROM users WHERE org_id=? AND id=? AND status='active' AND NOT pending AND ` + orgActiveSQL("users")
	}
	raw, err := crypto.GenerateRandomHex(32)
	if err != nil {
		return "", "", err
	}
	now := time.Now().UTC()
	var email string
	err = o.s.auditedTx(audit, func(tx *sql.Tx) error {
		err := tx.QueryRow(eligible, o.org, userID).Scan(&email)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if err := expireAccountTokensTx(tx, now, `user_id=? AND kind=?`, userID, kind); err != nil {
			return err
		}
		_, err = tx.Exec(`INSERT INTO account_tokens (id, user_id, kind, token_hash, delivery, expires_at, created_at) VALUES (?,?,?,?,?,?,?)`,
			uuid.NewString(), userID, kind, crypto.HashSHA256(raw), delivery, now.Add(ttl), now)
		return err
	})
	if err != nil {
		return "", "", err
	}
	return raw, email, nil
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
	var user *User
	err := s.auditedTx(audit, func(tx *sql.Tx) error {
		// Read the clock under the write lock: a time taken while waiting behind a
		// revocation would pass the expiry that revocation just set.
		now := time.Now().UTC()
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
		// Activation derives status from the source state, never a bare 'active': an owned
		// account stays disabled while the upstream says inactive or a local override holds.
		res, err = tx.Exec(`UPDATE users SET password_hash=?, pending=FALSE, password_change_required=FALSE,
 status=CASE WHEN ?='activation' THEN CASE WHEN source_connector_id IS NULL OR (source_active AND NOT locally_disabled) THEN 'active' ELSE 'disabled' END ELSE status END,
 email_verified_at=CASE WHEN email_verified_at IS NOT NULL THEN email_verified_at WHEN ?='email' THEN ? END, updated_at=?
 WHERE id=? AND ((?='activation' AND pending) OR (?='reset' AND status='active' AND NOT pending)) AND `+orgActiveSQL("users")+``, passwordHash, kind, delivery, now, now, userID, kind, kind)
		if errors.Is(staffOrgError(err), ErrSeatLimit) {
			return ErrNotFound // the seat-cap backstop at activation reads as an expired link
		}
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
		if user, err = scanUser(tx.QueryRow(`SELECT `+userColumns+` FROM users WHERE id=?`, userID)); err != nil {
			return err
		}
		// Billing hears of a customer member's activation (Events back to billing).
		if kind == "activation" {
			if err := queueCustomerMemberEventTx(tx, user, "activated", now); err != nil {
				return err
			}
		}
		// The row commits in this transaction, so it must name the account before it does.
		if audit != nil {
			audit.ActorID, audit.ActorUsername, audit.TargetID = user.ID, user.Username, user.ID
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return user, nil
}

// ChangePassword sets a new password for a signed-in owner: the session that proved
// itself stays, every other session, token, code and outstanding link ends.
func (o *OrgStore) ChangePassword(userID, keepSessionID, passwordHash string, audit *AuditEvent) error {
	now := time.Now().UTC()
	return o.s.auditedTx(audit, func(tx *sql.Tx) error {
		// The session that proved itself must still be live under the write lock: a request
		// held open past a reset or revocation must not overwrite the recovered password.
		res, err := tx.Exec(`UPDATE users SET password_hash=?, password_change_required=FALSE, updated_at=? WHERE org_id=? AND id=? AND status='active' AND NOT pending
 AND EXISTS(SELECT 1 FROM sessions WHERE id=? AND user_id=? AND expires_at>?)`, passwordHash, now, o.org, userID, keepSessionID, userID, now)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrNotFound
		}
		if _, err := revokeSessionsTx(tx, now, `user_id=? AND id<>?`, userID, keepSessionID); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE device_pairing_tokens SET expires_at=? WHERE user_id=? AND used_at IS NULL`, now, userID); err != nil {
			return err
		}
		if err := revokeSessionGrantsTx(tx, `user_id=?`, now, userID); err != nil {
			return err
		}
		if err := spendMFATokensTx(tx, now, userID); err != nil {
			return err
		}
		if err := denyApprovedDeviceCodesTx(tx, userID, ""); err != nil {
			return err
		}
		return expireAccountTokensTx(tx, now, `user_id=?`, userID)
	})
}

// An expired, unused activation link of a pending account holder of an active customer
// org with no other live link queues org.holder_invite_expired as it goes, once: the row
// goes in the same transaction. The holder stays; billing re-invites or names another.
func (s *Store) DeleteExpiredAccountTokens() error {
	return s.auditedTx(nil, func(tx *sql.Tx) error {
		now := time.Now().UTC()
		orgs, err := scanStrings(tx.Query(`SELECT DISTINCT o.id FROM account_tokens t JOIN users u ON u.id=t.user_id JOIN orgs o ON o.account_holder_user_id=u.id
 WHERE t.kind='activation' AND t.used_at IS NULL AND t.expires_at<? AND u.pending AND o.status='active' AND o.kind='`+customerKind+`'
 AND NOT EXISTS(SELECT 1 FROM account_tokens l WHERE l.user_id=u.id AND l.kind='activation' AND l.used_at IS NULL AND l.expires_at>=?) ORDER BY o.id`, now, now))
		if err != nil {
			return err
		}
		for _, org := range orgs {
			if err := queuePlatformEventTx(tx, org, "org.holder_invite_expired", "", "", now); err != nil {
				return err
			}
		}
		_, err = tx.Exec(`DELETE FROM account_tokens WHERE expires_at<? OR used_at IS NOT NULL`, now)
		return err
	})
}
