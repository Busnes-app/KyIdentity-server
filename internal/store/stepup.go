package store

import (
	"database/sql"
	"errors"
	"time"
)

type StepUpChallenge struct {
	TokenHash, UserID, SessionID, Operation, Method, Proof string
	PrimaryAuthenticatedAt                                 time.Time
	ExpiresAt                                              time.Time
	Attempts                                               int
}

func (s *Store) migrateStepUpChallenges() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, name := range []string{"operation", "factor_method"} {
		var count int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('step_up_tokens') WHERE name = ?`, name).Scan(&count); err != nil {
			return err
		}
		if count == 0 {
			if _, err := tx.Exec("ALTER TABLE step_up_tokens ADD COLUMN " + name + " TEXT NOT NULL DEFAULT ''"); err != nil {
				return err
			}
		}
	}
	if _, err := tx.Exec(`DELETE FROM step_up_tokens WHERE operation = '';
 CREATE TABLE IF NOT EXISTS step_up_challenges (
 token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
 operation TEXT NOT NULL, method TEXT NOT NULL, proof TEXT NOT NULL,
 primary_authenticated_at DATETIME NOT NULL, expires_at DATETIME NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0, used_at DATETIME
 );`); err != nil {
		return err
	}
	return tx.Commit()
}

func createStepUpTokenTx(tx *sql.Tx, t *StepUpToken, audit *AuditEvent) error {
	t.CreatedAt = time.Now().UTC()
	res, err := tx.Exec(`INSERT INTO step_up_tokens (id,user_id,session_id,token_hash,expires_at,created_at,operation,factor_method)
 SELECT ?,?,?,?,?,?,?,? WHERE ? <> '' AND EXISTS
 (SELECT 1 FROM sessions JOIN users ON users.id = sessions.user_id
 WHERE sessions.id = ? AND sessions.user_id = ? AND sessions.expires_at > ? AND users.status = 'active' AND `+orgActiveSQL("users")+`)`,
		t.ID, t.UserID, t.SessionID, t.TokenHash, t.ExpiresAt, t.CreatedAt, t.Operation, t.FactorMethod, t.Operation, t.SessionID, t.UserID, t.CreatedAt)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("step-up session or operation is no longer valid")
	}
	return recordAuditTx(tx, audit)
}

func (s *Store) CreateStepUpToken(t *StepUpToken, audit *AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := createStepUpTokenTx(tx, t, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CreateStepUpChallenge(c *StepUpChallenge, audit *AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO step_up_challenges
 (token_hash,user_id,session_id,operation,method,proof,primary_authenticated_at,expires_at)
 VALUES (?,?,?,?,?,?,?,?)`, c.TokenHash, c.UserID, c.SessionID, c.Operation, c.Method, c.Proof, c.PrimaryAuthenticatedAt, c.ExpiresAt)
	if err != nil {
		return err
	}
	if err := recordAuditTx(tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) GetStepUpChallenge(hash, userID, sessionID string) (*StepUpChallenge, error) {
	c := &StepUpChallenge{}
	err := s.db.QueryRow(`SELECT token_hash,user_id,session_id,operation,method,proof,primary_authenticated_at,expires_at,attempts
 FROM step_up_challenges WHERE token_hash = ? AND user_id = ? AND session_id = ? AND used_at IS NULL AND expires_at > ? AND attempts < 5`, hash, userID, sessionID, time.Now().UTC()).Scan(
		&c.TokenHash, &c.UserID, &c.SessionID, &c.Operation, &c.Method, &c.Proof, &c.PrimaryAuthenticatedAt, &c.ExpiresAt, &c.Attempts)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return c, err
}

func (s *Store) FailStepUpChallenge(hash string) error {
	_, err := s.db.Exec(`UPDATE step_up_challenges SET attempts = attempts + 1 WHERE token_hash = ? AND used_at IS NULL`, hash)
	return err
}

// Completion, grant and its audit record are one transaction; cancellation or a
// competing completion cannot mint a second grant. The opaque token changes purpose
// only after this commit, and is accepted by neither ordinary login nor OAuth.
func (s *Store) CompleteStepUpChallenge(c *StepUpChallenge, t *StepUpToken, audit *AuditEvent) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE step_up_challenges SET used_at = ? WHERE token_hash = ? AND user_id = ? AND session_id = ? AND operation = ? AND used_at IS NULL AND expires_at > ? AND attempts < 5`, time.Now().UTC(), c.TokenHash, t.UserID, t.SessionID, t.Operation, time.Now().UTC())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil || n != 1 {
		return false, err
	}
	if err := createStepUpTokenTx(tx, t, audit); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// Cancel also burns a grant whose completion response raced the browser's cancel.
func (s *Store) CancelStepUp(hash, userID, sessionID string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, table := range []string{"step_up_challenges", "step_up_tokens"} {
		if _, err := tx.Exec("UPDATE "+table+" SET used_at = ? WHERE token_hash = ? AND user_id = ? AND session_id = ?", time.Now().UTC(), hash, userID, sessionID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ConsumeStepUpToken(hash, userID, sessionID, operation string) (bool, error) {
	now := time.Now().UTC()
	res, err := s.db.Exec(`UPDATE step_up_tokens SET used_at = ? WHERE token_hash = ? AND user_id = ? AND session_id = ? AND operation = ? AND used_at IS NULL AND expires_at > ?
 AND EXISTS (SELECT 1 FROM sessions JOIN users ON users.id = sessions.user_id WHERE sessions.id = step_up_tokens.session_id AND sessions.expires_at > ? AND users.status = 'active' AND `+orgActiveSQL("users")+`)`, now, hash, userID, sessionID, operation, now, now)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (s *Store) HasValidStepUpToken(hash, userID, sessionID, operation string) (bool, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM step_up_tokens WHERE token_hash = ? AND user_id = ? AND session_id = ? AND operation = ? AND used_at IS NULL AND expires_at > ?`, hash, userID, sessionID, operation, time.Now().UTC()).Scan(&count)
	return count > 0, err
}

func (s *Store) DeleteExpiredStepUpTokens() error {
	for _, table := range []string{"step_up_tokens", "step_up_challenges"} {
		if _, err := s.db.Exec("DELETE FROM "+table+" WHERE expires_at < ?", time.Now().UTC()); err != nil {
			return err
		}
	}
	return nil
}
