package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

// ClientSession maps the opaque `sid` a relying party sees to the login behind it. One
// row per client and session, so two relying parties cannot correlate a user's logins
// through the claim and neither learns the internal session ID.
type ClientSession struct {
	SID, ClientID, SessionID, UserID string
}

func (s *Store) migrateClientSessions() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS oidc_client_sessions (
 sid TEXT PRIMARY KEY, client_id TEXT NOT NULL, session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL, created_at DATETIME NOT NULL, UNIQUE(client_id, session_id));
 CREATE INDEX IF NOT EXISTS idx_oidc_client_sessions_session ON oidc_client_sessions(session_id)`)
	return err
}

// EnsureClientSession returns the sid for clientID and sessionID, minting one on first
// use. The session must still exist: a sid for a dead login would advertise a logout
// nothing can act on.
func (s *Store) EnsureClientSession(clientID, sessionID, userID string) (string, error) {
	sid, err := generateSID()
	if err != nil {
		return "", err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT OR IGNORE INTO oidc_client_sessions (sid, client_id, session_id, user_id, created_at)
 SELECT ?, ?, ?, ?, ? WHERE EXISTS(SELECT 1 FROM sessions WHERE id=? AND user_id=?)`, sid, clientID, sessionID, userID, time.Now().UTC(), sessionID, userID); err != nil {
		return "", err
	}
	var stored string
	if err := tx.QueryRow(`SELECT sid FROM oidc_client_sessions WHERE client_id=? AND session_id=?`, clientID, sessionID).Scan(&stored); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	return stored, tx.Commit()
}

// GetClientSession resolves a sid, or nil when it is unknown or its session is gone.
func (s *Store) GetClientSession(sid string) (*ClientSession, error) {
	cs := &ClientSession{}
	err := s.db.QueryRow(`SELECT sid, client_id, session_id, user_id FROM oidc_client_sessions WHERE sid=?`, sid).Scan(&cs.SID, &cs.ClientID, &cs.SessionID, &cs.UserID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return cs, err
}

func generateSID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
