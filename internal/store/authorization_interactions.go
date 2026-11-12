package store

import (
	"database/sql"
	"errors"
	"time"
)

var ErrAuthorizationInteraction = errors.New("authorization interaction expired, cancelled, or belongs to another login")

// AuthorizationInteraction contains only a validated authorization request. The browser
// binding is independent of the login cookie, which rotates after re-authentication.
type AuthorizationInteraction struct {
	Hash, BrowserHash, UserID, OriginalSessionID, SessionID, Request, ClientID string
	CreatedAt, ExpiresAt                                                       time.Time
}

// Repair rows created before account limits existed. Prefer preserving completed
// proofs when reducing an account's excess; evicted requests must restart authorization.
const repairAuthorizationAccountsSQL = `
 UPDATE authorization_interactions SET user_id=(SELECT user_id FROM sessions WHERE id=authorization_interactions.session_id)
 WHERE user_id='' AND session_id<>'' AND EXISTS(SELECT 1 FROM sessions WHERE id=authorization_interactions.session_id);
 DELETE FROM authorization_interactions WHERE session_id<>'' AND NOT EXISTS(SELECT 1 FROM sessions WHERE id=authorization_interactions.session_id);
 DELETE FROM authorization_interactions WHERE hash IN (
 SELECT hash FROM (SELECT hash,ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY (session_id<>'') DESC,created_at DESC,hash) AS position
 FROM authorization_interactions WHERE user_id<>'') WHERE position>10);`

func (s *Store) migrateAuthorizationInteractions() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`CREATE TABLE IF NOT EXISTS authorization_interactions (
 hash TEXT PRIMARY KEY, browser_hash TEXT NOT NULL, user_id TEXT NOT NULL DEFAULT '',
 original_session_id TEXT NOT NULL DEFAULT '', session_id TEXT NOT NULL DEFAULT '',
 request TEXT NOT NULL, created_at DATETIME NOT NULL, expires_at DATETIME NOT NULL);
 CREATE INDEX IF NOT EXISTS idx_authorization_interactions_browser ON authorization_interactions(browser_hash);
 CREATE INDEX IF NOT EXISTS idx_authorization_interactions_expiry ON authorization_interactions(expires_at);
 CREATE INDEX IF NOT EXISTS idx_authorization_interactions_user ON authorization_interactions(user_id);`)
	if err != nil {
		return err
	}
	var exists int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('authorization_interactions') WHERE name='client_id'`).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		if _, err = tx.Exec(`ALTER TABLE authorization_interactions ADD COLUMN client_id TEXT NOT NULL DEFAULT ''; DELETE FROM authorization_interactions;`); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(`CREATE INDEX IF NOT EXISTS idx_authorization_interactions_client ON authorization_interactions(client_id)`); err != nil {
		return err
	}
	if err = reconcileAuthorizationInteractionsTx(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// reconcileAuthorizationInteractionsTx runs on every start (reconcileOnStart): it drops
// expired interactions and repairs account bindings and overages.
func reconcileAuthorizationInteractionsTx(tx *sql.Tx) error {
	if _, err := tx.Exec(`DELETE FROM authorization_interactions WHERE expires_at<=?`, time.Now().UTC()); err != nil {
		return err
	}
	_, err := tx.Exec(repairAuthorizationAccountsSQL)
	return err
}

func (s *Store) CreateAuthorizationInteraction(i *AuthorizationInteraction) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`DELETE FROM authorization_interactions WHERE expires_at<=?`, time.Now().UTC()); err != nil {
		return err
	}
	// Repair pre-limit account floods too, including before the next restart.
	var total int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM authorization_interactions`).Scan(&total); err != nil {
		return err
	}
	if total >= 10000 {
		if _, err = tx.Exec(repairAuthorizationAccountsSQL); err != nil {
			return err
		}
	}
	// Anonymous cookie churn cannot turn the global memory bound into a login
	// outage. Reclaim only the oldest pending, unowned requests under pressure;
	// in-limit account requests and completed proofs are preserved.
	if _, err = tx.Exec(`DELETE FROM authorization_interactions WHERE hash IN (
 SELECT hash FROM authorization_interactions WHERE session_id='' AND user_id=''
 ORDER BY created_at,hash LIMIT MAX(0,(SELECT COUNT(*) FROM authorization_interactions)-9999))`); err != nil {
		return err
	}
	// Bound concurrent tabs per browser and per account, independent of cookie rotation.
	result, err := tx.Exec(`INSERT INTO authorization_interactions(hash,browser_hash,user_id,original_session_id,request,created_at,expires_at,client_id)
 SELECT ?,?,?,?,?,?,?,? WHERE (SELECT COUNT(*) FROM authorization_interactions WHERE browser_hash=?)<10
 AND (?='' OR (SELECT COUNT(*) FROM authorization_interactions WHERE user_id=?)<10)
 AND (SELECT COUNT(*) FROM authorization_interactions)<10000`, i.Hash, i.BrowserHash, i.UserID, i.OriginalSessionID, i.Request, i.CreatedAt, i.ExpiresAt, i.ClientID, i.BrowserHash, i.UserID, i.UserID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrAuthorizationInteraction
	}
	return tx.Commit()
}

func (s *Store) GetAuthorizationInteraction(hash, browserHash string) (*AuthorizationInteraction, error) {
	i := &AuthorizationInteraction{}
	err := s.db.QueryRow(`SELECT hash,browser_hash,user_id,original_session_id,session_id,request,created_at,expires_at,client_id FROM authorization_interactions i
 WHERE hash=? AND browser_hash=? AND expires_at>? AND (original_session_id='' OR EXISTS(SELECT 1 FROM sessions WHERE id=i.original_session_id AND expires_at>?))`, hash, browserHash, time.Now().UTC(), time.Now().UTC()).Scan(&i.Hash, &i.BrowserHash, &i.UserID, &i.OriginalSessionID, &i.SessionID, &i.Request, &i.CreatedAt, &i.ExpiresAt, &i.ClientID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAuthorizationInteraction
	}
	return i, err
}

func (s *Store) CancelAuthorizationInteraction(hash, browserHash string) error {
	_, err := s.db.Exec(`DELETE FROM authorization_interactions WHERE hash=? AND browser_hash=?`, hash, browserHash)
	return err
}
