package store

import (
	"database/sql"
	"time"
)

// AppGrant summarises one client's live access tokens for a user. It is derived from the
// token registry, so it shows which apps can still call back, not whether an app's own
// cookie session is alive; downstream logout is a later contract.
type AppGrant struct {
	ClientID   string    `json:"clientId"`
	ClientName string    `json:"clientName"`
	Tokens     int       `json:"tokens"`
	IssuedAt   time.Time `json:"issuedAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

// ListUserSessions returns the browser sessions the middleware would still accept, most
// recently active first. The token hash is never loaded.
func (s *Store) ListUserSessions(userID string, idleTTL time.Duration) ([]Session, error) {
	now := time.Now().UTC()
	rows, err := s.db.Query(`SELECT id, user_id, ip_address, user_agent, expires_at, created_at, last_active_at, factor_method FROM sessions WHERE user_id=? AND expires_at>? AND last_active_at>? ORDER BY last_active_at DESC`, userID, now, now.Add(-idleTTL))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Session{}
	for rows.Next() {
		var sess Session
		if err := rows.Scan(&sess.ID, &sess.UserID, &sess.IPAddress, &sess.UserAgent, &sess.ExpiresAt, &sess.CreatedAt, &sess.LastActiveAt, &sess.FactorMethod); err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

// ListUserAppGrants groups a user's live tokens by client, most recently issued first.
// Grouping happens here because SQLite aggregates over DATETIME columns come back as text.
func (s *Store) ListUserAppGrants(userID string) ([]AppGrant, error) {
	rows, err := s.db.Query(`SELECT t.client_id, COALESCE(c.client_name, t.client_id), t.created_at, t.expires_at FROM issued_tokens t LEFT JOIN oauth_clients c ON c.id=t.client_id WHERE t.user_id=? AND t.revoked_at IS NULL AND t.expires_at>? ORDER BY t.created_at DESC`, userID, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AppGrant{}
	index := map[string]int{}
	for rows.Next() {
		var clientID, name string
		var issued, expires time.Time
		if err := rows.Scan(&clientID, &name, &issued, &expires); err != nil {
			return nil, err
		}
		i, ok := index[clientID]
		if !ok {
			i = len(out)
			index[clientID] = i
			out = append(out, AppGrant{ClientID: clientID, ClientName: name, IssuedAt: issued, ExpiresAt: expires})
		}
		g := &out[i]
		g.Tokens++
		if issued.Before(g.IssuedAt) {
			g.IssuedAt = issued
		}
		if expires.After(g.ExpiresAt) {
			g.ExpiresAt = expires
		}
	}
	return out, rows.Err()
}

// RevokeSession removes one of userID's sessions with everything it minted. A session that
// does not exist or belongs to someone else is ErrNotFound and writes nothing.
func (s *Store) RevokeSession(userID, sessionID string, audit *AuditEvent) error {
	return s.auditedTx(audit, func(tx *sql.Tx) error {
		n, err := revokeSessionsTx(tx, time.Now().UTC(), `id=? AND user_id=?`, sessionID, userID)
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// RevokeOtherSessions signs out every session of userID except keepSessionID.
func (s *Store) RevokeOtherSessions(userID, keepSessionID string, audit *AuditEvent) error {
	return s.auditedTx(audit, func(tx *sql.Tx) error {
		_, err := revokeSessionsTx(tx, time.Now().UTC(), `user_id=? AND id<>?`, userID, keepSessionID)
		return err
	})
}

// RevokeUserClientAccess revokes one app's tokens and pending codes for a user while
// leaving browser sessions and other apps alone.
func (s *Store) RevokeUserClientAccess(userID, clientID string, audit *AuditEvent) error {
	return s.auditedTx(audit, func(tx *sql.Tx) error {
		now := time.Now().UTC()
		if err := enqueueLogoutTx(tx, now, `cs.user_id=? AND cs.client_id=?`, userID, clientID); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE issued_tokens SET revoked_at=? WHERE user_id=? AND client_id=? AND revoked_at IS NULL`, now, userID, clientID); err != nil {
			return err
		}
		_, err := tx.Exec(`DELETE FROM authorization_codes WHERE user_id=? AND client_id=?`, userID, clientID)
		return err
	})
}

// revokeSessionsTx ends every session matching sessionWhere: it queues back-channel
// logout for the clients that saw those logins, invalidates everything the sessions
// minted, then deletes the rows. It reports how many sessions were removed.
func revokeSessionsTx(tx *sql.Tx, now time.Time, sessionWhere string, args ...any) (int64, error) {
	if err := enqueueLogoutTx(tx, now, `cs.session_id IN (SELECT id FROM sessions WHERE `+sessionWhere+`)`, args...); err != nil {
		return 0, err
	}
	if err := revokeSessionGrantsTx(tx, `session_id IN (SELECT id FROM sessions WHERE `+sessionWhere+`)`, now, args...); err != nil {
		return 0, err
	}
	res, err := tx.Exec(`DELETE FROM sessions WHERE `+sessionWhere, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// revokeSessionGrantsTx invalidates the codes, tokens, step-up grants and pending
// authorization interactions selected by a session predicate. Pending step-up challenges
// cascade with the session row.
func revokeSessionGrantsTx(tx *sql.Tx, where string, now time.Time, args ...any) error {
	statements := []struct {
		sql  string
		args []any
	}{
		{`UPDATE issued_tokens SET revoked_at=? WHERE revoked_at IS NULL AND ` + where, append([]any{now}, args...)},
		{`DELETE FROM authorization_codes WHERE ` + where, args},
		{`UPDATE step_up_tokens SET used_at=? WHERE used_at IS NULL AND ` + where, append([]any{now}, args...)},
		{`DELETE FROM authorization_interactions WHERE ` + where, args},
	}
	for _, st := range statements {
		if _, err := tx.Exec(st.sql, st.args...); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) auditedTx(audit *AuditEvent, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	if err := recordAuditTx(tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}
