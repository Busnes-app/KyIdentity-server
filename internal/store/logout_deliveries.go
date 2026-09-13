package store

import (
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

// LogoutDelivery is one back-channel logout owed to one client for one login. A row is
// queued when the session ends and survives restarts; the worker claims it under a lease
// and records each attempt, so an operator can see which apps were told and which were not.
type LogoutDelivery struct {
	ID, ClientID, ClientName, BackchannelLogoutURI, UserID, SID string
	Status                                                      string // queued, delivered, failed
	Attempts                                                    int
	LastError, ClaimToken                                       string
	NextAttemptAt, CreatedAt, UpdatedAt                         time.Time
}

const logoutDeliveryAttempts = 5

func (s *Store) migrateLogoutDeliveries() error {
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM pragma_table_info('oauth_clients') WHERE name='backchannel_logout_uri'`).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		if _, err := s.db.Exec(`ALTER TABLE oauth_clients ADD COLUMN backchannel_logout_uri TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS logout_deliveries (
 id TEXT PRIMARY KEY, client_id TEXT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL, sid TEXT NOT NULL, status TEXT NOT NULL CHECK (status IN ('queued','delivered','failed')),
 attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT NOT NULL DEFAULT '', claim_token TEXT NOT NULL DEFAULT '',
 lease_until DATETIME, next_attempt_at DATETIME NOT NULL, created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL);
 CREATE INDEX IF NOT EXISTS idx_logout_deliveries_due ON logout_deliveries(status, next_attempt_at);
 CREATE INDEX IF NOT EXISTS idx_logout_deliveries_user ON logout_deliveries(user_id, created_at)`)
	return err
}

// enqueueLogoutTx queues one delivery per client that saw a login matching the predicate
// over oidc_client_sessions (alias cs) and registered a back-channel receiver. It must run
// before the session rows are deleted, because the sid mapping cascades with them.
func enqueueLogoutTx(tx *sql.Tx, now time.Time, where string, args ...any) error {
	_, err := tx.Exec(`INSERT INTO logout_deliveries (id, client_id, user_id, sid, status, attempts, next_attempt_at, created_at, updated_at)
 SELECT lower(hex(randomblob(16))), cs.client_id, cs.user_id, cs.sid, 'queued', 0, ?, ?, ?
 FROM oidc_client_sessions cs JOIN oauth_clients c ON c.id=cs.client_id
 WHERE c.enabled AND c.backchannel_logout_uri<>'' AND `+where, append([]any{now, now, now}, args...)...)
	return err
}

const logoutDeliveryColumns = `d.id, d.client_id, COALESCE(c.client_name, d.client_id), COALESCE(c.backchannel_logout_uri, ''), d.user_id, d.sid, d.status, d.attempts, d.last_error, d.claim_token, d.next_attempt_at, d.created_at, d.updated_at`

func scanLogoutDelivery(row interface{ Scan(...any) error }) (*LogoutDelivery, error) {
	d := &LogoutDelivery{}
	err := row.Scan(&d.ID, &d.ClientID, &d.ClientName, &d.BackchannelLogoutURI, &d.UserID, &d.SID, &d.Status, &d.Attempts, &d.LastError, &d.ClaimToken, &d.NextAttemptAt, &d.CreatedAt, &d.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return d, err
}

// ClaimLogoutDelivery leases the oldest due delivery whose client has nothing in flight,
// or returns nil, so one unresponsive receiver never holds more than one worker. A lapsed
// lease is claimable again; a delivery out of attempts is marked failed rather than retried.
func (s *Store) ClaimLogoutDelivery(lease time.Duration) (*LogoutDelivery, error) {
	now := time.Now().UTC()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE logout_deliveries SET status='failed', last_error='interrupted repeatedly', claim_token='', lease_until=NULL, updated_at=?
 WHERE status='queued' AND lease_until IS NOT NULL AND lease_until<=? AND attempts>=?`, now, now, logoutDeliveryAttempts); err != nil {
		return nil, err
	}
	token := uuid.NewString()
	res, err := tx.Exec(`UPDATE logout_deliveries SET claim_token=?, lease_until=?, attempts=attempts+1, updated_at=?
 WHERE id=(SELECT id FROM logout_deliveries WHERE status='queued' AND next_attempt_at<=? AND (lease_until IS NULL OR lease_until<=?) AND attempts<?
   AND client_id NOT IN (SELECT client_id FROM logout_deliveries WHERE status='queued' AND lease_until>?) ORDER BY created_at LIMIT 1)`,
		token, now.Add(lease), now, now, now, logoutDeliveryAttempts, now)
	if err != nil {
		return nil, err
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return nil, err
	}
	d, err := scanLogoutDelivery(tx.QueryRow(`SELECT `+logoutDeliveryColumns+` FROM logout_deliveries d LEFT JOIN oauth_clients c ON c.id=d.client_id WHERE d.claim_token=?`, token))
	if err != nil {
		return nil, err
	}
	return d, tx.Commit()
}

// FinishLogoutDelivery records an attempt's outcome under the worker's claim token. A
// failure schedules the next attempt with exponential backoff until the attempts run out.
func (s *Store) FinishLogoutDelivery(d *LogoutDelivery, attemptErr error) error {
	now := time.Now().UTC()
	status, message, next := "delivered", "", now
	if attemptErr != nil {
		message = attemptErr.Error()
		if len(message) > 200 {
			message = message[:200]
		}
		status = "queued"
		if d.Attempts >= logoutDeliveryAttempts {
			status = "failed"
		}
		next = now.Add(logoutRetryDelay(d.Attempts))
	}
	res, err := s.db.Exec(`UPDATE logout_deliveries SET status=?, last_error=?, next_attempt_at=?, claim_token='', lease_until=NULL, updated_at=? WHERE id=? AND claim_token=? AND claim_token<>''`,
		status, message, next, now, d.ID, d.ClaimToken)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		if err != nil {
			return err
		}
		return ErrNotFound
	}
	return nil
}

func logoutRetryDelay(attempts int) time.Duration {
	delay := time.Duration(1<<attempts) * 30 * time.Second
	if delay > 30*time.Minute {
		delay = 30 * time.Minute
	}
	return delay
}

// RetryLogoutDeliveryNow makes one of userID's queued or failed deliveries due
// immediately with a fresh attempt budget; it reports whether a delivery was found.
func (s *Store) RetryLogoutDeliveryNow(userID, id string, audit *AuditEvent) (bool, error) {
	now := time.Now().UTC()
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE logout_deliveries SET status='queued', attempts=0, next_attempt_at=?, claim_token='', lease_until=NULL, updated_at=? WHERE id=? AND user_id=? AND status<>'delivered'`, now, now, id, userID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil || n == 0 {
		return false, err
	}
	if err := recordAuditTx(tx, audit); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// DeleteLogoutDeliveriesOlderThan prunes finished deliveries, delivered or failed, last
// touched before cutoff. Queued rows stay until they finish.
func (s *Store) DeleteLogoutDeliveriesOlderThan(cutoff time.Time) error {
	_, err := s.db.Exec(`DELETE FROM logout_deliveries WHERE status IN ('delivered','failed') AND updated_at<?`, cutoff)
	return err
}

// ListLogoutDeliveries returns a user's most recent deliveries, newest first.
func (s *Store) ListLogoutDeliveries(userID string, limit int) ([]LogoutDelivery, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.Query(`SELECT `+logoutDeliveryColumns+` FROM logout_deliveries d LEFT JOIN oauth_clients c ON c.id=d.client_id WHERE d.user_id=? ORDER BY d.created_at DESC, d.id LIMIT ?`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LogoutDelivery{}
	for rows.Next() {
		d, err := scanLogoutDelivery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}
