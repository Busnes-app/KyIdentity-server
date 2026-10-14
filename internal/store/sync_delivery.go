package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// No event/user foreign key: deleting a user replaces its outbox rows, but must
// not discard the fence protecting the subsequent remote deactivation. Events left by
// connectors deleted before DeletePairedSystem removed them are dropped on every start.
func (s *Store) migrateSyncDelivery() error {
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM pragma_table_info('account_sync_events') WHERE name='claim_token'`).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		if _, err := s.db.Exec(`ALTER TABLE account_sync_events ADD COLUMN claim_token TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS sync_delivery_attempts (
 system_id TEXT NOT NULL, user_id TEXT NOT NULL, token TEXT NOT NULL UNIQUE,
 event_id TEXT NOT NULL, event_type TEXT NOT NULL, started_at DATETIME NOT NULL,
 recover_after DATETIME NOT NULL, PRIMARY KEY(system_id,user_id));
 CREATE INDEX IF NOT EXISTS sync_resource_queue ON account_sync_events(system_id,user_id,status);
 CREATE TRIGGER IF NOT EXISTS delete_sync_delivery_system AFTER DELETE ON paired_systems
 BEGIN DELETE FROM sync_delivery_attempts WHERE system_id=OLD.id; END;
 DELETE FROM account_sync_events WHERE NOT EXISTS(SELECT 1 FROM paired_systems p WHERE p.id=account_sync_events.system_id);`)
	return err
}

// BeginSyncDelivery turns a valid unsent claim into a durable resource fence.
// Expiration is a diagnostic/recovery threshold, never permission to send again.
func (s *Store) BeginSyncDelivery(ev AccountSyncEvent, duration time.Duration) (bool, error) {
	now := time.Now().UTC()
	r, err := s.db.Exec(`INSERT INTO sync_delivery_attempts(system_id,user_id,token,event_id,event_type,started_at,recover_after)
 SELECT system_id,user_id,claim_token,id,event_type,?,? FROM account_sync_events
 WHERE id=? AND claim_token=? AND claim_token<>'' AND lease_until>? AND status='pending'
 ON CONFLICT(system_id,user_id) DO NOTHING`, now, now.Add(duration), ev.ID, ev.ClaimToken, now)
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n == 1, err
}

// FinishSyncDelivery only releases the exact attempt whose HTTP outcome is known.
// The event may have been removed by account deletion while the request ran.
func (s *Store) FinishSyncDelivery(ev AccountSyncEvent, status, message string, attempts int, next *time.Time) error {
	if status == "pending" && attempts >= 5 {
		status = "failed"
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := tx.Exec(`DELETE FROM sync_delivery_attempts WHERE token=?`, ev.ClaimToken)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("delivery attempt changed")
	}
	_, err = tx.Exec(`UPDATE account_sync_events SET status=?,last_error=?,attempts=?,next_attempt_at=?,lease_until=NULL,claim_token='',updated_at=? WHERE id=? AND claim_token=?`, status, message, attempts, next, time.Now().UTC(), ev.ID, ev.ClaimToken)
	if err != nil {
		return err
	}
	if status == "delivered" {
		if err = provisionedTx(tx, ev, time.Now().UTC()); err != nil {
			return err
		}
		_, err = tx.Exec(`UPDATE paired_systems SET status='active',last_synced_at=? WHERE id=? AND status<>'disabled'`, time.Now().UTC(), ev.SystemID)
	} else if message != "" {
		_, err = tx.Exec(`UPDATE paired_systems SET status='failing' WHERE id=? AND status<>'disabled'`, ev.SystemID)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

type SyncDeliveryAttempt struct {
	Token        string    `json:"token"`
	UserID       string    `json:"userId"`
	EventID      string    `json:"eventId"`
	EventType    string    `json:"eventType"`
	StartedAt    time.Time `json:"startedAt"`
	RecoverAfter time.Time `json:"recoverAfter"`
}

func (s *Store) ListSyncDeliveryAttempts(systemID string) ([]SyncDeliveryAttempt, error) {
	rows, err := s.db.Query(`SELECT token,user_id,event_id,event_type,started_at,recover_after FROM sync_delivery_attempts WHERE system_id=? ORDER BY started_at LIMIT 100`, systemID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []SyncDeliveryAttempt{}
	for rows.Next() {
		var a SyncDeliveryAttempt
		if err := rows.Scan(&a.Token, &a.UserID, &a.EventID, &a.EventType, &a.StartedAt, &a.RecoverAfter); err != nil {
			return nil, err
		}
		result = append(result, a)
	}
	return result, rows.Err()
}

// ResumeSyncDelivery requires an operator to establish remote quiescence first.
// A read-back or expired lease cannot establish that a timed-out write stopped.
func (s *Store) ResumeSyncDelivery(systemID, token string, allowCreateRetry bool, audit *AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var eventID, userID string
	err = tx.QueryRow(`DELETE FROM sync_delivery_attempts WHERE system_id=? AND token=? AND recover_after<=? RETURNING event_id,user_id`, systemID, token, time.Now().UTC()).Scan(&eventID, &userID)
	if err != nil {
		return errors.New("attempt changed or still within delivery window")
	}
	if allowCreateRetry {
		if _, err = tx.Exec(`DELETE FROM scim_user_links WHERE system_id=? AND local_id=? AND remote_id=''`, systemID, userID); err != nil {
			return err
		}
	}
	if err = releaseAttemptEventTx(tx, eventID); err != nil {
		return err
	}
	if err = recordAuditTx(tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func releaseAttemptEventTx(tx *sql.Tx, eventID string) error {
	_, err := tx.Exec(`UPDATE account_sync_events SET status='pending',attempts=0,next_attempt_at=NULL,lease_until=NULL,claim_token='',last_error='',updated_at=? WHERE id=?`, time.Now().UTC(), eventID)
	return err
}

// ResumeSyncDeliveries is ResumeSyncDelivery for every expired attempt of one
// connector under one audit, whose details gain the released tokens. It never clears
// an uncertain-create guard; that stays a per-attempt decision.
func (s *Store) ResumeSyncDeliveries(systemID string, audit *AuditEvent) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`DELETE FROM sync_delivery_attempts WHERE system_id=? AND recover_after<=? RETURNING token,event_id`, systemID, time.Now().UTC())
	if err != nil {
		return 0, err
	}
	var tokens, events []string
	for rows.Next() {
		var token, eventID string
		if err := rows.Scan(&token, &eventID); err != nil {
			rows.Close()
			return 0, err
		}
		tokens, events = append(tokens, token), append(events, eventID)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(tokens) == 0 {
		return 0, errors.New("no expired attempts")
	}
	for _, id := range events {
		if err := releaseAttemptEventTx(tx, id); err != nil {
			return 0, err
		}
	}
	details := map[string]any{}
	if audit.DetailsJSON != "" {
		if err := json.Unmarshal([]byte(audit.DetailsJSON), &details); err != nil {
			return 0, err
		}
	}
	details["attemptTokens"] = tokens
	body, err := json.Marshal(details)
	if err != nil {
		return 0, err
	}
	audit.DetailsJSON = string(body)
	if err := recordAuditTx(tx, audit); err != nil {
		return 0, err
	}
	return len(tokens), tx.Commit()
}

func (s *Store) MarkSyncDeliveryUncertain(ev AccountSyncEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`UPDATE account_sync_events SET last_error='remote write outcome uncertain; operator recovery required',updated_at=? WHERE id=? AND claim_token=?`, time.Now().UTC(), ev.ID, ev.ClaimToken)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`UPDATE paired_systems SET status='failing' WHERE id=? AND status<>'disabled'
 AND EXISTS(SELECT 1 FROM sync_delivery_attempts WHERE token=?)`, ev.SystemID, ev.ClaimToken)
	if err != nil {
		return err
	}
	return tx.Commit()
}
