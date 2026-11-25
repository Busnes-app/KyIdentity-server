package store

import (
	"database/sql"
	"errors"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/google/uuid"
)

// The events outbox to billing (tenancy design, "Events back to billing"): platform_events
// rows are queued in the transaction of the change and delivered at least once, unordered,
// signed with ky-primitives/syncauth under a secret sealed at rest.

// PlatformEventsSecretSetting holds the sealed signing secret.
const PlatformEventsSecretSetting = "platform_events_secret"

// PlatformEvent is a queued delivery.
type PlatformEvent struct {
	ID, OrgID, Type, Payload, ClaimToken string
	Attempts                             int
}

// SetPlatformEventsSecret seals and stores the signing secret, audited as a platform row.
func (s *Store) SetPlatformEventsSecret(secret string, key []byte, audit *AuditEvent) error {
	if len(secret) < 32 {
		return InputError("the secret must be at least 32 characters")
	}
	sealed, err := crypto.EncryptAESGCM(key, []byte(secret))
	if err != nil {
		return err
	}
	return s.auditedTx(audit, func(tx *sql.Tx) error {
		return settingsTx{tx}.SetSetting(PlatformEventsSecretSetting, sealed)
	})
}

// PlatformEventsSecret opens the signing secret; ErrNotFound when none is set.
func (s *Store) PlatformEventsSecret(key []byte) ([]byte, error) {
	sealed, err := s.GetSetting(PlatformEventsSecretSetting)
	if err != nil {
		return nil, err
	}
	return crypto.DecryptAESGCM(key, sealed)
}

// ClaimPlatformEvent leases the oldest due event, or returns nil.
func (p *PlatformStore) ClaimPlatformEvent(lease time.Duration) (*PlatformEvent, error) {
	now := time.Now().UTC()
	tx, err := p.s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var e PlatformEvent
	err = tx.QueryRow(`SELECT id,org_id,type,payload_json,attempts FROM platform_events
 WHERE status='queued' AND next_attempt_at<=? AND (lease_until IS NULL OR lease_until<=?) ORDER BY next_attempt_at,created_at LIMIT 1`, now, now).
		Scan(&e.ID, &e.OrgID, &e.Type, &e.Payload, &e.Attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	e.ClaimToken = uuid.NewString()
	e.Attempts++
	if _, err := tx.Exec(`UPDATE platform_events SET claim_token=?,lease_until=?,attempts=? WHERE id=?`, e.ClaimToken, now.Add(lease), e.Attempts, e.ID); err != nil {
		return nil, err
	}
	return &e, tx.Commit()
}

// FinishPlatformEvent records an attempt under its claim. A failure is retried, backing off
// from a minute, doubling, to an hour, without end: delivery is at least once.
func (p *PlatformStore) FinishPlatformEvent(e *PlatformEvent, attemptErr error) error {
	now := time.Now().UTC()
	if attemptErr == nil {
		_, err := p.s.db.Exec(`UPDATE platform_events SET status='delivered',lease_until=NULL,claim_token='' WHERE id=? AND claim_token=?`, e.ID, e.ClaimToken)
		return err
	}
	backoff := min(time.Minute<<min(e.Attempts-1, 6), time.Hour)
	_, err := p.s.db.Exec(`UPDATE platform_events SET next_attempt_at=?,lease_until=NULL,claim_token='' WHERE id=? AND claim_token=?`, now.Add(backoff), e.ID, e.ClaimToken)
	return err
}

// DeleteDeliveredPlatformEvents drops delivered events older than cutoff.
func (p *PlatformStore) DeleteDeliveredPlatformEvents(cutoff time.Time) error {
	_, err := p.s.db.Exec(`DELETE FROM platform_events WHERE status='delivered' AND created_at<?`, cutoff)
	return err
}
