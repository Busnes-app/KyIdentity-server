package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/config"
)

const sessionLimitsKey = "session_limits"

// SessionLimits are the browser session's absolute and idle lifetimes, in seconds. Every
// session lookup and refresh applies the current values, so a shorter limit also ends
// existing sessions; a longer one never extends a session past its stored expiry.
type SessionLimits struct {
	Absolute int64 `json:"absolute"`
	Idle     int64 `json:"idle"`
}

func (l SessionLimits) AbsoluteTTL() time.Duration { return time.Duration(l.Absolute) * time.Second }
func (l SessionLimits) IdleTTL() time.Duration     { return time.Duration(l.Idle) * time.Second }
func (l SessionLimits) Valid() bool                { return config.ValidSessionLimits(l.AbsoluteTTL(), l.IdleTTL()) }

// LoadSessionLimits caches the administrator's limits, or seed when none are stored.
func (s *Store) LoadSessionLimits(seed SessionLimits) error {
	l := seed
	raw, err := s.GetSetting(sessionLimitsKey)
	if err == nil {
		err = json.Unmarshal([]byte(raw), &l)
	} else if errors.Is(err, ErrNotFound) {
		err = nil
	}
	if err != nil {
		return err
	}
	if !l.Valid() {
		return errors.New("stored session limits are out of bounds")
	}
	s.limits.Store(&l)
	return nil
}

// SessionLimits returns the cached limits, or the defaults before any load.
func (s *Store) SessionLimits() SessionLimits {
	if l := s.limits.Load(); l != nil {
		return *l
	}
	return SessionLimits{Absolute: int64(config.DefaultSessionTTL / time.Second), Idle: int64(config.DefaultSessionIdleTTL / time.Second)}
}

// SetSessionLimits stores new limits and, in the same audited transaction, ends every
// session beyond the stricter of the old and new limits, with its tokens and refresh
// families, so relaxing the limits later can never revive one. It reports how many
// sessions it ended.
func (s *Store) SetSessionLimits(l SessionLimits, audit *AuditEvent) (int64, error) {
	if !l.Valid() {
		return 0, errors.New("session limits are out of bounds")
	}
	raw, err := json.Marshal(l)
	if err != nil {
		return 0, err
	}
	old := s.SessionLimits()
	strict := SessionLimits{Absolute: min(old.Absolute, l.Absolute), Idle: min(old.Idle, l.Idle)}
	var ended int64
	if err := s.auditedTx(audit, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO system_settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
 ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP`, sessionLimitsKey, string(raw)); err != nil {
			return err
		}
		now := time.Now().UTC()
		if ended, err = revokeSessionsTx(tx, now, `last_active_at<=? OR created_at<=?`, now.Add(-strict.IdleTTL()), now.Add(-strict.AbsoluteTTL())); err != nil {
			return err
		}
		if audit != nil {
			details, err := json.Marshal(map[string]any{"old": old, "new": l, "sessionsEnded": ended})
			if err != nil {
				return err
			}
			audit.DetailsJSON = string(details)
		}
		return nil
	}); err != nil {
		return 0, err
	}
	s.limits.Store(&l)
	return ended, nil
}
