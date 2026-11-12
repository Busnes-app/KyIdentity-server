package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
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

// sessionLimitsRefresh bounds how long a replica keeps applying limits another replica has
// since changed. The change itself ends over-limit sessions in the database at once; only
// the limit applied to later activity lags.
var sessionLimitsRefresh = 5 * time.Second

// LoadSessionLimits caches the administrator's limits, or seed when none are stored.
func (s *Store) LoadSessionLimits(seed SessionLimits) error {
	l, err := storedSessionLimits(s.db, seed)
	if err != nil {
		return err
	}
	s.limits.Store(&l)
	s.limitsSeed.Store(&seed)
	s.limitsAt.Store(time.Now().UnixNano())
	return nil
}

func storedSessionLimits(q settingsQuerier, seed SessionLimits) (SessionLimits, error) {
	l := seed
	raw, err := getSetting(q, sessionLimitsKey)
	if err == nil {
		err = json.Unmarshal([]byte(raw), &l)
	} else if errors.Is(err, ErrNotFound) {
		err = nil
	}
	if err == nil && !l.Valid() {
		err = errors.New("stored session limits are out of bounds")
	}
	return l, err
}

// SessionLimits returns the cached limits, or the defaults before any load. Once loaded
// they are re-read every sessionLimitsRefresh by one caller at a time; a failed re-read
// keeps the last good limits.
func (s *Store) SessionLimits() SessionLimits {
	if at, now := s.limitsAt.Load(), time.Now().UnixNano(); at != 0 && now-at > int64(sessionLimitsRefresh) && s.limitsAt.CompareAndSwap(at, now) {
		if err := s.LoadSessionLimits(*s.limitsSeed.Load()); err != nil {
			log.Printf("session limits: re-read failed, keeping the current ones: %v", err)
		}
	}
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
	var ended int64
	cached := s.SessionLimits()
	if err := s.auditedTx(audit, func(tx *sql.Tx) error {
		// The stored limits, not this replica's cache: another replica may have just changed them.
		old, err := storedSessionLimits(tx, cached)
		if err != nil {
			return err
		}
		strict := SessionLimits{Absolute: min(old.Absolute, l.Absolute), Idle: min(old.Idle, l.Idle)}
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
