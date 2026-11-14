package store

import (
	"database/sql"
	"errors"
)

// RateLimitExemptKey holds the administrator's office networks (netallow canonical form).
const RateLimitExemptKey = "rate_limit_exempt_networks"

// RateLimitExemptNetworks returns the stored list; unset reads as empty.
func (s *Store) RateLimitExemptNetworks() (string, error) {
	v, err := s.GetSetting(RateLimitExemptKey)
	if errors.Is(err, ErrNotFound) {
		return "", nil
	}
	return v, err
}

// SetRateLimitExemptNetworks stores the list and its audit row in one transaction.
// The caller validates it first.
func (s *Store) SetRateLimitExemptNetworks(networks string, audit *AuditEvent) error {
	return s.auditedTx(audit, func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO system_settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
 ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP`, RateLimitExemptKey, networks)
		return err
	})
}
