package store

import (
	"database/sql"
	"encoding/json"
	"errors"
)

const attestationSettingsKey = "attestation"

// AttestationSettings is the admin policy applied when grading device attestations.
type AttestationSettings struct {
	RequireLockedBootloader bool `json:"requireLockedBootloader"`
}

// AttestationSettings returns the stored policy, or the default (nothing enforced) when unset.
func (s *Store) AttestationSettings() (AttestationSettings, error) {
	var out AttestationSettings
	raw, err := s.GetSetting(attestationSettingsKey)
	if errors.Is(err, ErrNotFound) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	err = json.Unmarshal([]byte(raw), &out)
	return out, err
}

func (s *Store) SetAttestationSettings(a AttestationSettings, audit *AuditEvent) error {
	raw, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return s.auditedTx(audit, func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO system_settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
 ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP`, attestationSettingsKey, string(raw))
		return err
	})
}
