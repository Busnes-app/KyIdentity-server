package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

const MaxRecoveryEvidenceBytes = 256 << 10

var ErrRecoveryEvidenceUnavailable = errors.New("recovery evidence requires an active, unheld KyPost connection with a signing credential")
var ErrRecoveryEvidenceTooLarge = errors.New("complete recovery evidence exceeds the size limit")

type RecoverySubject struct {
	ID       string          `json:"id"`
	Revision *int            `json:"revision"` // nil is unknown, never an inferred revision zero.
	Profile  json.RawMessage `json:"profile"`
}
type RecoveryEvidence struct {
	Version   int               `json:"version"`
	Issuer    string            `json:"issuer"`
	SystemID  string            `json:"systemId"`
	Nonce     string            `json:"nonce"`
	IssuedAt  time.Time         `json:"issuedAt"`
	ExpiresAt time.Time         `json:"expiresAt"`
	Subjects  []RecoverySubject `json:"subjects"`
}

// ExportRecoveryEvidence snapshots only the requested subjects. sign must do local
// signing only: no network I/O or store re-entry while the transaction owns the writer
// lock. Nothing is returned unless signing and the durable audit both succeed.
// The API validates the bounded unique identifiers and consumer challenge first.
func (s *Store) ExportRecoveryEvidence(systemID, issuer, nonce string, subjects []string, audit *AuditEvent, sign func(*PairedSystem, []byte, time.Time) error) ([]byte, error) {
	var payload []byte
	err := s.auditedTx(audit, func(tx *sql.Tx) error {
		sys := &PairedSystem{ID: systemID}
		if err := tx.QueryRow(`SELECT system_type,status,provisioning_hold,hmac_secret_encrypted FROM paired_systems WHERE id=?`, systemID).Scan(&sys.SystemType, &sys.Status, &sys.ProvisioningHold, &sys.HMACSecretEncrypted); err != nil {
			return err
		}
		if sys.SystemType != "kypost" || sys.Status != "active" || sys.ProvisioningHold || sys.HMACSecretEncrypted == "" {
			return ErrRecoveryEvidenceUnavailable
		}
		var appID string
		if err := tx.QueryRow(`SELECT id FROM app_registry WHERE system_id=?`, systemID).Scan(&appID); err != nil {
			return err
		}
		now := time.Now().UTC().Truncate(time.Second)
		evidence := RecoveryEvidence{Version: 1, Issuer: issuer, SystemID: systemID, Nonce: nonce, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), Subjects: make([]RecoverySubject, 0, len(subjects))}
		profileBytes := 0
		for _, id := range subjects {
			entry := RecoverySubject{ID: id}
			var revision int
			err := tx.QueryRow(`SELECT revision FROM sync_resource_state WHERE system_id=? AND resource_id=? AND kind='user'`, systemID, id).Scan(&revision)
			if err == nil {
				entry.Revision = &revision
			} else if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			var allowed bool
			if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM effective_app_access WHERE app_id=? AND user_id=?)`, appID, id).Scan(&allowed); err != nil {
				return err
			}
			if allowed {
				u, err := scanUser(tx.QueryRow(`SELECT `+userColumns+` FROM users WHERE id=?`, id))
				if err != nil {
					return err
				}
				if u != nil && u.Status == "active" {
					entry.Profile, err = scimUserPayloadTx(tx, u, true, systemID)
					if err != nil {
						return err
					}
				}
			}
			if entry.Profile == nil {
				// A negative assertion discloses no profile or roles outside this app's scope.
				entry.Profile, _ = json.Marshal(map[string]any{"id": id, "externalId": id, "active": false, "roles": []string{}})
			}
			profileBytes += len(entry.Profile)
			if profileBytes > MaxRecoveryEvidenceBytes {
				return ErrRecoveryEvidenceTooLarge
			}
			evidence.Subjects = append(evidence.Subjects, entry)
		}
		var err error
		payload, err = json.Marshal(evidence)
		if err != nil {
			return err
		}
		if len(payload) > MaxRecoveryEvidenceBytes {
			return ErrRecoveryEvidenceTooLarge
		}
		return sign(sys, payload, now)
	})
	if err != nil {
		return nil, err
	}
	return payload, nil
}
