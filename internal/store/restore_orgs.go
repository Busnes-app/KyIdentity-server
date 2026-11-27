package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"time"
)

const restoreOrgReason = "restore_reconciliation"
const RestoreGenerationSetting = "org_restore_generation"

// A capsule cannot tell us about cancellations or erasures after it was taken. Billing
// must reconcile against its live ledger before any restored customer is admitted.
func holdRestoredOrgsTx(tx *sql.Tx, now time.Time, audit *AuditEvent) (int, error) {
	var multi bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM system_settings WHERE key=? AND value='multi')`, TenancySetting).Scan(&multi); err != nil || !multi {
		return 0, err
	}

	// The marker's restoredAt survives a crash after commit but before marker removal.
	// Reapplying that operation must not discard fresh reconciliation events or reset
	// every app's cache again. A new restore writes a new marker time.
	source := now.UTC().Format(time.RFC3339Nano)
	if audit != nil && audit.DetailsJSON != "" {
		var marker struct {
			RestoredAt time.Time `json:"restoredAt"`
		}
		if err := json.Unmarshal([]byte(audit.DetailsJSON), &marker); err != nil {
			return 0, err
		}
		if !marker.RestoredAt.IsZero() {
			source = marker.RestoredAt.UTC().Format(time.RFC3339Nano)
		}
	}
	sum := sha256.Sum256([]byte(source))
	generation := hex.EncodeToString(sum[:])
	var applied bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM system_settings WHERE key=? AND value=?)`, RestoreGenerationSetting, generation).Scan(&applied); err != nil || applied {
		return 0, err
	}
	// Snapshot-era answers and outbound billing changes are no longer authoritative.
	for _, q := range []string{
		`DELETE FROM platform_requests`,
		`UPDATE platform_events SET status='failed',claim_token='',lease_until=NULL WHERE status='queued'`,
		`UPDATE org_storage SET ceiling_bytes=used_bytes WHERE org_id IN (SELECT id FROM orgs WHERE kind='customer')`,
	} {
		if _, err := tx.Exec(q); err != nil {
			return 0, err
		}
	}
	ids, err := scanStrings(tx.Query(`SELECT id FROM orgs WHERE kind='customer' ORDER BY id`))
	if err != nil {
		return 0, err
	}
	held := 0
	for _, id := range ids {
		var status string
		if err := tx.QueryRow(`SELECT status FROM orgs WHERE id=?`, id).Scan(&status); err != nil {
			return 0, err
		}
		if status == "active" {
			if _, err := tx.Exec(`UPDATE orgs SET status='suspended',status_reason=?,revision=`+nextOrgRevisionSQL+`,updated_at=? WHERE id=?`, restoreOrgReason, now, id); err != nil {
				return 0, err
			}
			held++
		}
		// Include already suspended, scheduled and deleted orgs in billing reconciliation.
		if err := queuePlatformEventTx(tx, id, "org.restore_reconciliation_required", "", "", now); err != nil {
			return 0, err
		}
		if err := orgAuditTx(tx, id, &AuditEvent{ActorID: "system", ActorUsername: "system", Action: "org.restore_reconciliation_required", TargetID: id, TargetType: "org"}, map[string]any{"previous_status": status, "reason": restoreOrgReason}, now); err != nil {
			return 0, err
		}
	}
	if err := setSetting(tx, RestoreGenerationSetting, generation); err != nil {
		return 0, err
	}
	return held, nil
}

// OrgRestoreGeneration is a reset boundary for suite org caches and incremental cursors.
func (p *PlatformStore) OrgRestoreGeneration() (string, error) {
	var value string
	err := p.s.db.QueryRow(`SELECT value FROM system_settings WHERE key=?`, RestoreGenerationSetting).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}
