package store

import (
	"database/sql"
	"encoding/json"
	"time"
)

// A restored snapshot is a copy of the directory as it was, credentials included. Every
// login, token, link and queued delivery in it was minted for a world that has since
// moved on: the cookie in someone's browser, the invitation mailed last week, the
// create waiting in the outbox for a user who has since left. Restoring must bring back
// the directory, not the credentials, so applying a restore clears what is ephemeral
// and holds outbound provisioning until the operator has reconciled each connector
// against what is really on the far side.

// restoredRevision marks an outbox row as coming from a capsule. No sync_resource_state
// row can carry it, so the re-pending in reconcileProvisioningTx can never match it.
const restoredRevision = -1

// restoredCleared is every table whose rows are a credential or a queued task that
// cannot survive a restore. Long-lived credentials the user holds (passwords, enrolled
// factors, recovery codes) are deliberately absent: they are what the operator still
// has to work with, and the runbook covers rotating them. Queued back-channel logouts
// are absent for a different reason: they are work this server owes a relying party,
// and nothing would re-derive them.
var restoredCleared = []string{
	"sessions", // cascades oidc_client_sessions
	"issued_tokens",
	"authorization_codes",
	"authorization_interactions",
	"mfa_tokens",
	"mfa_challenges",
	"webauthn_challenges",
	"step_up_challenges",
	"step_up_tokens",
	"account_tokens",
	"device_pairing_tokens",
	"login_failures",
	"sync_delivery_attempts",
}

// RestoreReport is what one restore invalidated, for the log and the audit trail.
type RestoreReport struct {
	// Credentials counts the rows cleared across restoredCleared.
	Credentials int
	// QueuedDeliveries counts outbox rows closed out rather than delivered.
	QueuedDeliveries int
	// LogoutsQueued counts back-channel logouts newly queued for the logins this
	// restore ended. Logouts already owed are kept, not counted again.
	LogoutsQueued int
	// HeldConnectors counts connectors whose outbound provisioning is now held, and
	// Connectors names them: their stored credentials are in the capsule and the
	// runbook asks the operator to review them for rotation.
	HeldConnectors int
	Connectors     []string
}

func (s *Store) migrateRestoreHold() error {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('paired_systems') WHERE name='provisioning_hold'`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	_, err := s.db.Exec(`ALTER TABLE paired_systems ADD COLUMN provisioning_hold BOOLEAN NOT NULL DEFAULT 0`)
	return err
}

// ApplyRestoredState invalidates the ephemeral credentials and queued outbound work a
// restored snapshot carries, and holds provisioning on every connector that is not
// already disabled. It is idempotent: a second pass finds nothing left to clear and
// leaves the holds alone.
func (s *Store) ApplyRestoredState(now time.Time, audit *AuditEvent) (RestoreReport, error) {
	var report RestoreReport
	err := s.auditedTx(audit, func(tx *sql.Tx) error {
		report = RestoreReport{}
		// Before the sessions go: every login this restore ends is announced to the
		// relying parties that saw it, because a receiver told nothing keeps its own
		// session until its own timeout. The sid mapping cascades away with the
		// sessions, so this cannot be done afterwards. A logout only ever removes
		// access, so re-announcing one is safe; a login already announced is not
		// queued twice.
		res, err := tx.Exec(`INSERT INTO logout_deliveries (id, client_id, user_id, sid, status, attempts, next_attempt_at, created_at, updated_at)
 SELECT lower(hex(randomblob(16))), cs.client_id, cs.user_id, cs.sid, 'queued', 0, ?, ?, ?
 FROM oidc_client_sessions cs JOIN oauth_clients c ON c.id=cs.client_id
 WHERE c.enabled AND c.backchannel_logout_uri<>''
 AND NOT EXISTS (SELECT 1 FROM logout_deliveries d WHERE d.client_id=cs.client_id AND d.sid=cs.sid AND d.status<>'delivered')`, now, now, now)
		if err != nil {
			return err
		}
		queued, err := res.RowsAffected()
		if err != nil {
			return err
		}
		report.LogoutsQueued = int(queued)
		// A delivery that was in flight when the snapshot was taken is owed by a process
		// that no longer exists: release the lease and let it go out again.
		if _, err := tx.Exec(`UPDATE logout_deliveries SET claim_token='', lease_until=NULL, attempts=0, next_attempt_at=?, updated_at=? WHERE status='queued'`, now, now); err != nil {
			return err
		}
		for _, table := range restoredCleared {
			res, err := tx.Exec(`DELETE FROM ` + table)
			if err != nil {
				return err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return err
			}
			report.Credentials += int(n)
		}
		// Every undelivered provisioning event is closed out rather than deleted: an
		// operator reading the outbox after a restore should see why nothing was sent,
		// and reconciliation re-derives the work. Back-channel logouts are the opposite
		// case, handled above: nothing re-derives them, so they are kept and redelivered. The sentinel revision is what keeps it closed: the
		// worker's safety net re-pends exhausted work whose revision still matches the
		// connector's desired state (provisioning.go), and after a restore every row is
		// unfenced, so without this the capsule's queue would come back and deliver the
		// moment a hold lifted. A revision no state row can carry never matches, and the
		// same pass deletes the row once a real revision exists. Deletions and MFA resets
		// carry no desired state and still retry, which only ever removes access.
		res, err = tx.Exec(`UPDATE account_sync_events SET status='failed', revision=?, last_error=?, updated_at=?, lease_until=NULL, claim_token='' WHERE status IN ('pending','failed') AND revision<>?`,
			restoredRevision, "superseded by a restore; reconcile the connector to re-derive the work", now, restoredRevision)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		report.QueuedDeliveries = int(n)

		rows, err := tx.Query(`SELECT name FROM paired_systems WHERE status<>'disabled' ORDER BY name`)
		if err != nil {
			return err
		}
		report.Connectors = []string{}
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				rows.Close()
				return err
			}
			report.Connectors = append(report.Connectors, name)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		report.HeldConnectors = len(report.Connectors)
		// Every connector is held, including one that was disabled when the snapshot was
		// taken: its queue survived too, and re-enabling it must not deliver capsule-era
		// work without a reconciliation. Only the connectors an operator must act on now
		// are reported.
		if _, err = tx.Exec(`UPDATE paired_systems SET provisioning_hold=1`); err != nil {
			return err
		}
		// The caller's details say which capsule this came from; the counts join them
		// rather than replacing them.
		if audit != nil {
			details := map[string]any{}
			if audit.DetailsJSON != "" {
				if err := json.Unmarshal([]byte(audit.DetailsJSON), &details); err != nil {
					return err
				}
			}
			details["credentialsInvalidated"] = report.Credentials
			details["queuedDeliveriesClosed"] = report.QueuedDeliveries
			details["logoutsQueued"] = report.LogoutsQueued
			details["connectorsHeld"] = report.Connectors
			body, err := json.Marshal(details)
			if err != nil {
				return err
			}
			audit.DetailsJSON = string(body)
		}
		return nil
	})
	return report, err
}

// releaseProvisioningHoldTx lifts the hold once a repair reconciliation has compared the
// connector with what is really there. A preview proves nothing was repaired and a
// failed run proves nothing at all, so neither releases it.
func releaseProvisioningHoldTx(tx *sql.Tx, systemID string) error {
	_, err := tx.Exec(`UPDATE paired_systems SET provisioning_hold=0 WHERE id=? AND provisioning_hold=1`, systemID)
	return err
}

// ResumeProvisioning lifts a hold without the evidence a reconciliation would give.
// It exists for connectors whose remote cannot be listed at all, where no reconciliation
// can ever produce that evidence; it is an operator's decision to accept what was in the
// capsule, and the audit row is the record of it. It does not revive the queue the
// restore closed out.
func (s *Store) ResumeProvisioning(systemID string, audit *AuditEvent) error {
	return s.auditedTx(audit, func(tx *sql.Tx) error {
		var exists bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM paired_systems WHERE id=?)`, systemID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return sql.ErrNoRows
		}
		return releaseProvisioningHoldTx(tx, systemID)
	})
}

// HeldConnectors names the connectors whose outbound provisioning is waiting on a
// reconciliation.
func (s *Store) HeldConnectors() ([]string, error) {
	rows, err := s.db.Query(`SELECT name FROM paired_systems WHERE provisioning_hold=1 AND status<>'disabled' ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}
