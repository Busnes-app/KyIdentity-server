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

// restoredCleared is every table whose rows are a credential or a queued task that
// cannot survive a restore. Long-lived credentials the user holds (passwords, enrolled
// factors, recovery codes) are deliberately absent: they are what the operator still
// has to work with, and the runbook covers rotating them.
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
	"logout_deliveries",
	"sync_delivery_attempts",
}

// RestoreReport is what one restore invalidated, for the log and the audit trail.
type RestoreReport struct {
	// Credentials counts the rows cleared across restoredCleared.
	Credentials int
	// QueuedDeliveries counts outbox rows closed out rather than delivered.
	QueuedDeliveries int
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
		// The outbox is closed out rather than deleted: an operator reading it after a
		// restore should see why nothing was sent, and reconciliation re-derives the work.
		res, err := tx.Exec(`UPDATE account_sync_events SET status='failed', last_error=?, updated_at=?, lease_until=NULL, claim_token='' WHERE status='pending'`,
			"superseded by a restore; reconcile the connector to re-derive the work", now)
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
		if _, err = tx.Exec(`UPDATE paired_systems SET provisioning_hold=1 WHERE status<>'disabled'`); err != nil {
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
