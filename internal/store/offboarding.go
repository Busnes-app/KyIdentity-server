package store

import (
	"database/sql"
	"time"
)

// offboardUserTx is the one way a login stops: it revokes every local credential and
// records an inactive desired state for every connector that holds the account, whether
// through a tracked grant or only through a remote mapping. Disablement and deletion
// both run it, so a later account end date can too. deleted sends user.deleted instead
// of an inactive update.
func offboardUserTx(tx *sql.Tx, u *User, deleted bool, now time.Time) error {
	if err := revokeUserAccessTx(tx, u.ID, now); err != nil {
		return err
	}
	systems, err := scanStrings(tx.Query(`SELECT s.id FROM paired_systems s WHERE s.status<>'disabled'
 AND (EXISTS(SELECT 1 FROM sync_resource_state st WHERE st.system_id=s.id AND st.resource_id=? AND st.kind='user')
   OR EXISTS(SELECT 1 FROM scim_user_links l WHERE l.system_id=s.id AND l.local_id=? AND l.kind='user' AND l.remote_id<>'')) ORDER BY s.id`, u.ID, u.ID))
	if err != nil {
		return err
	}
	payload, err := scimUserPayload(u, false)
	if err != nil {
		return err
	}
	for _, sys := range systems {
		// A remote mapping proves the target holds the account even when no grant was ever
		// tracked, so it is deactivated rather than forgotten as an undelivered ghost.
		if _, err := tx.Exec(`INSERT OR IGNORE INTO sync_resource_state(system_id,resource_id,kind,active,provisioned,revision) VALUES(?,?,'user',1,1,0)`, sys, u.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE sync_resource_state SET provisioned=1 WHERE system_id=? AND resource_id=? AND NOT provisioned
 AND EXISTS(SELECT 1 FROM scim_user_links l WHERE l.system_id=sync_resource_state.system_id AND l.local_id=sync_resource_state.resource_id AND l.kind='user' AND l.remote_id<>'')`, sys, u.ID); err != nil {
			return err
		}
		if err := queueDesiredStateTx(tx, desiredState{systemID: sys, resourceID: u.ID, kind: "user", active: false, payload: payload, deleted: deleted}, now); err != nil {
			return err
		}
	}
	return nil
}

// OffboardingTarget is one connector's progress toward no longer serving the user.
// Recorded means the inactive state was queued, Acknowledged that the connector accepted
// the last delivery, Verified that a later listing saw the account inactive or gone.
type OffboardingTarget struct {
	SystemID     string             `json:"systemId"`
	SystemName   string             `json:"systemName"`
	SystemType   string             `json:"systemType"`
	SystemStatus string             `json:"systemStatus"`
	Revision     int                `json:"revision"`
	Recorded     bool               `json:"recorded"`
	Acknowledged bool               `json:"acknowledged"`
	Observed     string             `json:"observed"`
	ObservedAt   *time.Time         `json:"observedAt,omitempty"`
	Verified     bool               `json:"verified"`
	Blocked      bool               `json:"blocked"`
	LastEvent    *ProvisioningEvent `json:"lastEvent,omitempty"`
}

// Offboarding is the completion view for one user: every connector that holds or held
// the account and every app owed a sign-out. Acknowledged and Verified are true only
// when every target is; a pending or unsupported target keeps them false, and so does
// an account that is still active, because nothing has been removed.
type Offboarding struct {
	UserID       string              `json:"userId"`
	Active       bool                `json:"active"`
	Deleted      bool                `json:"deleted"`
	Targets      []OffboardingTarget `json:"targets"`
	Logouts      []LogoutDelivery    `json:"logouts"`
	Acknowledged bool                `json:"acknowledged"`
	Verified     bool                `json:"verified"`
}

// UserOffboarding reads the completion view. It works after the directory row is gone
// and returns sql.ErrNoRows only when nothing was ever recorded for the ID.
func (s *Store) UserOffboarding(userID string) (*Offboarding, error) {
	off := &Offboarding{UserID: userID, Targets: []OffboardingTarget{}, Acknowledged: true, Verified: true}
	var exists, active bool
	if err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM users WHERE id=?),EXISTS(SELECT 1 FROM users WHERE id=? AND status='active')`, userID, userID).Scan(&exists, &active); err != nil {
		return nil, err
	}
	off.Deleted, off.Active = !exists, active
	off.Acknowledged, off.Verified = !active, !active
	rows, err := s.db.Query(`SELECT s.id,s.name,s.system_type,s.status,st.revision,NOT st.active,st.provisioned,st.observed,st.observed_at,
 EXISTS(SELECT 1 FROM sync_delivery_attempts d WHERE d.system_id=s.id AND d.user_id=st.resource_id),
 ev.event_type,ev.status,ev.last_error,ev.attempts,ev.next_attempt_at,ev.updated_at
 FROM sync_resource_state st JOIN paired_systems s ON s.id=st.system_id
 LEFT JOIN account_sync_events ev ON ev.id=(SELECT id FROM account_sync_events x WHERE x.system_id=st.system_id AND x.user_id=st.resource_id ORDER BY x.rowid DESC LIMIT 1)
 WHERE st.resource_id=? AND st.kind='user' ORDER BY s.name COLLATE NOCASE,s.id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var t OffboardingTarget
		var provisioned bool
		var observedAt, evNext, evUpdated sql.NullTime
		var evType, evStatus, evError sql.NullString
		var evAttempts sql.NullInt64
		if err := rows.Scan(&t.SystemID, &t.SystemName, &t.SystemType, &t.SystemStatus, &t.Revision, &t.Recorded, &provisioned, &t.Observed, &observedAt, &t.Blocked,
			&evType, &evStatus, &evError, &evAttempts, &evNext, &evUpdated); err != nil {
			return nil, err
		}
		if observedAt.Valid {
			at := observedAt.Time
			t.ObservedAt = &at
		}
		if evType.Valid {
			t.LastEvent = &ProvisioningEvent{Type: evType.String, Status: evStatus.String, Error: evError.String, Attempts: int(evAttempts.Int64), UpdatedAt: evUpdated.Time}
			if evNext.Valid {
				at := evNext.Time
				t.LastEvent.NextAttempt = &at
			}
		}
		t.Acknowledged = t.Recorded && t.LastEvent != nil && t.LastEvent.Status == "delivered"
		t.Verified = t.Recorded && (t.Observed == "present_inactive" || t.Observed == "absent") && t.ObservedAt != nil && t.LastEvent != nil && !t.ObservedAt.Before(t.LastEvent.UpdatedAt)
		off.Acknowledged = off.Acknowledged && t.Acknowledged
		off.Verified = off.Verified && t.Verified
		off.Targets = append(off.Targets, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if off.Logouts, err = s.ListLogoutDeliveries(userID, 50); err != nil {
		return nil, err
	}
	for _, d := range off.Logouts {
		off.Acknowledged = off.Acknowledged && d.Status == "delivered"
	}
	off.Verified = off.Verified && off.Acknowledged && !off.Active
	if off.Deleted && len(off.Targets) == 0 && len(off.Logouts) == 0 {
		return nil, sql.ErrNoRows
	}
	return off, nil
}
