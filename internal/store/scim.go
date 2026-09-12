package store

import (
	"database/sql"
	"errors"
	"time"
)

func (s *Store) migrateSCIM() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS scim_user_links (
 system_id TEXT NOT NULL REFERENCES paired_systems(id) ON DELETE CASCADE,
 local_id TEXT NOT NULL,
 remote_id TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(system_id, local_id),
 CHECK(local_id <> '')
 ); CREATE UNIQUE INDEX IF NOT EXISTS scim_remote_user ON scim_user_links(system_id,remote_id) WHERE remote_id <> '';`)
	return err
}

// A blank remote ID records a create with an uncertain outcome. No user FK: removal
// from the local directory must leave enough state to deactivate the remote account.
// kind separates user and group collections, whose remote IDs may coincide.
func (s *Store) SCIMLink(systemID, kind, localID string) (remoteID string, started bool, err error) {
	err = s.db.QueryRow(`SELECT remote_id FROM scim_user_links WHERE system_id=? AND local_id=? AND kind=?`, systemID, localID, kind).Scan(&remoteID)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	return remoteID, err == nil, err
}

func (s *Store) SCIMUserLink(systemID, localID string) (remoteID string, started bool, err error) {
	return s.SCIMLink(systemID, "user", localID)
}

func (s *Store) StartSCIMCreate(systemID, kind, localID string) (bool, error) {
	r, err := s.db.Exec(`INSERT INTO scim_user_links(system_id,local_id,kind) VALUES(?,?,?) ON CONFLICT(system_id,local_id) DO NOTHING`, systemID, localID, kind)
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n == 1, err
}

func (s *Store) SaveSCIMLink(systemID, kind, localID, remoteID string) error {
	if remoteID == "" || remoteID == "." || remoteID == ".." {
		return errors.New("invalid remote ID")
	}
	r, err := s.db.Exec(`INSERT INTO scim_user_links(system_id,local_id,kind,remote_id) VALUES(?,?,?,?)
 ON CONFLICT(system_id,local_id) DO UPDATE SET remote_id=excluded.remote_id WHERE kind=excluded.kind AND (remote_id='' OR remote_id=excluded.remote_id)`, systemID, localID, kind, remoteID)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err == nil && n != 1 {
		return errors.New("remote mapping changed")
	}
	return err
}

func (s *Store) SaveSCIMUserLink(systemID, localID, remoteID string) error {
	return s.SaveSCIMLink(systemID, "user", localID, remoteID)
}

// ConfigureSystem preserves application identity, the endpoint and existing mappings.
// Enabling group delivery queues the connector's assigned groups in the same transaction.
func (s *Store) ConfigureSystem(id, oldType, newType, encrypted string, groups bool, reconcileHours int, audit *AuditEvent) error {
	if reconcileHours < 0 || reconcileHours > 24*30 {
		return errors.New("reconcile interval must be 0 to 720 hours")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := tx.Exec(`UPDATE paired_systems SET system_type=?,hmac_secret_encrypted=?,groups_enabled=?,reconcile_hours=? WHERE id=? AND system_type=?`, newType, encrypted, groups, reconcileHours, id, oldType)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("system changed; reload and retry")
	}
	if err = reconcileProvisioningTx(tx, time.Now().UTC()); err != nil {
		return err
	}
	if err = recordAuditTx(tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

// Only a definitive create rejection permits another create attempt.
func (s *Store) RejectSCIMCreate(systemID, kind, localID string) error {
	_, err := s.db.Exec(`DELETE FROM scim_user_links WHERE system_id=? AND local_id=? AND kind=? AND remote_id=''`, systemID, localID, kind)
	return err
}

// DeleteSCIMLink forgets a remote mapping after the remote resource is gone.
func (s *Store) DeleteSCIMLink(systemID, kind, localID string) error {
	_, err := s.db.Exec(`DELETE FROM scim_user_links WHERE system_id=? AND local_id=? AND kind=?`, systemID, localID, kind)
	return err
}
