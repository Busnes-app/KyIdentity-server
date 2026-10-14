package store

import (
	"database/sql"
	"time"
)

// CreateAccountSyncEvent writes a bare outbox row, for delivery tests that need work the
// mutation paths would only queue after configuring scope.
func (s *Store) CreateAccountSyncEvent(event *AccountSyncEvent) error {
	now := time.Now().UTC()
	event.CreatedAt, event.UpdatedAt = now, now
	_, err := s.db.Exec(`INSERT INTO account_sync_events (id, user_id, system_id, event_type, payload_json, attempts, status, created_at, updated_at, revision) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.ID, event.UserID, event.SystemID, event.EventType, event.PayloadJSON, event.Attempts, event.Status, event.CreatedAt, event.UpdatedAt, event.Revision)
	return err
}

// UpdateUserWithSyncEvents writes every local field of u (profile unless source-owned,
// password, pending, role, status, override, end date) through updateUser, the transaction
// EditUser uses, and copies the stored row back into u.
func (s *Store) UpdateUserWithSyncEvents(u *User, revokeAccess bool, audit *AuditEvent) error {
	stored, err := s.updateUser(u.ID, audit, func(_ *sql.Tx, next *User) (bool, error) {
		if next.SourceConnectorID == "" {
			next.Username, next.DisplayName, next.Email = u.Username, u.DisplayName, u.Email
		}
		next.PasswordHash, next.Pending, next.Role, next.Status, next.LocallyDisabled, next.EndsAt = u.PasswordHash, u.Pending, u.Role, u.Status, u.LocallyDisabled, u.EndsAt
		return revokeAccess, nil
	})
	if err == nil {
		*u = *stored
	}
	return err
}
