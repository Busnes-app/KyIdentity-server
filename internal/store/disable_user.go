package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
)

// ErrGuardAdministrator means the named guard is not another active, permanent
// administrator, so disabling the target could leave KyIdentity without one.
var ErrGuardAdministrator = errors.New("the guard must name another active administrator with no end date")

var errAlreadyDisabled = errors.New("account already disabled")

// DisableUserByName disables one account through the ordinary account update, so its
// sessions, tokens and app access are revoked and connectors receive the inactive state
// in the same transaction as the audit row. It never changes role, password or anything
// but status. Guard must name a different active administrator with no end date, checked
// under the same write lock. It reports false, writing nothing, when the account is
// already disabled. audit's TargetID and DetailsJSON are filled in here.
func (s *Store) DisableUserByName(username, guard string, audit *AuditEvent) (bool, error) {
	if strings.EqualFold(username, guard) {
		return false, ErrGuardAdministrator
	}
	u, err := s.GetUserByUsername(username)
	if err != nil {
		return false, err
	}
	if u == nil {
		return false, ErrNotFound
	}
	_, err = s.updateUser(u.ID, audit, func(tx *sql.Tx, u *User) (bool, error) {
		if !strings.EqualFold(u.Username, username) {
			return false, ErrNotFound // renamed since the lookup
		}
		if u.Status == "disabled" {
			return false, errAlreadyDisabled
		}
		if err := requirePermanentAdminTx(tx, `username=? COLLATE NOCASE AND id<>?`, guard, u.ID); err != nil {
			if errors.Is(err, ErrLastActiveAdmin) {
				return false, ErrGuardAdministrator
			}
			return false, err
		}
		u.Status = "disabled"
		if u.SourceConnectorID != "" {
			// As in the admin UI: a local disable is an override the upstream cannot lift.
			u.LocallyDisabled = true
		}
		if audit != nil {
			details, err := json.Marshal(map[string]any{"username": u.Username, "role": u.Role, "status": "disabled", "accessRevoked": true, "roleChanged": false, "guard": guard, "via": "cli"})
			if err != nil {
				return false, err
			}
			audit.TargetID, audit.DetailsJSON = u.ID, string(details)
		}
		return true, nil
	})
	if errors.Is(err, errAlreadyDisabled) {
		return false, nil
	}
	return err == nil, err
}
