package store

import (
	"encoding/json"
	"strings"
	"unicode"
)

// Launcher audiences. The empty value is unset and shows the card to everyone.
const (
	LauncherEveryone = "everyone"
	LauncherAdmins   = "admins"
)

// ValidLauncherName reports whether name can label a launcher card; empty means unset.
func ValidLauncherName(name string) bool {
	return len(name) <= 128 && name == strings.TrimSpace(name) && !strings.ContainsFunc(name, unicode.IsControl)
}

// ValidLauncherAudience reports whether audience is a stored launcher audience.
func ValidLauncherAudience(audience string) bool {
	return audience == "" || audience == LauncherEveryone || audience == LauncherAdmins
}

// LauncherAdminClients returns the client IDs whose launcher cards treat userID as an
// administrator: the user holds one of the app's administrator roles, or the app has none
// and the user is a KyIdentity administrator. It grants nothing; access is checked apart.
func (s *Store) LauncherAdminClients(userID string) (map[string]bool, error) {
	ids, err := scanStrings(s.db.Query(`SELECT a.client_id FROM app_registry a WHERE a.client_id IS NOT NULL AND (
 EXISTS(SELECT 1 FROM app_roles r WHERE r.app_id=a.id AND r.administrator AND (
  EXISTS(SELECT 1 FROM app_role_user_assignments x WHERE x.role_id=r.id AND x.user_id=?)
  OR EXISTS(SELECT 1 FROM app_role_group_assignments g JOIN live_group_memberships m ON m.group_id=g.group_id WHERE g.role_id=r.id AND m.user_id=?)))
 OR (NOT EXISTS(SELECT 1 FROM app_roles r WHERE r.app_id=a.id AND r.administrator)
  AND EXISTS(SELECT 1 FROM users u WHERE u.id=? AND u.role='admin')))`, userID, userID, userID))
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out, nil
}

// SetInstallerLauncherName gives a client setupID owns a launcher name while it has none.
func (s *Store) SetInstallerLauncherName(setupID, clientID, name string, audit *AuditEvent) (bool, error) {
	return s.setInstallerLauncher(setupID, clientID, "launcher_name", name, "", audit)
}

// SetInstallerLauncherAudience gives a client setupID owns a launcher audience while it
// has none. adminRole, the bundle's administrator role for the client, is marked as such
// so "admins" means that role's holders.
func (s *Store) SetInstallerLauncherAudience(setupID, clientID, audience, adminRole string, audit *AuditEvent) (bool, error) {
	return s.setInstallerLauncher(setupID, clientID, "launcher_audience", audience, adminRole, audit)
}

// setInstallerLauncher writes column only while it is empty, so an admin's choice stays.
// ErrNotFound means the setup does not own the client.
func (s *Store) setInstallerLauncher(setupID, clientID, column, value, adminRole string, audit *AuditEvent) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var owned bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM installer_setup_resources r JOIN oauth_clients c ON c.id=r.object_id WHERE r.kind='client' AND r.name=? AND r.setup_id=?)`, clientID, setupID).Scan(&owned); err != nil {
		return false, err
	}
	if !owned {
		return false, ErrNotFound
	}
	// column is one of two literals above, never input.
	res, err := tx.Exec(`UPDATE oauth_clients SET `+column+`=? WHERE id=? AND `+column+`=''`, value, clientID)
	if err != nil {
		return false, err
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return false, err
	}
	fields := map[string]string{column: value, "setupId": setupID, "via": "cli"}
	if adminRole != "" {
		if _, err := tx.Exec(`UPDATE app_roles SET administrator=1 WHERE lower(name)=lower(?) AND app_id IN (SELECT id FROM app_registry WHERE client_id=?)`, adminRole, clientID); err != nil {
			return false, err
		}
		fields["administratorRole"] = adminRole
	}
	details, err := json.Marshal(fields)
	if err != nil {
		return false, err
	}
	audit.TargetID, audit.DetailsJSON = clientID, string(details)
	if err := recordAuditTx(tx, audit); err != nil {
		return false, err
	}
	return true, tx.Commit()
}
