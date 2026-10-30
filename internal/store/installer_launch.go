package store

import "encoding/json"

// SetInstallerLaunchURL gives a client that setupID owns a launcher link while it has none,
// so a link an admin set stays. It reports whether it wrote one; ErrNotFound means the setup
// does not own the client.
func (s *Store) SetInstallerLaunchURL(setupID, clientID, launchURL string, audit *AuditEvent) (bool, error) {
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
	res, err := tx.Exec(`UPDATE oauth_clients SET launch_url=? WHERE id=? AND COALESCE(launch_url,'')=''`, launchURL, clientID)
	if err != nil {
		return false, err
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return false, err
	}
	details, err := json.Marshal(map[string]string{"launchUrl": launchURL, "setupId": setupID, "via": "cli"})
	if err != nil {
		return false, err
	}
	audit.TargetID, audit.DetailsJSON = clientID, string(details)
	if err := recordAuditTx(tx, audit); err != nil {
		return false, err
	}
	return true, tx.Commit()
}
