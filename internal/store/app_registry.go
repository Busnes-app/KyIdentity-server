package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var ErrAppLinkConflict = errors.New("application links changed or conflict")
var ErrAppRecordMissing = errors.New("application record not found")

type AppRecord struct {
	Authentication         AppAuthenticationPolicy `json:"authentication"`
	AuthenticationRevision int                     `json:"authenticationRevision"`
	// RoleRevision changes with every role, mapping or claim-setting edit; a code carries
	// the revision it was issued under and cannot be exchanged after a change.
	RoleRevision int `json:"roleRevision"`
	// LegacyRoleClaim keeps the global directory role in this app's tokens for clients
	// built before app roles existed; GroupsClaim adds the names of assigned groups.
	LegacyRoleClaim bool   `json:"legacyRoleClaim"`
	GroupsClaim     bool   `json:"groupsClaim"`
	AccessMode      string `json:"accessMode"`
	Enabled         bool   `json:"enabled"`
	ID              string `json:"id"`
	Revision        int    `json:"revision"`
	ClientID        string `json:"clientId"`
	ClientName      string `json:"clientName"`
	LauncherID      string `json:"launcherId"`
	LauncherName    string `json:"launcherName"`
	SystemID        string `json:"systemId"`
	SystemName      string `json:"systemName"`
}

// Source rows remain authoritative for connection settings. Triggers cover every
// creation path (including pairing), and never infer linkage from names or URLs.
func (s *Store) migrateAppRegistry() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS app_registry (
 id TEXT PRIMARY KEY,
 revision INTEGER NOT NULL DEFAULT 1,
 client_id TEXT UNIQUE REFERENCES oauth_clients(id) ON DELETE SET NULL,
 launcher_id TEXT UNIQUE REFERENCES applications(id) ON DELETE SET NULL,
 system_id TEXT UNIQUE REFERENCES paired_systems(id) ON DELETE SET NULL
 )`); err != nil {
		return err
	}
	for _, source := range []struct{ table, column string }{{"oauth_clients", "client_id"}, {"applications", "launcher_id"}, {"paired_systems", "system_id"}} {
		// Identifiers below are constants, never request data.
		ddl := fmt.Sprintf(`
 INSERT INTO app_registry(id,%[2]s) SELECT lower(hex(randomblob(16))),s.id FROM %[1]s s
 WHERE NOT EXISTS(SELECT 1 FROM app_registry a WHERE a.%[2]s=s.id);
 CREATE TRIGGER IF NOT EXISTS registry_insert_%[1]s AFTER INSERT ON %[1]s BEGIN
 INSERT INTO app_registry(id,%[2]s) VALUES(lower(hex(randomblob(16))),NEW.id); END;
 CREATE TRIGGER IF NOT EXISTS registry_delete_%[1]s BEFORE DELETE ON %[1]s BEGIN
 UPDATE app_registry SET revision=revision+1 WHERE %[2]s=OLD.id; END;
 CREATE TRIGGER IF NOT EXISTS registry_cleanup_%[1]s AFTER DELETE ON %[1]s BEGIN
 DELETE FROM app_registry WHERE client_id IS NULL AND launcher_id IS NULL AND system_id IS NULL; END;`, source.table, source.column)
		if _, err = tx.Exec(ddl); err != nil {
			return err
		}
	}
	return tx.Commit()
}

const appRecordFrom = ` FROM app_registry a
 LEFT JOIN oauth_clients c ON c.id=a.client_id
 LEFT JOIN applications l ON l.id=a.launcher_id
 LEFT JOIN paired_systems s ON s.id=a.system_id`
const appRecordSelect = `SELECT a.id,a.revision,COALESCE(a.client_id,''),COALESCE(c.client_name,''),COALESCE(a.launcher_id,''),COALESCE(l.name,''),COALESCE(a.system_id,''),COALESCE(s.name,''),a.access_mode,a.enabled,a.auth_mode,a.auth_primary_max_age,a.auth_factor,a.auth_factor_max_age,a.auth_revision,a.role_revision,a.legacy_role_claim,a.groups_claim`

func scanAppRecord(row interface{ Scan(...any) error }) (AppRecord, error) {
	var a AppRecord
	err := row.Scan(&a.ID, &a.Revision, &a.ClientID, &a.ClientName, &a.LauncherID, &a.LauncherName, &a.SystemID, &a.SystemName, &a.AccessMode, &a.Enabled, &a.Authentication.Mode, &a.Authentication.PrimaryMaxAge, &a.Authentication.Factor, &a.Authentication.FactorMaxAge, &a.AuthenticationRevision, &a.RoleRevision, &a.LegacyRoleClaim, &a.GroupsClaim)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrAppRecordMissing
	}
	return a, err
}
func (s *Store) ListAppRecords(query string, limit, offset int) ([]AppRecord, int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	where := ` WHERE instr(lower(COALESCE(c.client_name,'') || ' ' || COALESCE(l.name,'') || ' ' || COALESCE(s.name,'') || ' ' || a.id || ' ' || COALESCE(a.client_id,'') || ' ' || COALESCE(a.launcher_id,'') || ' ' || COALESCE(a.system_id,'')),lower(?))>0`
	var total int
	if err = tx.QueryRow(`SELECT COUNT(*)`+appRecordFrom+where, query).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := tx.Query(appRecordSelect+appRecordFrom+where+` ORDER BY lower(COALESCE(l.name,c.client_name,s.name)),a.id LIMIT ? OFFSET ?`, query, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	items := []AppRecord{}
	for rows.Next() {
		a, e := scanAppRecord(rows)
		if e != nil {
			rows.Close()
			return nil, 0, e
		}
		items = append(items, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, 0, err
	}
	return items, total, tx.Commit()
}

// A no-op write obtains SQLite's writer lock before reading either revision.
func lockAppRecord(tx *sql.Tx, id string, revision int) (AppRecord, error) {
	if _, err := tx.Exec(`UPDATE app_registry SET revision=revision WHERE id=?`, id); err != nil {
		return AppRecord{}, err
	}
	a, err := scanAppRecord(tx.QueryRow(appRecordSelect+appRecordFrom+` WHERE a.id=?`, id))
	if err == nil && a.Revision != revision {
		err = ErrAppLinkConflict
	}
	return a, err
}
func appRegistryAudit(audit *AuditEvent, details any) error {
	if audit == nil {
		return nil
	}
	b, err := json.Marshal(details)
	if err != nil {
		return err
	}
	audit.DetailsJSON = string(b)
	return nil
}

// LinkAppRecords retains target's stable registry ID and moves source's connection
// references only. Existing source IDs, credentials, URLs, tokens and sync jobs stay intact.
func (s *Store) LinkAppRecords(targetID, sourceID string, targetRevision, sourceRevision int, audit *AuditEvent) error {
	if targetID == sourceID {
		return ErrAppLinkConflict
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	target, err := lockAppRecord(tx, targetID, targetRevision)
	if err != nil {
		return err
	}
	source, err := lockAppRecord(tx, sourceID, sourceRevision)
	if err != nil {
		return err
	}
	if err = ensureAppLinkPoliciesTx(tx, target, source); err != nil {
		return err
	}
	if (target.ClientID != "" && source.ClientID != "") || (target.LauncherID != "" && source.LauncherID != "") || (target.SystemID != "" && source.SystemID != "") {
		return ErrAppLinkConflict
	}
	if _, err = tx.Exec(`DELETE FROM app_registry WHERE id=?`, sourceID); err != nil {
		return err
	}
	pick := func(a, b string) any {
		if a != "" {
			return a
		}
		if b != "" {
			return b
		}
		return nil
	}
	if _, err = tx.Exec(`UPDATE app_registry SET client_id=?,launcher_id=?,system_id=?,revision=revision+1 WHERE id=?`, pick(target.ClientID, source.ClientID), pick(target.LauncherID, source.LauncherID), pick(target.SystemID, source.SystemID), targetID); err != nil {
		return err
	}
	if err = reconcileProvisioningTx(tx, time.Now().UTC()); err != nil {
		return err
	}
	if err = appRegistryAudit(audit, map[string]any{"target": target, "source": source}); err != nil {
		return err
	}
	if err = recordAuditTx(tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

// Unlink creates a separate identity for one connection, making an accidental link
// reversible. The old record retains its ID and at least one connection.
func (s *Store) UnlinkAppRecord(id, kind string, revision int, audit *AuditEvent) (string, error) {
	column := ""
	switch kind {
	case "client":
		column = "client_id"
	case "launcher":
		column = "launcher_id"
	case "system":
		column = "system_id"
	default:
		return "", ErrAppLinkConflict
	}
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	a, err := lockAppRecord(tx, id, revision)
	if err != nil {
		return "", err
	}
	refs := map[string]string{"client": a.ClientID, "launcher": a.LauncherID, "system": a.SystemID}
	count := 0
	for _, v := range refs {
		if v != "" {
			count++
		}
	}
	if count < 2 || refs[kind] == "" {
		return "", ErrAppLinkConflict
	}
	newID := uuid.NewString()
	if _, err = tx.Exec(`UPDATE app_registry SET `+column+`=NULL,revision=revision+1 WHERE id=?`, id); err != nil {
		return "", err
	}
	if _, err = tx.Exec(`INSERT INTO app_registry(id,`+column+`) VALUES(?,?)`, newID, refs[kind]); err != nil {
		return "", err
	}
	var roles int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM app_roles WHERE app_id=?`, id).Scan(&roles); err != nil {
		return "", err
	}
	if roles > 0 {
		return "", fmt.Errorf("%w: remove app roles before unlinking", ErrAppLinkConflict)
	}
	if _, err = tx.Exec(`UPDATE app_registry SET access_mode=?,enabled=?,auth_mode=?,auth_primary_max_age=?,auth_factor=?,auth_factor_max_age=?,auth_revision=?,legacy_role_claim=?,groups_claim=? WHERE id=?`, a.AccessMode, a.Enabled, a.Authentication.Mode, a.Authentication.PrimaryMaxAge, a.Authentication.Factor, a.Authentication.FactorMaxAge, a.AuthenticationRevision, a.LegacyRoleClaim, a.GroupsClaim, newID); err != nil {
		return "", err
	}
	for _, spec := range []struct{ table, column string }{{"app_user_assignments", "user_id"}, {"app_group_assignments", "group_id"}} {
		if _, err = tx.Exec(`INSERT INTO `+spec.table+`(app_id,`+spec.column+`) SELECT ?,`+spec.column+` FROM `+spec.table+` WHERE app_id=?`, newID, id); err != nil {
			return "", err
		}
	}
	if err = reconcileProvisioningTx(tx, time.Now().UTC()); err != nil {
		return "", err
	}
	if err = appRegistryAudit(audit, map[string]any{"previous": a, "connection": kind, "newAppId": newID}); err != nil {
		return "", err
	}
	if err = recordAuditTx(tx, audit); err != nil {
		return "", err
	}
	return newID, tx.Commit()
}
