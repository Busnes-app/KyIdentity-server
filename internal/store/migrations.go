package store

import (
	"database/sql"
	"fmt"
	"sync/atomic"
	"time"
)

// Schema versions. Version 1 is the schema migrateLegacy produces; it is recorded the
// first time this code starts on a database, fresh or from any earlier release. Every
// later change is one entry in migrations, applied once, in order, in its own
// transaction together with its schema_migrations row. Append only: never edit, reorder
// or remove an entry that has shipped.
type migration struct {
	version int
	name    string
	up      func(tx *sql.Tx) error
	// pgUp, when set, replaces up on Postgres; leave it nil when up's SQL runs on both.
	pgUp func(tx *sql.Tx) error
}

var migrations = []migration{
	{version: 2, name: "forward_auth", up: migrateForwardAuth, pgUp: migrateForwardAuthPostgres},
	{version: 3, name: "hr_provisioning", up: migrateHR, pgUp: migrateHRPostgres},
	{version: 4, name: "suite_groups", up: migrateSuiteGroups, pgUp: migrateSuiteGroupsPostgres},
	{version: 5, name: "pairing_proof_key", up: migratePairingProofKey, pgUp: migratePairingProofKeyPostgres},
	{version: 6, name: "workstation_login", up: migrateWorkstationLogin, pgUp: migrateWorkstationLoginPostgres},
	{version: 7, name: "tenancy", up: migrateTenancy, pgUp: migrateTenancyPostgres},
	{version: 8, name: "active_directory", up: migrateAD, pgUp: migrateADPostgres},
	{version: 9, name: "staff_org", up: migrateStaffOrg, pgUp: migrateStaffOrgPostgres},
	{version: 10, name: "org_id_required", up: migrateOrgIDRequired, pgUp: migrateOrgIDRequiredPostgres},
	{version: 11, name: "workstation_password", up: migrateWorkstationPassword, pgUp: migrateWorkstationPasswordPostgres},
	{version: 12, name: "mailbox_address", up: migrateMailboxAddress, pgUp: migrateMailboxAddressPostgres},
	{version: 13, name: "erasure", up: migrateErasure, pgUp: migrateErasurePostgres},
	{version: 14, name: "export_only", up: migrateExportOnly, pgUp: migrateExportOnlyPostgres},
	{version: 15, name: "org_home_region", up: migrateHomeRegion, pgUp: migrateHomeRegionPostgres},
	{version: 16, name: "customer_kind", up: migrateCustomerKind, pgUp: migrateCustomerKindPostgres},
	{version: 17, name: "org_storage", up: migrateOrgStorage, pgUp: migrateOrgStoragePostgres},
	{version: 18, name: "keyring", up: migrateKeyring, pgUp: migrateKeyringPostgres},
}

// migratePairingProofKey adds the sealed pairing proof key; tokens issued before it have
// none and pair only by the legacy body or PIN. It reruns on an unversioned file that
// already has the column, like every migration.
func migratePairingProofKey(tx *sql.Tx) error {
	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM pragma_table_info('device_pairing_tokens') WHERE name = 'proof_key'`).Scan(&n); err != nil || n == 1 {
		return err
	}
	_, err := tx.Exec(`ALTER TABLE device_pairing_tokens ADD COLUMN proof_key TEXT NOT NULL DEFAULT ''`)
	return err
}

func migratePairingProofKeyPostgres(tx *sql.Tx) error {
	_, err := tx.Exec(`ALTER TABLE device_pairing_tokens ADD COLUMN IF NOT EXISTS proof_key TEXT NOT NULL DEFAULT ''`)
	return err
}

// legacyRuns counts migrateLegacy calls, so tests can prove a versioned start skips it.
var legacyRuns atomic.Int64

const schemaMigrationsSQL = `CREATE TABLE IF NOT EXISTS schema_migrations (
 version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at DATETIME NOT NULL)`

// Created reports whether this open created the database: it had no users table before
// it migrated. Only that first open may record a tenancy mode other than single.
func (s *Store) Created() bool { return s.created }

// migrate brings the database to the version this code knows, then runs the per-start
// reconciliation. New calls it under the migration lease.
func (s *Store) migrate() error {
	exists := `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='users'`
	if s.postgres {
		exists = `SELECT COUNT(*) FROM pg_tables WHERE schemaname=current_schema() AND tablename='users'`
	}
	var n int
	if err := s.db.QueryRow(exists).Scan(&n); err != nil {
		return err
	}
	s.created = n == 0
	ddl := schemaMigrationsSQL
	if s.postgres {
		ddl = pgSchemaMigrationsSQL
	}
	if _, err := s.db.Exec(ddl); err != nil {
		return err
	}
	known := 1
	if len(migrations) > 0 {
		known = migrations[len(migrations)-1].version
	}
	applied := map[int]bool{}
	rows, err := s.db.Query(`SELECT version FROM schema_migrations`)
	if err != nil {
		return err
	}
	top := 0
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		applied[v] = true
		top = max(top, v)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if top > known {
		return fmt.Errorf("database schema is version %d but this binary knows only up to %d: run a release at least as new as the one that last migrated it", top, known)
	}
	if !applied[1] && s.postgres {
		if err := s.inTx(pgSchemaV1Tx); err != nil {
			return fmt.Errorf("creating the Postgres schema: %w", err)
		}
	} else if !applied[1] {
		if err := s.migrateLegacy(); err != nil {
			return err
		}
		if _, err := s.db.Exec(`INSERT INTO schema_migrations(version, name, applied_at) VALUES(1, 'legacy', ?)`, time.Now().UTC()); err != nil {
			return err
		}
	}
	for _, m := range migrations {
		if applied[m.version] {
			continue
		}
		if err := s.applyMigration(m); err != nil {
			return fmt.Errorf("migration %d %s: %w", m.version, m.name, err)
		}
	}
	return s.reconcileOnStart()
}

func pgSchemaV1Tx(tx *sql.Tx) error {
	if _, err := tx.Exec(pgSchemaV1); err != nil {
		return err
	}
	_, err := tx.Exec(`INSERT INTO schema_migrations(version, name, applied_at) VALUES(1, 'postgres', ?)`, time.Now().UTC())
	return err
}

// createPostgresSchemaTx creates the whole current Postgres schema inside tx, for an
// import that must leave nothing behind when it fails.
func createPostgresSchemaTx(tx *sql.Tx) error {
	if _, err := tx.Exec(pgSchemaMigrationsSQL); err != nil {
		return err
	}
	if err := pgSchemaV1Tx(tx); err != nil {
		return err
	}
	for _, m := range migrations {
		up := m.up
		if m.pgUp != nil {
			up = m.pgUp
		}
		if err := up(tx); err != nil {
			return fmt.Errorf("migration %d %s: %w", m.version, m.name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(version, name, applied_at) VALUES(?, ?, ?)`, m.version, m.name, time.Now().UTC()); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) applyMigration(m migration) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	up := m.up
	if s.postgres && m.pgUp != nil {
		up = m.pgUp
	}
	if err := up(tx); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version, name, applied_at) VALUES(?, ?, ?)`, m.version, m.name, time.Now().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

// reconcileOnStart is the data repair every start runs, whatever the schema version. It
// is not a migration: it corrects rows that can go wrong while the server runs, so it
// must keep running after version 1 is recorded.
func (s *Store) reconcileOnStart() error {
	// Events whose connector is gone are dropped; exhausted legacy pending rows fail.
	if err := s.reconcileSyncEvents(); err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Expired interactions, ones whose session is gone, and per-account overages.
	if err := reconcileAuthorizationInteractionsTx(tx); err != nil {
		return err
	}
	// Every OAuth client, launcher card and paired system has an app record.
	if err := backfillAppRegistryTx(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) inTx(fn func(tx *sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}
