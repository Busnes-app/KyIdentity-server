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

var migrations = []migration{}

// legacyRuns counts migrateLegacy calls, so tests can prove a versioned start skips it.
var legacyRuns atomic.Int64

const schemaMigrationsSQL = `CREATE TABLE IF NOT EXISTS schema_migrations (
 version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at DATETIME NOT NULL)`

// migrate brings the database to the version this code knows, then runs the per-start
// reconciliation. New calls it under the migration lease.
func (s *Store) migrate() error {
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
		if err := s.inTx(func(tx *sql.Tx) error {
			if _, err := tx.Exec(pgSchemaV1); err != nil {
				return err
			}
			_, err := tx.Exec(`INSERT INTO schema_migrations(version, name, applied_at) VALUES(1, 'postgres', ?)`, time.Now().UTC())
			return err
		}); err != nil {
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
