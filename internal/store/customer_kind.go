package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// customerKind is the org of every paid plan (tenancy design, "Plans and orgs" P1); the
// plan itself is orgs.plan and its size max_seats.
const customerKind = "customer"

// customer_kind (schema version 16) renames person and household to customer. Version 7's
// DDL is shipped and stays as it is; version 16 changes the CHECK on both backends.
const (
	oldKindCheck = `CHECK (kind IN ('default','person','household','staff'))`
	newKindCheck = `CHECK (kind IN ('default','` + customerKind + `','staff'))`
)

func erasureHolderTrigger(now string) tenancyTrigger {
	for _, t := range erasureTriggers(now) {
		if t.name == "org_erasures_holder" {
			return t
		}
	}
	panic("store: no org_erasures_holder trigger")
}

func migrateCustomerKind(tx *sql.Tx) error {
	// SQLite cannot change a CHECK, and a rebuild of orgs would trip the foreign keys to it,
	// so the CHECK text is edited in place: SQLite's documented procedure for changing a
	// constraint (lang_altertable.html, "Making Other Kinds Of Table Schema Changes"). Rows
	// move after it, and the integrity check proves every row meets the new CHECK.
	var def string
	if err := tx.QueryRow(`SELECT sql FROM sqlite_schema WHERE type='table' AND name='orgs'`).Scan(&def); err != nil {
		return err
	}
	switch {
	case strings.Contains(def, newKindCheck): // a re-run of the migrations
	case strings.Count(def, oldKindCheck) == 1:
		if err := editSchema(tx, `UPDATE sqlite_schema SET sql=? WHERE type='table' AND name='orgs'`, strings.Replace(def, oldKindCheck, newKindCheck, 1)); err != nil {
			return err
		}
	default:
		return errors.New("store: customer_kind: orgs has neither kind CHECK")
	}
	if _, err := tx.Exec(`UPDATE orgs SET kind='` + customerKind + `' WHERE kind IN ('person','household')`); err != nil {
		return err
	}
	var check string
	if err := tx.QueryRow(`PRAGMA integrity_check(orgs)`).Scan(&check); err != nil || check != "ok" {
		return fmt.Errorf("store: customer_kind: integrity check %q %v", check, err)
	}
	t := erasureHolderTrigger("unixepoch()")
	_, err := tx.Exec(`DROP TRIGGER IF EXISTS org_erasures_holder;
DROP TRIGGER IF EXISTS users_mailbox_insert;
DROP TRIGGER IF EXISTS users_mailbox_update;
` + sqliteTriggerSQL(t, t.refusal) + mailboxTriggersSQLite())
	return err
}

// editSchema runs one write to sqlite_schema with writable_schema on, then bumps
// schema_version so every connection reloads the schema.
func editSchema(tx *sql.Tx, q string, args ...any) error {
	var version int64
	if err := tx.QueryRow(`PRAGMA schema_version`).Scan(&version); err != nil {
		return err
	}
	if _, err := tx.Exec(`PRAGMA writable_schema=ON`); err != nil {
		return err
	}
	res, err := tx.Exec(q, args...)
	if err == nil {
		var n int64
		if n, err = res.RowsAffected(); err == nil && n != 1 {
			err = fmt.Errorf("store: schema edit changed %d rows", n)
		}
	}
	if err == nil {
		_, err = tx.Exec(fmt.Sprintf(`PRAGMA schema_version=%d`, version+1))
	}
	if _, offErr := tx.Exec(`PRAGMA writable_schema=OFF`); err == nil {
		err = offErr
	}
	return err
}

func migrateCustomerKindPostgres(tx *sql.Tx) error {
	t := erasureHolderTrigger(`extract(epoch from now())`)
	var b strings.Builder
	b.WriteString(`ALTER TABLE orgs DROP CONSTRAINT orgs_kind_check;
UPDATE orgs SET kind='` + customerKind + `' WHERE kind IN ('person','household');
ALTER TABLE orgs ADD CONSTRAINT orgs_kind_check ` + newKindCheck + `;
DROP TRIGGER org_erasures_holder ON org_erasures;
DROP FUNCTION org_erasures_holder();
`)
	b.WriteString(pgTriggerSQL(t, t.refusal))
	b.WriteString(mailboxCheckPostgres)
	_, err := tx.Exec(b.String())
	return err
}
