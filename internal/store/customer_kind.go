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

// Versions 12 and 13 shipped with person and household; version 16 replaces their
// org_erasures_holder trigger and mailbox check with these.
const (
	msgErasureAskCustomer  = "only the holder of an active customer org asks, immediate exactly when no other member is live"
	mailboxCustomerKindSQL = `NEW.mailbox_address IS NOT NULL AND (NEW.mailbox_address<>lower(NEW.mailbox_address) OR NOT EXISTS(SELECT 1 FROM orgs o WHERE o.id=NEW.org_id AND o.kind='` + customerKind + `'))`
)

func customerHolderTrigger() tenancyTrigger {
	return tenancyTrigger{"org_erasures_holder", "BEFORE INSERT", "org_erasures", `NOT EXISTS(SELECT 1 FROM orgs o WHERE o.id=NEW.org_id AND o.account_holder_user_id=NEW.holder_user_id AND o.status='active' AND o.kind='` + customerKind + `')
 OR (NEW.immediate) <> (NOT ` + otherLiveSQL("NEW.org_id", "NEW.holder_user_id") + `)`, msgErasureAskCustomer}
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
	t := customerHolderTrigger()
	clash := `EXISTS(SELECT 1 FROM users u WHERE u.id<>NEW.id AND (u.mailbox_address=lower(NEW.email) OR u.email=NEW.mailbox_address))`
	body := fmt.Sprintf(`BEGIN SELECT RAISE(ABORT,'%s') WHERE %s; SELECT RAISE(ABORT,'UNIQUE constraint failed: users.mailbox_address') WHERE %s; END;`, msgMailboxCustomerOnly, mailboxCustomerKindSQL, clash)
	_, err := tx.Exec(`DROP TRIGGER IF EXISTS org_erasures_holder;
DROP TRIGGER IF EXISTS users_mailbox_insert;
DROP TRIGGER IF EXISTS users_mailbox_update;
` + sqliteTriggerSQL(t, t.refusal) + `CREATE TRIGGER users_mailbox_insert BEFORE INSERT ON users FOR EACH ROW ` + body + `
CREATE TRIGGER users_mailbox_update BEFORE UPDATE OF email, mailbox_address ON users FOR EACH ROW ` + body)
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
	t := customerHolderTrigger()
	var b strings.Builder
	b.WriteString(`ALTER TABLE orgs DROP CONSTRAINT orgs_kind_check;
UPDATE orgs SET kind='` + customerKind + `' WHERE kind IN ('person','household');
ALTER TABLE orgs ADD CONSTRAINT orgs_kind_check ` + newKindCheck + `;
DROP TRIGGER org_erasures_holder ON org_erasures;
DROP FUNCTION org_erasures_holder();
`)
	b.WriteString(pgTriggerSQL(t, t.refusal))
	b.WriteString(`CREATE OR REPLACE FUNCTION users_mailbox_check() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF (` + mailboxCustomerKindSQL + `) THEN RAISE EXCEPTION '` + msgMailboxCustomerOnly + `'; END IF;
 IF EXISTS(SELECT 1 FROM users u WHERE u.id<>NEW.id AND (u.mailbox_address=lower(NEW.email::text) OR u.email=NEW.mailbox_address::citext)) THEN
  RAISE EXCEPTION 'UNIQUE constraint failed: users.mailbox_address' USING ERRCODE = 'unique_violation'; END IF;
 RETURN NEW; END $$;
`)
	_, err := tx.Exec(b.String())
	return err
}
