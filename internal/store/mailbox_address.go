package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Mailbox address (tenancy design, "Mailbox address"): a hosted member's mailbox, separate
// from the sign-in email, on a suite mail domain, unique across the install and against
// every other account's sign-in email. Multi-tenant only: the triggers refuse it outside a
// customer org, so a single-tenant install never holds one.

// MailboxEmailType is the SCIM emails[].type that carries it in signed suite webhooks.
const MailboxEmailType = "mailbox"

const msgMailboxCustomerOnly = "mailbox addresses belong to customer accounts only"

var (
	ErrMailboxAddressSet   = errors.New("the account already has another mailbox address")
	ErrMailboxAddressTaken = errors.New("mailbox address already in use")
	ErrMailboxCustomerOnly = errors.New(msgMailboxCustomerOnly)
	ErrMailboxDomain       = errors.New("the mailbox address must be on a suite mail domain")
)

// DomainInUseError refuses removing a suite mail domain that mailbox addresses use.
type DomainInUseError struct {
	Domain string
	Count  int
}

func (e *DomainInUseError) Error() string {
	return fmt.Sprintf("%d mailbox addresses use %s; move them to another domain first", e.Count, e.Domain)
}

// The mailbox check: lowercase, a customer org, and no clash with another account's
// sign-in email either way. The clash is a unique violation, so every user-creating
// path already answers it as a conflict.
const mailboxCustomerSQL = `NEW.mailbox_address IS NOT NULL AND (NEW.mailbox_address<>lower(NEW.mailbox_address) OR NOT EXISTS(SELECT 1 FROM orgs o WHERE o.id=NEW.org_id AND o.kind IN ('person','household')))`

func migrateMailboxAddress(tx *sql.Tx) error {
	clash := `EXISTS(SELECT 1 FROM users u WHERE u.id<>NEW.id AND (u.mailbox_address=lower(NEW.email) OR u.email=NEW.mailbox_address))`
	body := fmt.Sprintf(`BEGIN SELECT RAISE(ABORT,'%s') WHERE %s; SELECT RAISE(ABORT,'UNIQUE constraint failed: users.mailbox_address') WHERE %s; END;`, msgMailboxCustomerOnly, mailboxCustomerSQL, clash)
	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM pragma_table_info('users') WHERE name='mailbox_address'`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := tx.Exec(`ALTER TABLE users ADD COLUMN mailbox_address TEXT`); err != nil {
			return err
		}
	}
	_, err := tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS users_mailbox_address ON users(mailbox_address) WHERE mailbox_address IS NOT NULL;
CREATE TRIGGER IF NOT EXISTS users_mailbox_insert BEFORE INSERT ON users FOR EACH ROW ` + body + `
CREATE TRIGGER IF NOT EXISTS users_mailbox_update BEFORE UPDATE OF email, mailbox_address ON users FOR EACH ROW ` + body)
	return err
}

func migrateMailboxAddressPostgres(tx *sql.Tx) error {
	_, err := tx.Exec(`ALTER TABLE users ADD COLUMN IF NOT EXISTS mailbox_address TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS users_mailbox_address ON users(mailbox_address) WHERE mailbox_address IS NOT NULL;
CREATE FUNCTION users_mailbox_check() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF (` + mailboxCustomerSQL + `) THEN RAISE EXCEPTION '` + msgMailboxCustomerOnly + `'; END IF;
 IF EXISTS(SELECT 1 FROM users u WHERE u.id<>NEW.id AND (u.mailbox_address=lower(NEW.email::text) OR u.email=NEW.mailbox_address::citext)) THEN
  RAISE EXCEPTION 'UNIQUE constraint failed: users.mailbox_address' USING ERRCODE = 'unique_violation'; END IF;
 RETURN NEW; END $$;
CREATE TRIGGER users_mailbox_insert BEFORE INSERT ON users FOR EACH ROW EXECUTE FUNCTION users_mailbox_check();
CREATE TRIGGER users_mailbox_update BEFORE UPDATE OF email, mailbox_address ON users FOR EACH ROW EXECUTE FUNCTION users_mailbox_check();`)
	return err
}

// NormalizeMailboxAddress returns the stored form, local@punycode-domain in lowercase, or
// an InputError. The local part is ASCII letters, digits, '.', '-' and '_' (no '+': KyPost
// reads it as plus addressing), at most 64 bytes, with no leading, trailing or double dot.
func NormalizeMailboxAddress(raw string) (string, error) {
	bad := InputError("A mailbox address is name@domain, the name in letters, digits, '.', '-' and '_'")
	a := strings.TrimSpace(raw)
	at := strings.LastIndexByte(a, '@')
	if at <= 0 || len(a) > 512 {
		return "", bad
	}
	local := strings.ToLower(a[:at])
	if len(local) > 64 || local[0] == '.' || local[len(local)-1] == '.' || strings.Contains(local, "..") ||
		strings.Trim(local, "abcdefghijklmnopqrstuvwxyz0123456789.-_") != "" {
		return "", bad
	}
	domain, err := NormalizeEmailDomain(a[at+1:])
	if err != nil || len(local)+1+len(domain) > 254 {
		return "", bad
	}
	return local + "@" + domain, nil
}

func mailboxDomain(addr string) string { return addr[strings.LastIndexByte(addr, '@')+1:] }

// SetMailboxAddress sets a user's mailbox address and queues user.updated to the apps that
// hold the account. Without overwrite it is write-once: the same value again changes
// nothing, another is ErrMailboxAddressSet (the platform API's member adds). Staff pass
// overwrite. It reports whether the value changed; an unchanged call writes no audit row.
// The audit details name the old and new domains only.
func (o *OrgStore) SetMailboxAddress(userID, raw string, overwrite bool, audit *AuditEvent) (*User, bool, error) {
	addr, err := NormalizeMailboxAddress(raw)
	if err != nil {
		return nil, false, err
	}
	tx, err := o.s.db.Begin()
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	u, changed, err := setMailboxAddressTx(tx, o.org, userID, addr, overwrite, audit)
	if err != nil || !changed {
		return u, false, err
	}
	return u, true, tx.Commit()
}

// setMailboxAddressTx is SetMailboxAddress inside the caller's transaction, addr normalised.
func setMailboxAddressTx(tx *sql.Tx, org, userID, addr string, overwrite bool, audit *AuditEvent) (*User, bool, error) {
	// Read under the writer lock, so a domain removal cannot race this write.
	domains, err := suiteEmailDomains(settingsTx{tx})
	if err != nil {
		return nil, false, err
	}
	if !slices.Contains(domains, mailboxDomain(addr)) {
		return nil, false, ErrMailboxDomain
	}
	u, err := scanUser(tx.QueryRow(`SELECT `+userColumns+` FROM users WHERE org_id=? AND id=?`, org, userID))
	if err != nil {
		return nil, false, err
	}
	if u == nil {
		return nil, false, ErrNotFound
	}
	old := u.MailboxAddress
	if old == addr {
		return u, false, nil
	}
	if old != "" && !overwrite {
		return nil, false, ErrMailboxAddressSet
	}
	now := rowTime()
	if _, err := tx.Exec(`UPDATE users SET mailbox_address=?, updated_at=? WHERE org_id=? AND id=?`, addr, now, org, userID); err != nil {
		switch {
		case strings.Contains(err.Error(), msgMailboxCustomerOnly):
			return nil, false, ErrMailboxCustomerOnly
		case isUniqueViolation(err):
			return nil, false, ErrMailboxAddressTaken
		}
		return nil, false, err
	}
	u.MailboxAddress, u.UpdatedAt = addr, now
	if err := queueUserUpdateTx(tx, u, now); err != nil {
		return nil, false, err
	}
	if audit != nil {
		oldDomain := ""
		if old != "" {
			oldDomain = mailboxDomain(old)
		}
		b, _ := json.Marshal(map[string]string{"oldDomain": oldDomain, "domain": mailboxDomain(addr)})
		audit.DetailsJSON = string(b)
	}
	if err := recordAuditTx(tx, audit); err != nil {
		return nil, false, err
	}
	return u, true, nil
}

// refuseRemovingUsedDomainsTx is the safe rule for shrinking the suite domain list: a
// domain that a mailbox address uses stays until staff move those addresses.
func refuseRemovingUsedDomainsTx(tx *sql.Tx, old, next []string) error {
	for _, d := range old {
		if slices.Contains(next, d) {
			continue
		}
		var n int
		// Stored domains are LDH names (NormalizeEmailDomain), so they hold no LIKE wildcard.
		if err := tx.QueryRow(`SELECT count(*) FROM users WHERE mailbox_address LIKE ?`, "%@"+d).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return &DomainInUseError{Domain: d, Count: n}
		}
	}
	return nil
}

// MailboxEligible reports whether the org's accounts may hold a mailbox address: a
// customer org. Staff and the single-tenant default org may not.
func (o *OrgStore) MailboxEligible() (bool, error) {
	var ok bool
	err := o.s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM orgs WHERE id=? AND kind=?)`, o.org, customerKind).Scan(&ok)
	return ok, err
}
