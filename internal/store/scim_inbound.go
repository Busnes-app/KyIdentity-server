package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/google/uuid"
)

// Inbound SCIM: an upstream directory owns some accounts. A connector is the upstream's
// identity here; its Bearer tokens are stored as hashes with a scope and a last-use
// stamp. An owned user is keyed by connector plus the upstream's immutable externalId;
// its profile fields are the upstream's to write, while a local administrator keeps a
// disable override the upstream cannot undo.

var ErrUserConflict = errors.New("username, email or external id already in use")

type SCIMConnector struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Status    string    `json:"status"` // active, disabled
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type SCIMConnectorToken struct {
	ID         string     `json:"id"`
	Scope      string     `json:"scope"` // read, write
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
}

func (s *Store) migrateInboundSCIM() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS scim_connectors (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL CHECK (status IN ('active','disabled')),
 created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL);
 CREATE TABLE IF NOT EXISTS scim_connector_tokens (
 id TEXT PRIMARY KEY, connector_id TEXT NOT NULL REFERENCES scim_connectors(id) ON DELETE CASCADE,
 token_hash TEXT NOT NULL UNIQUE, scope TEXT NOT NULL CHECK (scope IN ('read','write')),
 created_at DATETIME NOT NULL, last_used_at DATETIME, revoked_at DATETIME)`); err != nil {
		return err
	}
	for _, c := range []struct{ probe, ddl string }{
		{`SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='source_connector_id'`, `ALTER TABLE users ADD COLUMN source_connector_id TEXT`},
		{`SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='external_id'`, `ALTER TABLE users ADD COLUMN external_id TEXT`},
		{`SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='source_active'`, `ALTER TABLE users ADD COLUMN source_active BOOLEAN NOT NULL DEFAULT 1`},
		{`SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='locally_disabled'`, `ALTER TABLE users ADD COLUMN locally_disabled BOOLEAN NOT NULL DEFAULT 0`},
	} {
		var n int
		if err := s.db.QueryRow(c.probe).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			if _, err := s.db.Exec(c.ddl); err != nil {
				return err
			}
		}
	}
	_, err := s.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS users_source_external ON users(source_connector_id, external_id) WHERE source_connector_id IS NOT NULL`)
	return err
}

// ApplySourceState derives the effective status of an upstream-owned account: active
// only while the upstream says so, no local override is in force, and a password has
// been set. Local accounts are untouched.
func (u *User) ApplySourceState() {
	if u.SourceConnectorID == "" {
		return
	}
	if u.SourceActive && !u.LocallyDisabled && !u.Pending {
		u.Status = "active"
		return
	}
	u.Status = "disabled"
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// rejectCrossIdentityTx refuses a username or email that any other account already uses
// as either its username or its email: an upstream must not shadow a local identifier.
func rejectCrossIdentityTx(tx *sql.Tx, excludeID, username, email string) error {
	var clash bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM users WHERE id<>? AND (username=? COLLATE NOCASE OR email=? COLLATE NOCASE OR username=? COLLATE NOCASE OR email=? COLLATE NOCASE))`,
		excludeID, username, username, email, email).Scan(&clash); err != nil {
		return err
	}
	if clash {
		return ErrUserConflict
	}
	return nil
}

func (s *Store) CreateSCIMConnector(name string, audit *AuditEvent) (*SCIMConnector, error) {
	now := time.Now().UTC()
	c := &SCIMConnector{ID: uuid.NewString(), Name: strings.TrimSpace(name), Status: "active", CreatedAt: now, UpdatedAt: now}
	if c.Name == "" {
		return nil, errors.New("name is required")
	}
	err := s.auditedTx(audit, func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO scim_connectors (id, name, status, created_at, updated_at) VALUES (?,?,?,?,?)`, c.ID, c.Name, c.Status, now, now)
		return err
	})
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (s *Store) UpdateSCIMConnector(id, name, status string, audit *AuditEvent) error {
	if status != "active" && status != "disabled" {
		return errors.New("status must be active or disabled")
	}
	if name = strings.TrimSpace(name); name == "" {
		return errors.New("name is required")
	}
	return s.auditedTx(audit, func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE scim_connectors SET name=?, status=?, updated_at=? WHERE id=?`, name, status, time.Now().UTC(), id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrNotFound
		}
		return nil
	})
}

func scanConnector(row interface{ Scan(...any) error }) (*SCIMConnector, error) {
	c := &SCIMConnector{}
	err := row.Scan(&c.ID, &c.Name, &c.Status, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return c, err
}

func (s *Store) GetSCIMConnector(id string) (*SCIMConnector, error) {
	return scanConnector(s.db.QueryRow(`SELECT id, name, status, created_at, updated_at FROM scim_connectors WHERE id=?`, id))
}

func (s *Store) ListSCIMConnectors() ([]SCIMConnector, error) {
	rows, err := s.db.Query(`SELECT id, name, status, created_at, updated_at FROM scim_connectors ORDER BY name COLLATE NOCASE, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SCIMConnector{}
	for rows.Next() {
		c, err := scanConnector(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// ListSCIMConnectorTokens returns every token ever issued, revoked ones included, so an
// operator can see what was rotated and when it was last used.
func (s *Store) ListSCIMConnectorTokens(connectorID string) ([]SCIMConnectorToken, error) {
	rows, err := s.db.Query(`SELECT id, scope, created_at, last_used_at, revoked_at FROM scim_connector_tokens WHERE connector_id=? ORDER BY created_at DESC, id`, connectorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SCIMConnectorToken{}
	for rows.Next() {
		var t SCIMConnectorToken
		var used, revoked sql.NullTime
		if err := rows.Scan(&t.ID, &t.Scope, &t.CreatedAt, &used, &revoked); err != nil {
			return nil, err
		}
		if used.Valid {
			at := used.Time
			t.LastUsedAt = &at
		}
		if revoked.Valid {
			at := revoked.Time
			t.RevokedAt = &at
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// CountSCIMConnectorUsers reports how many accounts a connector owns.
func (s *Store) CountSCIMConnectorUsers(connectorID string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE source_connector_id=?`, connectorID).Scan(&n)
	return n, err
}

// IssueSCIMToken mints a Bearer credential for a connector. The raw value is returned
// once; only its hash is stored. Earlier tokens stay valid until revoked, so a rotation
// can overlap the upstream's cut-over.
func (s *Store) IssueSCIMToken(connectorID, scope string, audit *AuditEvent) (string, *SCIMConnectorToken, error) {
	if scope != "read" && scope != "write" {
		return "", nil, errors.New("scope must be read or write")
	}
	raw, err := crypto.GenerateRandomHex(32)
	if err != nil {
		return "", nil, err
	}
	t := &SCIMConnectorToken{ID: uuid.NewString(), Scope: scope, CreatedAt: time.Now().UTC()}
	err = s.auditedTx(audit, func(tx *sql.Tx) error {
		var exists bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM scim_connectors WHERE id=?)`, connectorID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		_, err := tx.Exec(`INSERT INTO scim_connector_tokens (id, connector_id, token_hash, scope, created_at) VALUES (?,?,?,?,?)`, t.ID, connectorID, crypto.HashSHA256(raw), scope, t.CreatedAt)
		return err
	})
	if err != nil {
		return "", nil, err
	}
	return "scim_" + raw, t, nil
}

func (s *Store) RevokeSCIMToken(connectorID, tokenID string, audit *AuditEvent) error {
	return s.auditedTx(audit, func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE scim_connector_tokens SET revoked_at=? WHERE id=? AND connector_id=? AND revoked_at IS NULL`, time.Now().UTC(), tokenID, connectorID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrNotFound
		}
		return nil
	})
}

// AuthenticateSCIMToken resolves a presented Bearer value to its live connector and
// scope, stamping last use at most once a minute. Anything else is ErrNotFound.
func (s *Store) AuthenticateSCIMToken(raw string) (*SCIMConnector, string, error) {
	raw = strings.TrimPrefix(raw, "scim_")
	if raw == "" {
		return nil, "", ErrNotFound
	}
	var id, scope string
	var used sql.NullTime
	c := &SCIMConnector{}
	err := s.db.QueryRow(`SELECT t.id, t.scope, t.last_used_at, c.id, c.name, c.status, c.created_at, c.updated_at
 FROM scim_connector_tokens t JOIN scim_connectors c ON c.id=t.connector_id
 WHERE t.token_hash=? AND t.revoked_at IS NULL AND c.status='active'`, crypto.HashSHA256(raw)).Scan(&id, &scope, &used, &c.ID, &c.Name, &c.Status, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", ErrNotFound
	}
	if err != nil {
		return nil, "", err
	}
	now := time.Now().UTC()
	if !used.Valid || now.Sub(used.Time) > time.Minute {
		if _, err := s.db.Exec(`UPDATE scim_connector_tokens SET last_used_at=? WHERE id=?`, now, id); err != nil {
			return nil, "", err
		}
	}
	return c, scope, nil
}

// CreateUpstreamUser creates an account the connector owns. It is pending until an
// activation link sets a password; the upstream never supplies one. Any clash with an
// existing username, email or (connector, externalId) is ErrUserConflict: an upstream
// account never takes over a local one.
func (s *Store) CreateUpstreamUser(u *User, audit *AuditEvent) error {
	if u.SourceConnectorID == "" || u.ExternalID == "" {
		return errors.New("connector and external id are required")
	}
	u.ID, u.Role, u.Pending, u.PasswordHash, u.LocallyDisabled = uuid.NewString(), "user", true, "", false
	u.ApplySourceState()
	now := time.Now().UTC()
	u.CreatedAt, u.UpdatedAt = now, now
	err := s.auditedTx(audit, func(tx *sql.Tx) error {
		if err := rejectCrossIdentityTx(tx, u.ID, u.Username, u.Email); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO users (id, username, display_name, email, password_hash, role, status, pending, source_connector_id, external_id, source_active, locally_disabled, created_at, updated_at)
 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, u.ID, u.Username, u.DisplayName, u.Email, u.PasswordHash, u.Role, u.Status, u.Pending, u.SourceConnectorID, u.ExternalID, u.SourceActive, u.LocallyDisabled, now, now)
		if isUniqueViolation(err) {
			return ErrUserConflict
		}
		return err
	})
	if err != nil {
		return err
	}
	if audit != nil {
		audit.TargetID = u.ID
	}
	return nil
}

// GetUpstreamUser returns the account only if this connector owns it.
func (s *Store) GetUpstreamUser(connectorID, userID string) (*User, error) {
	return scanUser(s.db.QueryRow(`SELECT `+userColumns+` FROM users WHERE id=? AND source_connector_id=?`, userID, connectorID))
}

// ListUpstreamUsers pages through a connector's accounts, optionally narrowed by one
// exact-match attribute. Unknown attributes are refused before any SQL runs.
func (s *Store) ListUpstreamUsers(connectorID, attribute, value string, startIndex, count int) ([]User, int, error) {
	where := `source_connector_id=?`
	args := []any{connectorID}
	switch attribute {
	case "":
	case "userName":
		where += ` AND username=? COLLATE NOCASE`
		args = append(args, value)
	case "externalId":
		where += ` AND external_id=?`
		args = append(args, value)
	case "emails.value", "emails":
		where += ` AND email=? COLLATE NOCASE`
		args = append(args, value)
	case "id":
		where += ` AND id=?`
		args = append(args, value)
	default:
		return nil, 0, errors.New("unsupported filter attribute")
	}
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if startIndex < 1 {
		startIndex = 1
	}
	if count < 0 {
		count = 0
	}
	if count > 200 {
		count = 200
	}
	rows, err := s.db.Query(`SELECT `+userColumns+` FROM users WHERE `+where+` ORDER BY created_at, id LIMIT ? OFFSET ?`, append(args, count, startIndex-1)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *u)
	}
	return out, total, rows.Err()
}

// UpdateUpstreamUser writes the upstream's view of an owned account: profile fields and
// its active flag. Local decisions (role, override, password, pending) are folded in
// from the row as it is at write time, under the same lock, so a local disable landing
// between the upstream's read and write is never lost. The external id never changes.
func (s *Store) UpdateUpstreamUser(u *User, audit *AuditEvent) error {
	err := s.updateUser(u, false, audit, func(tx *sql.Tx, current *User) error {
		if current.SourceConnectorID == "" || current.SourceConnectorID != u.SourceConnectorID {
			return ErrNotFound
		}
		if current.ExternalID != u.ExternalID {
			return errors.New("external id is immutable")
		}
		if err := rejectCrossIdentityTx(tx, u.ID, u.Username, u.Email); err != nil {
			return err
		}
		u.Role, u.LocallyDisabled, u.PasswordHash, u.Pending = current.Role, current.LocallyDisabled, current.PasswordHash, current.Pending
		u.ApplySourceState()
		return nil
	})
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if isUniqueViolation(err) {
		return ErrUserConflict
	}
	return err
}

// DeleteSCIMConnector removes the connector and its tokens. Its accounts become local:
// kept as they are, or disabled first when the operator chose deactivation. Either way
// the upstream can no longer touch them.
func (s *Store) DeleteSCIMConnector(id string, disableUsers bool, audit *AuditEvent) (int, error) {
	now := time.Now().UTC()
	affected := 0
	err := s.auditedTx(audit, func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT `+userColumns+` FROM users WHERE source_connector_id=?`, id)
		if err != nil {
			return err
		}
		var owned []*User
		for rows.Next() {
			u, err := scanUser(rows)
			if err != nil {
				rows.Close()
				return err
			}
			owned = append(owned, u)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if disableUsers {
			var total, ownedAdmins int
			if err := tx.QueryRow(`SELECT COUNT(*), COALESCE(SUM(source_connector_id=?),0) FROM users WHERE `+activeAdminSQL, id).Scan(&total, &ownedAdmins); err != nil {
				return err
			}
			if ownedAdmins > 0 && ownedAdmins >= total {
				return ErrLastActiveAdmin
			}
		}
		for _, u := range owned {
			if disableUsers && u.Status == "active" {
				if err := offboardUserTx(tx, u, false, now); err != nil {
					return err
				}
			}
			status := u.Status
			if disableUsers {
				status = "disabled"
			}
			if _, err := tx.Exec(`UPDATE users SET source_connector_id=NULL, external_id=NULL, source_active=1, locally_disabled=0, status=?, updated_at=? WHERE id=?`, status, now, u.ID); err != nil {
				return err
			}
		}
		affected = len(owned)
		if _, err := tx.Exec(`UPDATE directory_groups SET source_connector_id=NULL, external_id=NULL, updated_at=? WHERE source_connector_id=?`, now, id); err != nil {
			return err
		}
		res, err := tx.Exec(`DELETE FROM scim_connectors WHERE id=?`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrNotFound
		}
		return reconcileProvisioningTx(tx, now)
	})
	return affected, err
}
