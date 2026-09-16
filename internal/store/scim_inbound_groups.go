package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Inbound SCIM Groups map onto the flat directory groups. An upstream-owned group carries
// the connector and an optional immutable externalId; the upstream owns its name and its
// member set, and every member must be an account the same connector owns. Nothing here
// ever creates or deletes a user.

var (
	ErrGroupMemberForeign  = errors.New("member is not an account of this connector")
	ErrGroupExternalExists = errors.New("external id already in use for this connector")
	ErrGroupVersionStale   = errors.New("group changed since it was read")
)

// UpstreamGroup is a group as the upstream sees it: the row plus its member ids.
type UpstreamGroup struct {
	Group
	Members []string
}

func (s *Store) migrateInboundSCIMGroups() error {
	for _, c := range []struct{ probe, ddl string }{
		{`SELECT COUNT(*) FROM pragma_table_info('directory_groups') WHERE name='source_connector_id'`, `ALTER TABLE directory_groups ADD COLUMN source_connector_id TEXT`},
		{`SELECT COUNT(*) FROM pragma_table_info('directory_groups') WHERE name='external_id'`, `ALTER TABLE directory_groups ADD COLUMN external_id TEXT`},
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
	_, err := s.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS groups_source_external ON directory_groups(source_connector_id, external_id) WHERE source_connector_id IS NOT NULL AND external_id IS NOT NULL AND external_id<>''`)
	return err
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// membersOwnedTx checks that every id is an account this connector owns. A group id, a
// local account or another connector's account all fail the same way.
func membersOwnedTx(tx *sql.Tx, connectorID string, members []string) error {
	for _, id := range members {
		var owned bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM users WHERE id=? AND source_connector_id=?)`, id, connectorID).Scan(&owned); err != nil {
			return err
		}
		if !owned {
			return ErrGroupMemberForeign
		}
	}
	return nil
}

func externalGroupFreeTx(tx *sql.Tx, connectorID, external, excludeID string) error {
	if external == "" {
		return nil
	}
	var taken bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM directory_groups WHERE source_connector_id=? AND external_id=? AND id<>?)`, connectorID, external, excludeID).Scan(&taken); err != nil {
		return err
	}
	if taken {
		return ErrGroupExternalExists
	}
	return nil
}

func groupMembersTx(tx *sql.Tx, groupID string) ([]string, error) {
	rows, err := tx.Query(`SELECT user_id FROM group_memberships WHERE group_id=? ORDER BY user_id`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// CreateUpstreamGroup creates a connector-owned group with its initial members in one
// transaction; any foreign member fails the whole create.
func (s *Store) CreateUpstreamGroup(g *Group, members []string, audit *AuditEvent) error {
	if g.SourceConnectorID == "" {
		return errors.New("connector is required")
	}
	members = uniqueStrings(members)
	g.ID = uuid.NewString()
	now := time.Now().UTC()
	g.CreatedAt, g.UpdatedAt = now, now
	return s.auditedTx(audit, func(tx *sql.Tx) error {
		if err := externalGroupFreeTx(tx, g.SourceConnectorID, g.ExternalID, g.ID); err != nil {
			return err
		}
		if err := membersOwnedTx(tx, g.SourceConnectorID, members); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO directory_groups(id,name,description,source_connector_id,external_id,created_at,updated_at) VALUES (?,?,?,?,?,?,?)`,
			g.ID, g.Name, g.Description, g.SourceConnectorID, nullIfEmpty(g.ExternalID), now, now); err != nil {
			return groupWriteError(err)
		}
		for _, uid := range members {
			if _, _, err := applyGroupMembershipTx(tx, g.ID, uid, true, nil, ""); err != nil {
				return err
			}
		}
		if len(members) > 0 {
			if err := reconcileAccessTx(tx); err != nil {
				return err
			}
		}
		if audit != nil {
			audit.TargetID = g.ID
		}
		return nil
	})
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func scanUpstreamGroup(row interface{ Scan(...any) error }) (*Group, error) {
	g := &Group{}
	var source, external sql.NullString
	err := row.Scan(&g.ID, &g.Name, &g.Description, &source, &external, &g.CreatedAt, &g.UpdatedAt, &g.MemberCount)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	g.SourceConnectorID, g.ExternalID = source.String, external.String
	return g, err
}

const upstreamGroupColumns = `g.id,g.name,g.description,g.source_connector_id,g.external_id,g.created_at,g.updated_at,(SELECT COUNT(*) FROM group_memberships m WHERE m.group_id=g.id)`

// GetUpstreamGroup returns the group and its members only if this connector owns it.
func (s *Store) GetUpstreamGroup(connectorID, id string) (*UpstreamGroup, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	g, err := scanUpstreamGroup(tx.QueryRow(`SELECT `+upstreamGroupColumns+` FROM directory_groups g WHERE g.id=? AND g.source_connector_id=?`, id, connectorID))
	if err != nil || g == nil {
		return nil, err
	}
	members, err := groupMembersTx(tx, g.ID)
	if err != nil {
		return nil, err
	}
	return &UpstreamGroup{Group: *g, Members: members}, tx.Commit()
}

// ListUpstreamGroups pages a connector's groups, optionally narrowed by one exact match.
func (s *Store) ListUpstreamGroups(connectorID, attribute, value string, startIndex, count int) ([]UpstreamGroup, int, error) {
	where := `g.source_connector_id=?`
	args := []any{connectorID}
	switch attribute {
	case "":
	case "displayName":
		where += ` AND g.name=? COLLATE NOCASE`
		args = append(args, value)
	case "externalId":
		where += ` AND g.external_id=?`
		args = append(args, value)
	case "id":
		where += ` AND g.id=?`
		args = append(args, value)
	default:
		return nil, 0, errors.New("unsupported filter attribute")
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
	tx, err := s.db.Begin()
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	var total int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM directory_groups g WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := tx.Query(`SELECT `+upstreamGroupColumns+` FROM directory_groups g WHERE `+where+` ORDER BY g.created_at, g.id LIMIT ? OFFSET ?`, append(args, count, startIndex-1)...)
	if err != nil {
		return nil, 0, err
	}
	var groups []Group
	for rows.Next() {
		g, err := scanUpstreamGroup(rows)
		if err != nil {
			rows.Close()
			return nil, 0, err
		}
		groups = append(groups, *g)
	}
	rows.Close()
	out := make([]UpstreamGroup, 0, len(groups))
	for _, g := range groups {
		members, err := groupMembersTx(tx, g.ID)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, UpstreamGroup{Group: g, Members: members})
	}
	return out, total, tx.Commit()
}

// ReplaceUpstreamGroup writes the upstream's full view of an owned group: its name and
// its exact member set. The whole change applies or none of it does; the external id
// never changes and every member must be an account this connector owns. expect, when
// set, is the version the caller read (If-Match): a group changed since then is refused.
// A rename of a group carrying a required MFA policy fails closed like any other change
// to such a group, since no local administrator is behind an upstream write.
func (s *Store) ReplaceUpstreamGroup(connectorID string, g *Group, members []string, expect *time.Time, audit *AuditEvent) error {
	members = uniqueStrings(members)
	now := time.Now().UTC()
	return s.auditedTx(audit, func(tx *sql.Tx) error {
		current, err := scanUpstreamGroup(tx.QueryRow(`SELECT `+upstreamGroupColumns+` FROM directory_groups g WHERE g.id=? AND g.source_connector_id=?`, g.ID, connectorID))
		if err != nil {
			return err
		}
		if current == nil {
			return ErrGroupTargetMissing
		}
		if expect != nil && !current.UpdatedAt.Equal(*expect) {
			return ErrGroupVersionStale
		}
		if g.Name != current.Name {
			var required bool
			if err := tx.QueryRow(`SELECT required FROM enrollment_policies WHERE group_id=?`, g.ID).Scan(&required); err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if required {
				return ErrEmergencyAdministrator
			}
		}
		if g.ExternalID != "" && current.ExternalID != "" && g.ExternalID != current.ExternalID {
			return errors.New("external id is immutable")
		}
		if g.ExternalID == "" {
			g.ExternalID = current.ExternalID
		}
		if err := externalGroupFreeTx(tx, connectorID, g.ExternalID, g.ID); err != nil {
			return err
		}
		if err := membersOwnedTx(tx, connectorID, members); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE directory_groups SET name=?, external_id=?, updated_at=? WHERE id=?`, g.Name, nullIfEmpty(g.ExternalID), now, g.ID); err != nil {
			return groupWriteError(err)
		}
		have, err := groupMembersTx(tx, g.ID)
		if err != nil {
			return err
		}
		want := map[string]bool{}
		for _, id := range members {
			want[id] = true
		}
		changed := false
		for _, id := range have {
			if !want[id] {
				if _, _, err := applyGroupMembershipTx(tx, g.ID, id, false, nil, ""); err != nil {
					return err
				}
				changed = true
			}
			delete(want, id)
		}
		for id := range want {
			if _, _, err := applyGroupMembershipTx(tx, g.ID, id, true, nil, ""); err != nil {
				return err
			}
			changed = true
		}
		if changed {
			if err := reconcileAccessTx(tx); err != nil {
				return err
			}
		}
		g.UpdatedAt = now
		return nil
	})
}

// DeleteUpstreamGroup removes an owned group and its memberships. Its users are untouched.
// expect, when set, is the version the caller read.
func (s *Store) DeleteUpstreamGroup(connectorID, id string, expect *time.Time, audit *AuditEvent) error {
	return s.auditedTx(audit, func(tx *sql.Tx) error {
		var updated time.Time
		err := tx.QueryRow(`SELECT updated_at FROM directory_groups WHERE id=? AND source_connector_id=?`, id, connectorID).Scan(&updated)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrGroupTargetMissing
		}
		if err != nil {
			return err
		}
		if expect != nil && !updated.Equal(*expect) {
			return ErrGroupVersionStale
		}
		name, err := deleteGroupTx(tx, id, "")
		if err != nil {
			return err
		}
		setGroupAuditDetails(audit, map[string]string{"name": name})
		return nil
	})
}

// CountSCIMConnectorGroups reports how many groups a connector owns.
func (s *Store) CountSCIMConnectorGroups(connectorID string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM directory_groups WHERE source_connector_id=?`, connectorID).Scan(&n)
	return n, err
}
