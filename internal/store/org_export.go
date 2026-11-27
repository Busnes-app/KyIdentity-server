package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// OrgExportStatus is shown only to a holder in a billing-scheduled deletion window.
type OrgExportStatus struct {
	DeleteAfter int64 `json:"deleteAfter"`
}

func (o *OrgStore) OrgExportStatus(userID string) (OrgExportStatus, error) {
	var s OrgExportStatus
	err := o.s.db.QueryRow(`SELECT o.delete_after FROM orgs o WHERE o.id=? AND o.account_holder_user_id=? AND o.status='deletion_scheduled' AND o.delete_after>unixepoch() AND NOT EXISTS(SELECT 1 FROM org_erasures e WHERE e.org_id=o.id)`, o.org, userID).Scan(&s.DeleteAfter)
	if errors.Is(err, sql.ErrNoRows) {
		return s, ErrNotFound
	}
	return s, err
}

// orgExportMaxRows bounds each section in a single JSON export response.
// Package variable so tests can shrink it without seeding fifty thousand rows.
var orgExportMaxRows = 50000

// OrgExportOptions tunes a single directory export response.
type OrgExportOptions struct {
	// AuditOffset skips this many oldest audit rows (ORDER BY created_at, id) so large
	// audit logs can be paged across successive requests instead of aborting the export.
	AuditOffset int
}

// ExportOrg is a read-only directory export, never a capsule/import. Explicit columns
// exclude credentials, keyring ciphertext, app secrets and delivery payloads. All rows
// come from one snapshot and the access predicate is rechecked under the writer lock.
func (o *OrgStore) ExportOrg(ctx context.Context, userID string, audit *AuditEvent, opts ...OrgExportOptions) (map[string]any, error) {
	var opt OrgExportOptions
	if len(opts) > 0 {
		opt = opts[0]
	}
	return o.exportOrg(ctx, userID, false, audit, opt)
}

// ExportOrgForStaff is the selected-org staff export, on request by its holder.
func (o *OrgStore) ExportOrgForStaff(ctx context.Context, audit *AuditEvent, opts ...OrgExportOptions) (map[string]any, error) {
	var opt OrgExportOptions
	if len(opts) > 0 {
		opt = opts[0]
	}
	return o.exportOrg(ctx, "", true, audit, opt)
}
func (o *OrgStore) exportOrg(ctx context.Context, userID string, staff bool, audit *AuditEvent, opt OrgExportOptions) (map[string]any, error) {
	if audit == nil {
		return nil, errors.New("store: org export needs its audit row")
	}
	if opt.AuditOffset < 0 {
		return nil, InputError("audit_offset must not be negative.")
	}

	tx, err := o.s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var allowed bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM orgs o WHERE o.id=? AND o.kind='customer' AND o.status<>'deleted' AND (? OR (o.status='deletion_scheduled' AND o.delete_after>unixepoch() AND o.account_holder_user_id=? AND NOT EXISTS(SELECT 1 FROM org_erasures e WHERE e.org_id=o.id))))`, o.org, staff, userID).Scan(&allowed); err != nil {
		return nil, err
	}
	if !allowed {
		return nil, ErrNotFound
	}
	out, err := exportOrgTx(ctx, tx, o.org, opt)
	if err != nil {
		return nil, err
	}
	if err := orgAuditTx(tx, o.org, audit, nil, time.Now().UTC()); err != nil {
		return nil, err
	}
	return out, tx.Commit()
}

func exportOrgTx(ctx context.Context, tx *sql.Tx, org string, opt OrgExportOptions) (map[string]any, error) {
	maxRows := orgExportMaxRows
	out := map[string]any{}
	truncated := map[string]any{}
	for _, part := range []struct{ name, query string }{
		{"org", `SELECT id,name,status,status_reason,home_region,plan,max_seats,storage_bytes,storage_per_seat_bytes,account_holder_user_id,delete_after FROM orgs WHERE id=?`},
		{"users", `SELECT id,username,display_name,email,mailbox_address,role,status,pending,created_at,updated_at FROM users WHERE org_id=? ORDER BY id`},
		{"groups", `SELECT id,name,created_at,updated_at FROM directory_groups WHERE org_id=? ORDER BY id`},
		{"memberships", `SELECT group_id,user_id,expires_at FROM group_memberships WHERE org_id=? ORDER BY group_id,user_id`},
		{"user_assignments", `SELECT a.app_id,a.user_id,a.expires_at FROM app_user_assignments a JOIN users u ON u.id=a.user_id WHERE u.org_id=? ORDER BY a.app_id,a.user_id`},
		{"group_assignments", `SELECT a.app_id,a.group_id FROM app_group_assignments a JOIN directory_groups g ON g.id=a.group_id WHERE g.org_id=? ORDER BY a.app_id,a.group_id`},
		{"user_roles", `SELECT a.role_id,a.user_id FROM app_role_user_assignments a JOIN users u ON u.id=a.user_id WHERE u.org_id=? ORDER BY a.role_id,a.user_id`},
		{"group_roles", `SELECT a.role_id,a.group_id FROM app_role_group_assignments a JOIN directory_groups g ON g.id=a.group_id WHERE g.org_id=? ORDER BY a.role_id,a.group_id`},
		{"audit", `SELECT id,actor_id,actor_username,action,target_id,target_type,outcome,details_json,created_at FROM audit_events WHERE org_id=? ORDER BY created_at,id`},
	} {
		query := part.query + ` LIMIT ?`
		args := []any{org, maxRows + 1}
		if part.name == "audit" && opt.AuditOffset > 0 {
			query += ` OFFSET ?`
			args = append(args, opt.AuditOffset)
		}
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, err
		}
		data, more, err := exportRows(rows, maxRows)
		rows.Close()
		if err != nil {
			return nil, err
		}
		if part.name == "org" {
			out[part.name] = data[0]
		} else {
			out[part.name] = data
		}
		if more {
			info := map[string]any{
				"returned": len(data),
				"limit":    maxRows,
				"more":     true,
			}
			if part.name == "audit" {
				info["offset"] = opt.AuditOffset
				info["next_offset"] = opt.AuditOffset + len(data)
			}
			truncated[part.name] = info
		}
	}
	if len(truncated) > 0 {
		out["partial"] = true
		out["truncated"] = truncated
	}
	return out, nil
}

func exportRows(rows *sql.Rows, maxRows int) ([]map[string]any, bool, error) {
	cols, err := rows.Columns()
	if err != nil {
		return nil, false, err
	}
	out := []map[string]any{}
	for rows.Next() {
		if len(out) == maxRows {
			return out, true, rows.Err()
		}
		values := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, false, err
		}
		row := map[string]any{}
		for i, col := range cols {
			v := values[i]
			if b, ok := v.([]byte); ok {
				v = string(b)
			}
			if col == "details_json" {
				if s, ok := v.(string); ok {
					v = RedactAuditDetails(s)
				}
			}
			row[col] = v
		}
		out = append(out, row)
	}
	return out, false, rows.Err()
}
