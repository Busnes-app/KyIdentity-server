package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

// Audit search and export. Filters are bounded and indexed, order is total (created_at
// then id) so paging never repeats or skips a row under tied timestamps, and export
// streams the filtered trail with the same order. Retention is unchanged:
// DeleteAuditEventsOlderThan is the only thing that removes rows.

// AuditFilter narrows the trail. Action matches by prefix (`oauth.` covers every OAuth
// event); the rest match exactly. From is inclusive, To exclusive.
type AuditFilter struct {
	Actor, Target, TargetType, Action, Outcome string
	From, To                                   *time.Time
	Limit, Offset                              int
	// OmitStaffReadDetails excludes the listing's own staff.audit_read events from
	// both pages and totals so offset pagination remains stable while reads stay audited.
	OmitStaffReadDetails string
}

func (s *Store) migrateAuditIndexes() error {
	_, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_audit_events_created_id ON audit_events(created_at DESC, id DESC);
 CREATE INDEX IF NOT EXISTS idx_audit_events_action ON audit_events(action, created_at DESC, id DESC);
 CREATE INDEX IF NOT EXISTS idx_audit_events_actor ON audit_events(actor_id, created_at DESC, id DESC);
 CREATE INDEX IF NOT EXISTS idx_audit_events_target ON audit_events(target_id, created_at DESC, id DESC)`)
	return err
}

func likePrefix(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s) + "%"
}

// where filters the trail for one org: its own rows, and platform rows (NULL) for the org
// that administers the install (the default org, or the staff org).
func (f AuditFilter) where(org string) (string, []any) {
	return f.filters([]string{`(org_id=? OR org_id IS NULL AND EXISTS(SELECT 1 FROM orgs o WHERE o.id=? AND o.kind IN ('default','staff')))`}, []any{org, org})
}
func (f AuditFilter) filters(clauses []string, args []any) (string, []any) {
	if f.Actor != "" {
		clauses, args = append(clauses, "(actor_id=? OR actor_username=?)"), append(args, f.Actor, f.Actor)
	}
	if f.Target != "" {
		clauses, args = append(clauses, "target_id=?"), append(args, f.Target)
	}
	if f.TargetType != "" {
		clauses, args = append(clauses, "target_type=?"), append(args, f.TargetType)
	}
	if f.Action != "" {
		clauses, args = append(clauses, `action LIKE ? ESCAPE '\'`), append(args, likePrefix(f.Action))
	}
	if f.Outcome != "" {
		clauses, args = append(clauses, "outcome=?"), append(args, f.Outcome)
	}
	if f.From != nil {
		clauses, args = append(clauses, "created_at>=?"), append(args, f.From.UTC())
	}
	if f.To != nil {
		clauses, args = append(clauses, "created_at<?"), append(args, f.To.UTC())
	}
	if f.OmitStaffReadDetails != "" {
		clauses = append(clauses, `(action<>'staff.read' OR COALESCE(details_json, '')<>?)`)
		args = append(args, f.OmitStaffReadDetails)
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

const auditSelect = `SELECT id, actor_id, actor_username, action, target_id, target_type, ip_address, user_agent, outcome, details_json, created_at FROM audit_events`
const auditOrder = ` ORDER BY created_at DESC, id DESC`

func scanAuditEvent(rows *sql.Rows, extra ...any) (AuditEvent, error) {
	var e AuditEvent
	var actorID, actorUser, targetID, targetType, details sql.NullString
	if err := rows.Scan(append([]any{&e.ID, &actorID, &actorUser, &e.Action, &targetID, &targetType, &e.IPAddress, &e.UserAgent, &e.Outcome, &details, &e.CreatedAt}, extra...)...); err != nil {
		return e, err
	}
	e.ActorID, e.ActorUsername, e.TargetID, e.TargetType, e.DetailsJSON = actorID.String, actorUser.String, targetID.String, targetType.String, details.String
	return e, nil
}

// SearchAuditEvents pages the filtered trail with its total.
func (o *OrgStore) SearchAuditEvents(f AuditFilter) ([]AuditEvent, int, error) {
	return o.SearchAuditEventsContext(context.Background(), f)
}

// CountAuditEvents counts the filtered trail under the caller's deadline.
func (o *OrgStore) CountAuditEvents(ctx context.Context, f AuditFilter) (int, error) {
	s := o.s
	where, args := f.where(o.org)
	var total int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events`+where, args...).Scan(&total)
	return total, err
}

// SearchAuditEventsContext is SearchAuditEvents under the caller's deadline.
func (o *OrgStore) SearchAuditEventsContext(ctx context.Context, f AuditFilter) ([]AuditEvent, int, error) {
	s := o.s
	where, args := f.where(o.org)
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, auditSelect+where+auditOrder+` LIMIT ? OFFSET ?`, append(args, f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	events := []AuditEvent{}
	for rows.Next() {
		e, err := scanAuditEvent(rows)
		if err != nil {
			return nil, 0, err
		}
		events = append(events, e)
	}
	return events, total, rows.Err()
}

func (o *OrgStore) ListAuditEvents(limit, offset int) ([]AuditEvent, int, error) {
	return o.SearchAuditEvents(AuditFilter{Limit: limit, Offset: offset})
}

// StreamAuditEvents hands the filtered trail to fn in page order, at most maxRows of it,
// under the caller's deadline, and stops early when fn returns an error (a client gone
// or a deadline passed).
func (o *OrgStore) StreamAuditEvents(ctx context.Context, f AuditFilter, maxRows int, fn func(AuditEvent) error) (int, error) {
	s := o.s
	where, args := f.where(o.org)
	rows, err := s.db.QueryContext(ctx, auditSelect+where+auditOrder+` LIMIT ?`, append(args, maxRows)...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		e, err := scanAuditEvent(rows)
		if err != nil {
			return n, err
		}
		if err := fn(e); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

var secretKey = regexp.MustCompile(`(?i)secret|token|password|hash|credential|private`)

// RedactAuditDetails blanks any detail whose key looks like credential material, at any
// depth. Audit rows are written without secrets; this is the belt for the export.
func RedactAuditDetails(details string) string {
	if details == "" {
		return ""
	}
	var v any
	if err := json.Unmarshal([]byte(details), &v); err != nil {
		return `"[unparseable]"`
	}
	out, err := json.Marshal(redactValue(v))
	if err != nil {
		return `"[unparseable]"`
	}
	return string(out)
}

func redactValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if secretKey.MatchString(k) {
				t[k] = "[redacted]"
			} else {
				t[k] = redactValue(val)
			}
		}
		return t
	case []any:
		for i := range t {
			t[i] = redactValue(t[i])
		}
		return t
	}
	return v
}

// PlatformAuditEvent names the original org even when its user has since been removed.
type PlatformAuditEvent struct {
	AuditEvent
	OrgID *string `json:"orgId"`
}

// AuditByActor is a bounded cross-org staff query. It requires an exact actor and is
// deliberately available only on PlatformStore, never an OrgStore escape hatch.
func (p *PlatformStore) AuditByActor(ctx context.Context, f AuditFilter) ([]PlatformAuditEvent, int, error) {
	if strings.TrimSpace(f.Actor) == "" || len(f.Actor) > 200 || f.Limit < 1 || f.Limit > 500 || f.Offset < 0 || f.Offset > 1000000 {
		return nil, 0, InputError("actor and bounded pagination are required")
	}
	where, args := f.filters([]string{"action<>'staff.audit_read'"}, nil)
	var total int
	if err := p.s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := p.s.db.QueryContext(ctx, `SELECT id,actor_id,actor_username,action,target_id,target_type,ip_address,user_agent,outcome,details_json,created_at,org_id FROM audit_events`+where+auditOrder+` LIMIT ? OFFSET ?`, append(args, f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []PlatformAuditEvent{}
	for rows.Next() {
		var e PlatformAuditEvent
		var org sql.NullString
		e.AuditEvent, err = scanAuditEvent(rows, &org)
		if err != nil {
			return nil, 0, err
		}
		if org.Valid {
			e.OrgID = &org.String
		}
		e.DetailsJSON = RedactAuditDetails(e.DetailsJSON)
		out = append(out, e)
	}
	return out, total, rows.Err()
}
