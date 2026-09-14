package store

import (
	"database/sql"
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

// Audit search and export. Filters are bounded and indexed, order is total (created_at
// then id) so paging never repeats or skips a row under tied timestamps, and export
// streams the same filtered set with the same order. Retention is unchanged:
// DeleteAuditEventsOlderThan is the only thing that removes rows.

// AuditFilter narrows the trail. Action matches by prefix (`oauth.` covers every OAuth
// event); the rest match exactly. From is inclusive, To exclusive.
type AuditFilter struct {
	Actor, Target, TargetType, Action, Outcome string
	From, To                                   *time.Time
	Limit, Offset                              int
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

func (f AuditFilter) where() (string, []any) {
	clauses, args := []string{"1=1"}, []any{}
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
	return " WHERE " + strings.Join(clauses, " AND "), args
}

const auditSelect = `SELECT id, actor_id, actor_username, action, target_id, target_type, ip_address, user_agent, outcome, details_json, created_at FROM audit_events`
const auditOrder = ` ORDER BY created_at DESC, id DESC`

func scanAuditEvent(rows *sql.Rows) (AuditEvent, error) {
	var e AuditEvent
	var actorID, actorUser, targetID, targetType, details sql.NullString
	if err := rows.Scan(&e.ID, &actorID, &actorUser, &e.Action, &targetID, &targetType, &e.IPAddress, &e.UserAgent, &e.Outcome, &details, &e.CreatedAt); err != nil {
		return e, err
	}
	e.ActorID, e.ActorUsername, e.TargetID, e.TargetType, e.DetailsJSON = actorID.String, actorUser.String, targetID.String, targetType.String, details.String
	return e, nil
}

// SearchAuditEvents pages the filtered trail with its total.
func (s *Store) SearchAuditEvents(f AuditFilter) ([]AuditEvent, int, error) {
	where, args := f.where()
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_events`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(auditSelect+where+auditOrder+` LIMIT ? OFFSET ?`, append(args, f.Limit, f.Offset)...)
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

func (s *Store) ListAuditEvents(limit, offset int) ([]AuditEvent, int, error) {
	return s.SearchAuditEvents(AuditFilter{Limit: limit, Offset: offset})
}

// StreamAuditEvents hands the filtered trail to fn in page order, at most maxRows of it,
// and stops early when fn returns an error (a client gone or a deadline passed).
func (s *Store) StreamAuditEvents(f AuditFilter, maxRows int, fn func(AuditEvent) error) (int, error) {
	where, args := f.where()
	rows, err := s.db.Query(auditSelect+where+auditOrder+` LIMIT ?`, append(args, maxRows)...)
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
