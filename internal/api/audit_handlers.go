package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Busness-app/kysignon-server/internal/store"
)

// Export bounds. Package variables so a test can shrink them instead of seeding
// fifty thousand rows.
var (
	auditExportMaxRows = 50000
	auditExportTimeout = 30 * time.Second
)

// auditFilterFrom reads the bounded filters shared by the listing and the export.
func auditFilterFrom(r *http.Request) (store.AuditFilter, error) {
	q := r.URL.Query()
	f := store.AuditFilter{Actor: strings.TrimSpace(q.Get("actor")), Target: strings.TrimSpace(q.Get("target")), TargetType: strings.TrimSpace(q.Get("targetType")), Action: strings.TrimSpace(q.Get("action")), Outcome: q.Get("outcome")}
	for _, v := range []string{f.Actor, f.Target, f.TargetType, f.Action} {
		if len(v) > 200 {
			return f, errors.New("a filter value is longer than 200 characters")
		}
	}
	switch f.Outcome {
	case "", "success", "failure", "denied":
	default:
		return f, errors.New("outcome must be success, failure or denied")
	}
	for name, target := range map[string]**time.Time{"from": &f.From, "to": &f.To} {
		if raw := q.Get(name); raw != "" {
			at, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				return f, errors.New(name + " must be an RFC 3339 instant")
			}
			at = at.UTC()
			*target = &at
		}
	}
	if f.From != nil && f.To != nil && !f.To.After(*f.From) {
		return f, errors.New("to must be after from")
	}
	return f, nil
}

// invalidFilter answers a bad filter with a fixed description: the messages above are
// constants, never the caller's input.
func invalidFilter(w http.ResponseWriter, err error) {
	http.Error(w, `{"error":"invalid_request","error_description":"`+err.Error()+`"}`, http.StatusBadRequest)
}

func (h *AdminHandler) ListAuditEvents(w http.ResponseWriter, r *http.Request) {
	f, err := auditFilterFrom(r)
	if err != nil {
		invalidFilter(w, err)
		return
	}
	page := 1
	if p, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && p > 0 {
		page = p
	}
	f.Limit = 25
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 500 {
		f.Limit = l
	}
	f.Offset = (page - 1) * f.Limit
	if o, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && o >= 0 {
		f.Offset = o
		page = (f.Offset / f.Limit) + 1
	}
	if f.Offset > 1000000 {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	events, total, err := h.store.SearchAuditEventsContext(r.Context(), f)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"auditEvents": events, "total": total, "page": page, "limit": f.Limit, "offset": f.Offset})
}

// csvCell neutralises spreadsheet formula triggers: a leading =, +, -, @, tab or
// carriage return gets a quote prefix so the cell is text wherever it is opened.
func csvCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// exportSink writes one export format and reports its own write failures.
type exportSink struct {
	write  func(store.AuditEvent) error
	finish func() error
	// mark closes an incomplete export with an in-band terminator the reader cannot miss.
	mark func(reason string, rows, total int)
}

func csvSink(w http.ResponseWriter) exportSink {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"id", "created_at", "action", "outcome", "actor_id", "actor_username", "target_type", "target_id", "ip_address", "user_agent", "details"})
	return exportSink{
		write: func(e store.AuditEvent) error {
			return cw.Write([]string{e.ID, e.CreatedAt.UTC().Format(time.RFC3339Nano), csvCell(e.Action), e.Outcome, csvCell(e.ActorID), csvCell(e.ActorUsername), csvCell(e.TargetType), csvCell(e.TargetID), csvCell(e.IPAddress), csvCell(e.UserAgent), csvCell(store.RedactAuditDetails(e.DetailsJSON))})
		},
		finish: func() error { cw.Flush(); return cw.Error() },
		mark: func(reason string, rows, total int) {
			_ = cw.Write([]string{"_export", "", "incomplete", reason, "", "", "", "", "", "", `{"reason":"` + reason + `","rows":` + strconv.Itoa(rows) + `,"total":` + strconv.Itoa(total) + `}`})
			cw.Flush()
		},
	}
}

func jsonlSink(w http.ResponseWriter) exportSink {
	w.Header().Set("Content-Type", "application/x-ndjson")
	enc := json.NewEncoder(w)
	return exportSink{
		write: func(e store.AuditEvent) error {
			e.DetailsJSON = store.RedactAuditDetails(e.DetailsJSON)
			return enc.Encode(e)
		},
		finish: func() error { return nil },
		mark: func(reason string, rows, total int) {
			// Shaped so a consumer decoding events sees id "_export" and action
			// "incomplete", not a blank event.
			_ = enc.Encode(map[string]any{"_export": "incomplete", "reason": reason, "rows": rows, "total": total,
				"id": "_export", "action": "incomplete", "outcome": reason, "detailsJson": `{"reason":"` + reason + `","rows":` + strconv.Itoa(rows) + `,"total":` + strconv.Itoa(total) + `}`})
		},
	}
}

// ExportAuditEvents streams the same filtered set the listing shows as JSONL or CSV,
// bounded in rows and time, with credential-shaped detail keys redacted. The intent is
// audited before a byte leaves, the outcome after; an export that stopped short of the
// filtered set ends with an in-band incomplete marker as well as the headers.
func (h *AdminHandler) ExportAuditEvents(w http.ResponseWriter, r *http.Request) {
	f, err := auditFilterFrom(r)
	if err != nil {
		invalidFilter(w, err)
		return
	}
	format := r.URL.Query().Get("format")
	if format != "jsonl" && format != "csv" {
		http.Error(w, `{"error":"invalid_request","error_description":"format must be jsonl or csv"}`, http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), auditExportTimeout)
	defer cancel()
	total, err := h.store.CountAuditEvents(ctx, f)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	actor := GetUserFromContext(r.Context())
	filter := map[string]any{"actor": f.Actor, "target": f.Target, "targetType": f.TargetType, "action": f.Action, "outcome": f.Outcome, "from": f.From, "to": f.To}
	// No record, no disclosure: the intent row must exist before the first byte.
	if err := h.audit.Record("admin.audit_export_started", actor.ID, actor.Username, "", "audit", h.middleware.ClientIP(r), r.UserAgent(), "success", map[string]any{"format": format, "total": total, "filter": filter}); err != nil {
		http.Error(w, `{"error":"audit_unavailable","error_description":"The export could not be recorded, so it was not produced"}`, http.StatusServiceUnavailable)
		return
	}
	stamp := time.Now().UTC().Format("20060102-150405")
	w.Header().Set("Content-Disposition", `attachment; filename="kysignon-audit-`+stamp+`.`+format+`"`)
	w.Header().Set("X-KySignOn-Export-Total", strconv.Itoa(total))
	w.Header().Set("X-KySignOn-Export-Limit", strconv.Itoa(auditExportMaxRows))
	if total > auditExportMaxRows {
		w.Header().Set("X-KySignOn-Export-Truncated", "true")
	}
	sink := jsonlSink(w)
	if format == "csv" {
		sink = csvSink(w)
	}
	// The row bound is detected from the stream itself: one probe row past the bound is
	// never written, only noted. A count taken earlier is advisory, since rows keep
	// arriving (the export's own intent row among them).
	limited, rows := false, 0
	_, streamErr := h.store.StreamAuditEvents(ctx, f, auditExportMaxRows+1, func(e store.AuditEvent) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if rows == auditExportMaxRows {
			limited = true
			return nil
		}
		rows++
		return sink.write(e)
	})
	if err := sink.finish(); err != nil && streamErr == nil {
		streamErr = err
	}
	reason := ""
	switch {
	case streamErr != nil && errors.Is(streamErr, context.DeadlineExceeded):
		reason = "timeout"
	case streamErr != nil:
		reason = "error"
	case limited:
		reason = "limit"
	}
	if reason != "" {
		sink.mark(reason, rows, total)
	}
	outcome := "success"
	if streamErr != nil {
		outcome = "failure"
	}
	if err := h.audit.Record("admin.audit_exported", actor.ID, actor.Username, "", "audit", h.middleware.ClientIP(r), r.UserAgent(), outcome, map[string]any{
		"format": format, "rows": rows, "total": total, "incomplete": reason, "filter": filter,
	}); err != nil {
		log.Printf("audit export completion record failed: %v", err)
	}
}
