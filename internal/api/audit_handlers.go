package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Busness-app/kysignon-server/internal/store"
)

const (
	auditExportMaxRows = 50000
	auditExportTimeout = 30 * time.Second
)

// auditFilterFrom reads the bounded filters shared by the listing and the export.
func auditFilterFrom(r *http.Request) (store.AuditFilter, error) {
	q := r.URL.Query()
	f := store.AuditFilter{Actor: strings.TrimSpace(q.Get("actor")), Target: strings.TrimSpace(q.Get("target")), TargetType: strings.TrimSpace(q.Get("targetType")), Action: strings.TrimSpace(q.Get("action")), Outcome: q.Get("outcome")}
	for _, v := range []string{f.Actor, f.Target, f.TargetType, f.Action} {
		if len(v) > 200 {
			return f, errors.New("filter too long")
		}
	}
	switch f.Outcome {
	case "", "success", "failure", "denied":
	default:
		return f, errors.New("unknown outcome")
	}
	for name, target := range map[string]**time.Time{"from": &f.From, "to": &f.To} {
		if raw := q.Get(name); raw != "" {
			at, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				return f, err
			}
			at = at.UTC()
			*target = &at
		}
	}
	if f.From != nil && f.To != nil && !f.To.After(*f.From) {
		return f, errors.New("empty range")
	}
	return f, nil
}

func (h *AdminHandler) ListAuditEvents(w http.ResponseWriter, r *http.Request) {
	f, err := auditFilterFrom(r)
	if err != nil {
		http.Error(w, `{"error":"invalid_request","error_description":"`+err.Error()+`"}`, http.StatusBadRequest)
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
	events, total, err := h.store.SearchAuditEvents(f)
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

// ExportAuditEvents streams the same filtered set the listing shows as JSONL or CSV,
// bounded in rows and time, with credential-shaped detail keys redacted, and audits the
// export itself.
func (h *AdminHandler) ExportAuditEvents(w http.ResponseWriter, r *http.Request) {
	f, err := auditFilterFrom(r)
	if err != nil {
		http.Error(w, `{"error":"invalid_request","error_description":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}
	format := r.URL.Query().Get("format")
	if format != "jsonl" && format != "csv" {
		http.Error(w, `{"error":"invalid_request","error_description":"format must be jsonl or csv"}`, http.StatusBadRequest)
		return
	}
	f.Limit = 1
	_, total, err := h.store.SearchAuditEvents(f)
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	stamp := time.Now().UTC().Format("20060102-150405")
	w.Header().Set("Content-Disposition", `attachment; filename="kysignon-audit-`+stamp+`.`+format+`"`)
	w.Header().Set("X-KySignOn-Export-Total", strconv.Itoa(total))
	w.Header().Set("X-KySignOn-Export-Limit", strconv.Itoa(auditExportMaxRows))
	if total > auditExportMaxRows {
		w.Header().Set("X-KySignOn-Export-Truncated", "true")
	}
	ctx, cancel := context.WithTimeout(r.Context(), auditExportTimeout)
	defer cancel()
	var write func(store.AuditEvent) error
	var finish func()
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"id", "created_at", "action", "outcome", "actor_id", "actor_username", "target_type", "target_id", "ip_address", "user_agent", "details"})
		write = func(e store.AuditEvent) error {
			return cw.Write([]string{e.ID, e.CreatedAt.UTC().Format(time.RFC3339Nano), csvCell(e.Action), e.Outcome, csvCell(e.ActorID), csvCell(e.ActorUsername), csvCell(e.TargetType), csvCell(e.TargetID), csvCell(e.IPAddress), csvCell(e.UserAgent), csvCell(store.RedactAuditDetails(e.DetailsJSON))})
		}
		finish = cw.Flush
	} else {
		w.Header().Set("Content-Type", "application/x-ndjson")
		enc := json.NewEncoder(w)
		write = func(e store.AuditEvent) error {
			e.DetailsJSON = store.RedactAuditDetails(e.DetailsJSON)
			return enc.Encode(e)
		}
		finish = func() {}
	}
	rows, streamErr := h.store.StreamAuditEvents(f, auditExportMaxRows, func(e store.AuditEvent) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return write(e)
	})
	finish()
	actor := GetUserFromContext(r.Context())
	outcome := "success"
	if streamErr != nil {
		outcome = "failure"
	}
	h.audit.Record("admin.audit_exported", actor.ID, actor.Username, "", "audit", h.middleware.ClientIP(r), r.UserAgent(), outcome, map[string]any{
		"format": format, "rows": rows, "total": total, "truncated": total > auditExportMaxRows,
		"filter": map[string]any{"actor": f.Actor, "target": f.Target, "targetType": f.TargetType, "action": f.Action, "outcome": f.Outcome, "from": f.From, "to": f.To},
	})
}
