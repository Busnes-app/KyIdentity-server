package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func seedAudit(t *testing.T, s *Store, n int, at time.Time, spread bool) {
	t.Helper()
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for i := 0; i < n; i++ {
		e := &AuditEvent{ID: "e" + strings.Repeat("0", 6-len(itoa(i))) + itoa(i), Action: []string{"oauth.authorize", "admin.user_updated", "scim.user_replaced"}[i%3], Outcome: []string{"success", "denied", "failure"}[i%3], ActorID: "actor" + itoa(i%7), ActorUsername: "user" + itoa(i%7), TargetID: "target" + itoa(i%11), TargetType: "user", IPAddress: "::1", UserAgent: "t", DetailsJSON: `{"password":"hunter2","note":"n","nested":{"apiToken":"x","ok":1}}`, CreatedAt: at}
		if spread {
			e.CreatedAt = at.Add(time.Duration(i) * time.Second)
		}
		if _, err := insertAuditEvent(tx, e); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// Paging under tied timestamps never repeats or skips: the order is total.
func TestAuditPagingIsStableUnderTiedTimestamps(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	seedAudit(t, s, 60, time.Now().UTC().Truncate(time.Second), false)
	seen := map[string]bool{}
	for offset := 0; offset < 60; offset += 25 {
		page, total, err := s.SearchAuditEvents(AuditFilter{Limit: 25, Offset: offset})
		if err != nil || total != 60 {
			t.Fatalf("page at %d: %d %v", offset, total, err)
		}
		for _, e := range page {
			if seen[e.ID] {
				t.Fatalf("row %s repeated across pages", e.ID)
			}
			seen[e.ID] = true
		}
	}
	if len(seen) != 60 {
		t.Fatalf("paged %d of 60 rows", len(seen))
	}
}

// Filters narrow by actor, target, type, action prefix, outcome and time range, and
// the filtered queries use the indexes at a representative volume.
func TestAuditFiltersAndIndexes(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	base := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Second)
	seedAudit(t, s, 6000, base, true)
	cases := []struct {
		name   string
		filter AuditFilter
		want   int
	}{
		{"actor by id", AuditFilter{Actor: "actor3"}, 857},
		{"actor by username", AuditFilter{Actor: "user3"}, 857},
		{"target", AuditFilter{Target: "target5"}, 545},
		{"action prefix", AuditFilter{Action: "oauth."}, 2000},
		{"action exact", AuditFilter{Action: "admin.user_updated"}, 2000},
		{"outcome", AuditFilter{Outcome: "denied"}, 2000},
		{"like metacharacters are literal", AuditFilter{Action: "oauth%"}, 0},
		{"combined", AuditFilter{Action: "oauth.", Outcome: "success", TargetType: "user"}, 2000},
	}
	from, to := base.Add(100*time.Second), base.Add(200*time.Second)
	cases = append(cases, struct {
		name   string
		filter AuditFilter
		want   int
	}{"time range", AuditFilter{From: &from, To: &to}, 100})
	for _, c := range cases {
		c.filter.Limit = 10
		_, total, err := s.SearchAuditEvents(c.filter)
		if err != nil || total != c.want {
			t.Fatalf("%s: total %d %v, want %d", c.name, total, err, c.want)
		}
	}
	for _, q := range []struct{ name, sql string }{
		{"action", `SELECT id FROM audit_events WHERE action LIKE 'oauth.%' ORDER BY created_at DESC, id DESC LIMIT 25`},
		{"actor", `SELECT id FROM audit_events WHERE actor_id='actor3' ORDER BY created_at DESC, id DESC LIMIT 25`},
		{"target", `SELECT id FROM audit_events WHERE target_id='target5' ORDER BY created_at DESC, id DESC LIMIT 25`},
		{"range", `SELECT id FROM audit_events WHERE created_at>='2026-01-01' ORDER BY created_at DESC, id DESC LIMIT 25`},
	} {
		rows, err := s.db.Query(`EXPLAIN QUERY PLAN ` + q.sql)
		if err != nil {
			t.Fatal(err)
		}
		var plan []string
		for rows.Next() {
			var a, b, c int
			var detail string
			if err := rows.Scan(&a, &b, &c, &detail); err != nil {
				t.Fatal(err)
			}
			plan = append(plan, detail)
		}
		rows.Close()
		joined := strings.Join(plan, " | ")
		if !strings.Contains(joined, "INDEX idx_audit_events_") || strings.Contains(joined, "USE TEMP B-TREE") {
			t.Fatalf("%s filter does not use an index or sorts in memory: %s", q.name, joined)
		}
	}
}

// Export streams the filtered order, stops at the row bound or when the sink refuses,
// and redacts credential-shaped detail keys at any depth.
func TestAuditExportIsBoundedAndRedacted(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	seedAudit(t, s, 30, time.Now().UTC().Truncate(time.Second), true)
	var got []AuditEvent
	n, err := s.StreamAuditEvents(context.Background(), AuditFilter{Action: "oauth."}, 5, func(e AuditEvent) error { got = append(got, e); return nil })
	if err != nil || n != 5 || len(got) != 5 {
		t.Fatalf("bounded stream = %d %v", n, err)
	}
	for i := 1; i < len(got); i++ {
		if got[i].CreatedAt.After(got[i-1].CreatedAt) {
			t.Fatal("export order is not the page order")
		}
	}
	stop := errors.New("client gone")
	if n, err := s.StreamAuditEvents(context.Background(), AuditFilter{}, 100, func(AuditEvent) error { return stop }); !errors.Is(err, stop) || n != 0 {
		t.Fatalf("sink refusal not honoured: %d %v", n, err)
	}
	// A deadline that has already passed reaches the query itself.
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if n, err := s.StreamAuditEvents(expired, AuditFilter{}, 100, func(AuditEvent) error { return nil }); err == nil || n != 0 {
		t.Fatalf("expired context ignored by the query: %d %v", n, err)
	}
	red := RedactAuditDetails(got[0].DetailsJSON)
	if strings.Contains(red, "hunter2") || strings.Contains(red, `"apiToken":"x"`) || !strings.Contains(red, `"note":"n"`) || !strings.Contains(red, `"ok":1`) {
		t.Fatalf("redaction = %s", red)
	}
	if RedactAuditDetails("not json") != `"[unparseable]"` || RedactAuditDetails("") != "" {
		t.Fatal("malformed details not neutralised")
	}
}
