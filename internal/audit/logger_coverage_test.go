package audit

import (
	"bytes"
	"encoding/json"
	"log"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// captureLogger returns a logger on a real store whose console copies land in buffers.
func captureLogger(t *testing.T) (*Logger, *store.Store, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	s, err := store.New(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	var out, errOut bytes.Buffer
	l := NewLogger(s)
	l.stdout = log.New(&out, "", 0)
	l.stderr = log.New(&errOut, "", 0)
	return l, s, &out, &errOut
}

func decodeEntry(t *testing.T, b *bytes.Buffer) LogEntry {
	t.Helper()
	var e LogEntry
	if err := json.Unmarshal(bytes.TrimSpace(b.Bytes()), &e); err != nil {
		t.Fatalf("console line is not one JSON entry: %v: %q", err, b.String())
	}
	return e
}

// A recorded success is durable, goes to stdout at INFO and leaves readiness healthy.
func TestRecordPersistsAndEmitsInfo(t *testing.T) {
	l, s, out, errOut := captureLogger(t)
	if err := l.Record("admin.user_created", "a1", "admin", "u1", "user", "10.0.0.1", "ua", "success", map[string]any{"k": "v"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	rows, total, err := s.ListAuditEvents(10, 0)
	if err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("rows=%d total=%d err=%v", len(rows), total, err)
	}
	if r := rows[0]; r.Action != "admin.user_created" || r.ActorID != "a1" || r.TargetID != "u1" || r.Outcome != "success" || r.DetailsJSON != `{"k":"v"}` {
		t.Fatalf("persisted row %+v", r)
	}
	if errOut.Len() != 0 {
		t.Fatalf("success written to stderr: %q", errOut.String())
	}
	e := decodeEntry(t, out)
	if e.Level != "INFO" || e.Action != "admin.user_created" || e.IPAddress != "10.0.0.1" || e.Details["k"] != "v" || e.AuditPersistError != "" {
		t.Fatalf("console entry %+v", e)
	}
	if degraded, n, _, _ := l.Health(); degraded || n != 0 {
		t.Fatalf("healthy write reported degraded=%v failures=%d", degraded, n)
	}
}

// Denials and failures are warnings on stderr, so they stand out from routine traffic.
func TestRecordDeniedIsWarning(t *testing.T) {
	for _, outcome := range []string{"denied", "failure"} {
		l, _, out, errOut := captureLogger(t)
		if err := l.Record("auth.login", "", "mallory", "", "user", "", "", outcome, nil); err != nil {
			t.Fatal(err)
		}
		if out.Len() != 0 {
			t.Fatalf("%s written to stdout: %q", outcome, out.String())
		}
		if e := decodeEntry(t, errOut); e.Level != "WARN" || e.Outcome != outcome {
			t.Fatalf("%s entry %+v", outcome, e)
		}
	}
}

// A lost durable write must be returned to the caller, escalate the console copy to ERROR
// with the cause, and keep readiness degraded until a later write succeeds.
func TestRecordStoreFailureIsReturnedAndDegradesHealth(t *testing.T) {
	l, s, out, errOut := captureLogger(t)
	_ = s.Close()

	for i := 1; i <= 2; i++ {
		errOut.Reset()
		err := l.Record("admin.key_rotated", "a1", "admin", "k1", "key", "", "", "success", nil)
		if err == nil {
			t.Fatal("write to a closed store reported success")
		}
		e := decodeEntry(t, errOut)
		if e.Level != "ERROR" || e.AuditPersistError == "" || e.Action != "admin.key_rotated" {
			t.Fatalf("console copy of a lost event: %+v", e)
		}
		degraded, n, last, at := l.Health()
		if !degraded || n != uint64(i) || last != err.Error() || at.IsZero() {
			t.Fatalf("health after %d failures: degraded=%v n=%d last=%q at=%v", i, degraded, n, last, at)
		}
	}
	if out.Len() != 0 {
		t.Fatalf("lost events written to stdout: %q", out.String())
	}

	// A committed transactional event proves persistence works again.
	l.Prepare("admin.user_created", "", "", "", "", "", "", "success", nil).Committed()
	if degraded, n, last, _ := l.Health(); degraded || n != 0 || last != "" {
		t.Fatalf("health not reset by a committed write: degraded=%v n=%d last=%q", degraded, n, last)
	}
}

// Observe is for events no mutation depends on: a lost write is logged, never surfaced.
func TestObserveSwallowsStoreFailure(t *testing.T) {
	l, s, _, errOut := captureLogger(t)
	_ = s.Close()
	var std bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&std)
	defer log.SetOutput(prev)

	l.Observe("auth.login", "", "u", "", "user", "", "", "denied", nil)
	if !strings.Contains(std.String(), "audit auth.login not persisted") {
		t.Fatalf("lost observation not logged: %q", std.String())
	}
	if e := decodeEntry(t, errOut); e.Level != "ERROR" || e.AuditPersistError == "" {
		t.Fatalf("console copy %+v", e)
	}
	if degraded, _, _, _ := l.Health(); !degraded {
		t.Fatal("swallowed failure did not degrade health")
	}
}

// Details that cannot be serialized must not take the event with them, and must not vanish.
func TestRecordUnserializableDetailsKeepsEvent(t *testing.T) {
	l, s, _, _ := captureLogger(t)
	if err := l.Record("admin.odd", "", "", "", "", "", "", "success", map[string]any{"ch": make(chan int)}); err != nil {
		t.Fatal(err)
	}
	rows, _, err := s.ListAuditEvents(1, 0)
	if err != nil || len(rows) != 1 {
		t.Fatalf("event lost: %v", err)
	}
	var d map[string]string
	if err := json.Unmarshal([]byte(rows[0].DetailsJSON), &d); err != nil || d["audit_detail_error"] == "" {
		t.Fatalf("details %q not replaced by an error marker", rows[0].DetailsJSON)
	}
}

// A committed row whose details a store rewrote into invalid JSON still gets a console copy,
// marked rather than silently dropped.
func TestCommittedMarksUnreadableDetails(t *testing.T) {
	var out bytes.Buffer
	l := NewLogger(nil)
	l.stdout = log.New(&out, "", 0)
	p := l.Prepare("admin.group_deleted", "", "", "g1", "group", "", "", "success", nil)
	p.Row.DetailsJSON = "{not json"
	p.Committed()
	e := decodeEntry(t, &out)
	if e.Action != "admin.group_deleted" || e.Details["audit_detail_error"] == nil {
		t.Fatalf("console entry %+v", e)
	}

	// Committed on a nil or detached pending is a no-op, not a panic.
	var nilPending *Pending
	nilPending.Committed()
	(&Pending{Row: p.Row}).Committed()
}

// Without a store the logger is console-only: nothing to fail, nothing to report.
func TestRecordWithoutStoreIsConsoleOnly(t *testing.T) {
	var out bytes.Buffer
	l := NewLogger(nil)
	l.stdout = log.New(&out, "", 0)
	if err := l.Record("system.start", "", "", "", "", "", "", "success", nil); err != nil {
		t.Fatal(err)
	}
	if e := decodeEntry(t, &out); e.Action != "system.start" || e.Level != "INFO" {
		t.Fatalf("entry %+v", e)
	}
	if degraded, _, _, _ := l.Health(); degraded {
		t.Fatal("console-only logger reported degraded")
	}
}
