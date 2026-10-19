package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// A restored downstream app needs the installer to replay removals without an admin session.
func TestResyncSystem(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KYIDENTITY_DATA_DIR", dir)
	t.Setenv("KYIDENTITY_DB_PATH", "")
	resyncPoll = 5 * time.Millisecond
	dbPath := filepath.Join(dir, "kyidentity.db")
	s, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CreateOAuthClient(&store.OAuthClient{ID: "kyq-app", ClientName: "App", ClientType: "confidential", ClientSecretHash: "x", RedirectURIsJSON: `["https://app.test/cb"]`, AllowedScopesJSON: `["openid"]`, Enabled: true}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePairedSystem(&store.PairedSystem{ID: "target", Name: "target", SystemType: "scim", CallbackURL: "https://app.test/scim", Status: "active"}, nil); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var appID, clientApp string
	if err := raw.QueryRow(`SELECT (SELECT id FROM app_registry WHERE system_id='target'),(SELECT id FROM app_registry WHERE client_id='kyq-app')`).Scan(&appID, &clientApp); err != nil {
		t.Fatal(err)
	}
	if err := s.LinkAppRecords(appID, clientApp, 1, 1, nil); err != nil {
		t.Fatal(err)
	}
	u := &store.User{ID: uuid.NewString(), Username: "leaver", DisplayName: "Leaver", Email: "leaver@example.test", PasswordHash: "x", Role: "user", Status: "active"}
	if err := s.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	deliver := func() {
		t.Helper()
		events, err := s.ClaimDueSyncEvents(50, time.Minute)
		if err != nil {
			t.Error(err)
			return
		}
		for _, ev := range events {
			if ok, err := s.BeginSyncDelivery(ev, time.Minute); err != nil || !ok {
				t.Error("begin", ok, err)
				return
			}
			if err := s.FinishSyncDelivery(ev, "delivered", "", ev.Attempts+1, nil); err != nil {
				t.Error(err)
			}
		}
	}
	for _, on := range []bool{true, false} {
		if err := s.SetAppAssignment(appID, "users", u.ID, on, nil); err != nil {
			t.Fatal(err)
		}
		deliver()
	}
	run := func(args ...string) (resyncResult, error) {
		t.Helper()
		var out bytes.Buffer
		err := runResyncSystem(args, &out)
		var r resyncResult
		if out.Len() > 0 {
			d := json.NewDecoder(&out)
			if d.Decode(&r) != nil || d.More() || r.Schema != "kyidentity.resync-system/1" {
				t.Fatalf("stdout is not exactly one result: %q", out.String())
			}
		}
		return r, err
	}
	count := func(q string) int {
		t.Helper()
		var n int
		if err := raw.QueryRow(q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	audits := `SELECT COUNT(*) FROM audit_events WHERE actor_username='kyidentity-cli' AND action='admin.system_resynced' AND target_id='target' AND details_json LIKE '%"via":"cli"%'`
	replays := `SELECT COUNT(*) FROM account_sync_events WHERE system_id='target' AND event_type='user.updated' AND status='delivered' AND payload_json LIKE '%"active":false%'`

	for _, args := range [][]string{{}, {"--client", "nope"}, {"--client", "kyq-app", "--wait", "-1s"}, {"--client", "kyq-app", "--wait", "25h"}} {
		if r, err := run(args...); err == nil || r.Schema != "" {
			t.Fatal("refusal", args, r, err)
		}
	}
	if n := count(audits); n != 0 {
		t.Fatal("refusal audited", n)
	}

	// Without --wait it only queues, and a repeat queues nothing extra.
	for range 2 {
		r, err := run("--client", "kyq-app")
		if err != nil || r.Status != "queued" || r.SystemID != "target" || r.ClientID != "kyq-app" || r.Pending != 1 {
			t.Fatal("queue", r, err)
		}
	}
	// Nobody delivers: the wait times out and reports what is left.
	if r, err := run("--client", "kyq-app", "--wait", "30ms"); err == nil || r.Status != "timeout" || r.Pending != 1 {
		t.Fatal("timeout", r, err)
	}

	before := count(replays)
	// Stands in for the running server's worker.
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
				deliver()
			}
		}
	}()
	r, err := run("--client", "kyq-app", "--wait", "5s")
	close(stop)
	<-done
	if err != nil || r.Status != "delivered" || r.Pending != 0 || r.Failed != 0 {
		t.Fatal("wait", r, err)
	}
	if got := count(replays); got <= before {
		t.Fatal("removal not replayed and delivered", before, got)
	}
	if n := count(audits); n != 4 {
		t.Fatal("each resync audits once", n)
	}

	// A remote write whose outcome is unknown needs an operator: fail now, not at the deadline.
	if _, err := run("--client", "kyq-app"); err != nil {
		t.Fatal(err)
	}
	events, err := s.ClaimDueSyncEvents(50, time.Minute)
	if err != nil || len(events) != 1 {
		t.Fatal(events, err)
	}
	if ok, err := s.BeginSyncDelivery(events[0], time.Minute); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if err := s.MarkSyncDeliveryUncertain(events[0]); err != nil {
		t.Fatal(err)
	}
	if r, err := run("--client", "kyq-app", "--wait", "5s"); err == nil || r.Status != "failed" || r.Failed != 1 || !strings.Contains(err.Error(), "failed") {
		t.Fatal("failure", r, err)
	}
	if err := s.FinishSyncDelivery(events[0], "delivered", "", 1, nil); err != nil {
		t.Fatal(err)
	}
	deliver()
	if _, err := raw.Exec(`UPDATE paired_systems SET provisioning_hold=1 WHERE id='target'`); err != nil {
		t.Fatal(err)
	}
	if r, err := run("--client", "kyq-app", "--wait", "5s"); err == nil || r.Status != "blocked" || r.Blocked != "held" {
		t.Fatal("held", r, err)
	}
}
