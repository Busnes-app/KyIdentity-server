package main

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/netguard"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/Busnes-app/kyidentity-server/internal/sync"
	"github.com/google/uuid"
)

// syncTarget is a store at dbPath whose suite connector shares an app with OAuth client
// "kydrive", delivering to callback. It returns the store, its sync engine, the connector
// ID and its app ID.
func syncTarget(t *testing.T, dbPath, callback string) (*store.Store, *sync.Engine, string, string) {
	t.Helper()
	s, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	e := sync.NewEngine(s, make([]byte, 32))
	sys, _, err := e.CreateSystem(&sync.CreateSystemRequest{Name: "drive", SystemType: "suite_webhook", CallbackURL: callback}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateOAuthClient(&store.OAuthClient{ID: "kydrive", ClientName: "D", ClientType: "confidential", ClientSecretHash: "x", RedirectURIsJSON: `["https://d.test/cb"]`, AllowedScopesJSON: `["openid"]`, Enabled: true}, nil); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var appID, clientApp string
	if err := raw.QueryRow(`SELECT (SELECT id FROM app_registry WHERE system_id=?),(SELECT id FROM app_registry WHERE client_id='kydrive')`, sys.ID).Scan(&appID, &clientApp); err != nil {
		t.Fatal(err)
	}
	if err := s.LinkAppRecords(appID, clientApp, 1, 1, nil); err != nil {
		t.Fatal(err)
	}
	return s, e, sys.ID, appID
}

// assignUser creates an account with access to the connector's app, queueing its create.
func assignUser(t *testing.T, s *store.Store, appID, name string) {
	t.Helper()
	u := &store.User{ID: uuid.NewString(), Username: name, DisplayName: name, Email: name + "@example.test", PasswordHash: "x", Role: "user", Status: "active"}
	if err := s.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppAssignment(appID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
}

// Shutdown mid-delivery must not exit before the worker records the attempt's outcome:
// an exit in between leaves a fence with nothing recorded, which holds the account's
// later work. The receiver holds the request, so cancellation finds its headers written
// and the worker records the outcome as uncertain.
func TestShutdownWaitsForSyncWorker(t *testing.T) {
	netguard.AllowPrivate, netguard.AllowLoopback = true, true
	t.Cleanup(func() { netguard.AllowPrivate, netguard.AllowLoopback = false, false })
	received := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The server notices the client hanging up only after the body is read.
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case received <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	s, e, systemID, appID := syncTarget(t, filepath.Join(t.TempDir(), "kyidentity.db"), srv.URL)
	assignUser(t, s, appID, "in-flight")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wait := startSyncWorker(ctx, e)
	select {
	case <-received:
	case <-time.After(30 * time.Second):
		t.Fatal("worker never delivered")
	}
	cancel()
	deadline, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if !wait(deadline) {
		t.Fatal("worker did not stop within the shutdown deadline")
	}
	if b, err := s.SyncBacklog(systemID); err != nil || b != (store.SyncBacklog{Pending: 1, Failed: 1}) {
		t.Fatalf("backlog after shutdown = %+v, %v; want the interrupted write recorded as uncertain", b, err)
	}
}
