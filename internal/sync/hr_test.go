package sync

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Busnes-app/ky-primitives/syncauth"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

func TestHRCallsKyPostBeforeCreatingSSOIdentity(t *testing.T) {
	e, s, _, cleanup := setupTestSyncEngine(t)
	defer cleanup()
	const secret = "signed-hr-mailbox-secret-32-bytes!!"
	mailCalls, writeCalls := 0, 0
	var id string
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/api/sync/hr-mailbox":
			event, err := syncauth.Verify([]byte(secret), syncauth.FromRequest(r), body, syncauth.Options{})
			if err != nil || event.Type != "hr.mailbox.reserve" {
				t.Error("invalid KyPost authentication", err)
				w.WriteHeader(401)
				return
			}
			var req struct {
				ID     string `json:"userId"`
				Name   string `json:"preferredName"`
				Domain string `json:"domain"`
			}
			if err := json.Unmarshal(body, &req); err != nil {
				t.Error(err)
			}
			id = req.ID
			mailCalls++
			if req.Name != "alice" || req.Domain != "example.test" {
				t.Error("bad allocation request", string(body))
			}
			if u, _ := s.DefaultOrg().GetUserByID(id); u != nil {
				t.Error("identity exists before mailbox allocation")
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"userId": id, "email": "alice.2@example.test"})
		case "/writeback":
			writeCalls++
			if r.Method != "PUT" || r.Header.Get("Authorization") != "Bearer HR-target-secret" {
				t.Error("invalid HR authentication/method")
			}
			var req struct {
				SourceUID string `json:"sourceUid"`
				ID        string `json:"userId"`
				Email     string `json:"email"`
			}
			_ = json.Unmarshal(body, &req)
			if req.SourceUID != "employee-1" || req.ID != id || req.Email != "alice.2@example.test" {
				t.Error("bad writeback", string(body))
			}
			u, _ := s.DefaultOrg().GetUserByID(id)
			if u == nil || u.Username != req.Email || !u.Pending || u.Status != "disabled" {
				t.Error("wrong identity at writeback", u)
			}
			w.WriteHeader(204)
		default:
			t.Error("wrong endpoint", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer target.Close()
	e.httpClient = target.Client()
	encrypted, err := crypto.Seal(e.encryptionKey, store.SealConnector, "post", []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePairedSystem(&store.PairedSystem{ID: "post", Name: "KyPost", SystemType: "kypost", CallbackURL: target.URL + "/api/sync/webhook", HMACSecretEncrypted: encrypted, Status: "active"}, nil); err != nil {
		t.Fatal(err)
	}
	c, err := s.CreateSCIMConnector("HR", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigureHR(store.HRConnection{ConnectorID: c.ID, SystemID: "post", Domain: "example.test", WritebackURL: target.URL + "/writeback"}, "HR-target-secret", nil); err != nil {
		t.Fatal(err)
	}
	input := store.HRInput{SourceUID: "employee-1", PreferredName: "alice", DisplayName: "Alice", Active: true, SourceVersion: 1}
	worker, err := s.ImportHR(c.ID, input, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.DispatchHR(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Dispatcher recreation represents a restart between durable stages.
	e2 := NewEngine(s, e.encryptionKey)
	e2.httpClient = target.Client()
	if err := e2.DispatchHR(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ImportHR(c.ID, input, nil); err != nil {
		t.Fatal(err)
	}
	if err := e2.DispatchHR(context.Background()); err != nil {
		t.Fatal(err)
	}
	worker, err = s.HRWorker(c.ID, input.SourceUID)
	if err != nil || worker.State != "complete" || worker.ID != id || mailCalls != 1 || writeCalls != 1 {
		t.Fatal(worker, err, mailCalls, writeCalls)
	}
}

func TestHRTransportRefusesRedirectAndUnsafeConfiguration(t *testing.T) {
	e, s, _, cleanup := setupTestSyncEngine(t)
	defer cleanup()
	redirected := false
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/private" {
			redirected = true
		}
		w.Header().Set("Location", "/private")
		w.WriteHeader(307)
	}))
	defer target.Close()
	e.httpClient = target.Client()
	if _, err := e.hrRequest(context.Background(), "PUT", target.URL+"/writeback", []byte(`{}`), func(*http.Request) {}); err == nil || redirected {
		t.Fatal("redirect followed", err)
	}
	c, err := s.CreateSCIMConnector("HR", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"http://hr.example/writeback", "https://user:password@hr.example/writeback", "https://hr.example/writeback?token=secret"} {
		if err := e.ConfigureHR(store.HRConnection{ConnectorID: c.ID, SystemID: "post", Domain: "example.test", WritebackURL: endpoint}, "secret", nil); err == nil {
			t.Fatal("unsafe configuration accepted", endpoint)
		}
	}
	_, err = e.hrRequest(context.Background(), "PUT", target.URL, []byte(`{}`), func(r *http.Request) { r.Header.Set("Authorization", "Bearer private-secret") })
	if err == nil || strings.Contains(err.Error(), "private-secret") {
		t.Fatal("unsafe error", err)
	}
}
