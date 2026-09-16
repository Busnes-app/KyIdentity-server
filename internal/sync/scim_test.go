package sync

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/Busness-app/ky-primitives/scim"
)

func TestGenericSCIMLifecycle(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal", true: "lost create response"}[lost], func(t *testing.T) {
			e, s, u, cleanup := setupTestSyncEngine(t)
			defer cleanup()
			var mu sync.Mutex
			var remote *scim.User
			posts := 0
			puts := 0
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				if r.Header.Get("Authorization") != "Bearer target-token" {
					t.Error("wrong bearer")
					w.WriteHeader(401)
					return
				}
				if r.Header.Get("X-KySignOn-Signature") != "" || r.Header.Get("X-Sync-Signature") != "" {
					t.Error("generic request signed")
				}
				w.Header().Set("Content-Type", "application/scim+json")
				switch {
				case r.Method == "GET" && r.URL.Path == "/scim/v2/Users":
					if r.URL.Query().Get("filter") != `externalId eq "`+u.ID+`"` {
						t.Errorf("bad filter %s", r.URL.RawQuery)
					}
					users := []scim.User{}
					if remote != nil {
						users = append(users, *remote)
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"totalResults": len(users), "Resources": users, "startIndex": 1})
				case r.Method == "POST" && r.URL.Path == "/scim/v2/Users":
					posts++
					var in scim.User
					if json.NewDecoder(r.Body).Decode(&in) != nil {
						t.Error("bad create")
					}
					if in.ID != "" || in.Meta != nil || in.ExternalID != u.ID {
						t.Error("server-owned fields sent or external ID missing")
					}
					in.ID = "remote-unrelated-id"
					remote = &in
					if lost {
						conn, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						_ = conn.Close()
						return
					}
					w.WriteHeader(201)
					_ = json.NewEncoder(w).Encode(remote)
				case r.Method == "PUT" && r.URL.Path == "/scim/v2/Users/remote-unrelated-id":
					puts++
					var in scim.User
					_ = json.NewDecoder(r.Body).Decode(&in)
					in.ID = "remote-unrelated-id"
					remote = &in
					_ = json.NewEncoder(w).Encode(remote)
				case r.Method == "PATCH" && r.URL.Path == "/scim/v2/Users/remote-unrelated-id":
					puts++
					var patch struct{ Operations []scim.PatchOperation }
					if json.NewDecoder(r.Body).Decode(&patch) != nil || len(patch.Operations) != 1 || patch.Operations[0].Path != "active" || patch.Operations[0].Value != false {
						t.Error("bad deactivation patch")
					}
					remote.Active = false
					w.WriteHeader(204)
				case r.Method == "GET" && r.URL.Path == "/scim/v2/Users/remote-unrelated-id":
					_ = json.NewEncoder(w).Encode(remote)
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
					w.WriteHeader(400)
				}
			}))
			defer srv.Close()
			e.httpClient = srv.Client()
			sys, shown, err := e.CreateSystem(&CreateSystemRequest{Name: "test", SystemType: "scim", CallbackURL: srv.URL + "/scim/v2", BearerToken: "target-token"})
			if err != nil {
				t.Fatal(err)
			}
			if shown != "" {
				t.Fatal("configured token returned")
			}
			sealed, _ := s.GetPairedSystemByID(sys.ID)
			if strings.Contains(sealed.HMACSecretEncrypted, "target-token") {
				t.Fatal("token not encrypted")
			}
			payload, _ := json.Marshal(UserToSCIMResource(u))
			err = e.deliver(context.Background(), sys, "target-token", "create", "user.created", u.ID, payload)
			if lost {
				if err == nil {
					t.Fatal("lost response accepted")
				}
				err = e.deliver(context.Background(), sys, "target-token", "create", "user.created", u.ID, payload)
			}
			if err != nil {
				t.Fatal(err)
			}
			id, started, err := s.SCIMUserLink(sys.ID, u.ID)
			if err != nil || !started || id != "remote-unrelated-id" {
				t.Fatalf("mapping %q %v %v", id, started, err)
			}
			if err = e.deliver(context.Background(), sys, "target-token", "update", "user.updated", u.ID, payload); err != nil {
				t.Fatal(err)
			}
			if err = e.deliver(context.Background(), sys, "target-token", "delete", "user.deleted", u.ID, []byte(`{}`)); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			if posts != 1 || puts < 2 || remote.Active {
				t.Fatalf("posts=%d puts=%d active=%v", posts, puts, remote.Active)
			}
		})
	}
}

func TestSCIMLookupFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"incomplete", `{"totalResults":1,"Resources":[]}`, 200},
		{"ambiguous", `{"totalResults":2,"Resources":[]}`, 200},
		{"missing total", `{"Resources":[]}`, 200},
		{"wrong page", `{"totalResults":0,"Resources":[],"startIndex":2}`, 200},
		{"unrelated", `{"totalResults":1,"Resources":[{"id":"other","externalId":"other"}]}`, 200},
		{"oversized", strings.Repeat(" ", 1<<20) + `{}`, 200},
		{"wrong token", `{"detail":"target-token"}`, 401},
		{"missing endpoint", `{}`, 404},
		{"redirect", `{}`, 302},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, s, u, cleanup := setupTestSyncEngine(t)
			defer cleanup()
			posts := 0
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "POST" {
					posts++
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			e.httpClient = srv.Client()
			sys, _, err := e.CreateSystem(&CreateSystemRequest{Name: "test", SystemType: "scim", CallbackURL: srv.URL, BearerToken: "target-token"})
			if err != nil {
				t.Fatal(err)
			}
			payload, _ := json.Marshal(UserToSCIMResource(u))
			err = e.deliver(context.Background(), sys, "target-token", "event", "user.created", u.ID, payload)
			if err == nil || posts != 0 {
				t.Fatalf("err=%v creates=%d", err, posts)
			}
			_, started, _ := s.SCIMUserLink(sys.ID, u.ID)
			if started {
				t.Fatal("started create despite failed lookup")
			}
			if strings.Contains(deliveryError(err), "target-token") {
				t.Fatal("token in error")
			}
		})
	}
}

func TestSCIMUncertainCreateNeverRepeats(t *testing.T) {
	e, _, u, cleanup := setupTestSyncEngine(t)
	defer cleanup()
	posts := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			_, _ = w.Write([]byte(`{"totalResults":0,"Resources":[]}`))
			return
		}
		posts++
		w.WriteHeader(500)
	}))
	defer srv.Close()
	e.httpClient = srv.Client()
	sys, _, err := e.CreateSystem(&CreateSystemRequest{Name: "test", SystemType: "scim", CallbackURL: srv.URL, BearerToken: "target-token"})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(UserToSCIMResource(u))
	if e.deliver(context.Background(), sys, "target-token", "event", "user.created", u.ID, payload) == nil {
		t.Fatal("create failed but delivery succeeded")
	}
	err = e.deliver(context.Background(), sys, "target-token", "event", "user.created", u.ID, payload)
	if !errors.Is(err, errCreateUncertain) || posts != 1 {
		t.Fatalf("err=%v creates=%d", err, posts)
	}
}

func TestSCIMConflictAndRetryAfter(t *testing.T) {
	for _, status := range []int{409, 429} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			e, s, u, cleanup := setupTestSyncEngine(t)
			defer cleanup()
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					_, _ = w.Write([]byte(`{"totalResults":0,"Resources":[]}`))
					return
				}
				w.Header().Set("Retry-After", "600")
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"detail":"target-token"}`))
			}))
			defer srv.Close()
			e.httpClient = srv.Client()
			_, _, err := e.CreateSystem(&CreateSystemRequest{Name: "test", SystemType: "scim", CallbackURL: srv.URL, BearerToken: "target-token"})
			if err != nil {
				t.Fatal(err)
			}
			if err = func() error { queueForAll(t, e, u.ID, "user.created", UserToSCIMResource(u)); return nil }(); err != nil {
				t.Fatal(err)
			}
			before := time.Now()
			if err = e.DispatchPendingEvents(context.Background()); err != nil {
				t.Fatal(err)
			}
			events, err := s.GetDueSyncEvents(10)
			if err != nil {
				t.Fatal(err)
			}
			if len(events) != 0 {
				t.Fatal("retry ignored backoff")
			}
			pending, err := s.GetPendingSyncEvents(10)
			if err != nil || len(pending) != 1 || pending[0].Status != "pending" || strings.Contains(pending[0].LastError, "target-token") {
				t.Fatalf("bad failure record: %+v %v", pending, err)
			}
			if status == 429 && (pending[0].NextAttempt == nil || pending[0].NextAttempt.Before(before.Add(599*time.Second))) {
				t.Fatal("Retry-After ignored")
			}
		})
	}
}

func TestLegacyCustomDoesNotGuessProtocol(t *testing.T) {
	e, s, u, cleanup := setupTestSyncEngine(t)
	defer cleanup()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer srv.Close()
	sys := &store.PairedSystem{ID: "legacy", Name: "legacy", SystemType: "custom", CallbackURL: srv.URL + "/scim/v2", HMACSecretEncrypted: mustEncrypt(t, e, "old-secret"), Status: "active"}
	if err := s.CreatePairedSystem(sys); err != nil {
		t.Fatal(err)
	}
	if err := func() error { queueForAll(t, e, u.ID, "user.created", u); return nil }(); err != nil {
		t.Fatal(err)
	}
	if err := e.DispatchPendingEvents(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("ambiguous connector sent credentials")
	}
	events, err := s.GetDueSyncEvents(10)
	if err != nil || len(events) != 1 || events[0].Attempts != 0 {
		t.Fatalf("queue lost: %+v %v", events, err)
	}
}

func TestSCIMRedirectNeverForwardsCredentials(t *testing.T) {
	e, _, u, cleanup := setupTestSyncEngine(t)
	defer cleanup()
	hits := 0
	sink := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer sink.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/Users/remote" {
			_ = json.NewEncoder(w).Encode(scim.User{ID: "remote", ExternalID: u.ID, UserName: u.Username})
			return
		}
		http.Redirect(w, r, sink.URL+"/target-token", 307)
	}))
	defer source.Close()
	e.httpClient = source.Client()
	sys, _, err := e.CreateSystem(&CreateSystemRequest{Name: "redirect", SystemType: "scim", CallbackURL: source.URL, BearerToken: "target-token"})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(UserToSCIMResource(u))
	err = e.deliver(context.Background(), sys, "target-token", "event", "user.created", u.ID, body)
	if err == nil || hits != 0 || strings.Contains(deliveryError(err), "target-token") {
		t.Fatalf("redirect failure err=%v hits=%d", err, hits)
	}
	// Also exercise the shared client's write redirect path directly through a mapped user.
	if err = e.store.SaveSCIMUserLink(sys.ID, u.ID, "remote"); err != nil {
		t.Fatal(err)
	}
	err = e.deliver(context.Background(), sys, "target-token", "event", "user.updated", u.ID, body)
	if err == nil || hits != 0 || strings.Contains(deliveryError(err), "target-token") {
		t.Fatalf("write redirect failure err=%v hits=%d", err, hits)
	}
}

func TestGenericSCIMRejectsReassignedRemoteID(t *testing.T) {
	e, s, u, cleanup := setupTestSyncEngine(t)
	defer cleanup()
	writes := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"id":"reused","externalId":"someone-else","userName":"other"}`))
			return
		}
		writes++
		w.WriteHeader(204)
	}))
	defer srv.Close()
	e.httpClient = srv.Client()
	sys, _, err := e.CreateSystem(&CreateSystemRequest{Name: "reassigned", SystemType: "scim", CallbackURL: srv.URL, BearerToken: "token"})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SaveSCIMUserLink(sys.ID, u.ID, "reused"); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(UserToSCIMResource(u))
	err = e.deliver(context.Background(), sys, "token", "event", "user.updated", u.ID, body)
	if !errors.Is(err, scim.ErrMalformedResponse) || writes != 0 {
		t.Fatalf("unrelated account overwritten: err=%v writes=%d", err, writes)
	}
}
