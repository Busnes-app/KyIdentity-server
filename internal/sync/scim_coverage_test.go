package sync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	stdsync "sync"
	"testing"

	"github.com/Busnes-app/ky-primitives/scim"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// covCall is one request a covTarget received.
type covCall struct {
	method, path, filter, auth, body string
}

// covTarget is a TLS SCIM target driven by a per-test handler. It records every
// request so tests can assert exactly what reached the wire, and what did not.
type covTarget struct {
	mu     stdsync.Mutex
	calls  []covCall
	handle func(w http.ResponseWriter, r *http.Request, body []byte)
}

func (c *covTarget) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	c.calls = append(c.calls, covCall{r.Method, r.URL.Path, r.URL.Query().Get("filter"), r.Header.Get("Authorization"), string(body)})
	h := c.handle
	c.mu.Unlock()
	w.Header().Set("Content-Type", "application/scim+json")
	h(w, r, body)
}

func (c *covTarget) seen() []covCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]covCall(nil), c.calls...)
}

func (c *covTarget) count(method string) int {
	n := 0
	for _, call := range c.seen() {
		if call.method == method {
			n++
		}
	}
	return n
}

// covList renders a SCIM ListResponse body.
func covList(total int, resources ...map[string]any) string {
	if resources == nil {
		resources = []map[string]any{}
	}
	raw, _ := json.Marshal(map[string]any{"totalResults": total, "startIndex": 1, "Resources": resources})
	return string(raw)
}

// covSCIMSystem pairs a generic SCIM connector with a covTarget behind a TLS
// httptest server, following the package's loopback pattern for outbound targets.
func covSCIMSystem(t *testing.T, path string, handle func(w http.ResponseWriter, r *http.Request, body []byte)) (*Engine, *store.Store, *store.User, *store.PairedSystem, *covTarget) {
	t.Helper()
	e, s, u, cleanup := setupTestSyncEngine(t)
	t.Cleanup(cleanup)
	target := &covTarget{handle: handle}
	srv := httptest.NewTLSServer(target)
	t.Cleanup(srv.Close)
	e.httpClient = srv.Client()
	sys, _, err := e.CreateSystem(&CreateSystemRequest{Name: "target", SystemType: "scim", CallbackURL: srv.URL + path, BearerToken: "target-token"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return e, s, u, sys, target
}

func covUserPayload(t *testing.T, u *store.User) []byte {
	t.Helper()
	raw, err := json.Marshal(UserToSCIMResource(u))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Requests deliverSCIM must refuse before any network I/O: they carry nothing the
// target can safely apply, and must never reach it as a half-formed write.
func TestDeliverSCIMRefusesUnusableEventsWithoutRequests(t *testing.T) {
	e, _, u, sys, target := covSCIMSystem(t, "/scim/v2", func(w http.ResponseWriter, r *http.Request, _ []byte) {
		t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
	})
	payload := covUserPayload(t, u)
	for _, tc := range []struct {
		name, secret, event, id string
		payload                 []byte
		want                    error
		wantText                string
	}{
		{name: "missing local id", secret: "target-token", event: "user.created", payload: payload, wantText: "missing local user ID"},
		{name: "unsupported event", secret: "target-token", event: "user.renamed", id: u.ID, payload: payload, wantText: "unsupported user event"},
		{name: "empty token", secret: "", event: "user.created", id: u.ID, payload: payload, wantText: "bearer token"},
		{name: "token with space", secret: "a b", event: "user.created", id: u.ID, payload: payload, wantText: "bearer token"},
		{name: "payload not json", secret: "target-token", event: "user.created", id: u.ID, payload: []byte("not json"), want: scim.ErrMalformedResponse},
		{name: "active without userName", secret: "target-token", event: "user.updated", id: u.ID, payload: []byte(`{"active":true}`), want: scim.ErrMalformedResponse},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := e.deliverSCIM(context.Background(), sys, tc.secret, tc.event, tc.id, tc.payload)
			if err == nil {
				t.Fatal("refusal expected")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err=%v want %v", err, tc.want)
			}
			if tc.wantText != "" && !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("err=%v want text %q", err, tc.wantText)
			}
		})
	}
	// MFA state is never provisioned through generic SCIM: acknowledged, nothing sent.
	if err := e.deliverSCIM(context.Background(), sys, "target-token", "user.mfa_reset", u.ID, payload); err != nil {
		t.Fatal(err)
	}
	if calls := target.seen(); len(calls) != 0 {
		t.Fatalf("refused events reached the target: %+v", calls)
	}
}

// Scope loss for an account the target never held must not create it: one lookup,
// no POST, and no create marker that would later block a genuine create.
func TestDeliverSCIMInactiveUpdateForUnknownUserCreatesNothing(t *testing.T) {
	e, s, u, sys, target := covSCIMSystem(t, "/scim/v2", func(w http.ResponseWriter, r *http.Request, _ []byte) {
		_, _ = w.Write([]byte(covList(0)))
	})
	u.Status = "disabled"
	if err := e.deliverSCIM(context.Background(), sys, "target-token", "user.updated", u.ID, covUserPayload(t, u)); err != nil {
		t.Fatal(err)
	}
	calls := target.seen()
	if len(calls) != 1 || calls[0].method != "GET" || calls[0].filter != `externalId eq "`+u.ID+`"` {
		t.Fatalf("calls=%+v", calls)
	}
	if remoteID, started, err := s.SCIMUserLink(sys.ID, u.ID); err != nil || started || remoteID != "" {
		t.Fatal("deactivation left a create marker", remoteID, started, err)
	}
}

// A 409 on create whose externalId lookup then finds our user is our own create with
// a lost response: link it and PUT the profile, never POST a second account.
func TestDeliverSCIMConflictResolvedByLookupLinksExistingUser(t *testing.T) {
	var mu stdsync.Mutex
	posted := false
	e, s, u, sys, target := covSCIMSystem(t, "/scim/v2", func(w http.ResponseWriter, r *http.Request, body []byte) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == "GET" && r.URL.Path == "/scim/v2/Users":
			if !posted {
				_, _ = w.Write([]byte(covList(0)))
				return
			}
			ext := strings.TrimSuffix(strings.TrimPrefix(r.URL.Query().Get("filter"), `externalId eq "`), `"`)
			_, _ = w.Write([]byte(covList(1, map[string]any{"id": "remote-7", "externalId": ext})))
		case r.Method == "POST":
			posted = true
			w.WriteHeader(http.StatusConflict)
		case r.Method == "PUT" && r.URL.Path == "/scim/v2/Users/remote-7":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	})
	if err := e.deliverSCIM(context.Background(), sys, "target-token", "user.created", u.ID, covUserPayload(t, u)); err != nil {
		t.Fatal(err)
	}
	if target.count("POST") != 1 || target.count("PUT") != 1 {
		t.Fatalf("calls=%+v", target.seen())
	}
	if remoteID, _, err := s.SCIMUserLink(sys.ID, u.ID); err != nil || remoteID != "remote-7" {
		t.Fatal("conflict recovery did not link the found user", remoteID, err)
	}
	var put scimUserBody
	for _, c := range target.seen() {
		if c.method == "PUT" {
			if err := json.Unmarshal([]byte(c.body), &put); err != nil {
				t.Fatal(err)
			}
		}
	}
	if put.ExternalID != u.ID || put.UserName != u.Username || put.ID != "" {
		t.Fatalf("replace body %+v", put)
	}
}

// A 409 that no lookup explains is an unrelated conflict: it is returned as such, the
// create marker is cleared (the target refused), and nothing is linked.
func TestDeliverSCIMUnexplainedConflictIsNotSuccess(t *testing.T) {
	e, s, u, sys, target := covSCIMSystem(t, "/scim/v2", func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if r.Method == "GET" {
			_, _ = w.Write([]byte(covList(0)))
			return
		}
		w.WriteHeader(http.StatusConflict)
	})
	err := e.deliverSCIM(context.Background(), sys, "target-token", "user.created", u.ID, covUserPayload(t, u))
	if !errors.Is(err, scim.ErrConflict) {
		t.Fatalf("err=%v", err)
	}
	if remoteID, started, lerr := s.SCIMUserLink(sys.ID, u.ID); lerr != nil || started || remoteID != "" {
		t.Fatal("refused create left a link or marker", remoteID, started, lerr)
	}
	if target.count("POST") != 1 || target.count("PUT") != 0 {
		t.Fatalf("calls=%+v", target.seen())
	}
}

// A create answer that names a different externalId, or no usable ID, is never
// linked. The marker stays, so the next attempt reports an uncertain create instead of
// POSTing a duplicate account.
func TestDeliverSCIMMalformedCreateResponseFencesRetry(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"foreign externalId", `{"id":"remote-1","externalId":"someone-else"}`},
		{"no id", `{"externalId":"x"}`},
		{"dot id", `{"id":".."}`},
		{"not json", `<html>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, s, u, sys, target := covSCIMSystem(t, "/scim/v2", func(w http.ResponseWriter, r *http.Request, _ []byte) {
				if r.Method == "GET" {
					_, _ = w.Write([]byte(covList(0)))
					return
				}
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(tc.body))
			})
			payload := covUserPayload(t, u)
			if err := e.deliverSCIM(context.Background(), sys, "target-token", "user.created", u.ID, payload); !errors.Is(err, scim.ErrMalformedResponse) {
				t.Fatalf("err=%v", err)
			}
			if remoteID, started, err := s.SCIMUserLink(sys.ID, u.ID); err != nil || !started || remoteID != "" {
				t.Fatal("malformed create was linked or unfenced", remoteID, started, err)
			}
			if err := e.deliverSCIM(context.Background(), sys, "target-token", "user.created", u.ID, payload); !errors.Is(err, errCreateUncertain) {
				t.Fatalf("retry err=%v", err)
			}
			if target.count("POST") != 1 {
				t.Fatalf("create repeated: %+v", target.seen())
			}
		})
	}
}

// Deactivating through a stored mapping rechecks ownership, then PATCHes active=false.
// A target that has since dropped the account (404) has nothing left to deactivate.
func TestDeliverSCIMDeactivationThroughStoredMapping(t *testing.T) {
	var localID string
	e, s, u, sys, target := covSCIMSystem(t, "/scim/v2", func(w http.ResponseWriter, r *http.Request, _ []byte) {
		switch r.Method {
		case "GET":
			_, _ = fmt.Fprintf(w, `{"id":"r1","externalId":%q,"userName":"x"}`, localID)
		case "PATCH":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	})
	localID = u.ID
	if err := s.SaveSCIMUserLink(sys.ID, u.ID, "r1"); err != nil {
		t.Fatal(err)
	}
	if err := e.deliverSCIM(context.Background(), sys, "target-token", "user.deleted", u.ID, covUserPayload(t, u)); err != nil {
		t.Fatal(err)
	}
	calls := target.seen()
	if len(calls) != 2 || calls[0].method != "GET" || calls[0].path != "/scim/v2/Users/r1" || calls[1].method != "PATCH" || calls[1].path != "/scim/v2/Users/r1" {
		t.Fatalf("calls=%+v", calls)
	}
	var patch struct {
		Operations []scim.PatchOperation `json:"Operations"`
	}
	if err := json.Unmarshal([]byte(calls[1].body), &patch); err != nil || len(patch.Operations) != 1 || patch.Operations[0].Path != "active" || patch.Operations[0].Value != false {
		t.Fatalf("deactivation body %s %v", calls[1].body, err)
	}
	if target.count("DELETE") != 0 {
		t.Fatal("deletion erased downstream data")
	}
}

// covGroupSystem is covSCIMSystem with a local group the tests deliver directly.
func covGroupSystem(t *testing.T, handle func(w http.ResponseWriter, r *http.Request, body []byte)) (*Engine, *store.Store, *store.PairedSystem, *store.Group, *covTarget) {
	t.Helper()
	e, s, _, sys, target := covSCIMSystem(t, "/scim/v2", handle)
	group := &store.Group{ID: uuid.NewString(), Name: "staff"}
	if err := s.CreateGroup(group, nil); err != nil {
		t.Fatal(err)
	}
	return e, s, sys, group, target
}

// Group delivery refuses an event with no group ID or an unusable token before any
// request, and an unknown event type after the lookup without writing anything.
func TestDeliverSCIMGroupRefusals(t *testing.T) {
	e, s, sys, group, target := covGroupSystem(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		_, _ = w.Write([]byte(covList(0)))
	})
	ctx := context.Background()
	if err := e.deliverSCIMGroup(ctx, sys, "target-token", "group.updated", ""); err == nil || !strings.Contains(err.Error(), "missing local group ID") {
		t.Fatalf("err=%v", err)
	}
	if err := e.deliverSCIMGroup(ctx, sys, "", "group.updated", group.ID); err == nil {
		t.Fatal("empty token accepted")
	}
	if n := len(target.seen()); n != 0 {
		t.Fatalf("refusals reached the target: %d", n)
	}
	if err := e.deliverSCIMGroup(ctx, sys, "target-token", "group.renamed", group.ID); err == nil || !strings.Contains(err.Error(), "unsupported group event") {
		t.Fatalf("err=%v", err)
	}
	// Deleting a group the target never held is complete without a DELETE.
	if err := e.deliverSCIMGroup(ctx, sys, "target-token", "group.deleted", group.ID); err != nil {
		t.Fatal(err)
	}
	// A group already deleted locally waits for its own group.deleted: no create.
	if err := e.deliverSCIMGroup(ctx, sys, "target-token", "group.updated", uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if target.count("GET") != 3 || len(target.seen()) != 3 {
		t.Fatalf("only lookups expected: %+v", target.seen())
	}
	if remoteID, started, err := s.SCIMLink(sys.ID, "group", group.ID); err != nil || started || remoteID != "" {
		t.Fatal("refused events left a link", remoteID, started, err)
	}
}

// A group create sends the full member list (empty stated, not omitted), keyed by
// externalId, and links the ID the target assigned.
func TestDeliverSCIMGroupCreateLinksAssignedID(t *testing.T) {
	e, s, sys, group, target := covGroupSystem(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		if r.Method == "GET" {
			_, _ = w.Write([]byte(covList(0)))
			return
		}
		var g scimGroup
		_ = json.Unmarshal(body, &g)
		g.ID = "rg-9"
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(g)
	})
	if err := e.deliverSCIMGroup(context.Background(), sys, "target-token", "group.updated", group.ID); err != nil {
		t.Fatal(err)
	}
	calls := target.seen()
	if len(calls) != 2 || calls[1].method != "POST" || calls[1].path != "/scim/v2/Groups" || calls[1].auth != "Bearer target-token" {
		t.Fatalf("calls=%+v", calls)
	}
	if !strings.Contains(calls[1].body, `"members":[]`) || !strings.Contains(calls[1].body, `"externalId":"`+group.ID+`"`) || !strings.Contains(calls[1].body, `"displayName":"staff"`) {
		t.Fatalf("create body %s", calls[1].body)
	}
	if remoteID, _, err := s.SCIMLink(sys.ID, "group", group.ID); err != nil || remoteID != "rg-9" {
		t.Fatal("assigned ID not linked", remoteID, err)
	}
}

// A 4xx create refusal clears the marker so a corrected target can be retried; a 5xx
// may have been applied, so the marker stays and the retry is refused as uncertain.
func TestDeliverSCIMGroupCreateFailureClassification(t *testing.T) {
	for _, tc := range []struct {
		status    int
		cleared   bool
		wantRetry error
	}{
		{http.StatusBadRequest, true, nil},
		{http.StatusInternalServerError, false, errCreateUncertain},
		{http.StatusRequestTimeout, false, errCreateUncertain},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			e, s, sys, group, target := covGroupSystem(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
				if r.Method == "GET" {
					_, _ = w.Write([]byte(covList(0)))
					return
				}
				w.WriteHeader(tc.status)
			})
			err := e.deliverSCIMGroup(context.Background(), sys, "target-token", "group.updated", group.ID)
			var remote *scim.Error
			if !errors.As(err, &remote) || remote.Status != tc.status {
				t.Fatalf("err=%v", err)
			}
			_, started, lerr := s.SCIMLink(sys.ID, "group", group.ID)
			if lerr != nil || started == tc.cleared {
				t.Fatalf("marker started=%v want cleared=%v (%v)", started, tc.cleared, lerr)
			}
			err = e.deliverSCIMGroup(context.Background(), sys, "target-token", "group.updated", group.ID)
			wantPosts := 1
			if tc.cleared {
				wantPosts = 2
				if !errors.As(err, &remote) {
					t.Fatalf("retry err=%v", err)
				}
			} else if !errors.Is(err, tc.wantRetry) {
				t.Fatalf("retry err=%v", err)
			}
			if got := target.count("POST"); got != wantPosts {
				t.Fatalf("posts=%d want %d", got, wantPosts)
			}
		})
	}
}

// A group create answer naming a different externalId or no ID is never linked.
func TestDeliverSCIMGroupMalformedCreateResponse(t *testing.T) {
	for _, body := range []string{`{"id":"rg-1","externalId":"other"}`, `{"id":""}`, `{"id":"."}`, `nope`} {
		e, s, sys, group, _ := covGroupSystem(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
			if r.Method == "GET" {
				_, _ = w.Write([]byte(covList(0)))
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(body))
		})
		if err := e.deliverSCIMGroup(context.Background(), sys, "target-token", "group.updated", group.ID); !errors.Is(err, scim.ErrMalformedResponse) {
			t.Fatalf("%s: err=%v", body, err)
		}
		if remoteID, started, err := s.SCIMLink(sys.ID, "group", group.ID); err != nil || remoteID != "" || !started {
			t.Fatalf("%s: linked %q started=%v %v", body, remoteID, started, err)
		}
	}
}

// Deleting through a stored mapping keeps the link unless the target confirms the
// removal (200/204) or already lacks the group; a 202 or a 5xx keeps it for retry.
func TestDeliverSCIMGroupDeleteOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		get, del   int
		wantErr    error
		wantStatus int
		kept       bool
		deletes    int
	}{
		{name: "confirmed", get: 200, del: 204, deletes: 1},
		{name: "already gone on delete", get: 200, del: 404, deletes: 1},
		{name: "gone before delete", get: 404, deletes: 0},
		{name: "accepted only", get: 200, del: 202, wantErr: scim.ErrMalformedResponse, kept: true, deletes: 1},
		{name: "server error", get: 200, del: 500, wantStatus: 500, kept: true, deletes: 1},
		{name: "verify fails", get: 503, wantStatus: 503, kept: true, deletes: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var groupID string
			e, s, sys, group, target := covGroupSystem(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
				switch r.Method {
				case "GET":
					w.WriteHeader(tc.get)
					if tc.get == 200 {
						_, _ = fmt.Fprintf(w, `{"id":"rg-1","externalId":%q,"displayName":"staff","members":[]}`, groupID)
					}
				case "DELETE":
					w.WriteHeader(tc.del)
				default:
					w.WriteHeader(400)
				}
			})
			groupID = group.ID
			if err := s.SaveSCIMLink(sys.ID, "group", group.ID, "rg-1"); err != nil {
				t.Fatal(err)
			}
			err := e.deliverSCIMGroup(context.Background(), sys, "target-token", "group.deleted", group.ID)
			var remote *scim.Error
			switch {
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err=%v", err)
				}
			case tc.wantStatus != 0:
				if !errors.As(err, &remote) || remote.Status != tc.wantStatus {
					t.Fatalf("err=%v", err)
				}
			default:
				if err != nil {
					t.Fatal(err)
				}
			}
			remoteID, _, lerr := s.SCIMLink(sys.ID, "group", group.ID)
			if lerr != nil || (remoteID == "rg-1") != tc.kept {
				t.Fatalf("link %q kept-want=%v %v", remoteID, tc.kept, lerr)
			}
			if got := target.count("DELETE"); got != tc.deletes {
				t.Fatalf("deletes=%d want %d", got, tc.deletes)
			}
			for _, c := range target.seen() {
				if c.method == "DELETE" && c.path != "/scim/v2/Groups/rg-1" {
					t.Fatalf("delete path %s", c.path)
				}
			}
		})
	}
}

// A group whose create response was lost is found by externalId on the next update:
// the link is restored and the update PUT through it, with no second POST.
func TestGroupLostCreateResponseRecoveredByLookup(t *testing.T) {
	e, s, remote, group, cleanup := groupFixture(t)
	defer cleanup()
	systems, _ := s.ListAllPairedSystems()
	sysID := systems[0].ID
	before, _, _ := s.SCIMLink(sysID, "group", group.ID)
	execRaw(t, s, `DELETE FROM scim_user_links WHERE kind='group'`)
	group.Name = "renamed"
	if err := s.UpdateGroup(group, nil); err != nil {
		t.Fatal(err)
	}
	drain(t, e)
	if remote.posts["Groups"] != 1 {
		t.Fatal("lookup did not prevent a duplicate group", remote.posts)
	}
	if g, _ := remote.groupByExternal(group.ID); g.DisplayName != "renamed" || len(g.Members) != 1 {
		t.Fatal("update not applied through recovered link", g)
	}
	if after, _, err := s.SCIMLink(sysID, "group", group.ID); err != nil || after != before {
		t.Fatal("link not restored", before, after, err)
	}
}

// Two remote groups claiming one externalId are ambiguous: nothing is created or
// overwritten and the event stays pending with the fixed classification.
func TestGroupAmbiguousLookupLeavesEventPending(t *testing.T) {
	e, s, remote, group, cleanup := groupFixture(t)
	defer cleanup()
	execRaw(t, s, `DELETE FROM scim_user_links WHERE kind='group'`)
	remote.mu.Lock()
	remote.groups["dup"] = scimGroup{ID: "dup", ExternalID: group.ID, DisplayName: "copy"}
	remote.mu.Unlock()
	group.Name = "renamed"
	if err := s.UpdateGroup(group, nil); err != nil {
		t.Fatal(err)
	}
	drain(t, e)
	remote.mu.Lock()
	for _, g := range remote.groups {
		if g.DisplayName == "renamed" {
			t.Error("ambiguous group overwritten", g)
		}
	}
	posts := remote.posts["Groups"]
	remote.mu.Unlock()
	if posts != 1 {
		t.Fatal("ambiguous lookup created a group", posts)
	}
	pending, err := s.GetPendingSyncEvents(10)
	if err != nil || len(pending) != 1 || pending[0].EventType != "group.updated" || pending[0].LastError != scim.ErrAmbiguous.Error() {
		t.Fatalf("pending=%+v err=%v", pending, err)
	}
}

// A create marker without a remote ID, and no group found by externalId, means an
// earlier create's outcome is unknown: the update must not POST another group.
func TestGroupUnresolvedCreateMarkerBlocksSecondCreate(t *testing.T) {
	e, s, remote, group, cleanup := groupFixture(t)
	defer cleanup()
	execRaw(t, s, `UPDATE scim_user_links SET remote_id='' WHERE kind='group'`)
	remote.mu.Lock()
	remote.groups = map[string]scimGroup{}
	remote.mu.Unlock()
	group.Name = "renamed"
	if err := s.UpdateGroup(group, nil); err != nil {
		t.Fatal(err)
	}
	drain(t, e)
	if remote.posts["Groups"] != 1 {
		t.Fatal("unresolved create repeated", remote.posts)
	}
	pending, err := s.GetPendingSyncEvents(10)
	if err != nil || len(pending) != 1 || pending[0].LastError != errCreateUncertain.Error() {
		t.Fatalf("pending=%+v err=%v", pending, err)
	}
}

// Connection tests prove authenticated Users lookup only: a filtered GET with the
// stored Bearer token. Wrong protocol, unreadable secret, 401 and a non-200 answer fail.
func TestTestSystemOutcomes(t *testing.T) {
	status := http.StatusOK
	var mu stdsync.Mutex
	e, _, _, sys, target := covSCIMSystem(t, "/scim/v2/Users", func(w http.ResponseWriter, r *http.Request, _ []byte) {
		mu.Lock()
		defer mu.Unlock()
		w.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = w.Write([]byte(covList(0)))
		}
	})
	ctx := context.Background()
	if err := e.TestSystem(ctx, sys); err != nil {
		t.Fatal(err)
	}
	calls := target.seen()
	// The legacy /Users callback form is migrated, never doubled to /Users/Users.
	if len(calls) != 1 || calls[0].method != "GET" || calls[0].path != "/scim/v2/Users" || calls[0].filter != `externalId eq "kyidentity-connection-test"` || calls[0].auth != "Bearer target-token" {
		t.Fatalf("calls=%+v", calls)
	}
	mu.Lock()
	status = http.StatusUnauthorized
	mu.Unlock()
	if err := e.TestSystem(ctx, sys); !errors.Is(err, scim.ErrUnauthorized) {
		t.Fatalf("401 err=%v", err)
	}
	mu.Lock()
	status = http.StatusNoContent
	mu.Unlock()
	if err := e.TestSystem(ctx, sys); !errors.Is(err, scim.ErrMalformedResponse) {
		t.Fatalf("204 err=%v", err)
	}

	before := len(target.seen())
	suite := *sys
	suite.SystemType = "suite_webhook"
	if err := e.TestSystem(ctx, &suite); err == nil || !strings.Contains(err.Error(), "generic SCIM") {
		t.Fatalf("suite err=%v", err)
	}
	broken := *sys
	broken.HMACSecretEncrypted = mustEncrypt(t, e, uuid.NewString(), "target-token")
	if err := e.TestSystem(ctx, &broken); err == nil {
		t.Fatal("secret sealed for another connector opened")
	}
	empty := *sys
	empty.HMACSecretEncrypted = ""
	if _, err := e.SigningSecret(&empty); err == nil {
		t.Fatal("missing secret accepted")
	}
	if len(target.seen()) != before {
		t.Fatal("refused connection tests reached the target")
	}
}

// ReadBackSyncResource reports observation only, reading the collection matching the
// event type, and never surfaces remote text in its error.
func TestReadBackSyncResourceOutcomes(t *testing.T) {
	var mu stdsync.Mutex
	mode := "absent"
	e, _, u, sys, target := covSCIMSystem(t, "/scim/v2", func(w http.ResponseWriter, r *http.Request, _ []byte) {
		mu.Lock()
		defer mu.Unlock()
		ext := strings.TrimSuffix(strings.TrimPrefix(r.URL.Query().Get("filter"), `externalId eq "`), `"`)
		switch mode {
		case "absent":
			_, _ = w.Write([]byte(covList(0)))
		case "present":
			_, _ = w.Write([]byte(covList(1, map[string]any{"id": "rg-3", "externalId": ext})))
		default:
			w.WriteHeader(500)
			_, _ = w.Write([]byte(`{"detail":"target-token leaked"}`))
		}
	})
	ctx := context.Background()
	got, err := e.ReadBackSyncResource(ctx, sys, "user.created", u.ID)
	if err != nil || got["state"] != "absent" {
		t.Fatal(got, err)
	}
	mu.Lock()
	mode = "present"
	mu.Unlock()
	got, err = e.ReadBackSyncResource(ctx, sys, "group.updated", "grp-1")
	if err != nil || got["state"] != "present" || got["remoteId"] != "rg-3" {
		t.Fatal(got, err)
	}
	mu.Lock()
	mode = "fail"
	mu.Unlock()
	if _, err = e.ReadBackSyncResource(ctx, sys, "user.updated", u.ID); err == nil || strings.Contains(err.Error(), "target-token") || !strings.Contains(err.Error(), "read-back failed") {
		t.Fatalf("err=%v", err)
	}
	calls := target.seen()
	if len(calls) != 3 || calls[0].path != "/scim/v2/Users" || calls[1].path != "/scim/v2/Groups" || calls[1].filter != `externalId eq "grp-1"` {
		t.Fatalf("calls=%+v", calls)
	}
	for _, c := range calls {
		if c.method != "GET" {
			t.Fatalf("read-back wrote to the target: %+v", c)
		}
	}

	suite := *sys
	suite.SystemType = "suite_webhook"
	if got, err := e.ReadBackSyncResource(ctx, &suite, "user.created", u.ID); err != nil || got["state"] != "unsupported" {
		t.Fatal(got, err)
	}
	broken := *sys
	broken.HMACSecretEncrypted = "not-a-sealed-secret"
	if _, err := e.ReadBackSyncResource(ctx, &broken, "user.created", u.ID); err == nil {
		t.Fatal("unreadable secret accepted")
	}
	if len(target.seen()) != 3 {
		t.Fatal("unsupported or unreadable connectors reached the target")
	}
}

// ReviewSystem only allows protocol choices an administrator can make safely: a SCIM
// token replacement, the group/reconcile flags on SCIM, and an explicit choice for a
// legacy custom connector. Every refusal leaves the stored connector unchanged.
func TestReviewSystemRefusalsAndChanges(t *testing.T) {
	e, s, _, sys, _ := covSCIMSystem(t, "/scim/v2", func(w http.ResponseWriter, r *http.Request, _ []byte) {})
	var input store.InputError
	for _, tc := range []struct {
		name, kind, token string
		groups            bool
		hours             int
	}{
		{"unknown kind", "ldap", "", false, 0},
		{"protocol switch", "suite_webhook", "", false, 0},
		{"token with space", "scim", "bad token", false, 0},
	} {
		if err := e.ReviewSystem(sys, tc.kind, tc.token, tc.groups, tc.hours, nil); !errors.As(err, &input) {
			t.Fatalf("%s: err=%v", tc.name, err)
		}
	}
	reload := func(id string) *store.PairedSystem {
		t.Helper()
		got, err := s.GetPairedSystemByID(id)
		if err != nil || got == nil {
			t.Fatal(got, err)
		}
		return got
	}
	if secret, err := e.SigningSecret(reload(sys.ID)); err != nil || secret != "target-token" {
		t.Fatal("refused review changed the token", secret, err)
	}
	if err := e.ReviewSystem(sys, "scim", "new-token", true, 12, nil); err != nil {
		t.Fatal(err)
	}
	after := reload(sys.ID)
	if secret, err := e.SigningSecret(after); err != nil || secret != "new-token" || !after.GroupsEnabled || after.ReconcileHours != 12 {
		t.Fatalf("token replacement not stored: %q %v %+v", secret, err, after)
	}
	// No token supplied keeps the established one.
	if err := e.ReviewSystem(after, "scim", "", false, 0, nil); err != nil {
		t.Fatal(err)
	}
	if secret, _ := e.SigningSecret(reload(sys.ID)); secret != "new-token" {
		t.Fatal("empty token replaced the stored one", secret)
	}

	// A suite webhook cannot gain group delivery, reconciliation, or a supplied secret.
	suite, secret, err := e.CreateSystem(&CreateSystemRequest{Name: "suite", SystemType: "suite_webhook", CallbackURL: "https://suite.example.test/hook"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		token  string
		groups bool
		hours  int
	}{{"", true, 0}, {"", false, 6}, {"chosen", false, 0}} {
		if err := e.ReviewSystem(suite, "suite_webhook", tc.token, tc.groups, tc.hours, nil); !errors.As(err, &input) {
			t.Fatalf("suite %+v err=%v", tc, err)
		}
	}
	if got, _ := e.SigningSecret(reload(suite.ID)); got != secret {
		t.Fatal("suite secret changed")
	}

	// A legacy custom connector needs a token to become SCIM, keeps its secret to become
	// a suite webhook.
	execRaw(t, s, `UPDATE paired_systems SET system_type='custom' WHERE id=?`, suite.ID)
	custom := reload(suite.ID)
	if err := e.ReviewSystem(custom, "scim", "", false, 0, nil); !errors.As(err, &input) {
		t.Fatalf("tokenless SCIM choice err=%v", err)
	}
	if err := e.ReviewSystem(custom, "suite_webhook", "", false, 0, nil); err != nil {
		t.Fatal(err)
	}
	if got := reload(suite.ID); got.SystemType != "suite_webhook" {
		t.Fatal("explicit choice not stored", got.SystemType)
	} else if s2, _ := e.SigningSecret(got); s2 != secret {
		t.Fatal("suite choice replaced the signing secret")
	}
}

// covListingTarget answers unfiltered Users listings from pages in order.
func covListingTarget(pages []string, statuses []int) func(w http.ResponseWriter, r *http.Request, _ []byte) {
	var mu stdsync.Mutex
	n := 0
	return func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if r.Method != "GET" || r.URL.Query().Get("filter") != "" {
			w.WriteHeader(400)
			return
		}
		mu.Lock()
		i := min(n, len(pages)-1)
		n++
		mu.Unlock()
		if statuses != nil && statuses[i] != 0 {
			w.WriteHeader(statuses[i])
		}
		_, _ = w.Write([]byte(pages[i]))
	}
}

// Any listing that cannot be trusted as the whole collection makes the run incomplete
// with a fixed reason, so reconciliation infers no missing, stale or orphaned accounts.
func TestReconcileListingFailsClosed(t *testing.T) {
	a := map[string]any{"id": "a", "externalId": "x-a", "userName": "a"}
	b := map[string]any{"id": "b", "externalId": "x-b", "userName": "b"}
	for _, tc := range []struct {
		name     string
		pages    []string
		statuses []int
	}{
		{"no content", []string{""}, []int{204}},
		{"not json", []string{"<html>"}, nil},
		{"negative total", []string{`{"totalResults":-1,"Resources":[]}`}, nil},
		{"wrong start", []string{`{"totalResults":1,"startIndex":5,"Resources":[]}`}, nil},
		{"total changes", []string{covList(3, a, b), `{"totalResults":4,"startIndex":3,"Resources":[{"id":"c"}]}`}, nil},
		{"too large", []string{covList(20001, a)}, nil},
		{"short listing", []string{covList(3, a, b), `{"totalResults":3,"startIndex":3,"Resources":[]}`}, nil},
		{"more than total", []string{covList(1, a, b)}, nil},
		{"duplicate id", []string{covList(2, a, a)}, nil},
		{"empty id", []string{covList(1, map[string]any{"externalId": "x"})}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, s, _, sys, target := covSCIMSystem(t, "/scim/v2", covListingTarget(tc.pages, tc.statuses))
			report := runJob(t, e, s, sys.ID, "repair")
			if !report.Supported || report.Complete || report.ListingError != scim.ErrMalformedResponse.Error() {
				t.Fatalf("report %+v", report)
			}
			if report.OrphanedCount != 0 || report.StaleCount != 0 {
				t.Fatalf("incomplete listing inferred drift: %+v", report)
			}
			for _, c := range target.seen() {
				if c.method != "GET" {
					t.Fatalf("incomplete listing wrote to the target: %+v", c)
				}
			}
		})
	}
}

// With group delivery on, a failed Groups listing marks the run incomplete even
// though Users listed cleanly; remote status text is reduced to the fixed form.
func TestReconcileGroupListingFailureIsIncomplete(t *testing.T) {
	e, s, _, sys, _ := covSCIMSystem(t, "/scim/v2", func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if strings.HasSuffix(r.URL.Path, "/Groups") {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("target-token"))
			return
		}
		_, _ = w.Write([]byte(covList(0)))
	})
	if err := e.ReviewSystem(sys, "scim", "", true, 0, nil); err != nil {
		t.Fatal(err)
	}
	report := runJob(t, e, s, sys.ID, "preview")
	if report.Complete || report.ListingError != "SCIM HTTP 502" {
		t.Fatalf("report %+v", report)
	}
}

// A connector whose stored token cannot be opened is reported, not listed, and the
// reason carries no secret material.
func TestReconcileUnreadableSecretIsReported(t *testing.T) {
	e, s, _, sys, target := covSCIMSystem(t, "/scim/v2", func(w http.ResponseWriter, r *http.Request, _ []byte) {
		_, _ = w.Write([]byte(covList(0)))
	})
	execRaw(t, s, `UPDATE paired_systems SET hmac_secret_encrypted=? WHERE id=?`, mustEncrypt(t, e, uuid.NewString(), "target-token"), sys.ID)
	report := runJob(t, e, s, sys.ID, "repair")
	if report.Complete || report.ListingError == "" || strings.Contains(report.ListingError, "target-token") {
		t.Fatalf("report %+v", report)
	}
	if len(target.seen()) != 0 {
		t.Fatal("listed without a usable token")
	}
}
