package sync

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path"
	"sort"
	"strconv"
	"strings"
	stdsync "sync"
	"testing"
	"time"

	"github.com/Busness-app/ky-primitives/scim"
	"github.com/Busness-app/kysignon-server/internal/store"
	"github.com/google/uuid"
)

// fakeSCIM is a minimal Users+Groups server that assigns its own IDs and supports the
// externalId filter, PUT, PATCH active and DELETE, so tests observe real HTTP effects.
type fakeSCIM struct {
	mu     stdsync.Mutex
	users  map[string]scim.User
	groups map[string]scimGroup
	posts  map[string]int
	next   int
	// putStatus, when set, is answered to every Group PUT without applying it.
	putStatus int
	// failPage, when set, answers 500 to that unfiltered listing page (1-based).
	failPage int
	pages    int
	// pageDelay slows every unfiltered listing page.
	pageDelay time.Duration
}

func newFakeSCIM() *fakeSCIM {
	return &fakeSCIM{users: map[string]scim.User{}, groups: map[string]scimGroup{}, posts: map[string]int{}}
}

func (f *fakeSCIM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer target-token" {
		w.WriteHeader(401)
		return
	}
	w.Header().Set("Content-Type", "application/scim+json")
	collection, id := path.Base(path.Dir(r.URL.Path)), path.Base(r.URL.Path)
	if id == "Users" || id == "Groups" {
		collection, id = id, ""
	}
	external := strings.TrimSuffix(strings.TrimPrefix(r.URL.Query().Get("filter"), `externalId eq "`), `"`)
	switch {
	case r.Method == "GET" && id == "" && r.URL.Query().Get("filter") == "":
		// Unfiltered listing: stable order, honours startIndex/count, optionally fails a page.
		f.pages++
		if f.pages == f.failPage {
			w.WriteHeader(500)
			return
		}
		if f.pageDelay > 0 {
			f.mu.Unlock()
			time.Sleep(f.pageDelay)
			f.mu.Lock()
		}
		var all []any
		if collection == "Users" {
			ids := make([]string, 0, len(f.users))
			for id := range f.users {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			for _, id := range ids {
				all = append(all, f.users[id])
			}
		} else {
			ids := make([]string, 0, len(f.groups))
			for id := range f.groups {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			for _, id := range ids {
				all = append(all, f.groups[id])
			}
		}
		start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
		count, _ := strconv.Atoi(r.URL.Query().Get("count"))
		if start < 1 {
			start = 1
		}
		if count < 1 || count > 2 {
			count = 2 // Small pages force multi-page walks in tests.
		}
		page := []any{}
		for i := start - 1; i < len(all) && len(page) < count; i++ {
			page = append(page, all[i])
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"totalResults": len(all), "startIndex": start, "itemsPerPage": len(page), "Resources": page})
	case r.Method == "GET" && id == "" && collection == "Users":
		found := []scim.User{}
		for _, u := range f.users {
			if u.ExternalID == external {
				found = append(found, u)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"totalResults": len(found), "startIndex": 1, "Resources": found})
	case r.Method == "GET" && id == "" && collection == "Groups":
		found := []scimGroup{}
		for _, g := range f.groups {
			if g.ExternalID == external {
				found = append(found, g)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"totalResults": len(found), "startIndex": 1, "Resources": found})
	case r.Method == "POST" && collection == "Users":
		var u scim.User
		_ = json.NewDecoder(r.Body).Decode(&u)
		f.next++
		u.ID = "u" + strconv.Itoa(f.next)
		f.users[u.ID] = u
		f.posts["Users"]++
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(u)
	case r.Method == "POST" && collection == "Groups":
		var g scimGroup
		_ = json.NewDecoder(r.Body).Decode(&g)
		f.next++
		g.ID = "g" + strconv.Itoa(f.next)
		f.groups[g.ID] = g
		f.posts["Groups"]++
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(g)
	case collection == "Users":
		u, ok := f.users[id]
		if !ok {
			w.WriteHeader(404)
			return
		}
		switch r.Method {
		case "GET":
		case "PUT":
			_ = json.NewDecoder(r.Body).Decode(&u)
			u.ID = id
		case "PATCH":
			var patch struct{ Operations []scim.PatchOperation }
			_ = json.NewDecoder(r.Body).Decode(&patch)
			for _, op := range patch.Operations {
				if op.Path == "active" {
					u.Active = op.Value == true
				}
			}
		}
		f.users[id] = u
		_ = json.NewEncoder(w).Encode(u)
	case collection == "Groups":
		g, ok := f.groups[id]
		if !ok {
			w.WriteHeader(404)
			return
		}
		switch r.Method {
		case "PUT":
			if f.putStatus != 0 {
				w.WriteHeader(f.putStatus)
				return
			}
			_ = json.NewDecoder(r.Body).Decode(&g)
			g.ID = id
			f.groups[id] = g
		case "DELETE":
			delete(f.groups, id)
			w.WriteHeader(204)
			return
		}
		_ = json.NewEncoder(w).Encode(g)
	default:
		w.WriteHeader(400)
	}
}

func (f *fakeSCIM) userByExternal(external string) (scim.User, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.users {
		if u.ExternalID == external {
			return u, true
		}
	}
	return scim.User{}, false
}

func (f *fakeSCIM) groupByExternal(external string) (scimGroup, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, g := range f.groups {
		if g.ExternalID == external {
			return g, true
		}
	}
	return scimGroup{}, false
}

func appRecordFor(t *testing.T, s *store.Store, systemID string) store.AppRecord {
	t.Helper()
	apps, _, err := s.ListAppRecords("", 1000, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range apps {
		if a.SystemID == systemID {
			return a
		}
	}
	t.Fatalf("no app record for %s", systemID)
	return store.AppRecord{}
}

func drain(t *testing.T, e *Engine) {
	t.Helper()
	for i := 0; i < 5; i++ {
		if err := e.DispatchPendingEvents(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGenericSCIMFollowsAssignments(t *testing.T) {
	e, s, u, cleanup := setupTestSyncEngine(t)
	defer cleanup()
	remote := newFakeSCIM()
	srv := httptest.NewTLSServer(remote)
	defer srv.Close()
	e.httpClient = srv.Client()
	sys, _, err := e.CreateSystem(&CreateSystemRequest{Name: "target", SystemType: "scim", CallbackURL: srv.URL + "/scim/v2", BearerToken: "target-token"})
	if err != nil {
		t.Fatal(err)
	}
	other := &store.User{ID: uuid.NewString(), Username: "other", DisplayName: "Other", Email: "other@example.com", PasswordHash: "x", Role: "user", Status: "active"}
	if err := s.CreateUser(other); err != nil {
		t.Fatal(err)
	}
	app := appRecordFor(t, s, sys.ID)
	group := &store.Group{ID: uuid.NewString(), Name: "staff"}
	if err := s.CreateGroup(group, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGroupMembership(group.ID, u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppAssignment(app.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppAssignment(app.ID, "groups", group.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	drain(t, e)
	created, ok := remote.userByExternal(u.ID)
	if !ok || !created.Active {
		t.Fatal("assigned user not provisioned", created, ok)
	}
	if _, ok := remote.userByExternal(other.ID); ok {
		t.Fatal("unassigned user provisioned")
	}
	if err := e.ResyncAllAccounts(sys.ID); err != nil {
		t.Fatal(err)
	}
	drain(t, e)
	if _, ok := remote.userByExternal(other.ID); ok || remote.posts["Users"] != 1 {
		t.Fatal("resync provisioned an unassigned user", ok, remote.posts)
	}
	// One of two grants goes: the account stays active.
	if err := s.SetAppAssignment(app.ID, "users", u.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	drain(t, e)
	if got, _ := remote.userByExternal(u.ID); !got.Active {
		t.Fatal("removing one grant deactivated the account")
	}
	if err := s.SetAppAssignment(app.ID, "groups", group.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	drain(t, e)
	if got, _ := remote.userByExternal(u.ID); got.Active {
		t.Fatal("final removal left the account active")
	}
	if err := s.SetAppAssignment(app.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	drain(t, e)
	if got, _ := remote.userByExternal(u.ID); !got.Active || remote.posts["Users"] != 1 {
		t.Fatal("regain did not reactivate the existing account", got, remote.posts)
	}
	// A deactivation for an account the target no longer holds creates nothing.
	remote.mu.Lock()
	remote.users = map[string]scim.User{}
	remote.mu.Unlock()
	if err := s.SetAppAssignment(app.ID, "users", u.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	drain(t, e)
	if remote.posts["Users"] != 1 {
		t.Fatal("deactivation created an account", remote.posts)
	}
	pending, err := s.GetPendingSyncEvents(10)
	if err != nil || len(pending) != 0 {
		t.Fatal("undelivered work remains", pending, err)
	}
}

func TestGenericSCIMGroupDelivery(t *testing.T) {
	e, s, u, cleanup := setupTestSyncEngine(t)
	defer cleanup()
	remote := newFakeSCIM()
	srv := httptest.NewTLSServer(remote)
	defer srv.Close()
	e.httpClient = srv.Client()
	sys, _, err := e.CreateSystem(&CreateSystemRequest{Name: "target", SystemType: "scim", CallbackURL: srv.URL + "/scim/v2", BearerToken: "target-token"})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.ReviewSystem(sys, "scim", "", true, 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.ReviewSystem(&store.PairedSystem{ID: sys.ID, SystemType: "suite_webhook"}, "suite_webhook", "", true, 0, nil); err == nil {
		t.Fatal("suite connector accepted group delivery")
	}
	sys, _ = s.GetPairedSystemByID(sys.ID)
	if !sys.GroupsEnabled {
		t.Fatal("flag not persisted")
	}
	app := appRecordFor(t, s, sys.ID)
	second := &store.User{ID: uuid.NewString(), Username: "second", DisplayName: "Second", Email: "second@example.com", PasswordHash: "x", Role: "user", Status: "active"}
	if err := s.CreateUser(second); err != nil {
		t.Fatal(err)
	}
	group := &store.Group{ID: uuid.NewString(), Name: "staff"}
	if err := s.CreateGroup(group, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGroupMembership(group.ID, u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppAssignment(app.ID, "groups", group.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	drain(t, e)
	members := func() []string {
		g, ok := remote.groupByExternal(group.ID)
		if !ok {
			return nil
		}
		out := []string{}
		for _, m := range g.Members {
			out = append(out, m.Value)
		}
		return out
	}
	first, _ := remote.userByExternal(u.ID)
	if got := members(); len(got) != 1 || got[0] != first.ID {
		t.Fatal("group not delivered with its provisioned member", got, first.ID)
	}
	if err := s.SetGroupMembership(group.ID, second.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	drain(t, e)
	if got := members(); len(got) != 2 {
		t.Fatal("new member missing after its create", got)
	}
	if err := s.SetGroupMembership(group.ID, second.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	drain(t, e)
	if got := members(); len(got) != 1 || got[0] != first.ID {
		t.Fatal("removed member kept", got)
	}
	if got, _ := remote.userByExternal(second.ID); got.Active {
		t.Fatal("member that lost scope stayed active")
	}
	if g, _ := remote.groupByExternal(group.ID); g.DisplayName != "staff" || remote.posts["Groups"] != 1 {
		t.Fatal(g, remote.posts)
	}
	if err := s.SetAppAssignment(app.ID, "groups", group.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	drain(t, e)
	if _, ok := remote.groupByExternal(group.ID); ok {
		t.Fatal("unassigned group survived at the target")
	}
	pending, err := s.GetPendingSyncEvents(10)
	if err != nil || len(pending) != 0 {
		t.Fatal("undelivered work remains", pending, err)
	}
}

func groupFixture(t *testing.T) (*Engine, *store.Store, *fakeSCIM, *store.Group, func()) {
	t.Helper()
	e, s, u, cleanup := setupTestSyncEngine(t)
	remote := newFakeSCIM()
	srv := httptest.NewTLSServer(remote)
	e.httpClient = srv.Client()
	sys, _, err := e.CreateSystem(&CreateSystemRequest{Name: "target", SystemType: "scim", CallbackURL: srv.URL + "/scim/v2", BearerToken: "target-token"})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.ReviewSystem(sys, "scim", "", true, 0, nil); err != nil {
		t.Fatal(err)
	}
	app := appRecordFor(t, s, sys.ID)
	group := &store.Group{ID: uuid.NewString(), Name: "staff"}
	if err := s.CreateGroup(group, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGroupMembership(group.ID, u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppAssignment(app.ID, "groups", group.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	drain(t, e)
	if g, ok := remote.groupByExternal(group.ID); !ok || len(g.Members) != 1 {
		t.Fatal("fixture group not delivered", g, ok)
	}
	return e, s, remote, group, func() { srv.Close(); cleanup() }
}

func TestGroupWriteRefusesForeignMapping(t *testing.T) {
	e, s, remote, group, cleanup := groupFixture(t)
	defer cleanup()
	// The target restored from backup: our stored ID now names someone else's group.
	remote.mu.Lock()
	for id, g := range remote.groups {
		g.ExternalID = "foreign"
		remote.groups[id] = g
	}
	remote.mu.Unlock()
	group.Name = "renamed"
	if err := s.UpdateGroup(group, nil); err != nil {
		t.Fatal(err)
	}
	drain(t, e)
	remote.mu.Lock()
	defer remote.mu.Unlock()
	for _, g := range remote.groups {
		if g.DisplayName != "staff" || len(g.Members) != 1 {
			t.Fatal("foreign group overwritten", g)
		}
	}
	if pending, _ := s.GetPendingSyncEvents(10); len(pending) != 1 || pending[0].EventType != "group.updated" {
		t.Fatal("refused write not retained", pending)
	}
}

func TestGroupWriteRequiresCompletion(t *testing.T) {
	e, s, remote, group, cleanup := groupFixture(t)
	defer cleanup()
	remote.mu.Lock()
	remote.putStatus = http.StatusAccepted
	remote.mu.Unlock()
	group.Name = "renamed"
	if err := s.UpdateGroup(group, nil); err != nil {
		t.Fatal(err)
	}
	drain(t, e)
	if g, _ := remote.groupByExternal(group.ID); g.DisplayName != "staff" {
		t.Fatal("unapplied write changed the fake", g)
	}
	sys, _ := s.ListAllPairedSystems()
	attempts, err := s.ListSyncDeliveryAttempts(sys[0].ID)
	if err != nil || len(attempts) != 1 || attempts[0].EventType != "group.updated" {
		t.Fatal("202 did not stay fenced as uncertain", attempts, err)
	}
	if pending, _ := s.GetPendingSyncEvents(10); len(pending) != 1 {
		t.Fatal("accepted write recorded as delivered", pending)
	}
}

type suiteHit struct {
	revision int
	active   bool
	event    string
}

// newSuiteReceiver records every signed suite event per user with its meta.version, and
// answers 404 for users it has never seen so inactive updates can prove their acceptance.
func newSuiteReceiver(t *testing.T, delay time.Duration) (*httptest.Server, func() map[string][]suiteHit) {
	var mu stdsync.Mutex
	hits := map[string][]suiteHit{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body SCIMUserResource
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Meta == nil {
			t.Error("bad suite body", err)
			w.WriteHeader(400)
			return
		}
		rev, err := strconv.Atoi(strings.Trim(strings.TrimPrefix(body.Meta.Version, "W/"), `"`))
		if err != nil {
			t.Errorf("bad version %q", body.Meta.Version)
		}
		mu.Lock()
		known := len(hits[body.ID]) > 0
		hits[body.ID] = append(hits[body.ID], suiteHit{revision: rev, active: body.Active, event: r.Header.Get("X-KySignOn-Event-Type")})
		mu.Unlock()
		time.Sleep(delay)
		if !known && r.Header.Get("X-KySignOn-Event-Type") != "user.created" {
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(200)
	}))
	return srv, func() map[string][]suiteHit {
		mu.Lock()
		defer mu.Unlock()
		out := map[string][]suiteHit{}
		for k, v := range hits {
			out[k] = append([]suiteHit(nil), v...)
		}
		return out
	}
}

func TestSuiteReceiverRevisionsAndInactiveNotFound(t *testing.T) {
	e, s, u, cleanup := setupTestSyncEngine(t)
	defer cleanup()
	srv, hits := newSuiteReceiver(t, 0)
	defer srv.Close()
	sys, _, err := e.CreateSystem(&CreateSystemRequest{Name: "suite", SystemType: "suite_webhook", CallbackURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	app := appRecordFor(t, s, sys.ID)
	if err := s.SetAppAssignment(app.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	drain(t, e)
	if err := s.SetAppAssignment(app.ID, "users", u.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	drain(t, e)
	got := hits()[u.ID]
	if len(got) != 2 || got[0] != (suiteHit{1, true, "user.created"}) || got[1] != (suiteHit{2, false, "user.updated"}) {
		t.Fatalf("suite sequence %+v", got)
	}
	// A receiver that never held a disabled account answers 404; that completes the disable.
	stranger := &store.User{ID: uuid.NewString(), Username: "stranger", DisplayName: "S", Email: "s@example.com", PasswordHash: "x", Role: "user", Status: "active"}
	if err := s.CreateUser(stranger); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppAssignment(app.ID, "users", stranger.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	ev, err := s.ClaimDueSyncEvents(10, time.Minute)
	if err != nil || len(ev) != 1 {
		t.Fatal(ev, err)
	}
	if ok, err := s.BeginSyncDelivery(ev[0], time.Minute); err != nil || !ok {
		t.Fatal(ok, err)
	}
	// The create is fenced when scope is lost, so the disable queues behind it; the
	// fenced create is then abandoned without ever reaching the receiver.
	if err := s.SetAppAssignment(app.ID, "users", stranger.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishSyncDelivery(ev[0], "failed", "rejected", 5, nil); err != nil {
		t.Fatal(err)
	}
	drain(t, e)
	if got := hits()[stranger.ID]; len(got) != 1 || got[0] != (suiteHit{2, false, "user.updated"}) {
		t.Fatalf("inactive update after 404: %+v", got)
	}
	pending, err := s.GetPendingSyncEvents(10)
	if err != nil || len(pending) != 0 {
		t.Fatal("undelivered work remains", pending, err)
	}
}

func TestConcurrentDispatchAndRestartPreserveOrdering(t *testing.T) {
	e, s, u, cleanup := setupTestSyncEngine(t)
	defer cleanup()
	srv, hits := newSuiteReceiver(t, 20*time.Millisecond)
	defer srv.Close()
	sys, _, err := e.CreateSystem(&CreateSystemRequest{Name: "suite", SystemType: "suite_webhook", CallbackURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	app := appRecordFor(t, s, sys.ID)
	dispatchers := func(eng *Engine) {
		var wg stdsync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = eng.DispatchPendingEvents(context.Background())
			}()
		}
		wg.Wait()
	}
	assigned := false
	for i := 0; i < 6; i++ {
		assigned = !assigned
		if err := s.SetAppAssignment(app.ID, "users", u.ID, assigned, nil); err != nil {
			t.Fatal(err)
		}
		dispatchers(e)
	}
	// A restart dispatches whatever the previous process left queued.
	restarted := NewEngine(s, e.encryptionKey)
	for i := 0; i < 5; i++ {
		dispatchers(restarted)
	}
	got := hits()[u.ID]
	if len(got) == 0 {
		t.Fatal("nothing delivered")
	}
	for i := 1; i < len(got); i++ {
		if got[i].revision <= got[i-1].revision {
			t.Fatalf("revision went backwards: %+v", got)
		}
	}
	if got[len(got)-1].active != assigned {
		t.Fatalf("final remote state %v, desired %v: %+v", got[len(got)-1].active, assigned, got)
	}
	pending, err := s.GetPendingSyncEvents(10)
	if err != nil || len(pending) != 0 {
		t.Fatal("undelivered work remains", pending, err)
	}
}
