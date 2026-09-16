package sync

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	stdsync "sync"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/netguard"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

func setupSync(t *testing.T) (*Engine, *store.Store, *store.User, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "kyidentity-sync-sec-*")
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	key, _ := crypto.GenerateRandomBytes(32)
	admin := &store.User{
		ID: uuid.New().String(), Username: "admin" + uuid.New().String()[:6],
		DisplayName: "A", Email: uuid.New().String()[:6] + "@x.test",
		PasswordHash: "x", Role: "admin", Status: "active",
	}
	if err := db.CreateUser(admin); err != nil {
		t.Fatal(err)
	}
	// These tests point callbacks at httptest servers on loopback.
	netguard.AllowPrivate = true
	t.Cleanup(func() { netguard.AllowPrivate = false })

	return NewEngine(db, key), db, admin, func() {
		_ = db.Close()
		_ = os.RemoveAll(dir)
	}
}

// The callback URL must not be able to name an internal address unless explicitly allowed.
func TestCallbackURLIsValidated(t *testing.T) {
	e, _, _, cleanup := setupSync(t)
	defer cleanup()
	netguard.AllowPrivate = false // the production default

	rejected := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://127.0.0.1:5867/api/admin/users",
		"http://[::1]:8080/hook",
		"file:///etc/passwd",
		"gopher://evil.test/_x",
		"https://10.89.0.2/internal",
		"not a url at all",
		"",
	}
	for _, target := range rejected {
		if _, _, err := e.CreateSystem(&CreateSystemRequest{
			Name: "x", SystemType: "kypost", CallbackURL: target,
		}); err == nil {
			t.Errorf("callback URL %q was accepted", target)
		}
	}
}

// Events must reach only the system they belong to. Fanning every user record out to every
// paired system means the least trusted integration receives the whole directory.
func TestEventsAreScopedToTheirSystem(t *testing.T) {
	e, db, _, cleanup := setupSync(t)
	defer cleanup()

	var hitsA, hitsB int
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hitsA++ }))
	defer srvA.Close()
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hitsB++ }))
	defer srvB.Close()

	pair := func(name, url string) string {
		ps, _, err := e.CreateSystem(&CreateSystemRequest{
			Name: name, SystemType: "suite_webhook", CallbackURL: url,
		})
		if err != nil {
			t.Fatalf("pairing %s: %v", name, err)
		}
		return ps.ID
	}

	idA := pair("system-a", srvA.URL)
	idB := pair("system-b", srvB.URL)
	grantAllUsers(t, db, idA)
	grantAllUsers(t, db, idB)
	// Scope grants queue creates for both systems; only the resync must reach A.
	if err := e.DispatchPendingEvents(context.Background()); err != nil {
		t.Fatal(err)
	}
	hitsA, hitsB = 0, 0

	if err := e.ResyncAllAccounts(idA); err != nil {
		t.Fatal(err)
	}
	if err := e.DispatchPendingEvents(context.Background()); err != nil {
		t.Fatal(err)
	}

	if hitsA == 0 {
		t.Error("the system that was resynced received nothing")
	}
	if hitsB != 0 {
		t.Errorf("resyncing system A delivered %d event(s) to system B", hitsB)
	}
	_ = db
}

// Delivery being impossible right now is not delivery. An event queued for a system that
// is temporarily disabled must wait for it, not be marked delivered and dropped, or a
// deprovision silently never reaches a downstream that still holds the account.
func TestUndeliverableEventStaysQueued(t *testing.T) {
	e, db, _, cleanup := setupSync(t)
	defer cleanup()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	ps, _, err := e.CreateSystem(&CreateSystemRequest{
		Name: "mail", SystemType: "suite_webhook", CallbackURL: srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	u := &store.User{
		ID: uuid.New().String(), Username: "leaver", DisplayName: "L", Email: "l@x.test",
		PasswordHash: "x", Role: "user", Status: "active",
	}
	if err := db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	if err := func() error { queueForAll(t, e, u.ID, "user.deleted", map[string]any{"id": u.ID}); return nil }(); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdatePairedSystemStatus(ps.ID, "disabled"); err != nil {
		t.Fatal(err)
	}

	if err := e.DispatchPendingEvents(context.Background()); err != nil {
		t.Fatal(err)
	}

	pending, err := db.GetPendingSyncEvents(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) == 0 {
		t.Error("user.deleted was marked delivered while its target system was unreachable")
	}
}

// Retrying every 3 seconds with no backoff hammers a system that is already failing.
func TestFailedDeliveryBacksOff(t *testing.T) {
	e, db, _, cleanup := setupSync(t)
	defer cleanup()

	var attempts int
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failing.Close()

	ps, _, err := e.CreateSystem(&CreateSystemRequest{
		Name: "flaky", SystemType: "suite_webhook", CallbackURL: failing.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	u := &store.User{
		ID: uuid.New().String(), Username: "x", DisplayName: "X", Email: "x2@x.test",
		PasswordHash: "x", Role: "user", Status: "active",
	}
	if err := db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateAccountSyncEvent(&store.AccountSyncEvent{
		ID: uuid.New().String(), UserID: u.ID, SystemID: ps.ID,
		EventType: "user.created", PayloadJSON: `{"id":"x"}`, Status: "pending",
	}); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 5; i++ {
		if err := e.DispatchPendingEvents(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if attempts > 1 {
		t.Errorf("a failing endpoint was retried %d times back-to-back with no backoff", attempts)
	}
}

// A secret that signs every outbound webhook must not sit in the database in the clear.
func TestHMACSecretIsNotStoredInPlaintext(t *testing.T) {
	e, db, _, cleanup := setupSync(t)
	defer cleanup()

	_, token, err := e.CreateSystem(&CreateSystemRequest{
		Name: "mail", SystemType: "kypost", CallbackURL: "https://mail.urlxl.com/scim/v2",
	})
	if err != nil {
		t.Fatal(err)
	}

	systems, err := db.ListAllPairedSystems()
	if err != nil || len(systems) != 1 {
		t.Fatalf("expected 1 system: %v", err)
	}
	for _, s := range systems {
		if strings.Contains(s.HMACSecretEncrypted, token) {
			t.Error("the webhook signing secret is stored in plaintext")
		}
	}

	// It must still be usable for signing after the round trip.
	got, err := e.SigningSecret(&systems[0])
	if err != nil {
		t.Fatalf("could not recover the signing secret: %v", err)
	}
	if got != token {
		t.Error("the recovered signing secret does not match the one handed to the system")
	}
}

// Two dispatchers must not both deliver the same event. Without a claim, overlapping ticks
// or two instances during a rolling deploy each read the same pending user.created and
// create duplicate downstream accounts.
func TestConcurrentDispatchDeliversEachEventOnce(t *testing.T) {
	e, _, _, cleanup := setupSync(t)
	defer cleanup()

	var mu stdsync.Mutex
	seen := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.Header.Get("X-KySignOn-Event-Id")]++
		mu.Unlock()
		// Hold the connection so the second dispatcher runs while this delivery is in
		// flight, which is exactly the window an unclaimed read leaves open.
		time.Sleep(50 * time.Millisecond)
	}))
	defer srv.Close()

	ps, _, err := e.CreateSystem(&CreateSystemRequest{Name: "dup-check", SystemType: "suite_webhook", CallbackURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	grantAllUsers(t, e.store, ps.ID)
	if err := e.ResyncAllAccounts(ps.ID); err != nil {
		t.Fatal(err)
	}

	var wg stdsync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = e.DispatchPendingEvents(context.Background())
		}()
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 {
		t.Fatal("no events were delivered at all")
	}
	for id, count := range seen {
		if id == "" {
			t.Error("an event was delivered with no idempotency key; a recipient cannot deduplicate it")
		}
		if count > 1 {
			t.Errorf("event %s was delivered %d times", id, count)
		}
	}
}
