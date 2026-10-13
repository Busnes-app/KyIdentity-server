package sync

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

func TestInstallerGroupsThroughNativeSCIMWorker(t *testing.T) {
	e, s, foreign, cleanup := setupTestSyncEngine(t)
	defer cleanup()
	remote := newFakeSCIM()
	token := strings.Repeat("s", 48)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("incorrect connector token")
			w.WriteHeader(401)
			return
		}
		r.Header.Set("Authorization", "Bearer target-token")
		remote.ServeHTTP(w, r)
	}))
	defer srv.Close()
	e.httpClient = srv.Client()
	p := store.InstallerSetup{ID: uuid.NewString(), EncryptionKey: e.encryptionKey, Admin: store.InstallerUser{Username: "owner-admin", Email: "owner-admin@example.test", Role: "admin", PasswordHash: "fixture-admin"}, Everyday: store.InstallerUser{Username: "owner", Email: "owner@example.test", Role: "user", PasswordHash: "fixture-day"}, Groups: []store.InstallerGroup{{Name: "Suite users", IncludeEveryday: true}}, Clients: []store.InstallerClient{{ID: "drive", Name: "Drive", SecretHash: "fixture-client", RedirectURIs: []string{"https://drive.test/callback"}, PostLogoutURIs: []string{}, AdministratorRole: "admin", EverydayRole: "editor", Groups: []string{"Suite users"}, SCIM: &store.InstallerSCIM{URL: srv.URL + "/scim/v2/drive", Token: token, Groups: true}}}}
	report, err := s.ApplyInstallerSetup(p, false)
	if err != nil {
		t.Fatal(err)
	}
	var groupID string
	for _, object := range report.Created {
		if object.Kind == "group" {
			groupID = object.ID
		}
	}
	day, err := s.GetUserByUsername("owner")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := s.GetUserByUsername("owner-admin")
	if err != nil {
		t.Fatal(err)
	}
	drain(t, e)
	dayRemote, ok := remote.userByExternal(day.ID)
	group, held := remote.groupByExternal(groupID)
	if !ok || !held || group.DisplayName != "Suite users" || len(group.Members) != 1 || group.Members[0].Value != dayRemote.ID {
		t.Fatalf("native group/member delivery %+v %+v", group, dayRemote)
	}
	if _, ok := remote.userByExternal(foreign.ID); ok {
		t.Fatal("unassigned user provisioned")
	}
	if _, err := s.ApplyInstallerSetup(p, true); err != nil {
		t.Fatal("worker delivery disturbed setup ownership", err)
	}
	day.Status = "disabled"
	if err := s.UpdateUserWithSyncEvents(day, true, nil); err != nil {
		t.Fatal(err)
	}
	drain(t, e)
	group, held = remote.groupByExternal(groupID)
	dayRemote, ok = remote.userByExternal(day.ID)
	adminRemote, adminHeld := remote.userByExternal(admin.ID)
	if !held || len(group.Members) != 0 || !ok || dayRemote.Active || !adminHeld || !adminRemote.Active {
		t.Fatal("offboarding did not preserve group/admin and remove ordinary access")
	}
}
