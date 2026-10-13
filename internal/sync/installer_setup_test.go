package sync

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// Native setup feeds the existing worker: no direct inserts into connector,
// mapping or desired-state tables from this cross-boundary fixture.
func TestInstallerSCIMNativeDeliveryAndAccessLoss(t *testing.T) {
	for _, cause := range []string{"unassign", "disable", "expiry", "delete"} {
		t.Run(cause, func(t *testing.T) {
			e, s, foreign, cleanup := setupTestSyncEngine(t)
			defer cleanup()
			remote := newFakeSCIM()
			token := strings.Repeat("s", 48)
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer "+token {
					t.Error("wrong protected native credential")
					w.WriteHeader(401)
					return
				}
				r.Header.Set("Authorization", "Bearer target-token")
				remote.ServeHTTP(w, r)
			}))
			defer srv.Close()
			e.httpClient = srv.Client()
			p := store.InstallerSetup{ID: uuid.NewString(), EncryptionKey: e.encryptionKey,
				Admin:    store.InstallerUser{Username: "owner-admin", Email: "owner-admin@example.test", Role: "admin", PasswordHash: "fixture-admin-hash"},
				Everyday: store.InstallerUser{Username: "owner", Email: "owner@example.test", Role: "user", PasswordHash: "fixture-user-hash"},
				Clients: []store.InstallerClient{{ID: "bookstack", Name: "BookStack", SecretHash: "fixture-client-hash", RedirectURIs: []string{"https://bookstack.test/callback"}, PostLogoutURIs: []string{},
					AdministratorRole: "admin", EverydayRole: "editor", SCIM: &store.InstallerSCIM{URL: srv.URL + "/scim/v2/bookstack", Token: token}}}}
			r, err := s.ApplyInstallerSetup(p, false)
			if err != nil {
				t.Fatal(err)
			}
			systemID := ""
			for _, object := range r.Created {
				if object.Kind == "connector" {
					systemID = object.ID
				}
			}
			app := appRecordFor(t, s, systemID)
			if app.ClientID != "bookstack" {
				t.Fatal("connector detached from exact OIDC app")
			}
			day, err := s.GetUserByUsername("owner")
			if err != nil {
				t.Fatal(err)
			}
			owner, err := s.GetUserByUsername("owner-admin")
			if err != nil {
				t.Fatal(err)
			}
			drain(t, e)
			for id, role := range map[string]string{day.ID: "editor", owner.ID: "admin"} {
				got, ok := remote.userByExternal(id)
				if !ok || !got.Active || len(got.Roles) != 1 || got.Roles[0].Value != role {
					t.Fatalf("native role/profile delivery %+v found %v", got, ok)
				}
			}
			if _, ok := remote.userByExternal(foreign.ID); ok {
				t.Fatal("unassigned global administrator provisioned")
			}
			switch cause {
			case "unassign":
				err = s.SetAppAssignment(app.ID, "users", day.ID, false, nil)
			case "disable":
				day.Status = "disabled"
				err = s.UpdateUserWithSyncEvents(day, true, nil)
			case "delete":
				err = s.DeleteUserWithSyncEvents(day.ID, nil)
			case "expiry":
				expiry := time.Now().Add(1100 * time.Millisecond)
				err = s.SetAppAssignmentUntil(app.ID, "users", day.ID, &expiry, nil)
				if err == nil {
					time.Sleep(1200 * time.Millisecond)
					_, err = s.RunDueExpiries(time.Now())
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			drain(t, e)
			got, ok := remote.userByExternal(day.ID)
			if !ok || got.Active {
				t.Fatalf("%s failed to deactivate retained resource %+v", cause, got)
			}
			if got, ok := remote.userByExternal(owner.ID); !ok || !got.Active {
				t.Fatal("everyday access loss affected owner")
			}
		})
	}
}
