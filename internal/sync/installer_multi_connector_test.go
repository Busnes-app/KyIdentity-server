package sync

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/google/uuid"
)

// Real setup, access mutations, outbox and worker; the TLS receivers model SCIM
// resources, not downstream native sessions or product authorization.
func TestInstallerSCIMGlobalDisableAcrossOwnedConnectors(t *testing.T) {
	for _, loseOneFirst := range []bool{false, true} {
		name := "global-disable"
		if loseOneFirst {
			name = "app-loss-then-global-disable"
		}
		t.Run(name, func(t *testing.T) {
			e, s, foreign, cleanup := setupTestSyncEngine(t)
			defer cleanup()
			remotes := map[string]*fakeSCIM{"first": newFakeSCIM(), "second": newFakeSCIM(), "management": newFakeSCIM()}
			tokens := map[string]string{"first": strings.Repeat("a", 48), "second": strings.Repeat("b", 48), "management": strings.Repeat("c", 48)}
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				app, _, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, "/scim/"), "/")
				remote := remotes[app]
				if !ok || remote == nil || r.Header.Get("Authorization") != "Bearer "+tokens[app] {
					t.Error("connector endpoint or protected token crossed app scope")
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				r.Header.Set("Authorization", "Bearer target-token")
				remote.ServeHTTP(w, r)
			}))
			defer srv.Close()
			e.httpClient = srv.Client()
			p := store.InstallerSetup{ID: uuid.NewString(), EncryptionKey: e.encryptionKey,
				Admin:    store.InstallerUser{Username: "owner-admin", Email: "owner-admin@example.test", Role: "admin", PasswordHash: "fixture-admin-hash"},
				Everyday: store.InstallerUser{Username: "owner", Email: "owner@example.test", Role: "user", PasswordHash: "fixture-user-hash"}}
			for _, app := range []string{"first", "second", "management"} {
				role := "user"
				if app == "management" {
					role = ""
				}
				p.Clients = append(p.Clients, store.InstallerClient{ID: app, Name: app, SecretHash: "fixture-client-hash",
					RedirectURIs: []string{"https://" + app + ".example.test/callback"}, PostLogoutURIs: []string{},
					AdministratorRole: "admin", EverydayRole: role, SCIM: &store.InstallerSCIM{URL: srv.URL + "/scim/" + app, Token: tokens[app]}})
			}
			report, err := s.ApplyInstallerSetup(p, false)
			if err != nil {
				t.Fatal(err)
			}
			systems := map[string]string{}
			for _, object := range report.Created {
				if object.Kind == "connector" {
					systems[object.Name] = object.ID
					if appRecordFor(t, s, object.ID).ClientID != object.Name {
						t.Fatal("owned connector detached from its OIDC app")
					}
				}
			}
			if len(systems) != 3 {
				t.Fatal("setup did not create all owned connectors")
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
			retained := map[string]string{}
			for _, app := range []string{"first", "second"} {
				user, ok := remotes[app].userByExternal(day.ID)
				if !ok || !user.Active || len(user.Roles) != 1 || user.Roles[0].Value != "user" {
					t.Fatal("ordinary assigned account not delivered", app)
				}
				remoteID, present, err := s.SCIMUserLink(systems[app], day.ID)
				if err != nil || !present || remoteID != user.ID {
					t.Fatal("connector-local ordinary mapping missing", app, err)
				}
				retained[app] = remoteID
			}
			if loseOneFirst {
				app := appRecordFor(t, s, systems["first"])
				if err := s.SetAppAssignment(app.ID, "users", day.ID, false, nil); err != nil {
					t.Fatal(err)
				}
				drain(t, e)
				first, firstHeld := remotes["first"].userByExternal(day.ID)
				second, secondHeld := remotes["second"].userByExternal(day.ID)
				if !firstHeld || first.Active || !secondHeld || !second.Active {
					t.Fatal("single-app assignment loss escaped its connector")
				}
			}
			day.Status = "disabled"
			if err := s.UpdateUserWithSyncEvents(day, true, nil); err != nil {
				t.Fatal(err)
			}
			// Recreate the dispatcher before delivery: its memory is not the
			// authority for held scope, target credentials or pending work.
			e = NewEngine(s, e.encryptionKey)
			e.httpClient = srv.Client()
			drain(t, e)
			for _, app := range []string{"first", "second"} {
				user, ok := remotes[app].userByExternal(day.ID)
				remoteID, present, err := s.SCIMUserLink(systems[app], day.ID)
				if !ok || user.Active || user.ID != retained[app] || err != nil || !present || remoteID != retained[app] {
					t.Fatal("global disable failed to retain and deactivate owned resource", app, err)
				}
				rows, _, err := s.ListProvisioningState(systems[app], "", 100, 0)
				if err != nil {
					t.Fatal(err)
				}
				acknowledged := false
				for _, row := range rows {
					if row.UserID == day.ID {
						acknowledged = !row.Desired && !row.Recorded && row.Acknowledged && !row.Blocked && row.LastEvent != nil && row.LastEvent.Status == "delivered"
					}
				}
				if !acknowledged {
					t.Fatal("global disable lacked durable per-connector acknowledgment", app)
				}
			}
			for app, remote := range remotes {
				admin, ok := remote.userByExternal(owner.ID)
				if !ok || !admin.Active || len(admin.Roles) != 1 || admin.Roles[0].Value != "admin" {
					t.Fatal("ordinary disable changed independent administrator", app)
				}
				if _, ok := remote.userByExternal(foreign.ID); ok {
					t.Fatal("unassigned global administrator reached a connector", app)
				}
			}
			if _, ok := remotes["management"].userByExternal(day.ID); ok {
				t.Fatal("global disable created an account at an unheld connector")
			}
			remoteID, present, err := s.SCIMUserLink(systems["management"], day.ID)
			if err != nil || remoteID != "" || present {
				t.Fatal("unheld connector gained an ordinary mapping", err)
			}
		})
	}
}
