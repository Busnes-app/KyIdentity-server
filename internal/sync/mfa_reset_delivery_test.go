package sync

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/syncauth"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// This is KyCalendar's ApplyInstallerDirectory contract: reject nonpositive/stale
// versions and different bytes at an acknowledged version BEFORE revoking grants.
// Accepted resets apply active/roles as well as deleting sessions and app passwords.
func TestSignedMFAResetDelivery(t *testing.T) {
	for _, scenario := range []string{"ordinary", "retry", "uncertain-applied", "restart", "restore", "legacy-demoted", "legacy-disabled", "removal-regain"} {
		t.Run(scenario, func(t *testing.T) {
			e, s, _, cleanup := setupTestSyncEngine(t)
			u := member(t, s)
			defer cleanup()
			var secret string
			uncertain := false
			var last int
			var digest [32]byte
			active, administrator := false, false
			sessions, passwords, resets, failures := 1, 1, 0, 0
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, err := io.ReadAll(r.Body)
				if err == nil {
					_, err = syncauth.Verify([]byte(secret), syncauth.FromRequest(r), raw, syncauth.Options{})
				}
				if err != nil {
					t.Error(err)
					w.WriteHeader(401)
					return
				}
				var body SCIMUserResource
				if err = json.Unmarshal(raw, &body); err != nil || body.Meta == nil {
					t.Error("invalid SCIM", err)
					w.WriteHeader(400)
					return
				}
				revision := 0
				_, _ = fmt.Sscanf(body.Meta.Version, `W/"%d"`, &revision)
				next := sha256.Sum256(append([]byte(r.Header.Get(syncauth.HeaderEventType)+"\x00"), raw...))
				if failures > 0 {
					failures--
					w.WriteHeader(503)
					return
				}
				if revision <= 0 || revision < last || revision == last && next != digest {
					w.WriteHeader(422)
					return
				}
				if revision == last {
					return
				}
				last, digest = revision, next
				active = body.Active
				administrator = false
				for _, role := range body.Roles {
					administrator = administrator || role.Value == "admin"
				}
				if !active || r.Header.Get("X-KySignOn-Event-Type") == "user.mfa_reset" {
					sessions, passwords = 0, 0
				}
				if r.Header.Get("X-KySignOn-Event-Type") == "user.mfa_reset" {
					resets++
					if uncertain {
						uncertain = false
						w.WriteHeader(202)
					}
				}
			}))
			defer srv.Close()
			e.httpClient = srv.Client()
			sys, token, err := e.CreateSystem(&CreateSystemRequest{Name: "reset", SystemType: "suite_webhook", CallbackURL: srv.URL}, nil)
			if err != nil {
				t.Fatal(err)
			}
			secret = token
			app := appRecordFor(t, s, sys.ID)
			var appRoleID string
			if scenario == "uncertain-applied" {
				role, roleErr := s.CreateAppRole(app.ID, "admin", "", nil)
				if roleErr != nil {
					t.Fatal(roleErr)
				}
				appRoleID = role.ID
				if err = s.SetAppRoleAssignment(app.ID, appRoleID, "users", u.ID, true, nil); err != nil {
					t.Fatal(err)
				}
			}
			if err = s.SetAppAssignment(app.ID, "users", u.ID, true, nil); err != nil {
				t.Fatal(err)
			}
			dispatch(t, e)
			if !active || sessions != 1 || passwords != 1 {
				t.Fatal("initial profile not applied")
			}
			if err = e.ResetUserMFAAndRevoke(u.ID, nil); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "retry":
				failures = store.SyncAttemptBudget + 1
				for i := 0; i < store.SyncAttemptBudget; i++ {
					elapse(t, s)
					dispatch(t, e)
				}
				// Newer desired state must not overtake an exhausted reset.
				if err = s.ResyncSystem(sys.ID, nil); err != nil {
					t.Fatal(err)
				}
				elapse(t, s)
				dispatch(t, e)
				if resets != 0 {
					t.Fatal("reset unexpectedly applied while down")
				}
			case "uncertain-applied":
				uncertain = true
				dispatch(t, e)
				if resets != 1 {
					t.Fatal("uncertain reset did not land at receiver")
				}
				// The receiver committed before its incomplete response. Recovery must
				// deliver a fresh version with current roles, rather than conflict.
				sessions, passwords = 1, 1
				if err = s.SetAppRoleAssignment(app.ID, appRoleID, "users", u.ID, false, nil); err != nil {
					t.Fatal(err)
				}
				attempts, listErr := s.ListSyncDeliveryAttempts(sys.ID)
				if listErr != nil || len(attempts) != 1 {
					t.Fatal(attempts, listErr)
				}
				elapse(t, s)
				if err = s.ResumeSyncDelivery(sys.ID, attempts[0].Token, false, nil); err != nil {
					t.Fatal(err)
				}
			case "restart":
				failures = 1
				dispatch(t, e)
				path := syncTestDBs[s]
				if err = s.Close(); err != nil {
					t.Fatal(err)
				}
				s, err = store.New(path)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				syncTestDBs[s] = path
				e.store = s
			case "restore":
				if _, err = s.ApplyRestoredState(time.Now().UTC(), nil); err != nil {
					t.Fatal(err)
				}
				var resetRevision int
				db, openErr := sql.Open("sqlite", syncTestDBs[s])
				if openErr != nil {
					t.Fatal(openErr)
				}
				err = db.QueryRow(`SELECT revision FROM account_sync_events WHERE system_id=? AND event_type='user.mfa_reset'`, sys.ID).Scan(&resetRevision)
				db.Close()
				if err != nil || resetRevision < 0 {
					t.Fatalf("restored reset revision=%d: %v", resetRevision, err)
				}
				if err = s.ResumeProvisioning(sys.ID, nil); err != nil {
					t.Fatal(err)
				}
				if err = s.ReconcileProvisioning(); err != nil {
					t.Fatal(err)
				}
			case "legacy-demoted", "legacy-disabled":
				// A pre-upgrade reset reused an already-acknowledged revision and retained
				// queue-time authority. It must keep its ID/type, but never restore that role.
				execRaw(t, s, `UPDATE account_sync_events SET revision=?,payload_json=json_set(payload_json,'$.roles',json('[{"value":"admin"}]')),status='failed',attempts=5 WHERE event_type='user.mfa_reset' AND system_id=?`, last, sys.ID)
				if scenario == "legacy-disabled" {
					setStatus(t, s, u, "disabled")
				}
				if err = s.ReconcileProvisioning(); err != nil {
					t.Fatal(err)
				}
			case "removal-regain":
				setStatus(t, s, u, "disabled")
				setStatus(t, s, u, "active")
			}
			for i := 0; i < 5; i++ {
				elapse(t, s)
				dispatch(t, e)
			}
			wantResets := 1
			if scenario == "uncertain-applied" {
				wantResets = 2
			}
			if resets != wantResets || sessions != 0 || passwords != 0 || administrator {
				t.Fatalf("reset effects: resets=%d sessions=%d passwords=%d admin=%v outbox=%+v", resets, sessions, passwords, administrator, outbox(t, s, sys.ID, u.ID))
			}
			if active != (scenario != "legacy-disabled") {
				t.Fatalf("final active=%v", active)
			}
			if got := outbox(t, s, sys.ID, u.ID); len(got) != 0 {
				t.Fatalf("undelivered: %+v", got)
			}
		})
	}
}
