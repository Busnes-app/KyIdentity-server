package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kyidentity-server/internal/store"
)

// The completion view outlives the directory row: an administrator can watch a deleted
// user's downstream removal finish, and nobody else can read it.
func TestOffboardingViewSurvivesDeletionAndIsAdminOnly(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	exp := time.Now().UTC().Add(time.Hour)
	admin := newSession(t, db, newUser(t, db, "admin"), exp)
	plain := newSession(t, db, newUser(t, db, "user"), exp)
	u := newUser(t, db, "user")
	if err := db.CreatePairedSystem(&store.PairedSystem{ID: "notes", Name: "KyNotes", SystemType: "scim", CallbackURL: "https://notes.urlxl.com/scim", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveSCIMUserLink("notes", u.ID, "remote-1"); err != nil {
		t.Fatal(err)
	}
	newClient(t, db, "kynotes", []string{"https://notes.urlxl.com/callback"}, []string{"openid"})
	c, _ := db.GetOAuthClientByID("kynotes")
	c.BackchannelLogoutURI = "https://notes.urlxl.com/backchannel"
	if err := db.UpdateOAuthClient(c); err != nil {
		t.Fatal(err)
	}
	if _, err := db.EnsureClientSession("kynotes", sessionIDFor(t, db, newSession(t, db, u, exp)), u.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteUserWithSyncEvents(u.ID, nil); err != nil {
		t.Fatal(err)
	}

	if got := call(t, srv, plain, "GET", "/api/admin/users/"+u.ID+"/offboarding"); got.Code != http.StatusForbidden {
		t.Fatalf("non-admin: %d", got.Code)
	}
	got := call(t, srv, admin, "GET", "/api/admin/users/"+u.ID+"/offboarding")
	if got.Code != http.StatusOK {
		t.Fatalf("admin: %d %s", got.Code, got.Body.String())
	}
	var off struct {
		Deleted      bool `json:"deleted"`
		Acknowledged bool `json:"acknowledged"`
		Targets      []struct {
			SystemID   string `json:"systemId"`
			SystemName string `json:"systemName"`
			Recorded   bool   `json:"recorded"`
			LastEvent  *struct {
				Type string `json:"type"`
			} `json:"lastEvent"`
		} `json:"targets"`
		Logouts []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"logouts"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &off); err != nil {
		t.Fatal(err)
	}
	// The sign-out list uses the same wire shape as the sessions inventory and carries
	// no worker or session identifiers.
	if len(off.Logouts) != 1 || off.Logouts[0].ID == "" || off.Logouts[0].Status != "queued" {
		t.Fatalf("logouts = %+v", off.Logouts)
	}
	for _, secret := range []string{"ClaimToken", "claimToken", `"SID"`, `"sid"`, "BackchannelLogoutURI", "backchannel"} {
		if strings.Contains(got.Body.String(), secret) {
			t.Fatalf("response leaks %s: %s", secret, got.Body.String())
		}
	}
	if !off.Deleted || off.Acknowledged || len(off.Targets) != 1 || off.Targets[0].SystemName != "KyNotes" || !off.Targets[0].Recorded || off.Targets[0].LastEvent == nil || off.Targets[0].LastEvent.Type != "user.deleted" {
		t.Fatalf("offboarding = %+v", off)
	}
	if got := call(t, srv, admin, "GET", "/api/admin/users/nobody/offboarding"); got.Code != http.StatusNotFound {
		t.Fatalf("unknown user: %d", got.Code)
	}
}
