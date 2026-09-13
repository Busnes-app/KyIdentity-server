package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/Busness-app/kysignon-server/internal/store"
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
		Logouts []any `json:"logouts"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &off); err != nil {
		t.Fatal(err)
	}
	if !off.Deleted || off.Acknowledged || len(off.Targets) != 1 || off.Targets[0].SystemName != "KyNotes" || !off.Targets[0].Recorded || off.Targets[0].LastEvent == nil || off.Targets[0].LastEvent.Type != "user.deleted" {
		t.Fatalf("offboarding = %+v", off)
	}
	if got := call(t, srv, admin, "GET", "/api/admin/users/nobody/offboarding"); got.Code != http.StatusNotFound {
		t.Fatalf("unknown user: %d", got.Code)
	}
}
