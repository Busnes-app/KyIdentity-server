package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/auth"
)

// An administrator's edit sets only the fields it names, on the row as it is at write
// time: a display-name edit and a password reset racing each other both land, and so
// does a password change made outside the admin API.
func TestAdminUserEditsDoNotRevertConcurrentChanges(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newSession(t, db, newUser(t, db, "admin"), time.Now().UTC().Add(time.Hour))
	target := newUser(t, db, "user")
	path := "/api/admin/users/" + target.ID
	put := func(rec **httptest.ResponseRecorder, body, stepUp string) func() {
		return func() { *rec = adminRequestWithStepUp(t, srv, "PUT", path, admin, body, stepUp) }
	}
	for i := range 10 {
		name, password := fmt.Sprintf("Renamed %d", i), fmt.Sprintf("Fresh-password-%02d-xyz", i)
		var renamed, reset *httptest.ResponseRecorder
		together(
			put(&renamed, `{"displayName":"`+name+`"}`, mintStepUp(t, srv, admin, "PUT "+path)),
			put(&reset, `{"password":"`+password+`"}`, mintStepUp(t, srv, admin, "PUT "+path)),
		)
		if renamed.Code != http.StatusOK || reset.Code != http.StatusOK {
			t.Fatalf("round %d: %d %s / %d %s", i, renamed.Code, renamed.Body.String(), reset.Code, reset.Body.String())
		}
		u := mustUser(t, db, target.ID)
		if ok, _ := auth.VerifyPassword(password, u.PasswordHash); !ok || u.DisplayName != name {
			t.Fatalf("round %d lost an update: password kept=%v name=%q", i, ok, u.DisplayName)
		}
	}
	for i := range 10 {
		name, hash := fmt.Sprintf("Again %d", i), fmt.Sprintf("changed-hash-%d", i)
		var renamed *httptest.ResponseRecorder
		var changeErr error
		together(
			put(&renamed, `{"displayName":"`+name+`"}`, mintStepUp(t, srv, admin, "PUT "+path)),
			func() { changeErr = db.ChangePassword(target.ID, "", hash, nil) },
		)
		if renamed.Code != http.StatusOK || changeErr != nil {
			t.Fatalf("round %d: %d %s / %v", i, renamed.Code, renamed.Body.String(), changeErr)
		}
		if u := mustUser(t, db, target.ID); u.PasswordHash != hash || u.DisplayName != name {
			t.Fatalf("round %d lost an update: hash=%q name=%q", i, u.PasswordHash, u.DisplayName)
		}
	}
}
