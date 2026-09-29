package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
)

func TestSetDeviceSignOnTogglesOwnDeviceOnly(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	u := newUser(t, db, "user")
	cookie := newSession(t, db, u, time.Now().UTC().Add(time.Hour))
	if err := db.UpsertNativeDevice(&store.NativeDevice{ID: "dev-1", UserID: u.ID, DeviceName: "p", DeviceIdentifier: "i", CanSignOn: true}); err != nil {
		t.Fatal(err)
	}
	other := newUser(t, db, "user")
	if err := db.UpsertNativeDevice(&store.NativeDevice{ID: "dev-2", UserID: other.ID, DeviceName: "q", DeviceIdentifier: "j"}); err != nil {
		t.Fatal(err)
	}
	do := func(id, body string) int {
		return adminRequestNoStepUp(t, srv, http.MethodPut, "/api/notifications/native/devices/"+id+"/sign-on", cookie, body).Code
	}

	if c := do("dev-1", `{"canSignOn":false}`); c != http.StatusOK {
		t.Fatalf("own device: status %d", c)
	}
	if got, _ := db.GetNativeDevice("dev-1"); got.CanSignOn {
		t.Fatal("toggle off did not persist")
	}
	if c := do("dev-2", `{"canSignOn":true}`); c != http.StatusNotFound {
		t.Fatalf("foreign device: status %d", c)
	}
	if got, _ := db.GetNativeDevice("dev-2"); got.CanSignOn {
		t.Fatal("foreign toggle changed the row")
	}
	if c := do("dev-1", `{"canSignOn":`); c != http.StatusBadRequest {
		t.Fatalf("malformed: status %d", c)
	}

	for _, want := range []string{"success", "failure"} {
		evs, _, err := db.SearchAuditEvents(store.AuditFilter{Action: "device.sign_on_changed", Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, e := range evs {
			if e.Outcome == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("no %s audit event", want)
		}
	}
}
