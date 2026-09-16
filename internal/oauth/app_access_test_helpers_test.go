package oauth

import (
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"testing"
)

func allowTestAppAccess(t *testing.T, db *store.Store, connectionID string) {
	t.Helper()
	rows, _, err := db.ListAppRecords(connectionID, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range rows {
		if a.ClientID == connectionID || a.LauncherID == connectionID || a.SystemID == connectionID {
			found = true
			if err := db.SetAppPolicy(a.ID, "all_active_users", true, a.Revision, nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !found {
		t.Fatalf("missing app connection %s", connectionID)
	}
}
