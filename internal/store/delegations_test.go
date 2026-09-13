package store

import (
	"errors"
	"testing"
	"time"
)

// Delegations are explicit rows a global administrator sets; they follow the user and
// the app they name, and commit with their audit row or not at all.
func TestDelegationsFollowUserAndApp(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	u := createTestUser(t, s)
	if err := s.CreateOAuthClient(&OAuthClient{ID: "billing", ClientName: "Billing", ClientType: "public", RedirectURIsJSON: `["https://b/cb"]`, AllowedScopesJSON: `["openid"]`, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rows, _, _ := s.ListAppRecords("billing", 25, 0)
	app := rows[0]

	if err := s.SetDelegations(u.ID, Delegations{Helpdesk: true, AppOwner: []string{"missing-app"}}, nil); !errors.Is(err, ErrAppRecordMissing) {
		t.Fatalf("unknown app accepted: %v", err)
	}
	if err := s.SetDelegations("missing-user", Delegations{Auditor: true}, nil); !errors.Is(err, ErrUserMissing) {
		t.Fatalf("unknown user accepted: %v", err)
	}
	if err := s.SetDelegations(u.ID, Delegations{Helpdesk: true, Auditor: true, AppOwner: []string{app.ID, app.ID}}, nil); err != nil {
		t.Fatal(err)
	}
	d, err := s.Delegations(u.ID)
	if err != nil || !d.Helpdesk || !d.Auditor || len(d.AppOwner) != 1 || d.AppOwner[0] != app.ID {
		t.Fatalf("delegations = %+v %v", d, err)
	}
	owned, total, err := s.ListAppRecordsOwnedBy(u.ID, "", 25, 0)
	if err != nil || total != 1 || len(owned) != 1 || owned[0].ID != app.ID {
		t.Fatalf("owned listing = %+v %d %v", owned, total, err)
	}

	// A poisoned audit row rolls the whole change back.
	if _, err := s.db.Exec(`CREATE TRIGGER fail_delegation_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	audit := &AuditEvent{ID: "audit", Action: "admin.delegations_updated", Outcome: "success", CreatedAt: time.Now().UTC()}
	if err := s.SetDelegations(u.ID, Delegations{}, audit); err == nil {
		t.Fatal("change committed without its audit row")
	}
	if _, err := s.db.Exec(`DROP TRIGGER fail_delegation_audit`); err != nil {
		t.Fatal(err)
	}
	if d, _ = s.Delegations(u.ID); !d.Helpdesk {
		t.Fatal("failed audit lost the delegation")
	}

	// Replacing the set is exact: only what the caller states remains.
	if err := s.SetDelegations(u.ID, Delegations{Auditor: true}, nil); err != nil {
		t.Fatal(err)
	}
	if d, _ = s.Delegations(u.ID); d.Helpdesk || !d.Auditor || len(d.AppOwner) != 0 {
		t.Fatalf("replace left stale rows: %+v", d)
	}
	if _, total, _ = s.ListAppRecordsOwnedBy(u.ID, "", 25, 0); total != 0 {
		t.Fatal("ownership survived its removal")
	}

	// Deleting the app or the user removes the rows that named them.
	if err := s.SetDelegations(u.ID, Delegations{AppOwner: []string{app.ID}}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteOAuthClient("billing", nil); err != nil {
		t.Fatal(err)
	}
	if d, _ = s.Delegations(u.ID); len(d.AppOwner) != 0 {
		t.Fatalf("ownership outlived the app: %+v", d)
	}
	if err := s.DeleteUserWithSyncEvents(u.ID, nil); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM admin_delegations WHERE user_id=?`, u.ID).Scan(&n); err != nil || n != 0 {
		t.Fatal("delegations outlived the user", n, err)
	}
}
