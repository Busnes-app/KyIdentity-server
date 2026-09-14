package store

import (
	"errors"
	"testing"
	"time"
)

func requestFixture(t *testing.T) (*Store, *User, *User, *User, AppRecord) {
	t.Helper()
	s, u, a := appAccessFixture(t)
	if err := s.SetAppPolicy(a.ID, "assigned_only", true, a.Revision, nil); err != nil {
		t.Fatal(err)
	}
	admin := createTestUserNamed(t, s, "root")
	admin.Role = "admin"
	if err := s.UpdateUserWithSyncEvents(admin, false, nil); err != nil {
		t.Fatal(err)
	}
	owner := createTestUserNamed(t, s, "owner")
	if err := s.SetDelegations(owner.ID, Delegations{AppOwner: []string{a.ID}}, nil); err != nil {
		t.Fatal(err)
	}
	a, _ = s.GetAppRecord(a.ID)
	return s, u, admin, owner, a
}

// Only requestable, assigned-only, enabled apps the user lacks are offered; a request
// is refused for anything else, for access already held, for duplicates and past a cap.
func TestAccessRequestsExposeOnlyRequestableApps(t *testing.T) {
	s, u, _, _, a := requestFixture(t)
	if apps, _ := s.RequestableApps(u.ID); len(apps) != 0 {
		t.Fatalf("closed app offered: %+v", apps)
	}
	if _, err := s.CreateAccessRequest(u.ID, a.ID, "please", 0, nil); !errors.Is(err, ErrAppNotRequestable) {
		t.Fatalf("closed app requestable: %v", err)
	}
	if _, err := s.CreateAccessRequest(u.ID, "no-such-app", "please", 0, nil); !errors.Is(err, ErrAppNotRequestable) {
		t.Fatalf("missing app distinguishable from a closed one: %v", err)
	}
	if err := s.SetAppRequestable(a.ID, true, a.Revision, nil); err != nil {
		t.Fatal(err)
	}
	apps, _ := s.RequestableApps(u.ID)
	if len(apps) != 1 || apps[0].AppID != a.ID || apps[0].Pending {
		t.Fatalf("requestable listing = %+v", apps)
	}
	if _, err := s.CreateAccessRequest(u.ID, a.ID, "", 0, nil); err == nil {
		t.Fatal("empty reason accepted")
	}
	if _, err := s.CreateAccessRequest(u.ID, a.ID, "please", MaxRequestDuration+time.Second, nil); err == nil {
		t.Fatal("over-long duration accepted")
	}
	req, err := s.CreateAccessRequest(u.ID, a.ID, "  Need billing for the quarter  ", 7*24*time.Hour, nil)
	if err != nil || req.Status != "pending" || req.Reason != "Need billing for the quarter" || req.DurationSeconds != 7*24*3600 {
		t.Fatalf("request = %+v %v", req, err)
	}
	if _, err := s.CreateAccessRequest(u.ID, a.ID, "again", 0, nil); !errors.Is(err, ErrDuplicateRequest) {
		t.Fatalf("duplicate pending accepted: %v", err)
	}
	if apps, _ = s.RequestableApps(u.ID); !apps[0].Pending {
		t.Fatal("pending request not reflected")
	}
	if err := s.SetAppAssignment(a.ID, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if apps, _ = s.RequestableApps(u.ID); len(apps) != 0 {
		t.Fatal("app still offered to a user who has it")
	}
	if err := s.SetAppAssignment(a.ID, "users", u.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	// The cap counts pending requests across apps.
	for i := 0; i < maxPendingRequests; i++ {
		id := "app-" + string(rune('a'+i))
		if err := s.CreateOAuthClient(&OAuthClient{ID: id, ClientName: id, ClientType: "public", RedirectURIsJSON: `["https://x/cb"]`, AllowedScopesJSON: `["openid"]`, Enabled: true}); err != nil {
			t.Fatal(err)
		}
		rows, _, _ := s.ListAppRecords(id, 1, 0)
		if err := s.SetAppRequestable(rows[0].ID, true, rows[0].Revision, nil); err != nil {
			t.Fatal(err)
		}
		_, err := s.CreateAccessRequest(u.ID, rows[0].ID, "more", 0, nil)
		if i < maxPendingRequests-1 && err != nil {
			t.Fatalf("request %d refused: %v", i, err)
		}
		if i == maxPendingRequests-1 && !errors.Is(err, ErrTooManyRequests) {
			t.Fatalf("cap not enforced: %v", err)
		}
	}
	if err := s.CancelAccessRequest(req.ID, u.ID, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.CancelAccessRequest(req.ID, u.ID, nil); !errors.Is(err, ErrRequestNotPending) {
		t.Fatalf("cancelled twice: %v", err)
	}
	if _, err := s.CreateAccessRequest(u.ID, a.ID, "after cancel", 0, nil); err != nil {
		t.Fatalf("cancelled request still blocks a new one: %v", err)
	}
}

// A decision re-reads authority, state and policy under the lock: no self-approval, no
// second decision, no approval by someone who lost ownership, none for a closed app; an
// approval is one ordinary assignment with the requested expiry.
func TestAccessRequestDecisionsAreRecheckedUnderTheLock(t *testing.T) {
	s, u, admin, owner, a := requestFixture(t)
	if err := s.SetAppRequestable(a.ID, true, a.Revision, nil); err != nil {
		t.Fatal(err)
	}
	other := createTestUserNamed(t, s, "other")
	req, err := s.CreateAccessRequest(u.ID, a.ID, "please", time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DecideAccessRequest(req.ID, u.ID, true, "", nil); !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("self-approval: %v", err)
	}
	if _, err := s.DecideAccessRequest(req.ID, other.ID, true, "", nil); !errors.Is(err, ErrCannotDecide) {
		t.Fatalf("bystander decided: %v", err)
	}
	// Ownership withdrawn between form and submit: the stale form grants nothing.
	if err := s.SetDelegations(owner.ID, Delegations{}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DecideAccessRequest(req.ID, owner.ID, true, "", nil); !errors.Is(err, ErrCannotDecide) {
		t.Fatalf("former owner decided: %v", err)
	}
	if err := s.SetDelegations(owner.ID, Delegations{AppOwner: []string{a.ID}}, nil); err != nil {
		t.Fatal(err)
	}
	// The app closed to requests since: approval is refused, denial still works later.
	a, _ = s.GetAppRecord(a.ID)
	if err := s.SetAppRequestable(a.ID, false, a.Revision, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DecideAccessRequest(req.ID, owner.ID, true, "", nil); !errors.Is(err, ErrAppNotRequestable) {
		t.Fatalf("closed app approved: %v", err)
	}
	a, _ = s.GetAppRecord(a.ID)
	if err := s.SetAppRequestable(a.ID, true, a.Revision, nil); err != nil {
		t.Fatal(err)
	}
	decided, err := s.DecideAccessRequest(req.ID, owner.ID, true, "ok for the quarter", nil)
	if err != nil || decided.Status != "approved" || decided.DecidedBy != owner.ID {
		t.Fatalf("approval = %+v %v", decided, err)
	}
	if allowed, _ := s.ClientAccessAllowed(u.ID, "client"); !allowed {
		t.Fatal("approval granted no access")
	}
	end, _ := s.AccessEndsAt(u.ID, "client")
	if end == nil || end.Sub(time.Now().UTC()) > time.Hour || end.Sub(time.Now().UTC()) < 59*time.Minute {
		t.Fatalf("approval expiry = %v, want about an hour", end)
	}
	page, _ := s.ListAppAccessUsers(a.ID, u.Username, "", nil, 10, 0)
	if len(page.Users) != 1 || !page.Users[0].Direct || page.Users[0].DirectExpiresAt == nil {
		t.Fatalf("approval is not an ordinary bounded assignment: %+v", page.Users)
	}
	if _, err := s.DecideAccessRequest(req.ID, admin.ID, true, "", nil); !errors.Is(err, ErrRequestNotPending) {
		t.Fatalf("second decision: %v", err)
	}
	if _, err := s.DecideAccessRequest(req.ID, admin.ID, false, "", nil); !errors.Is(err, ErrRequestNotPending) {
		t.Fatalf("denial after approval: %v", err)
	}
	// A cancelled request cannot be approved afterwards; an administrator may deny any.
	if err := s.SetAppAssignment(a.ID, "users", u.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	second, err := s.CreateAccessRequest(u.ID, a.ID, "again", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CancelAccessRequest(second.ID, u.ID, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DecideAccessRequest(second.ID, admin.ID, true, "", nil); !errors.Is(err, ErrRequestNotPending) {
		t.Fatalf("cancelled request approved: %v", err)
	}
	if allowed, _ := s.ClientAccessAllowed(u.ID, "client"); allowed {
		t.Fatal("cancelled request granted access")
	}
	third, _ := s.CreateAccessRequest(u.ID, a.ID, "third", 0, nil)
	if d, err := s.DecideAccessRequest(third.ID, admin.ID, false, "no", nil); err != nil || d.Status != "denied" {
		t.Fatalf("admin denial = %+v %v", d, err)
	}
	// Inbox scoping: the owner sees requests for their app; a bystander sees none.
	inbox, total, _ := s.ListAccessRequests(AccessRequestFilter{ActorID: owner.ID, Limit: 10})
	if total != 3 || len(inbox) != 3 {
		t.Fatalf("owner inbox = %d", total)
	}
	if _, total, _ = s.ListAccessRequests(AccessRequestFilter{ActorID: other.ID, Limit: 10}); total != 0 {
		t.Fatalf("bystander inbox = %d", total)
	}
	if mine, total, _ := s.ListAccessRequests(AccessRequestFilter{UserID: u.ID, Status: "denied", Limit: 10}); total != 1 || mine[0].ID != third.ID {
		t.Fatalf("own listing = %+v %d", mine, total)
	}
	// An unanswered request expires with the other due work and can no longer be approved.
	fourth, _ := s.CreateAccessRequest(u.ID, a.ID, "fourth", 0, nil)
	if _, err := s.db.Exec(`UPDATE access_requests SET expires_at=unixepoch()-1 WHERE id=?`, fourth.ID); err != nil {
		t.Fatal(err)
	}
	if _, total, _ := s.ListAccessRequests(AccessRequestFilter{ActorID: admin.ID, Status: "pending", Limit: 10}); total != 0 {
		t.Fatalf("expired request still listed as pending: %d", total)
	}
	if _, err := s.RunDueExpiries(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DecideAccessRequest(fourth.ID, admin.ID, true, "", nil); !errors.Is(err, ErrRequestNotPending) {
		t.Fatalf("expired request approved: %v", err)
	}
}
