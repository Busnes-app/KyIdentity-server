package store

import (
	"errors"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
)

// erasureOrg is a household with an activated holder and the members given (id: status).
func erasureOrg(t *testing.T, s *Store, org string, members map[string]string) {
	t.Helper()
	newTestOrg(t, s, org, "active")
	newOrgUser(t, s, org+"-holder", org, "active", false)
	for _, id := range slices.Sorted(maps.Keys(members)) {
		if members[id] == "pending" {
			newOrgUser(t, s, org+"-"+id, org, "disabled", true)
		} else {
			newOrgUser(t, s, org+"-"+id, org, members[id], false)
		}
	}
	tenancyExec(t, s, `UPDATE orgs SET account_holder_user_id='`+org+`-holder' WHERE id='`+org+`'`)
}

// erasureGrant gives userID a session and a step-up grant for the button proved with factor.
func erasureGrant(t *testing.T, s *Store, userID, factor string) (session, hash string) {
	t.Helper()
	session, hash = uuid.NewString(), uuid.NewString()
	if err := s.CreateSession(&Session{ID: session, UserID: userID, SessionTokenHash: uuid.NewString(), ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateStepUpToken(&StepUpToken{ID: uuid.NewString(), UserID: userID, SessionID: session, TokenHash: hash,
		Operation: testEraseOp, FactorMethod: factor, ExpiresAt: time.Now().UTC().Add(time.Minute)}, nil); err != nil {
		t.Fatal(err)
	}
	return session, hash
}

const testEraseOp = "POST /api/user/erase"

func erase(t *testing.T, s *Store, org, userID, factor string) (*Erasure, error) {
	t.Helper()
	session, hash := erasureGrant(t, s, userID, factor)
	return s.Org(OrgID{org}).Erase(userID, session, hash, testEraseOp, &AuditEvent{ID: uuid.NewString(), ActorID: userID, Action: "account.erased", TargetID: userID, TargetType: "user", Outcome: "success"})
}

func rowCount(t *testing.T, s *Store, q string, args ...any) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

// The new trigger paths, and every refusal around them.
func TestErasureTriggers(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	erasureOrg(t, s, "solo", nil)
	erasureOrg(t, s, "home", map[string]string{"kid": "active"})
	newTestOrg(t, s, "gone", "suspended")
	ins := func(org, holder, immediate string) string {
		return `INSERT INTO org_erasures(org_id,holder_user_id,immediate,requested_at) VALUES('` + org + `','` + holder + `',` + immediate + `,CURRENT_TIMESTAMP)`
	}
	// Only the holder of an active person or household org asks, and immediate is exact.
	refused(t, s, msgErasureAsk, ins("home", "home-kid", "FALSE"))
	refused(t, s, msgErasureAsk, ins("home", "home-holder", "TRUE"))
	refused(t, s, msgErasureAsk, ins("solo", "solo-holder", "FALSE"))
	refused(t, s, msgErasureAsk, ins("gone", "nobody", "TRUE"))
	refused(t, s, msgErasureAsk, ins(DefaultOrgID, "nobody", "TRUE"))
	// Without a request, active never goes straight to deleted.
	refused(t, s, msgDeleted, `UPDATE orgs SET status='deleted' WHERE id='solo'`)
	refused(t, s, msgHolderNotLive, `UPDATE orgs SET account_holder_user_id=NULL WHERE id='solo'`)

	// holder_erased: with the request, and nobody else live, it does.
	tenancyExec(t, s, ins("solo", "solo-holder", "TRUE"))
	refused(t, s, msgErasureKept, `UPDATE org_erasures SET immediate=FALSE WHERE org_id='solo'`)
	refused(t, s, msgErasureKept, `DELETE FROM org_erasures WHERE org_id='solo'`)
	refused(t, s, "org_erasures", ins("solo", "solo-holder", "TRUE")) // a second request
	// A member who turns up live closes the path.
	newOrgUser(t, s, "solo-late", "solo", "active", false)
	refused(t, s, msgDeleted, `UPDATE orgs SET status='deleted' WHERE id='solo'`)
	tenancyExec(t, s, `UPDATE users SET status='disabled' WHERE id='solo-late'`,
		`UPDATE orgs SET status='deleted', name='', account_holder_user_id=NULL WHERE id='solo'`)
	refused(t, s, msgDeleted, `UPDATE orgs SET status='active' WHERE id='solo'`)

	// The scheduled path: resume, suspension and a new delete_after are refused.
	tenancyExec(t, s, ins("home", "home-holder", "FALSE"),
		`UPDATE orgs SET status='deletion_scheduled', delete_after=4102444800 WHERE id='home'`)
	for _, q := range []string{
		`UPDATE orgs SET status='active', delete_after=NULL WHERE id='home'`,
		`UPDATE orgs SET status='active' WHERE id='home'`,
		`UPDATE orgs SET status='suspended' WHERE id='home'`,
		`UPDATE orgs SET delete_after=4102444801 WHERE id='home'`,
		`UPDATE orgs SET delete_after=1 WHERE id='home'`,
	} {
		refused(t, s, msgErased, q)
	}
	refused(t, s, msgDeleted, `UPDATE orgs SET status='deleted', name='', account_holder_user_id=NULL WHERE id='home'`)
	tenancyExec(t, s, `UPDATE orgs SET plan='x' WHERE id='home'`) // other columns are not the request's

	// Tombstones are kept, and their subjects never come back.
	tenancyExec(t, s, `INSERT INTO erased_subjects(subject,org_id,revision,erased_at) VALUES('home-kid2','home',1,CURRENT_TIMESTAMP)`)
	refused(t, s, msgErasureKept, `UPDATE erased_subjects SET revision=2`)
	refused(t, s, msgErasureKept, `DELETE FROM erased_subjects`)
	refused(t, s, msgErasedReused, `INSERT INTO users(id,username,display_name,email,password_hash,role,status,org_id) VALUES('home-kid2','k2','k2','k2@test.invalid','','user','active','home')`)
}

// A holder alone: the org is deleted now, every org row goes, and the tombstones stay.
func TestEraseHolderAlone(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	erasureOrg(t, s, "solo", map[string]string{"old": "disabled", "invited": "pending"})
	// A pending member is live, so the org would be scheduled; end the invite first.
	tenancyExec(t, s, `DELETE FROM users WHERE id='solo-invited'`)
	erasureOrg(t, s, "next", nil)
	if err := s.CreatePairedSystem(&PairedSystem{ID: "post", Name: "Post", SystemType: "kypost", CallbackURL: "https://post.example/api/sync/events", Status: "active"}, nil); err != nil {
		t.Fatal(err)
	}
	g := &Group{ID: "solo-g", Name: "solo group"}
	if err := s.Org(OrgID{"solo"}).CreateGroup(g, nil); err != nil {
		t.Fatal(err)
	}
	// The holder is signed in to an app that takes back-channel logout.
	session, hash := erasureGrant(t, s, "solo-holder", "totp")
	seedLogoutClient(t, s, "app", "https://app.example/bc")
	if _, err := s.EnsureClientSession("app", session, "solo-holder"); err != nil {
		t.Fatal(err)
	}
	out, err := s.Org(OrgID{"solo"}).Erase("solo-holder", session, hash, testEraseOp, &AuditEvent{ID: uuid.NewString(), ActorID: "solo-holder", Action: "account.erased", TargetID: "solo-holder", TargetType: "user", Outcome: "success"})
	if err != nil || !out.Holder || !out.Deleted || out.Notices != 0 {
		t.Fatalf("erase = %+v, %v", out, err)
	}
	if n := rowCount(t, s, `SELECT COUNT(*) FROM logout_deliveries WHERE user_id='solo-holder' AND client_id='app' AND status='queued'`); n != 1 {
		t.Errorf("%d back-channel logouts queued for the holder's app, want 1", n)
	}
	var status, name string
	if err := s.db.QueryRow(`SELECT status,name FROM orgs WHERE id='solo'`).Scan(&status, &name); err != nil || status != "deleted" || name != "" {
		t.Fatalf("org is %q %q (%v)", status, name, err)
	}
	for _, table := range orgRowTables {
		if n := rowCount(t, s, `SELECT COUNT(*) FROM `+table+` WHERE org_id='solo'`); n != 0 {
			t.Errorf("%s keeps %d rows of the deleted org", table, n)
		}
	}
	if n := rowCount(t, s, `SELECT COUNT(*) FROM audit_events WHERE org_id='solo'`); n != 0 {
		t.Errorf("the org's audit kept %d rows", n)
	}
	if n := rowCount(t, s, `SELECT COUNT(*) FROM audit_events WHERE org_id IS NULL AND action='account.erased' AND target_id='solo' AND target_type='org'`); n != 1 {
		t.Errorf("%d platform erasure rows, want 1", n)
	}
	// Every member is offboarded first: the suite app is told to erase each, with bare bodies.
	for _, id := range []string{"solo-holder", "solo-old"} {
		var payload string
		if err := s.db.QueryRow(`SELECT payload_json FROM account_sync_events WHERE system_id='post' AND user_id=? AND event_type='user.erased' AND status='pending'`, id).Scan(&payload); err != nil || payload != string(scimInactivePayload(id)) {
			t.Errorf("%s: user.erased %q (%v)", id, payload, err)
		}
	}
	if n := rowCount(t, s, `SELECT COUNT(*) FROM erased_subjects WHERE org_id='solo'`); n != 2 {
		t.Errorf("%d tombstones, want the holder and the disabled member", n)
	}
	if n := rowCount(t, s, `SELECT COUNT(*) FROM platform_events WHERE org_id='solo' AND type='org.deleted'`); n != 1 {
		t.Errorf("%d org.deleted events", n)
	}
	// The other org is untouched.
	if n := rowCount(t, s, `SELECT COUNT(*) FROM users WHERE org_id='next'`); n != 1 {
		t.Errorf("the other org lost its users: %d", n)
	}
}

// A holder with members: deletion is scheduled, everyone's access ends, nobody can resume,
// and the sweep deletes the org only once the window has passed.
func TestEraseHolderWithMembers(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	erasureOrg(t, s, "home", map[string]string{"kid": "active", "invited": "pending"})
	kidSession, _ := erasureGrant(t, s, "home-kid", "totp")
	out, err := erase(t, s, "home", "home-holder", "webauthn")
	if err != nil || !out.Holder || out.Deleted || out.Notices != 1 {
		t.Fatalf("erase = %+v, %v", out, err)
	}
	if d := time.Until(out.DeleteAfter); d < 6*24*time.Hour || d > 7*24*time.Hour {
		t.Fatalf("delete after %v", out.DeleteAfter)
	}
	if n := rowCount(t, s, `SELECT COUNT(*) FROM sessions WHERE user_id IN ('home-holder','home-kid')`); n != 0 {
		t.Errorf("%d sessions survive the request (kid's was %s)", n, kidSession)
	}
	var status string
	if err := s.db.QueryRow(`SELECT status FROM orgs WHERE id='home'`).Scan(&status); err != nil || status != "deletion_scheduled" {
		t.Fatalf("org is %q (%v)", status, err)
	}
	if n := rowCount(t, s, `SELECT COUNT(*) FROM audit_events WHERE org_id='home' AND action='account.erased' AND target_type='org'`); n != 1 {
		t.Errorf("%d erasure rows in the org's log", n)
	}
	if _, err := s.db.Exec(`UPDATE orgs SET status='active' WHERE id='home'`); !errors.Is(erasureError(err), ErrOrgErased) {
		t.Fatalf("resume: %v", err)
	}
	if n, err := s.Platform().FinishDueErasures(); err != nil || n != 0 {
		t.Fatalf("sweep inside the window: %d %v", n, err)
	}
	if n := rowCount(t, s, `SELECT COUNT(*) FROM users WHERE org_id='home'`); n != 3 {
		t.Fatalf("the window deleted %d users early", 3-n)
	}

	// A second household whose window has already passed.
	erasureGrace = -time.Minute
	defer func() { erasureGrace = 7 * 24 * time.Hour }()
	erasureOrg(t, s, "past", map[string]string{"kid": "active"})
	if _, err := erase(t, s, "past", "past-holder", "push"); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Platform().FinishDueErasures(); err != nil || n != 1 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	if n, err := s.Platform().FinishDueErasures(); err != nil || n != 0 {
		t.Fatalf("second sweep: %d %v", n, err)
	}
	if n := rowCount(t, s, `SELECT COUNT(*) FROM users WHERE org_id='past'`); n != 0 {
		t.Errorf("%d users left after the sweep", n)
	}
	if n := rowCount(t, s, `SELECT COUNT(*) FROM erased_subjects WHERE org_id='past'`); n != 2 {
		t.Errorf("%d tombstones", n)
	}
	if n := rowCount(t, s, `SELECT COUNT(*) FROM users WHERE org_id='home'`); n != 3 {
		t.Errorf("the sweep reached the household still in its window")
	}
}

// A member erases only themselves: user.erased to suite webhooks, user.deleted to SCIM,
// both with the bare inactive body, their rows deleted, and their subject tombstoned.
func TestEraseMember(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	erasureOrg(t, s, "home", map[string]string{"kid": "active"})
	erasureOrg(t, s, "away", map[string]string{"kid": "active"})
	for _, ps := range []*PairedSystem{
		{ID: "post", Name: "Post", SystemType: "kypost", CallbackURL: "https://post.example/api/sync/events", Status: "active"},
		{ID: "scim", Name: "SCIM", SystemType: "scim", CallbackURL: "https://scim.example/scim", Status: "active"},
	} {
		if err := s.CreatePairedSystem(ps, nil); err != nil {
			t.Fatal(err)
		}
	}
	tenancyExec(t, s, `INSERT INTO audit_events(id,actor_id,actor_username,action,target_id,target_type,ip_address,user_agent,outcome,details_json,created_at,org_id)
 VALUES('ae-kid','home-kid','home-kid@test.invalid','user.password_changed','home-kid','user','','','success','{}',CURRENT_TIMESTAMP,'home')`,
		// A group change by the holder that names the member, and one that does not.
		`INSERT INTO audit_events(id,actor_id,actor_username,action,target_id,target_type,ip_address,user_agent,outcome,details_json,created_at,org_id)
 VALUES('ae-group','home-holder','','admin.group_member_added','g1','group','','','success','{"member":"home-kid"}',CURRENT_TIMESTAMP,'home')`,
		`INSERT INTO audit_events(id,actor_id,actor_username,action,target_id,target_type,ip_address,user_agent,outcome,details_json,created_at,org_id)
 VALUES('ae-other','home-holder','','admin.group_member_added','g1','group','','','success','{"member":"home-holder"}',CURRENT_TIMESTAMP,'home')`,
		// Rows that only contain the member's name as part of another value stay.
		`INSERT INTO audit_events(id,actor_id,actor_username,action,target_id,target_type,ip_address,user_agent,outcome,details_json,created_at,org_id)
 VALUES('ae-near','home-holder','','admin.group_member_added','g1','group','','','success','{"member":"home-kid-2","note":"x home-kid"}',CURRENT_TIMESTAMP,'home')`,
		`INSERT INTO alerts(id,rule,key,severity,title,summary,status,first_seen,last_seen,org_id) VALUES('al-kid','login_failures','home-kid','warning','Failed sign-ins','home-kid failed 9 times','open',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'home')`,
		`INSERT INTO alerts(id,rule,key,severity,title,summary,status,first_seen,last_seen,org_id) VALUES('al-other','login_failures','home-holder','warning','Failed sign-ins','home-holder failed 9 times','open',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'home')`)

	// Another org's handle finds no such member, and changes nothing.
	session, hash := erasureGrant(t, s, "home-kid", "totp")
	if _, err := s.Org(OrgID{"away"}).Erase("home-kid", session, hash, testEraseOp, nil); !errors.Is(err, ErrErasureStepUp) {
		t.Fatalf("cross-org erase: %v", err)
	}
	out, err := s.Org(OrgID{"home"}).Erase("home-kid", session, hash, testEraseOp, &AuditEvent{ID: "ae-erased", ActorID: "home-kid", Action: "account.erased", TargetID: "home-kid", TargetType: "user", Outcome: "success"})
	if err != nil || out.Holder || !out.Deleted {
		t.Fatalf("erase = %+v, %v", out, err)
	}
	// Replay: the grant and the session are spent.
	if _, err := s.Org(OrgID{"home"}).Erase("home-kid", session, hash, testEraseOp, nil); !errors.Is(err, ErrErasureStepUp) {
		t.Fatalf("replay: %v", err)
	}
	if n := rowCount(t, s, `SELECT COUNT(*) FROM users WHERE id='home-kid'`); n != 0 {
		t.Fatal("the member is still there")
	}
	for sys, want := range map[string]string{"post": "user.erased", "scim": "user.deleted"} {
		var typ, payload string
		if err := s.db.QueryRow(`SELECT event_type,payload_json FROM account_sync_events WHERE system_id=? AND user_id='home-kid' AND status='pending'`, sys).Scan(&typ, &payload); err != nil || typ != want {
			t.Errorf("%s: %q (%v), want %s", sys, typ, err, want)
		}
		if payload != string(scimInactivePayload("home-kid")) {
			t.Errorf("%s payload carries more than the subject: %s", sys, payload)
		}
	}
	if n := rowCount(t, s, `SELECT COUNT(*) FROM audit_events WHERE (actor_id='home-kid' OR target_id='home-kid') AND id<>'ae-erased'`); n != 0 {
		t.Errorf("%d audit rows still name the member", n)
	}
	if n := rowCount(t, s, `SELECT COUNT(*) FROM audit_events WHERE id='ae-group'`) + rowCount(t, s, `SELECT COUNT(*) FROM alerts WHERE id='al-kid'`); n != 0 {
		t.Errorf("%d audit rows or alerts still name the member in their text", n)
	}
	if n := rowCount(t, s, `SELECT COUNT(*) FROM audit_events WHERE id IN ('ae-other','ae-near')`) + rowCount(t, s, `SELECT COUNT(*) FROM alerts WHERE id='al-other'`); n != 3 {
		t.Errorf("rows about someone else went with the member: %d of 3 left", n)
	}
	if n := rowCount(t, s, `SELECT COUNT(*) FROM audit_events WHERE id='ae-erased' AND org_id='home'`); n != 1 {
		t.Error("the erasure row is not in the org's log")
	}
	if n := rowCount(t, s, `SELECT COUNT(*) FROM erased_subjects WHERE subject='home-kid' AND org_id='home'`); n != 1 {
		t.Error("no tombstone")
	}
	if n := rowCount(t, s, `SELECT COUNT(*) FROM users WHERE id IN ('home-holder','away-kid')`); n != 2 {
		t.Error("someone else was erased")
	}
	ev := AccountSyncEvent{EventType: "user.erased"}
	if !ev.Removal() {
		t.Error("user.erased is not a removal")
	}
}

// The grant must have proved a second factor, for this operation, and only once; the
// default org, staff, pending and non-active orgs have no button.
func TestErasureRefusals(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	erasureOrg(t, s, "home", map[string]string{"kid": "active"})
	for _, factor := range []string{"", "recovery", "password"} {
		if _, err := erase(t, s, "home", "home-kid", factor); !errors.Is(err, ErrErasureStepUp) {
			t.Errorf("factor %q: %v", factor, err)
		}
	}
	session, hash := erasureGrant(t, s, "home-kid", "totp")
	if _, err := s.Org(OrgID{"home"}).Erase("home-kid", session, hash, "POST /api/user/password", nil); !errors.Is(err, ErrErasureStepUp) {
		t.Errorf("another operation's grant: %v", err)
	}
	if _, err := s.Org(OrgID{"home"}).Erase("home-kid", uuid.NewString(), hash, testEraseOp, nil); !errors.Is(err, ErrErasureStepUp) {
		t.Errorf("another session: %v", err)
	}
	u := createTestUserNamed(t, s, "alice")
	if _, err := erase(t, s, DefaultOrgID, u.ID, "totp"); !errors.Is(err, ErrErasureRefused) {
		t.Errorf("default org: %v", err)
	}
	tenancyExec(t, s, `UPDATE orgs SET status='suspended' WHERE id='home'`)
	if _, err := erase(t, s, "home", "home-kid", "totp"); !errors.Is(err, ErrErasureRefused) {
		t.Errorf("suspended org: %v", err)
	}
	if n := rowCount(t, s, `SELECT COUNT(*) FROM org_erasures`) + rowCount(t, s, `SELECT COUNT(*) FROM erased_subjects`); n != 0 {
		t.Errorf("a refusal wrote %d rows", n)
	}
	if n := rowCount(t, s, `SELECT COUNT(*) FROM users`); n != 3 {
		t.Errorf("a refusal deleted users: %d left", n)
	}
}

// deleteOrgTx empties every org-owned table.
func TestDeleteOrgEmptiesEveryOrgTable(t *testing.T) {
	if got, want := slices.Sorted(slices.Values(append(append([]string{}, orgRowTables...), orgKeptTables...))), slices.Sorted(slices.Values(orgOwnedTables)); !slices.Equal(got, want) {
		t.Fatalf("orgRowTables and orgKeptTables %v, want the org-owned tables %v", got, want)
	}
}

// The notices are owed in the request's transaction and retried until one is sent.
func TestEraseNoticesAreRetriedUntilSent(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	erasureOrg(t, s, "home", map[string]string{"kid": "active", "invited": "pending"})
	out, err := erase(t, s, "home", "home-holder", "totp")
	if err != nil || out.Notices != 1 {
		t.Fatalf("erase = %+v, %v", out, err)
	}
	now := time.Now().UTC()
	var got []EraseNotice
	send := func(fail bool) func(EraseNotice) error {
		return func(n EraseNotice) error {
			got = append(got, n)
			if fail {
				return errors.New("relay down")
			}
			return nil
		}
	}
	// A failed send stays owed, backs off, and is audited once.
	if n, err := s.Platform().SendEraseNotices(now, send(true)); err != nil || n != 0 {
		t.Fatalf("failing pass = %d, %v", n, err)
	}
	if n, err := s.Platform().SendEraseNotices(now, send(false)); err != nil || n != 0 || len(got) != 1 {
		t.Fatalf("backed-off pass = %d, %v, %d sends", n, err, len(got))
	}
	if _, err := s.Platform().SendEraseNotices(now.Add(5*time.Minute), send(true)); err != nil {
		t.Fatal(err)
	}
	if n := rowCount(t, s, `SELECT COUNT(*) FROM audit_events WHERE org_id='home' AND action='account.erase_notice' AND outcome='failure'`); n != 1 {
		t.Errorf("%d failure rows, want 1", n)
	}
	if n, err := s.Platform().SendEraseNotices(now.Add(time.Hour), send(false)); err != nil || n != 1 {
		t.Fatalf("retry = %d, %v", n, err)
	}
	if len(got) != 3 || got[2].Email != "home-kid@test.invalid" || !got[2].DeleteAfter.Equal(out.DeleteAfter) {
		t.Fatalf("sends = %+v", got)
	}
	if n := rowCount(t, s, `SELECT COUNT(*) FROM erase_notices`); n != 0 {
		t.Errorf("%d notices still owed after a send", n)
	}
}
