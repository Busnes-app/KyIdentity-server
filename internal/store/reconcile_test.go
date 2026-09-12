package store

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

func TestReconcileJobsClaimLeaseAndInterrupt(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	provisioningFixture(t, s, "target")
	job, err := s.CreateReconcileJob("target", "preview", "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateReconcileJob("target", "repair", "admin", nil); !errors.Is(err, ErrReconcileBusy) {
		t.Fatal("second job accepted while one is queued", err)
	}
	if _, err := s.CreateReconcileJob("target", "audit", "admin", nil); err == nil {
		t.Fatal("bad kind accepted")
	}
	claimed, err := s.ClaimReconcileJob(time.Minute)
	if err != nil || claimed == nil || claimed.ID != job.ID || claimed.Status != "running" || claimed.Attempts != 1 {
		t.Fatalf("claim: %+v %v", claimed, err)
	}
	if again, _ := s.ClaimReconcileJob(time.Minute); again != nil {
		t.Fatal("leased job claimed twice")
	}
	// A crashed worker's lease expires; the job is re-claimed, but not forever.
	for attempt := 2; attempt <= reconcileAttempts; attempt++ {
		if _, err := s.db.Exec(`UPDATE sync_reconcile_jobs SET lease_until=? WHERE id=?`, time.Now().UTC().Add(-time.Second), job.ID); err != nil {
			t.Fatal(err)
		}
		if claimed, err = s.ClaimReconcileJob(time.Minute); err != nil || claimed == nil || claimed.Attempts != attempt {
			t.Fatalf("re-claim %d: %+v %v", attempt, claimed, err)
		}
	}
	if _, err := s.db.Exec(`UPDATE sync_reconcile_jobs SET lease_until=? WHERE id=?`, time.Now().UTC().Add(-time.Second), job.ID); err != nil {
		t.Fatal(err)
	}
	if again, _ := s.ClaimReconcileJob(time.Minute); again != nil {
		t.Fatal("interrupted job claimed past its attempt budget")
	}
	jobs, err := s.ListReconcileJobs("target", 10)
	if err != nil || len(jobs) != 1 || jobs[0].Status != "failed" || jobs[0].Error == "" {
		t.Fatalf("interrupted job not failed: %+v %v", jobs, err)
	}
	// A stale claim cannot finish a job it no longer owns.
	if err := s.FinishReconcileJob(claimed, &DriftReport{}, nil); err == nil {
		t.Fatal("stale claim finished the job")
	}
	next, err := s.CreateReconcileJob("target", "repair", "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	claimed, _ = s.ClaimReconcileJob(time.Minute)
	if err := s.FinishReconcileJob(claimed, &DriftReport{Supported: true}, nil); err != nil {
		t.Fatal(err)
	}
	jobs, _ = s.ListReconcileJobs("target", 10)
	if len(jobs) != 2 || jobs[0].ID != next.ID || jobs[0].Status != "done" || jobs[0].FinishedAt == nil || len(jobs[0].Result) == 0 {
		t.Fatalf("%+v", jobs)
	}
}

func TestScheduleReconcileJobs(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	provisioningFixture(t, s, "target")
	provisioningFixture(t, s, "off")
	now := time.Now().UTC()
	if err := s.ScheduleReconcileJobs(now); err != nil {
		t.Fatal(err)
	}
	if jobs, _ := s.ListReconcileJobs("target", 10); len(jobs) != 0 {
		t.Fatal("unscheduled connector got a job")
	}
	if err := s.ConfigureSystem("target", "scim", "scim", "secret", false, 6, nil); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := s.ScheduleReconcileJobs(now); err != nil {
			t.Fatal(err)
		}
	}
	jobs, _ := s.ListReconcileJobs("target", 10)
	if len(jobs) != 1 || jobs[0].Kind != "repair" || jobs[0].RequestedBy != "schedule" {
		t.Fatalf("%+v", jobs)
	}
	claimed, _ := s.ClaimReconcileJob(time.Minute)
	if err := s.FinishReconcileJob(claimed, &DriftReport{Supported: true, Complete: true, Repaired: true, OrphanedCount: 2}, nil); err != nil {
		t.Fatal(err)
	}
	// A scheduled repair leaves a durable trace of its request and its outcome.
	events, _, err := s.ListAuditEvents(50, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, ev := range events {
		if ev.TargetID == "target" {
			seen[ev.Action] = ev.DetailsJSON
		}
	}
	if !strings.Contains(seen["admin.reconcile_requested"], `"requestedBy":"schedule"`) || !strings.Contains(seen["admin.reconcile_completed"], `"orphaned":2`) {
		t.Fatalf("audit %+v", seen)
	}
	if err := s.ScheduleReconcileJobs(now.Add(5 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if jobs, _ = s.ListReconcileJobs("target", 10); len(jobs) != 1 {
		t.Fatal("scheduled before the interval elapsed", jobs)
	}
	if err := s.ScheduleReconcileJobs(now.Add(7 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if jobs, _ = s.ListReconcileJobs("target", 10); len(jobs) != 2 {
		t.Fatal("not scheduled after the interval", jobs)
	}
	if jobs, _ = s.ListReconcileJobs("off", 10); len(jobs) != 0 {
		t.Fatal("connector without a schedule got a job")
	}
}

func TestReconcileDriftRepairsManagedAccountsOnly(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	app := provisioningFixture(t, s, "target")
	wanted, orphan, stale := createTestUserNamed(t, s, "wanted"), createTestUserNamed(t, s, "orphan"), createTestUserNamed(t, s, "stale")
	for _, u := range []*User{wanted, stale, orphan} {
		if err := s.SetAppAssignment(app, "users", u.ID, true, nil); err != nil {
			t.Fatal(err)
		}
	}
	deliverAll(t, s)
	// The connector held orphan's account; access was revoked, but the target kept it active.
	if err := s.SetAppAssignment(app, "users", orphan.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	deliverAll(t, s)
	if _, err := s.db.Exec(`DELETE FROM account_sync_events`); err != nil {
		t.Fatal(err)
	}
	listing := RemoteListing{Supported: true, Complete: true, Users: []RemoteAccount{
		{ID: "r-stale", ExternalID: stale.ID, UserName: "old-name", DisplayName: stale.DisplayName, Email: stale.Email, Active: true},
		{ID: "r-orphan", ExternalID: orphan.ID, UserName: orphan.Username, Active: true},
		{ID: "r-foreign", ExternalID: "someone-else", UserName: "foreign", Active: true},
		{ID: "r-local", UserName: "local-only", Active: true},
	}}
	preview, err := s.ReconcileDrift("target", listing, false)
	if err != nil {
		t.Fatal(err)
	}
	if preview.MissingCount != 1 || preview.Missing[0].ID != wanted.ID || preview.StaleCount != 1 || preview.Stale[0].ID != stale.ID || preview.OrphanedCount != 1 || preview.Orphaned[0].ID != orphan.ID || preview.Unrelated != 2 || preview.Repaired {
		t.Fatalf("preview %+v", preview)
	}
	if pending, _ := s.GetPendingSyncEvents(10); len(pending) != 0 {
		t.Fatal("preview queued work", pending)
	}
	rows, _, err := s.ListProvisioningState("target", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	observed := map[string]string{}
	for _, r := range rows {
		observed[r.Username] = r.Observed
	}
	if observed["wanted"] != "absent" || observed["stale"] != "present_active" {
		t.Fatalf("observations %+v", observed)
	}
	// Repair lists fresh: an incomplete listing repairs nothing destructive.
	partial := listing
	partial.Complete = false
	report, err := s.ReconcileDrift("target", partial, true)
	if err != nil {
		t.Fatal(err)
	}
	if report.Complete || report.Repaired || report.OrphanedCount != 0 || report.MissingCount != 0 {
		t.Fatalf("incomplete listing inferred drift: %+v", report)
	}
	if pending, _ := s.GetPendingSyncEvents(10); len(pending) != 1 || pending[0].UserID != stale.ID {
		t.Fatal("incomplete listing queued more than the safe attribute repair", pending)
	}
	report, err = s.ReconcileDrift("target", listing, true)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Repaired || report.MissingCount != 1 || report.OrphanedCount != 1 {
		t.Fatalf("repair %+v", report)
	}
	if got := pendingFor(t, s, "target", wanted.ID); len(got) != 1 || got[0].Type != "user.created" || !got[0].Active {
		t.Fatal("missing account not re-created", got)
	}
	if got := pendingFor(t, s, "target", stale.ID); len(got) != 1 || !got[0].Active {
		t.Fatal("stale account not updated", got)
	}
	if got := pendingFor(t, s, "target", orphan.ID); len(got) != 1 || got[0].Type != "user.updated" || got[0].Active {
		t.Fatal("orphaned account not deactivated", got)
	}
	if got := pendingFor(t, s, "target", "someone-else"); len(got) != 0 {
		t.Fatal("unrelated account touched", got)
	}
	if id, _, _ := s.SCIMUserLink("target", orphan.ID); id != "r-orphan" {
		t.Fatal("listing did not record the remote mapping", id)
	}
}

func TestReconcilePreviewWritesNothingAndManagedIsConnectorScoped(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	app := provisioningFixture(t, s, "target")
	provisioningFixture(t, s, "other")
	stranger, held := createTestUserNamed(t, s, "stranger"), createTestUserNamed(t, s, "held")
	if err := s.SetAppAssignment(app, "users", held.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	deliverAll(t, s)
	if err := s.SaveSCIMUserLink("target", held.ID, "r-held"); err != nil {
		t.Fatal(err)
	}
	// The target names a local user this connector has no relationship with, and
	// disputes the mapping of one it holds.
	listing := RemoteListing{Supported: true, Complete: true, Users: []RemoteAccount{
		{ID: "r-stranger", ExternalID: stranger.ID, UserName: stranger.Username, Active: true},
		{ID: "r-other", ExternalID: held.ID, UserName: held.Username, DisplayName: held.DisplayName, Email: held.Email, Active: true},
	}}
	preview, err := s.ReconcileDrift("target", listing, false)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Unrelated != 1 || preview.OrphanedCount != 0 {
		t.Fatalf("stranger treated as managed: %+v", preview)
	}
	var links int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM scim_user_links WHERE system_id='target' AND local_id=?`, stranger.ID).Scan(&links); err != nil || links != 0 {
		t.Fatal("preview persisted a target-supplied mapping", links, err)
	}
	if id, _, _ := s.SCIMUserLink("target", held.ID); id != "r-held" {
		t.Fatal("preview rewrote a stored mapping", id)
	}
	repair, err := s.ReconcileDrift("target", listing, true)
	if err != nil {
		t.Fatal(err)
	}
	if repair.MappingConflicts != 1 || repair.Unrelated != 1 {
		t.Fatalf("conflict not observed: %+v", repair)
	}
	if id, _, _ := s.SCIMUserLink("target", held.ID); id != "r-held" {
		t.Fatal("repair rewrote a disputed mapping", id)
	}
	if got := pendingFor(t, s, "target", held.ID); len(got) != 0 {
		t.Fatal("repair wrote through a disputed mapping", got)
	}
	if err := s.DeleteUserWithSyncEvents(stranger.ID, nil); err != nil {
		t.Fatal(err)
	}
	var body string
	if err := s.db.QueryRow(`SELECT payload_json FROM account_sync_events WHERE system_id='target' AND user_id=?`, stranger.ID).Scan(&body); err != nil || strings.Contains(body, stranger.Username) {
		t.Fatal("connector that never held the account received its profile", body, err)
	}
}

func TestReconcileReportBoundsRemoteText(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	app := provisioningFixture(t, s, "target")
	var orphans []RemoteAccount
	huge := strings.Repeat("x", 200000)
	for i := 0; i < 5; i++ {
		u := createTestUser(t, s)
		if err := s.SetAppAssignment(app, "users", u.ID, true, nil); err != nil {
			t.Fatal(err)
		}
		deliverAll(t, s)
		if err := s.SetAppAssignment(app, "users", u.ID, false, nil); err != nil {
			t.Fatal(err)
		}
		deliverAll(t, s)
		orphans = append(orphans, RemoteAccount{ID: "r" + u.ID, ExternalID: u.ID, UserName: huge, DisplayName: huge, Active: true}.Bounded())
		if i == 4 {
			// A deleted user's orphan, still mapped at the target, has no local name to fall back on.
			if err := s.SaveSCIMUserLink("target", u.ID, "r"+u.ID); err != nil {
				t.Fatal(err)
			}
			if err := s.DeleteUserWithSyncEvents(u.ID, nil); err != nil {
				t.Fatal(err)
			}
			deliverAll(t, s)
		}
	}
	job, err := s.CreateReconcileJob("target", "repair", "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	job, _ = s.ClaimReconcileJob(time.Minute)
	report, err := s.ReconcileDrift("target", RemoteListing{Supported: true, Complete: true, Users: orphans}, true)
	if err != nil {
		t.Fatal(err)
	}
	if report.OrphanedCount != 5 {
		t.Fatalf("%+v", report)
	}
	for _, e := range report.Orphaned {
		if utf8.RuneCountInString(e.Username) > RemoteTextLimit {
			t.Fatalf("unbounded remote username retained: %d runes", utf8.RuneCountInString(e.Username))
		}
	}
	if err := s.FinishReconcileJob(job, report, nil); err != nil {
		t.Fatal(err)
	}
	var size int
	if err := s.db.QueryRow(`SELECT length(result_json) FROM sync_reconcile_jobs WHERE id=?`, job.ID).Scan(&size); err != nil || size > 8192 {
		t.Fatalf("report size %d %v", size, err)
	}
}

func TestReconcileDriftUnsupportedAndGroups(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	app := provisioningFixture(t, s, "target")
	u := createTestUser(t, s)
	if err := s.SetAppAssignment(app, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	deliverAll(t, s)
	report, err := s.ReconcileDrift("target", RemoteListing{}, true)
	if err != nil || report.Supported || report.Repaired {
		t.Fatal(report, err)
	}
	rows, _, _ := s.ListProvisioningState("target", "", 50, 0)
	if len(rows) != 1 || rows[0].Observed != "unsupported" || !rows[0].Acknowledged || !rows[0].Desired {
		t.Fatalf("%+v", rows)
	}
	g := &Group{ID: uuid.NewString(), Name: "staff"}
	if err := s.CreateGroup(g, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppAssignment(app, "groups", g.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfigureSystem("target", "scim", "scim", "secret", true, 0, nil); err != nil {
		t.Fatal(err)
	}
	orphanGroup := &Group{ID: uuid.NewString(), Name: "former"}
	if err := s.CreateGroup(orphanGroup, nil); err != nil {
		t.Fatal(err)
	}
	// A group this connector once delivered, since unassigned, still exists at the target.
	if err := s.SaveSCIMLink("target", "group", orphanGroup.ID, "g-orphan"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DELETE FROM account_sync_events`); err != nil {
		t.Fatal(err)
	}
	listing := RemoteListing{Supported: true, Complete: true, GroupsListed: true,
		Users:  []RemoteAccount{{ID: "r1", ExternalID: u.ID, UserName: u.Username, DisplayName: u.DisplayName, Email: u.Email, Active: true}},
		Groups: []RemoteGroup{{ID: "g-orphan", ExternalID: orphanGroup.ID, DisplayName: "former"}, {ID: "g-foreign", ExternalID: "not-ours"}}}
	report, err = s.ReconcileDrift("target", listing, true)
	if err != nil {
		t.Fatal(err)
	}
	if report.GroupsRequeued != 1 || report.GroupsOrphaned != 1 || report.StaleCount != 0 {
		t.Fatalf("%+v", report)
	}
	if got := pendingFor(t, s, "target", g.ID); len(got) != 1 || got[0].Type != "group.updated" {
		t.Fatal("assigned group not re-queued", got)
	}
	if got := pendingFor(t, s, "target", orphanGroup.ID); len(got) != 1 || got[0].Type != "group.deleted" {
		t.Fatal("orphaned group not removed", got)
	}
	if got := pendingFor(t, s, "target", "not-ours"); len(got) != 0 {
		t.Fatal("foreign group touched", got)
	}
}

func TestRetryProvisioningRequeuesDesiredState(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	app := provisioningFixture(t, s, "target")
	u := createTestUser(t, s)
	if err := s.RetryProvisioning("target", u.ID, nil); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("retry for a user outside scope with no state", err)
	}
	if err := s.SetAppAssignment(app, "users", u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	events, _ := s.ClaimDueSyncEvents(10, time.Minute)
	if ok, err := s.BeginSyncDelivery(events[0], time.Minute); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if err := s.FinishSyncDelivery(events[0], "failed", "boom", 5, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.RetryProvisioning("target", u.ID, nil); err != nil {
		t.Fatal(err)
	}
	if got := pendingFor(t, s, "target", u.ID); len(got) != 1 || got[0] != (queued{"user.created", 2, true}) {
		t.Fatal("retry did not supersede the exhausted create", got)
	}
	rows, total, err := s.ListProvisioningState("target", u.Username[:4], 25, 0)
	if err != nil || total != 1 || len(rows) != 1 || rows[0].LastEvent == nil || rows[0].LastEvent.Status != "pending" || !rows[0].Desired || !rows[0].Recorded || rows[0].Acknowledged {
		t.Fatalf("%+v %d %v", rows, total, err)
	}
	if err := s.RetryProvisioning("missing", u.ID, nil); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal(err)
	}
}
