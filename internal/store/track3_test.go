package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRestoreCustomerReconciliation(t *testing.T) {
	for _, multi := range []bool{false, true} {
		t.Run(map[bool]string{false: "single unchanged", true: "multi held"}[multi], func(t *testing.T) {
			s, done := setupTestStore(t)
			defer done()
			platformTestTokenRow(t, s)
			org, apps := poolFixture(t, s, OrgLimits{MaxSeats: 4, StorageBytes: 10 * gib})
			member := &User{ID: uuid.NewString(), Username: uuid.NewString(), Email: uuid.NewString() + "@test.example", Role: "user", Status: "active"}
			if err := s.Org(org).CreateUser(member); err != nil {
				t.Fatal(err)
			}
			staff, err := s.EnsureStaffOrg()
			if err != nil {
				t.Fatal(err)
			}
			beforeStaff := count(t, s, `SELECT revision FROM orgs WHERE id=?`, staff.id)
			beforeDefault := count(t, s, `SELECT revision FROM orgs WHERE id=?`, DefaultOrgID)
			scheduled, _ := CreateOrgForTest(s, "customer")
			suspended, _ := CreateOrgForTest(s, "customer")
			deleted, _ := CreateOrgForTest(s, "customer")
			for _, q := range []string{`UPDATE orgs SET status='suspended',status_reason='abuse' WHERE id='` + suspended.id + `'`, `UPDATE orgs SET status='deletion_scheduled',delete_after=1 WHERE id='` + deleted.id + `'`, `UPDATE orgs SET status='deleted' WHERE id='` + deleted.id + `'`, `UPDATE orgs SET status='deletion_scheduled',delete_after=4000000000 WHERE id='` + scheduled.id + `'`} {
				if _, err := s.db.Exec(q); err != nil {
					t.Fatal(err)
				}
			}
			if multi {
				if err := s.SetSetting(TenancySetting, "multi"); err != nil {
					t.Fatal(err)
				}
			}
			now := time.Now().UTC()
			seedSession(t, s, member.ID, now.Add(time.Hour), now)
			r := report(t, s, "kydrive", StorageReport{OrgID: org.id, UsedBytes: 123, Seq: 8, WantBytes: 1000})[0]
			if r.CeilingBytes != 1123 {
				t.Fatal(r)
			}
			if _, err := s.db.Exec(`INSERT INTO platform_requests(token_id,idempotency_key,request_hash,status,response_json,created_at) VALUES('tok','cached','h',200,'{}',?)`, now); err != nil {
				t.Fatal(err)
			}
			if err := s.inTx(func(tx *sql.Tx) error { return queuePlatformEventTx(tx, org.id, "org.created", "", "", now) }); err != nil {
				t.Fatal(err)
			}
			audit := &AuditEvent{ID: uuid.NewString(), Action: "system.restored", Outcome: "success", CreatedAt: now}
			report, err := s.ApplyRestoredState(now, audit)
			if err != nil {
				t.Fatal(err)
			}
			o, err := s.Platform().PlatformOrg(org.id)
			if err != nil {
				t.Fatal(err)
			}
			if o.StorageUsage["kydrive"].UsedBytes != 123 || o.StorageUsage["kydrive"].Seq != 8 {
				t.Fatal(o)
			}
			for id, want := range map[string]string{scheduled.id: "deletion_scheduled", suspended.id: "suspended", deleted.id: "deleted"} {
				var got string
				if err := s.db.QueryRow(`SELECT status FROM orgs WHERE id=?`, id).Scan(&got); err != nil || got != want {
					t.Fatal(got, want, err)
				}
			}
			if count(t, s, `SELECT revision FROM orgs WHERE id=?`, staff.id) != beforeStaff || count(t, s, `SELECT revision FROM orgs WHERE id=?`, DefaultOrgID) != beforeDefault {
				t.Fatal("platform org changed")
			}
			if !multi {
				if o.Status != "active" || report.HeldOrgs != 0 || o.StorageUsage["kydrive"].CeilingBytes != 1123 || count(t, s, `SELECT COUNT(*) FROM platform_requests`) != 1 || strings.Contains(audit.DetailsJSON, "customerOrgsHeld") {
					t.Fatal(o, report, audit)
				}
				if generation, _ := s.Platform().OrgRestoreGeneration(); generation != "" {
					t.Fatal(generation)
				}
				return
			}
			if o.Status != "suspended" || o.StatusReason != restoreOrgReason || report.HeldOrgs != 1 || o.StorageUsage["kydrive"].CeilingBytes != 123 {
				t.Fatal(o, report)
			}
			if count(t, s, `SELECT COUNT(*) FROM platform_requests`) != 0 || count(t, s, `SELECT COUNT(*) FROM platform_events WHERE status='queued' AND type='org.created'`) != 0 || count(t, s, `SELECT COUNT(*) FROM platform_events WHERE status='queued' AND type='org.restore_reconciliation_required'`) != 4 {
				t.Fatal("stale billing state survived")
			}
			if count(t, s, `SELECT COUNT(*) FROM audit_events WHERE org_id=? AND action='org.restore_reconciliation_required'`, org.id) != 1 {
				t.Fatal("missing audit")
			}
			if generation, err := s.Platform().OrgRestoreGeneration(); generation == "" || err != nil {
				t.Fatal(generation, err)
			}
			if err := s.CreateSessionForInteraction(&Session{ID: uuid.NewString(), UserID: member.ID, SessionTokenHash: uuid.NewString(), ExpiresAt: now.Add(time.Hour)}, "", ""); !errors.Is(err, ErrOrgSuspended) {
				t.Fatalf("held sign-in: %v", err)
			}
			replay := reportStorageForTest(t, s, org.id, 8)
			if replay.CeilingBytes != 123 {
				t.Fatal("replay restored headroom", replay)
			}
			if _, err := s.Platform().ResumeOrgForStaff(org, o.OrgRevision, &AuditEvent{ActorID: "staff"}); !errors.Is(err, ErrRestoreReconciliation) {
				t.Fatal("stale resume admitted", err)
			}
			generation, err := s.Platform().OrgRestoreGeneration()
			if err != nil {
				t.Fatal(err)
			}
			resumed, err := s.Platform().ResumeOrgForStaff(org, o.OrgRevision, &AuditEvent{ActorID: "staff"}, generation)
			if err != nil || resumed.Status != "active" || resumed.Revision != o.Revision || resumed.OrgRevision <= o.OrgRevision {
				t.Fatal(resumed, err)
			}
			if err := s.CreateSessionForInteraction(&Session{ID: uuid.NewString(), UserID: member.ID, SessionTokenHash: uuid.NewString(), ExpiresAt: now.Add(time.Hour)}, "", ""); err != nil {
				t.Fatal("resume sign-in", err)
			}
			if _, err := s.db.Exec(`INSERT INTO org_storage(org_id,app_id,used_bytes,seq,ceiling_bytes,reported_at) VALUES(?,?,20,1,20,?)`, org.id, apps["kypost"], now.Unix()); err != nil {
				t.Fatal(err)
			}
			o, err = s.Platform().PlatformOrg(org.id)
			if err != nil || o.UsedBytes != 143 || o.StorageUsage["kypost"].UsedBytes != 20 {
				t.Fatal(o, err)
			}
			list, err := s.Platform().PlatformOrgs("", "", "", 100)
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range list {
				if v.ID == org.id && v.UsedBytes != 143 {
					t.Fatal(v)
				}
			}
		})
	}
}
func reportStorageForTest(t *testing.T, s *Store, org string, seq int64) StorageResult {
	t.Helper()
	return report(t, s, "kydrive", StorageReport{OrgID: org, UsedBytes: 123, Seq: seq, WantBytes: 1000})[0]
}

func TestRestoreOrgHoldAuditRollback(t *testing.T) {
	s, done := setupTestStore(t)
	defer done()
	org, _ := poolFixture(t, s, OrgLimits{MaxSeats: 1, StorageBytes: gib})
	if err := s.SetSetting(TenancySetting, "multi"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	audit := &AuditEvent{ID: "same", Action: "system.restored", Outcome: "success", CreatedAt: now}
	if err := s.RecordAuditEvent(audit); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyRestoredState(now, audit); err == nil {
		t.Fatal("duplicate audit accepted")
	}
	o, _ := s.Platform().PlatformOrg(org.id)
	generation, _ := s.Platform().OrgRestoreGeneration()
	if o.Status != "active" || generation != "" {
		t.Fatal(o, generation)
	}
}

func TestOrgEnrollmentIsolation(t *testing.T) {
	s, _, admin := enrollmentFixture(t)
	if err := s.SetSetting(TenancySetting, "multi"); err != nil {
		t.Fatal(err)
	}
	a, _ := CreateOrgForTest(s, "customer")
	b, _ := CreateOrgForTest(s, "customer")
	member := func(org OrgID) *User {
		u := &User{ID: uuid.NewString(), Username: uuid.NewString(), Email: uuid.NewString() + "@test.example", Role: "user", Status: "active"}
		if err := s.Org(org).CreateUser(u); err != nil {
			t.Fatal(err)
		}
		return u
	}
	ua, ub := member(a), member(b)
	ps, err := s.Org(a).OrgEnrollmentPolicies()
	if err != nil || len(ps) != 1 {
		t.Fatal(ps, err)
	}
	p := ps[0]
	p.Required = true
	p.AllowedMethods = []string{"totp"}
	p.GraceSeconds = 100
	preview, err := s.PreviewEnrollmentPolicy(p, "admin-session")
	if err != nil || preview.Affected != 1 {
		t.Fatal(preview, err)
	}
	if err := s.SetEnrollmentPolicy(p, "admin-session", &AuditEvent{ID: uuid.NewString(), ActorID: admin.ID, Action: "policy.changed", Outcome: "success"}); err != nil {
		t.Fatal(err)
	}
	status, err := s.SessionEnrollmentStatus(ua.ID, "")
	if err != nil || !status.Required || len(status.AllowedMethods) != 1 {
		t.Fatal(status, err)
	}
	other, err := s.SessionEnrollmentStatus(ub.ID, "")
	if err != nil || other.Required {
		t.Fatal(other, err)
	}
	deadline := status.Deadline
	p.Revision++
	p.GraceSeconds = 5000
	if err := s.SetEnrollmentPolicy(p, "admin-session", nil); err != nil {
		t.Fatal(err)
	}
	status, _ = s.SessionEnrollmentStatus(ua.ID, "")
	if status.Deadline != deadline {
		t.Fatal("extended deadline")
	}
	fresh := member(a)
	status, _ = s.SessionEnrollmentStatus(fresh.ID, "")
	if !status.Required {
		t.Fatal("new member escaped policy")
	}
	p.Scope = "org:missing"
	if err := s.SetEnrollmentPolicy(p, "admin-session", nil); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	policies, _ := s.ListEnrollmentPolicies()
	if len(policies) != 2 {
		t.Fatal("org policies leaked into global list", policies)
	}
}

func TestHolderOrgExportIsolation(t *testing.T) {
	s, done := setupTestStore(t)
	defer done()
	erasureOrg(t, s, "export", map[string]string{"member": "active"})
	erasureOrg(t, s, "foreign", map[string]string{"secret-other": "active"})
	// erasureOrg's holder and org use the fixture's prefix.
	var org, holder string
	if err := s.db.QueryRow(`SELECT id,account_holder_user_id FROM orgs WHERE account_holder_user_id IS NOT NULL AND id='export'`).Scan(&org, &holder); err != nil {
		t.Fatal(err)
	}
	o := s.Org(OrgID{org})
	if _, err := o.ExportOrg(context.Background(), holder, &AuditEvent{}); !errors.Is(err, ErrNotFound) {
		t.Fatal("active export", err)
	}
	if _, err := s.db.Exec(`UPDATE orgs SET status='deletion_scheduled',delete_after=? WHERE id=?`, time.Now().Add(time.Hour).Unix(), org); err != nil {
		t.Fatal(err)
	}
	data, err := o.ExportOrg(context.Background(), holder, &AuditEvent{Action: "account.org_exported", ActorID: holder})
	if err != nil {
		t.Fatal(err)
	}
	bytes, _ := json.Marshal(data)
	for _, secret := range []string{"secret-other", "password_hash", "token_hash", "public_key", "ciphertext"} {
		if strings.Contains(string(bytes), secret) {
			t.Fatal("export leaked", secret)
		}
	}
	if _, err := o.ExportOrg(context.Background(), "member", &AuditEvent{}); !errors.Is(err, ErrNotFound) {
		t.Fatal("member exported org", err)
	}
}

func TestExportOrgTruncatesAndPagesLargeAudit(t *testing.T) {
	s, done := setupTestStore(t)
	defer done()
	prev := orgExportMaxRows
	orgExportMaxRows = 2
	t.Cleanup(func() { orgExportMaxRows = prev })

	erasureOrg(t, s, "biglog", map[string]string{"member": "active"})
	var org, holder string
	if err := s.db.QueryRow(`SELECT id,account_holder_user_id FROM orgs WHERE account_holder_user_id IS NOT NULL AND id='biglog'`).Scan(&org, &holder); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE orgs SET status='deletion_scheduled',delete_after=? WHERE id=?`, time.Now().Add(time.Hour).Unix(), org); err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Add(-time.Hour)
	for i := 0; i < 5; i++ {
		e := &AuditEvent{
			ID:      fmt.Sprintf("seed-audit-%d", i),
			Action:  fmt.Sprintf("seed.event.%d", i),
			ActorID: holder,
			Outcome: "success",
		}
		if err := orgAuditTx(tx, org, e, nil, base.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	o := s.Org(OrgID{org})
	// Both holder and staff exports must succeed with users intact and partial/truncated markers when audit exceeds orgExportMaxRows.
	staffData, err := o.ExportOrgForStaff(context.Background(), &AuditEvent{Action: "staff.org_exported", ActorID: "staff-1"})
	if err != nil {
		t.Fatalf("staff export failed on large audit log: %v", err)
	}
	if staffData["partial"] != true {
		t.Fatalf("expected partial=true on staff export, got %#v", staffData["partial"])
	}
	if users, ok := staffData["users"].([]map[string]any); !ok || len(users) != 2 {
		t.Fatalf("expected 2 users intact in staff export, got %#v", staffData["users"])
	}

	page1, err := o.ExportOrg(context.Background(), holder, &AuditEvent{Action: "account.org_exported", ActorID: holder})
	if err != nil {
		t.Fatalf("holder export page 1 failed: %v", err)
	}
	if page1["partial"] != true {
		t.Fatalf("expected partial=true on page 1, got %#v", page1["partial"])
	}
	trunc1, ok := page1["truncated"].(map[string]any)["audit"].(map[string]any)
	if !ok || trunc1["returned"] != 2 || trunc1["limit"] != 2 || trunc1["more"] != true || trunc1["next_offset"] != 2 {
		t.Fatalf("unexpected page 1 truncated metadata: %#v", page1["truncated"])
	}
	audit1 := page1["audit"].([]map[string]any)
	if len(audit1) != 2 || audit1[0]["id"] != "seed-audit-0" || audit1[1]["id"] != "seed-audit-1" {
		t.Fatalf("unexpected page 1 audit rows: %#v", audit1)
	}

	page2, err := o.ExportOrg(context.Background(), holder, &AuditEvent{Action: "account.org_exported", ActorID: holder}, OrgExportOptions{AuditOffset: 2})
	if err != nil {
		t.Fatalf("holder export page 2 failed: %v", err)
	}
	audit2 := page2["audit"].([]map[string]any)
	if len(audit2) != 2 || audit2[0]["id"] != "seed-audit-2" || audit2[1]["id"] != "seed-audit-3" {
		t.Fatalf("unexpected page 2 audit rows: %#v", audit2)
	}
	trunc2 := page2["truncated"].(map[string]any)["audit"].(map[string]any)
	if trunc2["offset"] != 2 || trunc2["next_offset"] != 4 {
		t.Fatalf("unexpected page 2 truncated metadata: %#v", trunc2)
	}

	if _, err := o.ExportOrg(context.Background(), holder, &AuditEvent{Action: "account.org_exported", ActorID: holder}, OrgExportOptions{AuditOffset: -1}); err == nil {
		t.Fatal("expected error for negative AuditOffset")
	}
}

func TestRestoreMarkerRetryKeepsReconciliation(t *testing.T) {
	s, done := setupTestStore(t)
	defer done()
	org, _ := poolFixture(t, s, OrgLimits{MaxSeats: 1, StorageBytes: gib})
	if err := s.SetSetting(TenancySetting, "multi"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	details, _ := json.Marshal(map[string]any{"restoredAt": now, "capsule": "saved.kycap"})
	event := func() *AuditEvent {
		return &AuditEvent{ID: uuid.NewString(), Action: "system.restored", Outcome: "success", DetailsJSON: string(details), CreatedAt: now}
	}
	if _, err := s.ApplyRestoredState(now, event()); err != nil {
		t.Fatal(err)
	}
	generation, _ := s.Platform().OrgRestoreGeneration()
	before := count(t, s, `SELECT COUNT(*) FROM platform_events`)
	if _, err := s.ApplyRestoredState(now.Add(time.Minute), event()); err != nil {
		t.Fatal(err)
	}
	next, _ := s.Platform().OrgRestoreGeneration()
	if generation != next || count(t, s, `SELECT COUNT(*) FROM platform_events`) != before || count(t, s, `SELECT COUNT(*) FROM platform_events WHERE status='queued'`) != 1 {
		t.Fatal("marker retry discarded reconciliation")
	}
	// A distinct restore operation invalidates the cache generation again.
	if _, err := s.ApplyRestoredState(now.Add(time.Hour), nil); err != nil {
		t.Fatal(err)
	}
	next, _ = s.Platform().OrgRestoreGeneration()
	if generation == next {
		t.Fatal("new restore reused generation")
	}
	if count(t, s, `SELECT COUNT(*) FROM orgs WHERE id=? AND status='suspended'`, org.id) != 1 {
		t.Fatal("hold was lost")
	}
}
