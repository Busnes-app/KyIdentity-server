package store

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

const gib = int64(1) << 30

// poolFixture is a customer org with a pool and two suite apps enabled for it.
func poolFixture(t *testing.T, s *Store, l OrgLimits) (org OrgID, apps map[string]string) {
	t.Helper()
	org, err := CreateOrgForTest(s, customerKind)
	if err != nil {
		t.Fatal(err)
	}
	apps = map[string]string{}
	for _, c := range []string{"kydrive", "kypost"} {
		app, err := s.suiteAppID(c)
		if err == nil && app == "" {
			if err = s.CreateOAuthClient(&OAuthClient{ID: c, ClientName: c, ClientType: "confidential", RedirectURIsJSON: `["https://` + c + `.test/cb"]`, AllowedScopesJSON: `["openid"]`, Enabled: true}, nil); err == nil {
				app, err = s.suiteAppID(c)
			}
		}
		if err != nil || app == "" {
			t.Fatal(app, err)
		}
		apps[c] = app
		if err := EnableOrgAppForTest(s, org, app, `{}`); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Platform().SetOrgLimits(org, l, false, &AuditEvent{}); err != nil {
		t.Fatal(err)
	}
	return org, apps
}

func report(t *testing.T, s *Store, client string, r ...StorageReport) []StorageResult {
	t.Helper()
	out, err := s.Platform().ReportStorage(client, r, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func overSince(t *testing.T, s *Store, org OrgID) (bool, int64) {
	t.Helper()
	var over *int64
	var rev int64
	if err := s.db.QueryRow(`SELECT storage_over_since,revision FROM orgs WHERE id=?`, org.id).Scan(&over, &rev); err != nil {
		t.Fatal(err)
	}
	return over != nil, rev
}

// The pool is storage + per_seat × max_seats; S3's bounds hold at the store and in SQL.
func TestOrgPoolFormulaAndBounds(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	org, _ := poolFixture(t, s, OrgLimits{MaxSeats: 3, StoragePerSeatBytes: 30 * gib})
	orgs, err := s.Platform().SuiteOrgs("kydrive", 0, "", 10)
	if err != nil || len(orgs) != 1 || orgs[0].Storage == nil || orgs[0].Storage.PoolBytes != 90*gib || orgs[0].Storage.OverSince != nil {
		t.Fatalf("suite orgs %+v %v", orgs, err)
	}
	for _, l := range []OrgLimits{
		{MaxSeats: 0, StorageBytes: 20 * gib}, {MaxSeats: MaxSeats + 1, StorageBytes: 20 * gib},
	} {
		if err := s.Platform().SetOrgLimits(org, l, false, &AuditEvent{}); err != ErrInvalidMaxSeats {
			t.Errorf("%+v: %v", l, err)
		}
	}
	for _, l := range []OrgLimits{
		{MaxSeats: 1, StorageBytes: gib - 1}, {MaxSeats: 1, StorageBytes: -1, StoragePerSeatBytes: 2 * gib},
		{MaxSeats: 1, StorageBytes: MaxStorageBytes + 1}, {MaxSeats: 1, StoragePerSeatBytes: MaxStoragePerSeatBytes + 1},
	} {
		if err := s.Platform().SetOrgLimits(org, l, false, &AuditEvent{}); err != ErrInvalidStorage {
			t.Errorf("%+v: %v", l, err)
		}
	}
	if err := s.Platform().SetOrgLimits(org, OrgLimits{MaxSeats: MaxSeats, StorageBytes: MaxStorageBytes, StoragePerSeatBytes: MaxStoragePerSeatBytes}, false, &AuditEvent{}); err != nil {
		t.Fatalf("the largest pool: %v", err)
	}
	refused(t, s, "storage_bytes", `UPDATE orgs SET storage_bytes=1125899906842625 WHERE id='`+org.id+`'`)
	refused(t, s, "storage_per_seat_bytes", `UPDATE orgs SET storage_per_seat_bytes=-1 WHERE id='`+org.id+`'`)
	// The default org has no pool and is not a customer org.
	if err := s.Platform().SetOrgLimits(OrgID{DefaultOrgID}, OrgLimits{MaxSeats: 1, StorageBytes: 20 * gib}, false, &AuditEvent{}); err != ErrNotFound {
		t.Fatalf("default org: %v", err)
	}
	if err := s.Platform().SetOrgLimits(org, OrgLimits{MaxSeats: 1, StorageBytes: 20 * gib}, false, nil); err == nil {
		t.Fatal("a change without its audit row")
	}
}

// A report is applied only above the stored seq, in either order; the same seq and bytes
// is a replay with the grant unchanged; the same seq with other bytes is stale.
func TestStorageReportSequence(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	org, _ := poolFixture(t, s, OrgLimits{MaxSeats: 1, StorageBytes: 20 * gib})
	first := report(t, s, "kydrive", StorageReport{OrgID: org.id, UsedBytes: gib, Seq: 5, WantBytes: gib})[0]
	if first.Result != "ok" || first.Seq != 5 || first.CeilingBytes != 2*gib || first.TTLSeconds != StorageGrantTTL || first.PoolBytes != 20*gib || first.OrgUsedBytes != gib {
		t.Fatalf("first %+v %+v", first, first.StorageGrant)
	}
	if r := report(t, s, "kydrive", StorageReport{OrgID: org.id, UsedBytes: gib, Seq: 5, WantBytes: 3 * gib})[0]; r.Result != "ok" || r.CeilingBytes != 2*gib {
		t.Fatalf("replay %+v", r.StorageGrant)
	}
	for _, r := range []StorageReport{{OrgID: org.id, UsedBytes: 0, Seq: 4}, {OrgID: org.id, UsedBytes: 7, Seq: 5}} {
		if got := report(t, s, "kydrive", r)[0]; got.Result != "stale" || got.Seq != 5 || got.CeilingBytes != 2*gib || got.OrgUsedBytes != gib {
			t.Fatalf("stale %+v: %+v %+v", r, got, got.StorageGrant)
		}
	}
	// Newer first, then older: the older changes nothing.
	report(t, s, "kydrive", StorageReport{OrgID: org.id, UsedBytes: 3 * gib, Seq: 9})
	if got := report(t, s, "kydrive", StorageReport{OrgID: org.id, UsedBytes: 0, Seq: 8})[0]; got.Result != "stale" || got.OrgUsedBytes != 3*gib {
		t.Fatalf("older after newer %+v", got.StorageGrant)
	}
	// Each app has its own sequence.
	if got := report(t, s, "kypost", StorageReport{OrgID: org.id, UsedBytes: gib, Seq: 1})[0]; got.Result != "ok" || got.OrgUsedBytes != 4*gib {
		t.Fatalf("second app %+v", got.StorageGrant)
	}
}

// Grants reserve bytes: two apps never hold more than the pool between them, and every
// grant an org holds at once stays under min(pool/8, 64 GiB).
func TestStorageGrantsReserve(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	org, _ := poolFixture(t, s, OrgLimits{MaxSeats: 1, StorageBytes: 16 * gib})
	a := report(t, s, "kydrive", StorageReport{OrgID: org.id, UsedBytes: 13 * gib, Seq: 1, WantBytes: 10 * gib})[0]
	if a.CeilingBytes != 15*gib { // the cap: 16/8 = 2
		t.Fatalf("drive %+v", a.StorageGrant)
	}
	b := report(t, s, "kypost", StorageReport{OrgID: org.id, UsedBytes: 0, Seq: 1, WantBytes: 10 * gib})[0]
	if b.CeilingBytes != 0 { // 16 − 13 used − 2 held leaves 1, but the cap is spent
		t.Fatalf("post %+v", b.StorageGrant)
	}
	report(t, s, "kydrive", StorageReport{OrgID: org.id, UsedBytes: 13 * gib, Seq: 2, WantBytes: 0})
	b = report(t, s, "kypost", StorageReport{OrgID: org.id, UsedBytes: 0, Seq: 2, WantBytes: 10 * gib})[0]
	if b.CeilingBytes != 2*gib {
		t.Fatalf("post after release %+v", b.StorageGrant)
	}
	if grantBytes(100*gib, 1<<50, 0, 0) != grantCapBytes {
		t.Fatal("the 64 GiB cap")
	}
}

// A suspended org, a disabled app and an org over its pool get no grant; their reports
// are still applied.
func TestStorageGrantZero(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	org, apps := poolFixture(t, s, OrgLimits{MaxSeats: 1, StorageBytes: 20 * gib})
	tenancyExec(t, s, `UPDATE org_apps SET enabled=FALSE WHERE org_id='`+org.id+`' AND app_id='`+apps["kypost"]+`'`)
	if r := report(t, s, "kypost", StorageReport{OrgID: org.id, UsedBytes: gib, Seq: 1, WantBytes: gib})[0]; r.Result != "ok" || r.CeilingBytes != gib || r.OrgUsedBytes != gib {
		t.Fatalf("disabled app %+v", r.StorageGrant)
	}
	tenancyExec(t, s, `UPDATE orgs SET status='suspended' WHERE id='`+org.id+`'`)
	if r := report(t, s, "kydrive", StorageReport{OrgID: org.id, UsedBytes: gib, Seq: 1, WantBytes: gib})[0]; r.Result != "ok" || r.CeilingBytes != gib {
		t.Fatalf("suspended %+v", r.StorageGrant)
	}
	tenancyExec(t, s, `UPDATE orgs SET status='active' WHERE id='`+org.id+`'`)
	_, rev := overSince(t, s, org)
	r := report(t, s, "kydrive", StorageReport{OrgID: org.id, UsedBytes: 21 * gib, Seq: 2, WantBytes: gib})[0]
	if r.CeilingBytes != 21*gib || r.OverSince == nil {
		t.Fatalf("over the pool %+v", r.StorageGrant)
	}
	if over, rev2 := overSince(t, s, org); !over || rev2 <= rev {
		t.Fatalf("over_since %v, revision %d → %d", over, rev, rev2)
	}
	orgs, _ := s.Platform().SuiteOrgs("kydrive", rev, "", 10)
	if len(orgs) != 1 || orgs[0].Storage.OverSince == nil {
		t.Fatalf("suite orgs since %d: %+v", rev, orgs)
	}
	// Back within the pool: cleared, with a new revision, and grants resume.
	r = report(t, s, "kydrive", StorageReport{OrgID: org.id, UsedBytes: 10 * gib, Seq: 3, WantBytes: gib})[0]
	if over, _ := overSince(t, s, org); over || r.OverSince != nil || r.CeilingBytes != 11*gib {
		t.Fatalf("within again %+v", r.StorageGrant)
	}
	var actions []string
	rows, err := s.db.Query(`SELECT action FROM audit_events WHERE org_id=? AND action LIKE 'org.storage%' ORDER BY created_at`, org.id)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var a string
		_ = rows.Scan(&a)
		actions = append(actions, a)
	}
	if strings.Join(actions, ",") != "org.storage_over,org.storage_within" {
		t.Fatalf("audit %v", actions)
	}
}

// Another app's org, a deleted org, a staff org and a missing one answer the same.
func TestStorageUnknownOrg(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	org, _ := poolFixture(t, s, OrgLimits{MaxSeats: 1, StorageBytes: 20 * gib})
	other, err := CreateOrgForTest(s, customerKind)
	if err != nil {
		t.Fatal(err)
	}
	staff, err := CreateOrgForTest(s, "staff")
	if err != nil {
		t.Fatal(err)
	}
	tenancyExec(t, s, `UPDATE orgs SET all_apps=TRUE WHERE id='`+staff.id+`'`)
	gone := deletedOrg(t, s)
	for _, id := range []string{other.id, gone, staff.id, uuid.NewString(), DefaultOrgID} {
		got := report(t, s, "kydrive", StorageReport{OrgID: id, UsedBytes: 1, Seq: 1})
		if len(got) != 1 || got[0].Result != "unknown_org" || got[0].StorageGrant != nil {
			t.Errorf("%s: %+v", id, got)
		}
	}
	// A client with no app row learns nothing either.
	if got := report(t, s, "nobody", StorageReport{OrgID: org.id, UsedBytes: 1, Seq: 1}); got[0].Result != "unknown_org" {
		t.Fatalf("no app: %+v", got)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM org_storage`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("rows written: %d %v", n, err)
	}
}

func deletedOrg(t *testing.T, s *Store) string {
	t.Helper()
	org, err := CreateOrgForTest(s, customerKind)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE orgs SET status='deletion_scheduled',delete_after=1 WHERE id=?`, org.id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE orgs SET status='deleted' WHERE id=?`, org.id); err != nil {
		t.Fatal(err)
	}
	return org.id
}

// The approved rule: a seat change that lowers the pool below usage needs the holder's
// acknowledgement, deletes nothing, and blocks new content until the org is back within.
func TestSeatChangeOverThePool(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	org, _ := poolFixture(t, s, OrgLimits{MaxSeats: 3, StoragePerSeatBytes: 30 * gib})
	report(t, s, "kydrive", StorageReport{OrgID: org.id, UsedBytes: 70 * gib, Seq: 1})
	two := OrgLimits{MaxSeats: 2, StoragePerSeatBytes: 30 * gib}
	err := s.Platform().SetOrgLimits(org, two, false, &AuditEvent{})
	var over *StorageOverPoolError
	if !errors.As(err, &over) || over.PoolBytes != 60*gib || over.UsedBytes != 70*gib {
		t.Fatalf("without ack: %v", err)
	}
	if o, _ := overSince(t, s, org); o {
		t.Fatal("a refused change took effect")
	}
	if err := s.Platform().SetOrgLimits(org, two, true, &AuditEvent{ActorID: "billing"}); err != nil {
		t.Fatal(err)
	}
	if o, _ := overSince(t, s, org); !o {
		t.Fatal("not over after the acknowledged change")
	}
	var details string
	if err := s.db.QueryRow(`SELECT details_json FROM audit_events WHERE org_id=? AND action='org.limits_changed' AND actor_id='billing'`, org.id).Scan(&details); err != nil || !strings.Contains(details, `"storage_over_pool_ack":true`) {
		t.Fatalf("audit %s %v", details, err)
	}
	if r := report(t, s, "kypost", StorageReport{OrgID: org.id, Seq: 1, WantBytes: gib})[0]; r.CeilingBytes != 0 {
		t.Fatalf("a grant over the pool %+v", r.StorageGrant)
	}
	var used int64
	if err := s.db.QueryRow(`SELECT used_bytes FROM org_storage WHERE org_id=? AND seq=1 AND used_bytes=?`, org.id, 70*gib).Scan(&used); err != nil {
		t.Fatalf("usage changed: %v", err)
	}
	// Raising the pool needs no acknowledgement and clears the state.
	if err := s.Platform().SetOrgLimits(org, OrgLimits{MaxSeats: 3, StoragePerSeatBytes: 30 * gib}, false, &AuditEvent{}); err != nil {
		t.Fatal(err)
	}
	if o, _ := overSince(t, s, org); o {
		t.Fatal("still over after seats were added")
	}
}

// Seats (P3): a seat is an active or pending everyday account, capped at add, enable and
// activation, and max_seats cannot drop below the seats in use. Other orgs are unlimited.
func TestSeatCaps(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	org, _ := poolFixture(t, s, OrgLimits{MaxSeats: 2, StorageBytes: 20 * gib})
	o := s.Org(org)
	add := func(id string, pending bool) error {
		status := "active"
		if pending {
			status = "disabled"
		}
		return o.CreateUser(&User{ID: id, Username: id, DisplayName: id, Email: id + "@test.invalid", Role: "user", Status: status, Pending: pending})
	}
	if err := add("seat-a", false); err != nil {
		t.Fatal(err)
	}
	if err := add("seat-b", true); err != nil {
		t.Fatal(err)
	}
	if err := add("seat-c", false); err != ErrSeatLimit {
		t.Fatalf("third seat: %v", err)
	}
	if err := add("seat-c", true); err != ErrSeatLimit {
		t.Fatalf("third pending seat: %v", err)
	}
	var seats *SeatsInUseError
	if err := s.Platform().SetOrgLimits(org, OrgLimits{MaxSeats: 1, StorageBytes: 20 * gib}, true, &AuditEvent{}); !errors.As(err, &seats) || seats.SeatsUsed != 2 {
		t.Fatalf("below the seats in use: %v", err)
	}
	// Disable frees a seat; enabling it again is refused while another holds it.
	tenancyExec(t, s, `UPDATE users SET status='disabled' WHERE id='seat-a'`)
	if err := add("seat-c", false); err != nil {
		t.Fatal(err)
	}
	refused(t, s, msgSeatLimit, `UPDATE users SET status='active' WHERE id='seat-a'`)
	// The activation backstop: two activated seats already, a pending one cannot activate.
	tenancyExec(t, s, `UPDATE orgs SET max_seats=3 WHERE id='`+org.id+`'`)
	tenancyExec(t, s, `UPDATE users SET status='active' WHERE id='seat-a'`)
	tenancyExec(t, s, `UPDATE orgs SET max_seats=2 WHERE id='`+org.id+`'`)
	refused(t, s, msgSeatLimit, `UPDATE users SET pending=FALSE,status='active' WHERE id='seat-b'`)
	raw, err := o.IssueAccountToken("seat-b", "activation", "email", time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RedeemAccountToken(raw, "activation", "hash", nil); err != ErrNotFound {
		t.Fatalf("activation past the cap: %v", err)
	}
	tenancyExec(t, s, `UPDATE orgs SET max_seats=3 WHERE id='`+org.id+`'`)
	if _, err := s.RedeemAccountToken(raw, "activation", "hash", nil); err != nil {
		t.Fatalf("the link was spent by the refused activation: %v", err)
	}
	// Default and staff orgs have no cap.
	for range 3 {
		createTestUser(t, s)
	}
	staff, err := CreateOrgForTest(s, "staff")
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		id := "staff-" + string(rune('a'+i))
		if err := s.Org(staff).CreateUser(&User{ID: id, Username: id, DisplayName: id, Email: id + "@test.invalid", Role: "user", Status: "active"}); err != nil {
			t.Fatal(err)
		}
	}
}

// Replicas: four handles report at once for two apps; the grants handed out never sum
// past the pool, and every report lands once.
func TestStorageReportRaceAcrossReplicas(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	org, _ := poolFixture(t, s, OrgLimits{MaxSeats: 1, StorageBytes: 8 * gib})
	stores := replicasOf(t, s, proofHandles)
	results := race(stores, proofPerHandle, func(i int, h *Store) error {
		client := []string{"kydrive", "kypost"}[i%2]
		r, err := h.Platform().ReportStorage(client, []StorageReport{{OrgID: org.id, UsedBytes: 6 * gib, Seq: int64(i + 1), WantBytes: gib}}, time.Now())
		if err == nil && r[0].Result == "unknown_org" {
			err = errors.New("unknown_org")
		}
		return err
	})
	for i, err := range results {
		if err != nil {
			t.Fatalf("report %d: %v", i, err)
		}
	}
	// Each app's highest seq won, whatever the order. 12 GiB used against 8: over. A grant
	// handed out before the other app's report stays reserved until its own next report,
	// within the org's cap (pool/8): the design's bound after a reduction.
	var used, ceiling, rows, maxSeq int64
	if err := s.db.QueryRow(`SELECT CAST(SUM(used_bytes) AS BIGINT),CAST(SUM(ceiling_bytes) AS BIGINT),COUNT(*),CAST(SUM(seq) AS BIGINT) FROM org_storage WHERE org_id=?`, org.id).Scan(&used, &ceiling, &rows, &maxSeq); err != nil {
		t.Fatal(err)
	}
	if n := int64(proofHandles * proofPerHandle); rows != 2 || maxSeq != 2*n-1 || used != 12*gib || ceiling-used > gib {
		t.Fatalf("rows %d seqs %d used %d ceiling %d", rows, maxSeq, used, ceiling)
	}
	if o, _ := overSince(t, s, org); !o {
		t.Fatal("over the pool not recorded")
	}
	// Within the pool: two apps racing for the last bytes never hold more than the pool.
	org2, _ := poolFixture(t, s, OrgLimits{MaxSeats: 1, StorageBytes: 16 * gib})
	for i, err := range race(stores, proofPerHandle, func(i int, h *Store) error {
		client := []string{"kydrive", "kypost"}[i%2]
		_, err := h.Platform().ReportStorage(client, []StorageReport{{OrgID: org2.id, UsedBytes: 7 * gib, Seq: int64(i + 1), WantBytes: 2 * gib}}, time.Now())
		return err
	}) {
		if err != nil {
			t.Fatalf("report %d: %v", i, err)
		}
	}
	if err := s.db.QueryRow(`SELECT CAST(SUM(ceiling_bytes) AS BIGINT) FROM org_storage WHERE org_id=?`, org2.id).Scan(&ceiling); err != nil {
		t.Fatal(err)
	}
	if ceiling > 16*gib || ceiling-14*gib > 2*gib {
		t.Fatalf("grants sum past the pool or the cap: ceilings %d", ceiling)
	}
}

// Replicas: many adds race for an org's last free seat; one wins, the rest are
// ErrSeatLimit, and the org never holds more seats than max_seats (build plan 6).
func TestSeatRaceAcrossReplicas(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	org, _ := poolFixture(t, s, OrgLimits{MaxSeats: 2, StorageBytes: 20 * gib})
	if err := s.Org(org).CreateUser(&User{ID: "seat-0", Username: "seat-0", DisplayName: "seat-0", Email: "seat-0@test.invalid", Role: "user", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	results := race(replicasOf(t, s, proofHandles), proofPerHandle, func(i int, h *Store) once {
		id := fmt.Sprintf("seat-race-%d", i)
		err := h.Org(org).CreateUser(&User{ID: id, Username: id, DisplayName: id, Email: id + "@test.invalid", Role: "user", Status: "disabled", Pending: true})
		if errors.Is(err, ErrSeatLimit) {
			return once{}
		}
		return once{ok: err == nil, err: err}
	})
	exactlyOne(t, "the last seat", results)
	var seats int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users u WHERE u.org_id=? AND `+seatSQL("u"), org.id).Scan(&seats); err != nil || seats != 2 {
		t.Fatalf("seats %d: %v", seats, err)
	}
}
