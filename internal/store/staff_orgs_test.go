package store

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/uuid"
)

func TestEnsureStaffOrgCreatesOnceAndIsIdempotent(t *testing.T) {
	s, err := NewTest(filepath.Join(t.TempDir(), "staff.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	first, err := s.EnsureStaffOrg()
	if err != nil {
		t.Fatalf("EnsureStaffOrg: %v", err)
	}
	if first.String() == "" || first.String() == DefaultOrgID {
		t.Fatalf("EnsureStaffOrg returned %q, want a fresh non-default org ID", first)
	}
	if _, err := uuid.Parse(first.String()); err != nil {
		t.Fatalf("EnsureStaffOrg returned non-UUID %q: %v", first, err)
	}
	isStaff, err := s.IsStaffOrg(first)
	if err != nil || !isStaff {
		t.Fatalf("IsStaffOrg(%s) = %v, %v; want true", first, isStaff, err)
	}
	resolved, customer, err := s.StaffOrg(first.String())
	if err != nil || resolved != first || customer {
		t.Fatalf("StaffOrg(%s) = (%s, %v, %v), want (%s, false, nil)", first, resolved, customer, err, first)
	}

	var name, kind, status, homeRegion string
	var allApps bool
	var maxSeats, storageBytes, storagePerSeat, revision int64
	if err := s.db.QueryRow(`SELECT name, kind, status, all_apps, home_region, max_seats, storage_bytes, storage_per_seat_bytes, revision FROM orgs WHERE id=?`, first.String()).
		Scan(&name, &kind, &status, &allApps, &homeRegion, &maxSeats, &storageBytes, &storagePerSeat, &revision); err != nil {
		t.Fatalf("select staff org: %v", err)
	}
	if name != "Staff" || kind != "staff" || status != "active" || allApps || homeRegion != HomeRegionLocal || maxSeats != 0 || storageBytes != 0 || storagePerSeat != 0 || revision <= 1 {
		t.Fatalf("staff org row = name:%q kind:%q status:%q all_apps:%v home_region:%q max_seats:%d storage:%d/%d rev:%d",
			name, kind, status, allApps, homeRegion, maxSeats, storageBytes, storagePerSeat, revision)
	}

	found, err := s.Platform().FindOrgs("")
	if err != nil || len(found) != 1 || found[0].ID != first.String() || found[0].Kind != "staff" {
		t.Fatalf("FindOrgs(\"\") = %+v, %v; want [%s]", found, err, first)
	}

	second, err := s.EnsureStaffOrg()
	if err != nil {
		t.Fatalf("second EnsureStaffOrg: %v", err)
	}
	if second != first {
		t.Fatalf("second EnsureStaffOrg = %s, want %s", second, first)
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM orgs WHERE kind='staff'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("staff org count = %d (%v), want 1", count, err)
	}
}

func TestEnsureStaffOrgReusesExistingStaffOrg(t *testing.T) {
	s, err := NewTest(filepath.Join(t.TempDir(), "staff-existing.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	existing, err := CreateOrgForTest(s, "staff")
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.EnsureStaffOrg()
	if err != nil {
		t.Fatalf("EnsureStaffOrg: %v", err)
	}
	if got != existing {
		t.Fatalf("EnsureStaffOrg = %s, want existing %s", got, existing)
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM orgs WHERE kind='staff'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("staff org count = %d (%v), want 1", count, err)
	}
}

func TestEnsureStaffOrgConcurrentCreatesOneOrg(t *testing.T) {
	path := filepath.Join(t.TempDir(), "staff-concurrent.db")
	const workers = 6
	stores := make([]*Store, workers)
	for i := range workers {
		s, err := NewTest(path)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		stores[i] = s
	}

	ids := make([]OrgID, workers)
	errs := make([]error, workers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			ids[i], errs[i] = stores[i].EnsureStaffOrg()
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d: EnsureStaffOrg: %v", i, err)
		}
		if ids[i] != ids[0] {
			t.Fatalf("worker %d got org %s, worker 0 got %s", i, ids[i], ids[0])
		}
	}
	var count int
	if err := stores[0].db.QueryRow(`SELECT COUNT(*) FROM orgs WHERE kind='staff'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("staff org count = %d (%v), want 1", count, err)
	}
}
