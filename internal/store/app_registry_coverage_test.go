package store

import (
	"errors"
	"testing"
)

// Guards UnlinkAppRecord refusals: unknown kinds, a kind the record does not hold, a
// record with a single connection, stale revisions, and a record that still has roles are
// all refused, and none of them splits the record.
func TestUnlinkAppRecordRefusals(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	c, l, p := registryFixtures(t, s)
	if err := s.LinkAppRecords(l.ID, c.ID, l.Revision, c.Revision, nil); err != nil {
		t.Fatal(err)
	}
	linked, err := s.GetAppRecord(l.ID)
	if err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]func() (string, error){
		"unknown kind":     func() (string, error) { return s.UnlinkAppRecord(linked.ID, "device", linked.Revision, nil) },
		"kind not held":    func() (string, error) { return s.UnlinkAppRecord(linked.ID, "system", linked.Revision, nil) },
		"single reference": func() (string, error) { return s.UnlinkAppRecord(p.ID, "system", p.Revision, nil) },
		"stale revision":   func() (string, error) { return s.UnlinkAppRecord(linked.ID, "launcher", linked.Revision-1, nil) },
	} {
		if id, err := call(); !errors.Is(err, ErrAppLinkConflict) || id != "" {
			t.Fatalf("%s: got %q, %v; want ErrAppLinkConflict", name, id, err)
		}
	}
	if _, err := s.UnlinkAppRecord("missing", "client", 1, nil); !errors.Is(err, ErrAppRecordMissing) {
		t.Fatal("missing record", err)
	}
	if _, err := s.CreateAppRole(linked.ID, "operator", "", nil); err != nil {
		t.Fatal(err)
	}
	linked, _ = s.GetAppRecord(l.ID)
	if _, err := s.UnlinkAppRecord(linked.ID, "launcher", linked.Revision, nil); !errors.Is(err, ErrAppLinkConflict) {
		t.Fatal("unlink with roles", err)
	}
	if _, total, _ := s.ListAppRecords("", 25, 0); total != 2 {
		t.Fatalf("refused unlink split the record: %d records", total)
	}
	if got, _ := s.GetAppRecord(l.ID); got.ClientID != "client" || got.LauncherID != "launcher" {
		t.Fatalf("refused unlink changed links: %+v", got)
	}
	// The launcher half can be split off once no roles hold the record together.
	mustExec(t, s, `DELETE FROM app_roles WHERE app_id=?`, linked.ID)
	linked, _ = s.GetAppRecord(l.ID)
	newID, err := s.UnlinkAppRecord(linked.ID, "launcher", linked.Revision, nil)
	if err != nil || newID == "" {
		t.Fatal(newID, err)
	}
	if split, _ := s.GetAppRecord(newID); split.LauncherID != "launcher" || split.ClientID != "" {
		t.Fatalf("split record = %+v", split)
	}
}
