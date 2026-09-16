package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/audit"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

func restoredDataDir(t *testing.T) (string, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	s, err := store.New(filepath.Join(dir, "kysignon.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	u := &store.User{ID: "u1", Username: "root", DisplayName: "Root", Email: "root@test.invalid", PasswordHash: "x", Role: "admin", Status: "active"}
	if err := s.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(&store.Session{ID: "s1", UserID: u.ID, SessionTokenHash: "token-from-the-capsule", ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	return dir, s
}

// The marker is the seam between unpacking a capsule and putting it into service. With
// one present, the next start invalidates what the capsule carried; without one, a
// normal start leaves live logins alone.
func TestRestoreMarkerAppliesOnceAndIsThenGone(t *testing.T) {
	dir, s := restoredDataDir(t)
	logger := audit.NewLogger(s)
	if err := applyRestoreMarker(dir, s, logger); err != nil {
		t.Fatal(err)
	}
	if sess, err := s.GetSessionByTokenHash("token-from-the-capsule", time.Hour); err != nil || sess == nil {
		t.Fatal("an ordinary start must not touch live sessions:", err)
	}

	marker := filepath.Join(dir, restoreMarkerName)
	body, err := json.Marshal(restoreMarker{Capsule: "kysignon-2026-09-14.kycap", Service: "KySignOn", RestoredAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := applyRestoreMarker(dir, s, logger); err != nil {
		t.Fatal(err)
	}
	if sess, err := s.GetSessionByTokenHash("token-from-the-capsule", time.Hour); err == nil && sess != nil {
		t.Fatal("a login from the capsule still works after the restore was applied")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("the marker outlived the restore it describes:", err)
	}
	events, _, err := s.SearchAuditEvents(store.AuditFilter{Action: "system.restored", Limit: 5})
	if err != nil || len(events) != 1 {
		t.Fatalf("restore audit: %d %v", len(events), err)
	}
	if !strings.Contains(events[0].DetailsJSON, "credentialsInvalidated") || !strings.Contains(events[0].DetailsJSON, "kysignon-2026-09-14.kycap") {
		t.Fatalf("the audit row should say what was invalidated and from which capsule: %s", events[0].DetailsJSON)
	}
}

// A capsule that unpacked nothing is not marked as restored: the operator would
// otherwise start an empty directory that reports a successful restore.
func TestRestoreMarkerNeedsARestoredDataDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := writeRestoreMarker(dir, "x.kycap", "KySignOn"); err == nil {
		t.Fatal("marked a target with no data directory as restored")
	}
	if err := os.Mkdir(filepath.Join(dir, "data"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeRestoreMarker(dir, "/tmp/x.kycap", "KySignOn"); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "data", restoreMarkerName))
	if err != nil {
		t.Fatal(err)
	}
	var marker restoreMarker
	if err := json.Unmarshal(body, &marker); err != nil || marker.Capsule != "x.kycap" || marker.RestoredAt.IsZero() {
		t.Fatalf("marker: %+v %v", marker, err)
	}
	if strings.Contains(string(body), "/tmp/") {
		t.Fatal("the marker records the capsule name, not where it sat on disk")
	}
}
