package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

// A file copy of a WAL-mode database can miss recently committed rows. The snapshot must
// contain them.
func TestSnapshotToCapturesCommittedWALWrites(t *testing.T) {
	SkipOnPostgres(t, "VACUUM INTO snapshot of the SQLite file (backup is not supported on Postgres yet)")
	dir := t.TempDir()
	s, err := New(filepath.Join(dir, "live.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	u := &User{ID: uuid.New().String(), Username: "wal-user", DisplayName: "W",
		Email: "wal@x.test", PasswordHash: "x", Role: "admin", Status: "active"}
	if err := s.CreateUser(u); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(dir, "snap.db")
	if err := s.SnapshotTo(dest); err != nil {
		t.Fatalf("SnapshotTo: %v", err)
	}

	db, err := sql.Open("sqlite", dest)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var got string
	if err := db.QueryRow(`SELECT username FROM users WHERE id = ?`, u.ID).Scan(&got); err != nil {
		t.Fatalf("snapshot is missing the committed user: %v", err)
	}
	if got != "wal-user" {
		t.Fatalf("snapshot has %q", got)
	}

	// A pre-existing destination must be refused rather than clobbered.
	if err := s.SnapshotTo(dest); err == nil {
		t.Error("SnapshotTo overwrote an existing file")
	}
	if _, err := os.Stat(dest); err != nil {
		t.Fatal(err)
	}
}
