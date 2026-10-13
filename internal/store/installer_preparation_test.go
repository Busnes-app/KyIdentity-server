package store

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestInstallerPreparationOwnershipAndAtomicAudit(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "identity.db")
	s, err := New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	id, contract := uuid.NewString(), strings.Repeat("a", 64)
	if err := s.RecordInstallerPreparation(id, contract, true); err == nil {
		t.Fatal("missing preparation passed inspection")
	}
	if exists, err := s.InstallerSetupExists(id); err != nil || exists {
		t.Fatal("inspection created ownership", err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER reject_preparation_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'fixture audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordInstallerPreparation(id, contract, false); err == nil {
		t.Fatal("preparation committed without audit")
	}
	if exists, err := s.InstallerSetupExists(id); err != nil || exists {
		t.Fatal("failed audit retained ownership", err)
	}
	if _, err := s.db.Exec(`DROP TRIGGER reject_preparation_audit`); err != nil {
		t.Fatal(err)
	}
	for _, inspect := range []bool{false, true, false} {
		if err := s.RecordInstallerPreparation(id, contract, inspect); err != nil {
			t.Fatal(err)
		}
	}
	var audits, users int
	if err := s.db.QueryRow(`SELECT count(*) FROM audit_events WHERE action='installer.credentials_prepared'`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Fatal("preparation did not record exactly one success audit")
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM users`).Scan(&users); err != nil || users != 0 {
		t.Fatal("preparation configured accounts", err)
	}
	for _, inspect := range []bool{false, true} {
		if err := s.RecordInstallerPreparation(id, strings.Repeat("b", 64), inspect); err == nil {
			t.Fatal("credential receipt drift accepted")
		}
	}
	readOnly, err := OpenInstallerStore(dbPath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Close()
	if err := readOnly.RecordInstallerPreparation(uuid.NewString(), contract, false); err == nil {
		t.Fatal("read-only connection permitted receipt creation")
	}
}
