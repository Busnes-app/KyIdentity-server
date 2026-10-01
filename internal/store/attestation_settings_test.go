package store

import (
	"testing"

	"github.com/google/uuid"
)

func TestAttestationSettingsRoundTrip(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	got, err := s.AttestationSettings()
	if err != nil || got.RequireLockedBootloader {
		t.Fatalf("default: %+v %v", got, err)
	}
	ev := &AuditEvent{ID: uuid.NewString(), Action: "admin.attestation_configured", Outcome: "success"}
	if err := s.SetAttestationSettings(AttestationSettings{RequireLockedBootloader: true}, ev); err != nil {
		t.Fatal(err)
	}
	if got, err = s.AttestationSettings(); err != nil || !got.RequireLockedBootloader {
		t.Fatalf("after set: %+v %v", got, err)
	}
	rows, _, err := s.SearchAuditEvents(AuditFilter{Action: "admin.attestation_configured", Limit: 10})
	if err != nil || len(rows) != 1 {
		t.Fatalf("audit rows: %d %v", len(rows), err)
	}
}
