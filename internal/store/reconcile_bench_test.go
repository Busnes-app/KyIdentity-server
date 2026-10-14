package store

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// BenchmarkMutationReconcile times one access mutation, whose transaction reconciles
// provisioning for the whole directory, against 3,000 held users.
func BenchmarkMutationReconcile(b *testing.B) {
	s, err := New(filepath.Join(b.TempDir(), "bench.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	if err := s.CreatePairedSystem(&PairedSystem{ID: "target", Name: "target", SystemType: "scim", CallbackURL: "https://example.com/scim", Status: "active"}, nil); err != nil {
		b.Fatal(err)
	}
	var app string
	var revision int
	if err := s.db.QueryRow(`SELECT id,revision FROM app_registry WHERE system_id='target'`).Scan(&app, &revision); err != nil {
		b.Fatal(err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		b.Fatal(err)
	}
	for i := range 3000 {
		if _, err := tx.Exec(`INSERT INTO users(id,username,display_name,email,password_hash,role,status) VALUES(?,?,?,?,'x','user','active')`, fmt.Sprint("u", i), fmt.Sprint("user", i), "U", fmt.Sprint("u", i, "@test.invalid")); err != nil {
			b.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	if err := s.SetAppPolicy(app, "all_active_users", true, revision, nil); err != nil {
		b.Fatal(err)
	}
	events, err := s.ClaimDueSyncEvents(10000, time.Minute)
	if err != nil || len(events) != 3000 {
		b.Fatal(len(events), err)
	}
	for _, ev := range events {
		if _, err := s.BeginSyncDelivery(ev, time.Minute); err != nil {
			b.Fatal(err)
		}
		if err := s.FinishSyncDelivery(ev, "delivered", "", 1, nil); err != nil {
			b.Fatal(err)
		}
	}
	runs := reconcileRuns.Load()
	b.ResetTimer()
	for i := range b.N {
		if err := s.SetAppAssignment(app, "users", "u0", i%2 == 0, nil); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	if got := reconcileRuns.Load() - runs; got != int64(b.N) {
		b.Fatal("mutations did not reconcile", got)
	}
}
