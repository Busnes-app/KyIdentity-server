package main

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
)

func TestHousekeepingPurgesExpiredStepUpGrants(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.db")
	s, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	u := &store.User{ID: "u", Username: "ada", Email: "ada@example.test", PasswordHash: "x", Role: "user", Status: "active"}
	if err := s.CreateUserWithSyncEvents(u, nil); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := s.CreateSession(&store.Session{ID: "sess", UserID: u.ID, SessionTokenHash: "sess", ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	for id, expires := range map[string]time.Time{"expired": now.Add(-time.Minute), "live": now.Add(time.Minute)} {
		if err := s.CreateStepUpToken(&store.StepUpToken{ID: id, UserID: u.ID, SessionID: "sess", TokenHash: id, Operation: "POST /x", ExpiresAt: expires}, nil); err != nil {
			t.Fatal(err)
		}
	}

	purgeExpired(s, now)

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var left []string
	rows, err := raw.Query(`SELECT id FROM step_up_tokens ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		left = append(left, id)
	}
	if len(left) != 1 || left[0] != "live" {
		t.Fatalf("step-up tokens after purge: %v", left)
	}
}
