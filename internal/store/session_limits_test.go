package store

import "testing"

func TestSessionLimitsStoredOverrideSeed(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	if err := s.LoadSessionLimits(SessionLimits{Absolute: 60, Idle: 60}); err == nil {
		t.Fatal("out-of-bounds seed accepted")
	}
	if err := s.LoadSessionLimits(SessionLimits{Absolute: 86400, Idle: 3600}); err != nil || s.SessionLimits().Idle != 3600 {
		t.Fatalf("seed: %+v %v", s.SessionLimits(), err)
	}
	if _, err := s.SetSessionLimits(SessionLimits{Absolute: 3600, Idle: 7200}, nil); err == nil {
		t.Fatal("idle longer than lifetime accepted")
	}
	if _, err := s.SetSessionLimits(SessionLimits{Absolute: 7200, Idle: 900}, nil); err != nil {
		t.Fatal(err)
	}
	// After a restart the administrator's choice wins over the environment.
	if err := s.LoadSessionLimits(SessionLimits{Absolute: 86400, Idle: 28800}); err != nil || s.SessionLimits() != (SessionLimits{Absolute: 7200, Idle: 900}) {
		t.Fatalf("reload: %+v %v", s.SessionLimits(), err)
	}
}
