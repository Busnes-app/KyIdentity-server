package auth

import (
	"errors"
	"testing"
	"time"
)

// Every Argon2 call allocates Memory KiB; past the slot cap callers get ErrBusy instead of
// another 64 MiB, and a freed slot is usable again.
func TestArgonSlotsBoundConcurrency(t *testing.T) {
	hash, err := HashPassword("correct-horse-battery-staple-123")
	if err != nil {
		t.Fatal(err)
	}
	wait := argonWait
	argonWait = 50 * time.Millisecond
	defer func() { argonWait = wait }()

	release := Saturate()
	if _, err := VerifyPassword("correct-horse-battery-staple-123", hash); !errors.Is(err, ErrBusy) {
		t.Errorf("VerifyPassword while saturated: %v, want ErrBusy", err)
	}
	if _, err := HashPassword("correct-horse-battery-staple-123"); !errors.Is(err, ErrBusy) {
		t.Errorf("HashPassword while saturated: %v, want ErrBusy", err)
	}
	if err := DummyVerify("anything"); !errors.Is(err, ErrBusy) {
		t.Errorf("DummyVerify while saturated: %v, want ErrBusy", err)
	}
	release()

	if ok, err := VerifyPassword("correct-horse-battery-staple-123", hash); err != nil || !ok {
		t.Fatalf("VerifyPassword after release: %v %v", ok, err)
	}
	if err := DummyVerify("anything"); err != nil {
		t.Fatalf("DummyVerify after release: %v", err)
	}
}

func TestArgon2idPasswordHashing(t *testing.T) {
	password := "correct-horse-battery-staple-123"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if len(hash) == 0 {
		t.Fatal("expected non-empty hash")
	}

	valid, err := VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if !valid {
		t.Fatal("expected valid password verification")
	}

	invalid, err := VerifyPassword("wrong-password-12345", hash)
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if invalid {
		t.Fatal("expected invalid password verification to fail")
	}
}

func TestPasswordLengthPolicy(t *testing.T) {
	shortPass := "short123"
	_, err := HashPassword(shortPass)
	if err == nil {
		t.Fatal("expected error for password < 12 characters")
	}
}
