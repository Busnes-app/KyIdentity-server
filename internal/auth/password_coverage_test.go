package auth

import (
	"errors"
	"strings"
	"testing"
)

// A stored hash that is truncated, from another algorithm or version, or carries bad
// parameters or encoding is an error and never a successful verification.
func TestVerifyPasswordRejectsMalformedHashes(t *testing.T) {
	good, err := HashPassword("correct-horse-battery-staple-123")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(good, "$")
	with := func(i int, v string) string {
		p := append([]string(nil), parts...)
		p[i] = v
		return strings.Join(p, "$")
	}
	cases := map[string]string{
		"empty":            "",
		"too few fields":   "$argon2id$v=19$m=65536,t=3,p=4$salt",
		"bcrypt":           "$2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234",
		"argon2i":          with(1, "argon2i"),
		"version garbled":  with(2, "v=x"),
		"old version":      with(2, "v=16"),
		"params garbled":   with(3, "m=lots,t=3,p=4"),
		"salt not base64":  with(4, "!!!"),
		"hash not base64":  with(5, "!!!"),
		"padded salt":      with(4, parts[4]+"=="),
		"plaintext stored": "correct-horse-battery-staple-123",
	}
	for name, hash := range cases {
		t.Run(name, func(t *testing.T) {
			ok, err := VerifyPassword("correct-horse-battery-staple-123", hash)
			if ok || err == nil {
				t.Fatalf("VerifyPassword(%q) = %v, %v; want false and an error", hash, ok, err)
			}
		})
	}
}

// The upper bound is policy, reported as a PolicyError whose text names the limit; the
// boundary itself is accepted.
func TestHashPasswordUpperBoundIsPolicy(t *testing.T) {
	_, err := HashPassword(strings.Repeat("a", MaxPasswordLength+1))
	var pe PolicyError
	if !errors.As(err, &pe) || !strings.Contains(pe.Error(), "at most 1024 characters") {
		t.Fatalf("over-long password: %v", err)
	}
	if _, err := HashPassword(strings.Repeat("a", 11)); !errors.As(err, &pe) || !strings.Contains(err.Error(), "at least 12") {
		t.Fatalf("short password: %v", err)
	}
	if _, err := HashPassword(strings.Repeat("a", MaxPasswordLength)); err != nil {
		t.Fatalf("password at the limit refused: %v", err)
	}
}

// DummyVerify must accept any input length without error, including one past the limit
// that a real login would truncate the same way.
func TestDummyVerifyAcceptsOverlongInput(t *testing.T) {
	if err := DummyVerify(strings.Repeat("x", 10*MaxPasswordLength)); err != nil {
		t.Fatalf("DummyVerify on an over-long password: %v", err)
	}
}
