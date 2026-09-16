package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

var DefaultParams = &Argon2Params{
	Memory:      64 * 1024, // 64 MB
	Iterations:  3,
	Parallelism: 4,
	SaltLength:  16,
	KeyLength:   32,
}

// HashPassword generates an Argon2id hash with standard encoded representation.
// MaxPasswordLength bounds the input to Argon2id, which allocates 64 MB per call. An
// unbounded password turns every login into a memory amplifier.
const MaxPasswordLength = 1024

func HashPassword(password string) (string, error) {
	if len(password) < 12 {
		return "", errors.New("password must be at least 12 characters")
	}
	if len(password) > MaxPasswordLength {
		return "", fmt.Errorf("password must be at most %d characters", MaxPasswordLength)
	}

	salt := make([]byte, DefaultParams.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		DefaultParams.Iterations,
		DefaultParams.Memory,
		DefaultParams.Parallelism,
		DefaultParams.KeyLength,
	)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		DefaultParams.Memory,
		DefaultParams.Iterations,
		DefaultParams.Parallelism,
		b64Salt,
		b64Hash,
	)

	return encoded, nil
}

// dummyHash is a real Argon2id hash of a value nobody knows. Verifying against it costs
// the same as verifying a real account, which is what keeps the unknown-username path
// from answering faster than the known-username one.
var dummyHash string

func init() {
	h, err := HashPassword("kyidentity-timing-equaliser-not-a-real-password")
	if err != nil {
		panic("failed to build dummy password hash: " + err.Error())
	}
	dummyHash = h
}

// DummyVerify burns the same work a real verification costs. Call it on every path that
// rejects a login before reaching VerifyPassword.
func DummyVerify(password string) {
	if len(password) > MaxPasswordLength {
		password = password[:MaxPasswordLength]
	}
	_, _ = VerifyPassword(password, dummyHash)
}

// VerifyPassword verifies a plaintext password against an Argon2id encoded hash.
func VerifyPassword(password, encodedHash string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false, errors.New("invalid hash format")
	}

	if parts[1] != "argon2id" {
		return false, errors.New("unsupported algorithm")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, err
	}
	if version != argon2.Version {
		return false, errors.New("incompatible argon2 version")
	}

	var memory, iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}

	calculatedHash := argon2.IDKey(
		[]byte(password),
		salt,
		iterations,
		memory,
		parallelism,
		uint32(len(expectedHash)),
	)

	if subtle.ConstantTimeCompare(calculatedHash, expectedHash) == 1 {
		return true, nil
	}

	return false, nil
}
