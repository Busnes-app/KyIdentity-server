package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

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

// MaxPasswordLength bounds the input to Argon2id, which allocates 64 MB per call. An
// unbounded password turns every login into a memory amplifier.
const MaxPasswordLength = 1024

// ErrBusy means every Argon2 slot stayed taken for argonWait. It is load, not a wrong
// password: callers answer 503 and never count it as a failed login.
var ErrBusy = errors.New("password hashing is at capacity")

// argonSlots caps concurrent Argon2id calls, so a login flood costs at most
// cap*Memory instead of an OOM kill. The cap fits the cgroup memory limit.
var (
	memoryLimit = cgroupMemoryLimit("/sys/fs/cgroup", "/proc/self/cgroup")
	argonSlots  = make(chan struct{}, argonSlotsFor(memoryLimit))
	argonWait   = 3 * time.Second
)

const (
	maxArgonSlots = 8
	// argonReserve is left for the rest of the process: requests, database, GC slack.
	argonReserve = 192 << 20
)

// argonSlotsFor fits DefaultParams.Memory-sized hashes into limit bytes minus
// argonReserve: at least one, at most maxArgonSlots. A limit of 0 means none.
func argonSlotsFor(limit int64) int {
	if limit <= 0 {
		return maxArgonSlots
	}
	n := (limit - argonReserve) / (int64(DefaultParams.Memory) << 10)
	return int(min(max(n, 1), maxArgonSlots))
}

// cgroupMemoryLimit returns the tightest cgroup v2 memory.max from this process's
// cgroup up to root, or 0 when there is none ("max", cgroup v1, not Linux).
func cgroupMemoryLimit(root, procCgroup string) int64 {
	b, err := os.ReadFile(procCgroup)
	if err != nil {
		return 0
	}
	var path string
	for line := range strings.Lines(string(b)) {
		if p, ok := strings.CutPrefix(strings.TrimSpace(line), "0::"); ok {
			path = p
		}
	}
	if path == "" {
		return 0
	}
	// A cgroup namespace can show a path outside its mount ("/../.."); only the
	// mount root is then ours to read.
	if path == "/.." || strings.HasPrefix(path, "/../") {
		path = "/"
	}
	var limit int64
	for dir := filepath.Join(root, path); ; dir = filepath.Dir(dir) {
		if b, err := os.ReadFile(filepath.Join(dir, "memory.max")); err == nil {
			if n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && n > 0 && (limit == 0 || n < limit) {
				limit = n
			}
		}
		if len(dir) <= len(root) {
			return limit
		}
	}
}

func idKey(password, salt []byte, iterations, memory uint32, threads uint8, keyLen uint32) ([]byte, error) {
	wait := time.NewTimer(argonWait)
	defer wait.Stop()
	select {
	case argonSlots <- struct{}{}:
	case <-wait.C:
		return nil, ErrBusy
	}
	defer func() { <-argonSlots }()
	return argon2.IDKey(password, salt, iterations, memory, threads, keyLen), nil
}

// Saturate takes every Argon2 slot until release is called. Tests use it to reach ErrBusy.
func Saturate() (release func()) {
	for range cap(argonSlots) {
		argonSlots <- struct{}{}
	}
	return func() {
		for range cap(argonSlots) {
			<-argonSlots
		}
	}
}

// PolicyError is a password the policy refuses; its text is safe to show the user.
type PolicyError string

func (e PolicyError) Error() string { return string(e) }

// HashPassword generates an Argon2id hash with standard encoded representation.
func HashPassword(password string) (string, error) {
	if len(password) < 12 {
		return "", PolicyError("password must be at least 12 characters")
	}
	if len(password) > MaxPasswordLength {
		return "", PolicyError(fmt.Sprintf("password must be at most %d characters", MaxPasswordLength))
	}

	salt := make([]byte, DefaultParams.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash, err := idKey(
		[]byte(password),
		salt,
		DefaultParams.Iterations,
		DefaultParams.Memory,
		DefaultParams.Parallelism,
		DefaultParams.KeyLength,
	)
	if err != nil {
		return "", err
	}

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
	// Freed hashes are garbage until the GC runs; without a soft limit the heap can
	// double past the cgroup limit before it does. GOMEMLIMIT, when set, wins.
	if memoryLimit > 0 && os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(memoryLimit / 10 * 9)
	}
	h, err := HashPassword("kyidentity-timing-equaliser-not-a-real-password")
	if err != nil {
		panic("failed to build dummy password hash: " + err.Error())
	}
	dummyHash = h
}

// DummyVerify burns the same work a real verification costs. Call it on every path that
// rejects a login before reaching VerifyPassword. It returns only ErrBusy, which callers
// must answer as the real path would, or the busy reply becomes a username oracle.
func DummyVerify(password string) error {
	if len(password) > MaxPasswordLength {
		password = password[:MaxPasswordLength]
	}
	if _, err := VerifyPassword(password, dummyHash); errors.Is(err, ErrBusy) {
		return err
	}
	return nil
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

	calculatedHash, err := idKey(
		[]byte(password),
		salt,
		iterations,
		memory,
		parallelism,
		uint32(len(expectedHash)),
	)
	if err != nil {
		return false, err
	}

	if subtle.ConstantTimeCompare(calculatedHash, expectedHash) == 1 {
		return true, nil
	}

	return false, nil
}
