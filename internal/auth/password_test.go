package auth

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
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

// A 512 MiB pod (fsn1 OOM) gets five 64 MiB slots and keeps argonReserve free; a 768 MiB
// pod gets the full eight. The limit is the tightest memory.max on the cgroup path.
func TestArgonSlotsFitMemoryLimit(t *testing.T) {
	root := t.TempDir()
	leaf := filepath.Join(root, "kubepods.slice", "pod.scope")
	if err := os.MkdirAll(leaf, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(path, s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	proc := filepath.Join(root, "proc-cgroup")
	write(proc, "12:memory:/legacy\n0::/kubepods.slice/pod.scope\n")
	write(filepath.Join(root, "kubepods.slice", "memory.max"), "1073741824\n")
	write(filepath.Join(leaf, "memory.max"), "536870912\n")

	limit := cgroupMemoryLimit(root, proc)
	if limit != 512<<20 {
		t.Fatalf("limit = %d, want 512 MiB", limit)
	}
	n := argonSlotsFor(limit)
	if n != 5 || int64(n)*int64(DefaultParams.Memory)<<10+argonReserve > limit {
		t.Fatalf("512 MiB: %d slots, want 5 that leave argonReserve free", n)
	}
	write(filepath.Join(leaf, "memory.max"), "max\n")
	if got := cgroupMemoryLimit(root, proc); got != 1<<30 {
		t.Fatalf("leaf max: limit = %d, want the parent's 1 GiB", got)
	}
	for limit, want := range map[int64]int{0: 8, 768 << 20: 8, 4 << 30: 8, 256 << 20: 1, 64 << 20: 1} {
		if got := argonSlotsFor(limit); got != want {
			t.Errorf("argonSlotsFor(%d MiB) = %d, want %d", limit>>20, got, want)
		}
	}
	// A cgroup namespace path outside the mount still reads the mount root's limit.
	write(filepath.Join(root, "memory.max"), "805306368\n")
	write(proc, "0::/../../kubepods.slice/other.scope\n")
	if got := cgroupMemoryLimit(root, proc); got != 768<<20 {
		t.Errorf("namespace-escaping path: limit = %d, want the mount root's 768 MiB", got)
	}
	if got := cgroupMemoryLimit(root, filepath.Join(root, "missing")); got != 0 {
		t.Errorf("no /proc/self/cgroup: limit = %d, want 0", got)
	}
}

// TestArgonFloodUnderRealLimit floods hashing from inside a real memory cgroup; the process
// must survive and answer every call with a result or ErrBusy. Opt-in, run it as
//
//	systemd-run --user --scope -p MemoryMax=512M -p MemorySwapMax=0 -- \
//	  env KYIDENTITY_ARGON_FLOOD=1 ./auth.test -test.run ArgonFlood
func TestArgonFloodUnderRealLimit(t *testing.T) {
	if os.Getenv("KYIDENTITY_ARGON_FLOOD") == "" {
		t.Skip("set KYIDENTITY_ARGON_FLOOD=1 inside a memory-limited cgroup")
	}
	t.Logf("memory limit %d MiB, %d slots", memoryLimit>>20, cap(argonSlots))
	hash, err := HashPassword("correct-horse-battery-staple-123")
	if err != nil {
		t.Fatal(err)
	}
	var ok, busy atomic.Int64
	var wg sync.WaitGroup
	for range 64 {
		wg.Go(func() {
			for range 4 {
				match, err := VerifyPassword("correct-horse-battery-staple-123", hash)
				switch {
				case errors.Is(err, ErrBusy):
					busy.Add(1)
				case err != nil || !match:
					t.Errorf("VerifyPassword: %v %v", match, err)
				default:
					ok.Add(1)
				}
			}
		})
	}
	wg.Wait()
	t.Logf("%d verified, %d busy", ok.Load(), busy.Load())
	if ok.Load() == 0 {
		t.Fatal("no verification completed")
	}
}
