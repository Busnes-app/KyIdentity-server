package store

import (
	"context"
	"database/sql"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Readiness follows the database: PingContext (what /readyz runs) fails while Postgres is
// unreachable or read-only and recovers on its own when it is back, without a restart.
// It stops and starts a real container, so it runs only when KYIDENTITY_TEST_PG_CONTAINER
// names one this test may control, and must not share it with other tests.
func TestPingFollowsAnOutageAndAReadOnlyPrimary(t *testing.T) {
	requirePostgres(t)
	container := os.Getenv("KYIDENTITY_TEST_PG_CONTAINER")
	if container == "" {
		t.Skip("set KYIDENTITY_TEST_PG_CONTAINER to a Postgres container this test may stop")
	}
	s, cleanup := setupTestStore(t)
	defer cleanup()
	ping := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		return s.PingContext(ctx)
	}
	recovers := func(what string) {
		t.Helper()
		deadline := time.Now().Add(90 * time.Second)
		for {
			err := ping()
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("readiness did not recover after %s: %v", what, err)
			}
			time.Sleep(500 * time.Millisecond)
		}
		if err := s.SetSetting("failover_probe", what); err != nil {
			t.Fatalf("write after %s: %v", what, err)
		}
	}
	docker := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
			t.Fatalf("docker %v: %v %s", args, err, out)
		}
	}
	if err := ping(); err != nil {
		t.Fatal(err)
	}

	docker("stop", container)
	stopped := true
	defer func() {
		if stopped {
			_ = exec.Command("docker", "start", container).Run()
		}
	}()
	if err := ping(); err == nil {
		t.Fatal("readiness passed while the database was stopped")
	}
	docker("start", container)
	stopped = false
	recovers("the restart")

	// A primary turned read-only, as a demoted primary or a standby is. ALTER SYSTEM runs
	// outside any transaction, so through plain pgx.
	admin, err := sql.Open("pgx", testDatabaseURL())
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.Exec(`ALTER SYSTEM SET default_transaction_read_only = on`); err != nil {
		t.Fatal(err)
	}
	reset := func() {
		// One connection: the SET lets this session write while the server default is read-only.
		c, err := admin.Conn(context.Background())
		if err != nil {
			return
		}
		defer c.Close()
		for _, q := range []string{`SET default_transaction_read_only = off`, `ALTER SYSTEM RESET default_transaction_read_only`, `SELECT pg_reload_conf()`} {
			_, _ = c.ExecContext(context.Background(), q)
		}
	}
	defer reset()
	if _, err := admin.Exec(`SELECT pg_reload_conf()`); err != nil {
		t.Fatal(err)
	}
	failed := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if ping() != nil {
			failed = true
			break
		}
	}
	if !failed {
		t.Fatal("readiness passed while the primary was read-only")
	}
	reset()
	recovers("read-only ended")
}
