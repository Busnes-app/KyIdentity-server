package store

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"math"
	"sync"
	"time"

	"github.com/google/uuid"
)

// State every replica must agree on lives here, in the database, never in process memory:
// leases for work that runs once, rate-limit buckets, and the push relay keys.

func (s *Store) migrateSharedState() error {
	if _, err := s.db.Exec(leasesSchema + `
 CREATE TABLE IF NOT EXISTS rate_limits (bucket TEXT PRIMARY KEY, tat INTEGER NOT NULL);
 CREATE INDEX IF NOT EXISTS idx_rate_limits_tat ON rate_limits(tat);
 CREATE TABLE IF NOT EXISTS push_relay_keys (
  name TEXT PRIMARY KEY, key_sealed TEXT NOT NULL, version INTEGER NOT NULL, updated_at DATETIME NOT NULL)`); err != nil {
		return err
	}
	return s.addColumnIfMissing("alert_deliveries", "lease_until_ms", `ALTER TABLE alert_deliveries ADD COLUMN lease_until_ms INTEGER NOT NULL DEFAULT 0`)
}

const leasesSchema = `CREATE TABLE IF NOT EXISTS leases (name TEXT PRIMARY KEY, token TEXT NOT NULL, until_ms INTEGER NOT NULL);`

// leaseNow is the database's clock in milliseconds. Every replica reads the one clock, so a
// replica whose own clock is wrong can neither take a live lease nor keep a dead one.
func (s *Store) leaseNow() string {
	if s.postgres {
		return `(floor(extract(epoch from clock_timestamp())*1000))::bigint`
	}
	return `CAST(unixepoch('subsec')*1000 AS INTEGER)`
}

// AcquireLease takes the named lease for ttl when nobody holds it. The upsert is one
// statement, so of any number of replicas asking at once exactly one gets ok. release
// gives it back early; a holder that dies simply lets it expire. There is no renewal:
// pick a ttl longer than the work, or use HoldLease.
func (s *Store) AcquireLease(name string, ttl time.Duration) (release func(), ok bool, err error) {
	token := uuid.New().String()
	if ok, err := s.takeLease(name, token, ttl); err != nil || !ok {
		return nil, false, err
	}
	return func() { s.dropLease(name, token) }, true, nil
}

func (s *Store) takeLease(name, token string, ttl time.Duration) (bool, error) {
	now := s.leaseNow()
	res, err := s.db.Exec(`INSERT INTO leases(name, token, until_ms) VALUES(?,?,`+now+`+?)
 ON CONFLICT(name) DO UPDATE SET token=excluded.token, until_ms=excluded.until_ms WHERE leases.until_ms<=`+now,
		name, token, ttl.Milliseconds())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (s *Store) dropLease(name, token string) {
	_, _ = s.db.Exec(`DELETE FROM leases WHERE name=? AND token=?`, name, token)
}

// ErrLeaseLost is the cause of a HoldLease context that ended because the lease did.
var ErrLeaseLost = errors.New("the lease was lost to another holder or could not be renewed in time")

// HoldLease takes the named lease like AcquireLease and keeps it for as long as the work
// runs, renewing it every ttl/4 on the database clock with a token-checked update. The
// returned context ends, with cause ErrLeaseLost, when renewal finds the lease is no longer
// this holder's, or when failed renewals leave less than one renewal interval of it; parent
// ending ends it too. release stops renewing and gives the lease back. A lease is single
// ownership of scheduling, not exactly-once: the work keeps its own idempotency.
func (s *Store) HoldLease(parent context.Context, name string, ttl time.Duration) (ctx context.Context, release func(), ok bool, err error) {
	token := uuid.New().String()
	if ok, err := s.takeLease(name, token, ttl); err != nil || !ok {
		return nil, nil, false, err
	}
	ctx, cancel := context.WithCancelCause(parent)
	stop, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		keepLease(ctx, stop, cancel, ttl, func() (bool, error) {
			res, err := s.db.Exec(`UPDATE leases SET until_ms=`+s.leaseNow()+`+? WHERE name=? AND token=?`, ttl.Milliseconds(), name, token)
			if err != nil {
				return false, err
			}
			n, err := res.RowsAffected()
			return n == 1, err
		})
	}()
	return ctx, sync.OnceFunc(func() {
		close(stop)
		<-stopped
		cancel(context.Canceled)
		s.dropLease(name, token)
	}), true, nil
}

// keepLease renews every ttl/4 until stop or ctx ends. A renewal that finds the row gone or
// another token's ends the hold at once; a failed one ends it only once what is left of the
// ttl is under one interval, since the next try would land after the lease expired.
func keepLease(ctx context.Context, stop <-chan struct{}, lost context.CancelCauseFunc, ttl time.Duration, renew func() (bool, error)) {
	every := ttl / 4
	expires := time.Now().Add(ttl)
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		start := time.Now()
		held, err := renew()
		switch {
		case err == nil && held:
			expires = start.Add(ttl)
		case err == nil:
			lost(ErrLeaseLost)
			return
		case time.Until(expires) < every:
			log.Printf("lease: renewal failed with too little of the lease left: %v", err)
			lost(ErrLeaseLost)
			return
		default:
			log.Printf("lease: renewal failed, retrying: %v", err)
		}
	}
}

// withMigrationLease runs fn while holding the migration lease, waiting out another
// process that is migrating the same database. A holder that died is waited out for
// migrationLease, which is why that is short.
func (s *Store) withMigrationLease(fn func() error) error {
	if s.postgres {
		return s.withPostgresMigrationLock(fn)
	}
	if _, err := s.db.Exec(leasesSchema); err != nil {
		return err
	}
	waited := false
	for {
		release, ok, err := s.AcquireLease("migrate", migrationLease)
		if err != nil {
			return err
		}
		if ok {
			defer release()
			return fn()
		}
		if !waited {
			waited = true
			log.Printf("database: another process is migrating; waiting for it (at most %s if it died)", migrationLease)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

const migrationLease = 2 * time.Minute

// AllowRate spends one request from a shared token bucket of burst requests refilling at
// perSecond, and reports whether it was there to spend. The bucket is one number, the
// time at which it will be full again (GCRA), so the check and the spend are a single
// statement and N replicas share one allowance. create=false never adds a bucket, for a
// table at its cap.
func (s *Store) AllowRate(bucket string, burst, perSecond float64, now time.Time, create bool) (bool, error) {
	// Microseconds one request takes to refill, capped at about 30 years so a rate of zero
	// never refills and burst*interval cannot overflow.
	interval := int64(1e15)
	if perSecond > 0 && 1e6/perSecond < 1e15 {
		interval = int64(1e6 / perSecond)
	}
	n, tolerance := now.UnixMicro(), int64(math.Min((burst-1)*float64(interval), 1e18))
	const spend = `tat = CASE WHEN rate_limits.tat > ? THEN rate_limits.tat ELSE ? END + ? WHERE rate_limits.tat - ? <= ?`
	var res sql.Result
	var err error
	if create {
		res, err = s.db.Exec(`INSERT INTO rate_limits(bucket, tat) VALUES(?, ?) ON CONFLICT(bucket) DO UPDATE SET `+spend,
			bucket, n+interval, n, n, interval, n, tolerance)
	} else {
		res, err = s.db.Exec(`UPDATE rate_limits SET `+spend+` AND bucket=?`, n, n, interval, n, tolerance, bucket)
	}
	if err != nil {
		return false, err
	}
	rows, err := res.RowsAffected()
	return rows == 1, err
}

// SweepRateLimits drops buckets that have refilled, which are indistinguishable from ones
// that never existed, and reports how many remain.
func (s *Store) SweepRateLimits(now time.Time) (int, error) {
	if _, err := s.db.Exec(`DELETE FROM rate_limits WHERE tat<=?`, now.UnixMicro()); err != nil {
		return 0, err
	}
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM rate_limits`).Scan(&n)
	return n, err
}

// RelayKey returns the sealed push relay key stored under name and its version, or "" and 0.
func (s *Store) RelayKey(name string) (sealed string, version int64, err error) {
	err = s.db.QueryRow(`SELECT key_sealed, version FROM push_relay_keys WHERE name=?`, name).Scan(&sealed, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, nil
	}
	return sealed, version, err
}

// SetRelayKey stores sealed under name only if the stored version is still version (0 for
// none), so a replica that lost a renewal race cannot overwrite the winner's key.
func (s *Store) SetRelayKey(name, sealed string, version int64) (bool, error) {
	res, err := s.db.Exec(`INSERT INTO push_relay_keys(name, key_sealed, version, updated_at) VALUES(?,?,?,?)
 ON CONFLICT(name) DO UPDATE SET key_sealed=excluded.key_sealed, version=excluded.version, updated_at=excluded.updated_at
 WHERE push_relay_keys.version=?`, name, sealed, version+1, time.Now().UTC(), version)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// RecordSetting stores value under key unless the key already holds one, and returns what
// it holds afterwards: of replicas starting at once, one records and the rest read its value.
func (s *Store) RecordSetting(key, value string) (string, error) {
	if _, err := s.db.Exec(`INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)`, key, value); err != nil {
		return "", err
	}
	return s.GetSetting(key)
}

// SwapSetting replaces key's value only while it still holds old.
func (s *Store) SwapSetting(key, old, value string) (bool, error) {
	res, err := s.db.Exec(`UPDATE system_settings SET value=?, updated_at=CURRENT_TIMESTAMP WHERE key=? AND value=?`, value, key, old)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}
