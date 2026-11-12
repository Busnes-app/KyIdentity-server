package store

import (
	"database/sql"
	"errors"
	"log"
	"math"
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

// AcquireLease takes the named lease for ttl when nobody holds it. The upsert is one
// statement, so of any number of replicas asking at once exactly one gets ok. release
// gives it back early; a holder that dies simply lets it expire. There is no renewal:
// pick a ttl longer than the work.
func (s *Store) AcquireLease(name string, ttl time.Duration) (release func(), ok bool, err error) {
	token, now := uuid.New().String(), time.Now().UnixMilli()
	res, err := s.db.Exec(`INSERT INTO leases(name, token, until_ms) VALUES(?,?,?)
 ON CONFLICT(name) DO UPDATE SET token=excluded.token, until_ms=excluded.until_ms WHERE leases.until_ms<=?`,
		name, token, now+ttl.Milliseconds(), now)
	if err != nil {
		return nil, false, err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return nil, false, err
	}
	return func() { _, _ = s.db.Exec(`DELETE FROM leases WHERE name=? AND token=?`, name, token) }, true, nil
}

// withMigrationLease runs fn while holding the migration lease, waiting out another
// process that is migrating the same database. A holder that died is waited out for
// migrationLease, which is why that is short.
func (s *Store) withMigrationLease(fn func() error) error {
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
