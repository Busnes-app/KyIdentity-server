package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Org storage pool and seat caps (tenancy design, "Org storage pool" and "Plans and orgs"
// P2/P3; schema version 17 org_storage). The pool is storage_bytes + storage_per_seat_bytes
// × max_seats of a customer org. Apps report their usage per org and get a headroom grant
// against it. Everything lives in the shared database: no replica holds any of it.

const (
	// MaxSeats is the seat ceiling of a customer org (P2); above it is Enterprise.
	MaxSeats = 1000
	// MaxStorageBytes and MaxStoragePerSeatBytes bound the pool fields (S3), so
	// per_seat × MaxSeats stays far inside an int64.
	MaxStorageBytes        = int64(1) << 50
	MaxStoragePerSeatBytes = int64(1) << 44
	// MinPoolBytes is the smallest pool a customer org may have (S3).
	MinPoolBytes = int64(1) << 30
	// MaxReportBytes bounds used_bytes and want_bytes in a usage report.
	MaxReportBytes = int64(1) << 53
	// StorageGrantTTL is how long an app may use a grant, by its own clock.
	StorageGrantTTL = 900
	grantCapBytes   = int64(64) << 30
)

var (
	ErrInvalidMaxSeats = errors.New("max_seats out of range")
	ErrInvalidStorage  = errors.New("storage out of range")
	// ErrSeatLimit: the org has no free seat (P3). Raised by the users triggers.
	ErrSeatLimit = errors.New("the org has no free seat")
)

// SeatsInUseError refuses a max_seats below the seats in use (P3).
type SeatsInUseError struct{ SeatsUsed int64 }

func (e *SeatsInUseError) Error() string { return "seats_in_use" }

// StorageOverPoolError refuses a pool reduction below usage without the holder's
// acknowledgement (the approved over-quota rule).
type StorageOverPoolError struct{ PoolBytes, UsedBytes int64 }

func (e *StorageOverPoolError) Error() string { return "storage_over_pool" }

const msgSeatLimit = "the org has no free seat"

// seatSQL is a users row that holds a seat: an everyday account, active or pending.
func seatSQL(u string) string {
	return "(" + u + ".role='user' AND (" + u + ".pending OR " + u + ".status='active'))"
}

// noFreeSeat: NEW's customer org already has `seats` at or above max_seats, NEW not counted.
func noFreeSeat(seats string) string {
	return `EXISTS(SELECT 1 FROM orgs o WHERE o.id=NEW.org_id AND o.kind='` + customerKind + `' AND
 (SELECT COUNT(*) FROM users s WHERE s.org_id=NEW.org_id AND s.id<>NEW.id AND ` + seats + `)>=o.max_seats)`
}

// seatTriggers refuse a new seat beyond max_seats on every write path (add, enable), and
// an activation beyond it (the first sign-in backstop). Customer orgs only.
func seatTriggers() []tenancyTrigger {
	activated := "(s.role='user' AND NOT s.pending AND s.status='active')"
	return []tenancyTrigger{
		{"users_seat_insert", "BEFORE INSERT", "users", seatSQL("NEW") + " AND " + noFreeSeat(seatSQL("s")), msgSeatLimit},
		{"users_seat_update", "BEFORE UPDATE OF role, status, pending", "users", seatSQL("NEW") + " AND NOT " + seatSQL("OLD") + " AND " + noFreeSeat(seatSQL("s")), msgSeatLimit},
		{"users_seat_activate", "BEFORE UPDATE OF pending", "users", "OLD.pending AND NOT NEW.pending AND NEW.role='user' AND NEW.status='active' AND " + noFreeSeat(activated), msgSeatLimit},
	}
}

func orgStorageSQL(num string) string {
	return `CREATE TABLE IF NOT EXISTS org_storage (
 org_id TEXT NOT NULL REFERENCES orgs(id), app_id TEXT NOT NULL REFERENCES app_registry(id) ON DELETE CASCADE,
 used_bytes ` + num + ` NOT NULL CHECK (used_bytes BETWEEN 0 AND ` + fmt.Sprint(MaxReportBytes) + `),
 seq ` + num + ` NOT NULL CHECK (seq>0),
 ceiling_bytes ` + num + ` NOT NULL CHECK (ceiling_bytes>=used_bytes),
 reported_at ` + num + ` NOT NULL, PRIMARY KEY(org_id,app_id));`
}

func orgStorageColumnsSQL(num string) string {
	return fmt.Sprintf(`ALTER TABLE orgs ADD COLUMN storage_bytes %[1]s NOT NULL DEFAULT 0 CHECK (storage_bytes BETWEEN 0 AND %[2]d);
ALTER TABLE orgs ADD COLUMN storage_per_seat_bytes %[1]s NOT NULL DEFAULT 0 CHECK (storage_per_seat_bytes BETWEEN 0 AND %[3]d);
ALTER TABLE orgs ADD COLUMN storage_over_since %[1]s;
`, num, MaxStorageBytes, MaxStoragePerSeatBytes)
}

func orgStorageTriggers(now string) []tenancyTrigger {
	r := tenancyRefusals(now)
	return append(seatTriggers(),
		tenancyTrigger{"org_storage_org_exists", "BEFORE INSERT", "org_storage", r["org_missing"], msgOrgMissing},
		tenancyTrigger{"org_storage_org_immutable", "BEFORE UPDATE OF org_id", "org_storage", r["org_changed"], msgOrgChanged})
}

func migrateOrgStorage(tx *sql.Tx) error {
	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM pragma_table_info('orgs') WHERE name='storage_bytes'`).Scan(&n); err != nil {
		return err
	}
	var b strings.Builder
	if n == 0 {
		b.WriteString(orgStorageColumnsSQL("INTEGER"))
	}
	b.WriteString(orgStorageSQL("INTEGER") + "\n")
	for _, t := range orgStorageTriggers("unixepoch()") {
		b.WriteString(sqliteTriggerSQL(t, t.refusal))
	}
	_, err := tx.Exec(b.String())
	return err
}

func migrateOrgStoragePostgres(tx *sql.Tx) error {
	var b strings.Builder
	b.WriteString(orgStorageColumnsSQL("BIGINT") + orgStorageSQL("BIGINT") + "\n")
	for _, t := range orgStorageTriggers(`extract(epoch from now())`) {
		b.WriteString(pgTriggerSQL(t, t.refusal))
	}
	_, err := tx.Exec(b.String())
	return err
}

// PoolBytes is the pool of an org with these fields (S1).
func PoolBytes(storageBytes, perSeatBytes, maxSeats int64) int64 {
	return storageBytes + perSeatBytes*maxSeats
}

// grantBytes is the headroom an accepted report gets: never more than the pool leaves
// after every other app's reservation, nor more than the org's cap on all grants at once.
func grantBytes(want, pool, used, held int64) int64 {
	limit := min(pool/8, grantCapBytes)
	return max(0, min(want, pool-used-held, limit-held))
}

// StorageReport is one app's usage of one org (POST /api/suite/storage).
type StorageReport struct {
	OrgID     string `json:"org_id"`
	UsedBytes int64  `json:"used_bytes"`
	Seq       int64  `json:"seq"`
	WantBytes int64  `json:"want_bytes"`
}

// StorageResult answers one report. Grant is nil for unknown_org.
type StorageResult struct {
	OrgID  string `json:"org_id"`
	Result string `json:"result"` // ok, stale or unknown_org
	*StorageGrant
}

// StorageGrant is the app's grant and the org's figures across every app.
type StorageGrant struct {
	Seq          int64  `json:"seq"`
	CeilingBytes int64  `json:"ceiling_bytes"`
	TTLSeconds   int    `json:"ttl_seconds"`
	PoolBytes    int64  `json:"pool_bytes"`
	OrgUsedBytes int64  `json:"org_used_bytes"`
	OverSince    *int64 `json:"over_since"`
}

// ReportStorage applies the calling client's usage reports in one write transaction, which
// every replica serialises, so two apps can never both take the last bytes. A report is
// applied only above the stored seq; the same seq and bytes is a replay. Reports are
// metering and are not audited; a flip of storage_over_since is.
func (p *PlatformStore) ReportStorage(clientID string, reports []StorageReport, now time.Time) ([]StorageResult, error) {
	app, err := p.s.suiteAppID(clientID)
	if err != nil {
		return nil, err
	}
	out := make([]StorageResult, 0, len(reports))
	tx, err := p.s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	for _, r := range reports {
		res := StorageResult{OrgID: r.OrgID, Result: "unknown_org"}
		if app != "" {
			if res, err = reportStorageTx(tx, app, r, now); err != nil {
				return nil, err
			}
		}
		out = append(out, res)
	}
	return out, tx.Commit()
}

type poolOrg struct {
	status                        string
	storage, perSeat, seats, pool int64
	overSince                     sql.NullInt64
}

func reportStorageTx(tx *sql.Tx, app string, r StorageReport, now time.Time) (StorageResult, error) {
	res := StorageResult{OrgID: r.OrgID, Result: "unknown_org"}
	var o poolOrg
	var enabled bool
	err := tx.QueryRow(`SELECT o.status,o.storage_bytes,o.storage_per_seat_bytes,o.max_seats,o.storage_over_since,(o.all_apps OR COALESCE(oa.enabled,FALSE))
 FROM orgs o LEFT JOIN org_apps oa ON oa.org_id=o.id AND oa.app_id=?
 WHERE o.id=? AND o.kind='`+customerKind+`' AND o.status<>'deleted' AND `+suiteOrgVisibleSQL, app, r.OrgID, app).
		Scan(&o.status, &o.storage, &o.perSeat, &o.seats, &o.overSince, &enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return res, nil
	}
	if err != nil {
		return res, err
	}
	o.pool = PoolBytes(o.storage, o.perSeat, o.seats)
	var used, seq, ceiling int64
	err = tx.QueryRow(`SELECT used_bytes,seq,ceiling_bytes FROM org_storage WHERE org_id=? AND app_id=?`, r.OrgID, app).Scan(&used, &seq, &ceiling)
	found := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return res, err
	}
	switch {
	case found && (r.Seq < seq || r.Seq == seq && r.UsedBytes != used):
		res.Result = "stale"
	case found && r.Seq == seq: // a replay: the stored grant, unchanged
		res.Result = "ok"
	default:
		var otherUsed, held int64
		if err := tx.QueryRow(`SELECT CAST(COALESCE(SUM(used_bytes),0) AS BIGINT),CAST(COALESCE(SUM(ceiling_bytes-used_bytes),0) AS BIGINT)
 FROM org_storage WHERE org_id=? AND app_id<>?`, r.OrgID, app).Scan(&otherUsed, &held); err != nil {
			return res, err
		}
		total := otherUsed + r.UsedBytes
		var grant int64
		if o.status == "active" && enabled && total <= o.pool {
			grant = grantBytes(r.WantBytes, o.pool, total, held)
		}
		seq, ceiling = r.Seq, r.UsedBytes+grant
		var q sql.Result
		if found {
			q, err = tx.Exec(`UPDATE org_storage SET used_bytes=?,seq=?,ceiling_bytes=?,reported_at=? WHERE org_id=? AND app_id=? AND seq<?`,
				r.UsedBytes, r.Seq, ceiling, now.Unix(), r.OrgID, app, r.Seq)
		} else {
			q, err = tx.Exec(`INSERT INTO org_storage(org_id,app_id,used_bytes,seq,ceiling_bytes,reported_at) VALUES(?,?,?,?,?,?)`,
				r.OrgID, app, r.UsedBytes, r.Seq, ceiling, now.Unix())
		}
		if err != nil {
			return res, err
		}
		if n, err := q.RowsAffected(); err != nil || n != 1 {
			return res, fmt.Errorf("store: org_storage write changed %d rows: %v", n, err)
		}
		if err := flipOverTx(tx, r.OrgID, &o, total, now); err != nil {
			return res, err
		}
		res.Result = "ok"
	}
	orgUsed, err := orgUsedTx(tx, r.OrgID)
	if err != nil {
		return res, err
	}
	g := &StorageGrant{Seq: seq, CeilingBytes: ceiling, TTLSeconds: StorageGrantTTL, PoolBytes: o.pool, OrgUsedBytes: orgUsed}
	if o.overSince.Valid {
		g.OverSince = &o.overSince.Int64
	}
	res.StorageGrant = g
	return res, nil
}

func orgUsedTx(tx *sql.Tx, org string) (int64, error) {
	var used int64
	err := tx.QueryRow(`SELECT CAST(COALESCE(SUM(used_bytes),0) AS BIGINT) FROM org_storage WHERE org_id=?`, org).Scan(&used)
	return used, err
}

// flipOverTx sets storage_over_since when used first passes the pool and clears it when
// used is back within it, each with a new org revision (so apps see it on /api/suite/orgs)
// and an audit row in the org's log with the two figures only. o is updated to match.
func flipOverTx(tx *sql.Tx, org string, o *poolOrg, used int64, now time.Time) error {
	over := used > o.pool
	if over == o.overSince.Valid {
		return nil
	}
	action, since := "org.storage_within", sql.NullInt64{}
	if over {
		action, since = "org.storage_over", sql.NullInt64{Int64: now.Unix(), Valid: true}
	}
	if _, err := tx.Exec(`UPDATE orgs SET storage_over_since=?,revision=`+nextOrgRevisionSQL+`,updated_at=? WHERE id=?`, since, now, org); err != nil {
		return err
	}
	o.overSince = since
	return orgAuditTx(tx, org, &AuditEvent{Action: action, TargetID: org, TargetType: "org", Outcome: "success"},
		map[string]any{"pool_bytes": o.pool, "used_bytes": used}, now)
}

// orgAuditTx writes e in the org's log, its details with the store's figures on top.
// insertAuditEvent places a row by its user or group, and an org target has neither.
func orgAuditTx(tx *sql.Tx, org string, e *AuditEvent, details map[string]any, now time.Time) error {
	merged := map[string]any{}
	if e.DetailsJSON != "" {
		if err := json.Unmarshal([]byte(e.DetailsJSON), &merged); err != nil {
			return err
		}
	}
	for k, v := range details {
		merged[k] = v
	}
	b, err := json.Marshal(merged)
	if err != nil {
		return err
	}
	if e.ID == "" {
		e.ID = uuid.NewString()
	}
	if e.Outcome == "" {
		e.Outcome = "success"
	}
	_, err = tx.Exec(`INSERT INTO audit_events(org_id,id,actor_id,actor_username,action,target_id,target_type,ip_address,user_agent,outcome,details_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		org, e.ID, e.ActorID, e.ActorUsername, e.Action, e.TargetID, e.TargetType, e.IPAddress, e.UserAgent, e.Outcome, string(b), now)
	return err
}

// OrgLimits are a customer org's seats and pool fields (P2, S1, S3).
type OrgLimits struct{ MaxSeats, StorageBytes, StoragePerSeatBytes int64 }

func (l OrgLimits) valid() error {
	if l.MaxSeats < 1 || l.MaxSeats > MaxSeats {
		return ErrInvalidMaxSeats
	}
	if l.StorageBytes < 0 || l.StorageBytes > MaxStorageBytes || l.StoragePerSeatBytes < 0 || l.StoragePerSeatBytes > MaxStoragePerSeatBytes ||
		PoolBytes(l.StorageBytes, l.StoragePerSeatBytes, l.MaxSeats) < MinPoolBytes {
		return ErrInvalidStorage
	}
	return nil
}

// SetOrgLimits changes a customer org's seats and pool in one write, so the Business pool
// follows its seats. Seats below those in use are refused (SeatsInUseError). A pool lowered
// below the org's usage is refused (StorageOverPoolError) unless ack says the holder
// confirmed the warning; the audit row records that it was given. For the platform API
// PATCH (build plan PR 4) and the staff org page (PR 5). A missing or deleted org, or one
// that is not a customer org, is ErrNotFound.
func (p *PlatformStore) SetOrgLimits(org OrgID, l OrgLimits, ack bool, audit *AuditEvent) error {
	if audit == nil {
		return errors.New("store: SetOrgLimits needs its audit row")
	}
	now := time.Now().UTC()
	tx, err := p.s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	details, err := setOrgLimitsTx(tx, org.id, l, ack, now)
	if err != nil {
		return err
	}
	audit.Action, audit.TargetID, audit.TargetType = "org.limits_changed", org.id, "org"
	if err := orgAuditTx(tx, org.id, audit, details, now); err != nil {
		return err
	}
	return tx.Commit()
}

// setOrgLimitsTx is SetOrgLimits' change, for a caller that audits it; it returns the
// figures for the audit row.
func setOrgLimitsTx(tx *sql.Tx, org string, l OrgLimits, ack bool, now time.Time) (map[string]any, error) {
	if err := l.valid(); err != nil {
		return nil, err
	}
	var o poolOrg
	err := tx.QueryRow(`SELECT status,storage_bytes,storage_per_seat_bytes,max_seats,storage_over_since FROM orgs WHERE id=? AND kind='`+customerKind+`' AND status<>'deleted'`, org).
		Scan(&o.status, &o.storage, &o.perSeat, &o.seats, &o.overSince)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var seats int64
	if err := tx.QueryRow(`SELECT COUNT(*) FROM users u WHERE u.org_id=? AND `+seatSQL("u"), org).Scan(&seats); err != nil {
		return nil, err
	}
	if l.MaxSeats < seats {
		return nil, &SeatsInUseError{SeatsUsed: seats}
	}
	used, err := orgUsedTx(tx, org)
	if err != nil {
		return nil, err
	}
	oldPool := PoolBytes(o.storage, o.perSeat, o.seats)
	o.pool = PoolBytes(l.StorageBytes, l.StoragePerSeatBytes, l.MaxSeats)
	if o.pool < oldPool && o.pool < used && !ack {
		return nil, &StorageOverPoolError{PoolBytes: o.pool, UsedBytes: used}
	}
	if _, err := tx.Exec(`UPDATE orgs SET max_seats=?,storage_bytes=?,storage_per_seat_bytes=?,revision=`+nextOrgRevisionSQL+`,updated_at=? WHERE id=?`,
		l.MaxSeats, l.StorageBytes, l.StoragePerSeatBytes, now, org); err != nil {
		return nil, err
	}
	if err := flipOverTx(tx, org, &o, used, now); err != nil {
		return nil, err
	}
	return map[string]any{"max_seats": l.MaxSeats, "storage_bytes": l.StorageBytes,
		"storage_per_seat_bytes": l.StoragePerSeatBytes, "pool_bytes": o.pool, "used_bytes": used, "storage_over_pool_ack": ack}, nil
}
