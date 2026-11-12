package pgdialect

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"hash/fnv"
	"io"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/stdlib"
)

// The single writer. SQLite lets one writer in at a time and the store's correctness rests
// on that, so on Postgres every read-write transaction takes one transaction-scoped
// advisory lock right after BEGIN, and every write statement outside a transaction is run
// in its own transaction under the same lock. Writes are therefore serialised across every
// replica sharing the database; reads take no lock.
//
// writerLockKey is the key in production. A test schema derives its own key from its
// name (LockKeys), so unrelated tests sharing one database do not queue on each other.
const writerLockKey int64 = 0x4b79_4964_0001 // "KyId", 1

func init() { sql.Register("kypg", Driver{}) }

// Driver is the kypg database/sql driver: pgx's stdlib driver with Translate applied to
// every statement, Go bools sent as 0/1, and the writer lock.
type Driver struct{}

func (Driver) Open(name string) (driver.Conn, error) {
	c, err := Driver{}.OpenConnector(name)
	if err != nil {
		return nil, err
	}
	return c.Connect(context.Background())
}

func (Driver) OpenConnector(name string) (driver.Connector, error) {
	return NewConnector(name, false)
}

// ErrBadURL is returned for a database URL pgx cannot parse. It never repeats the URL,
// which carries a password.
var ErrBadURL = errors.New("the database URL cannot be parsed (check KYIDENTITY_DATABASE_URL)")

// Config parses a postgres:// URL and applies the store's connection rules: a 5 s connect
// timeout, a writable primary (target_session_attrs=read-write unless the URL sets it),
// lock_timeout 5 s (SQLite's busy timeout) and idle_in_transaction_session_timeout 30 s
// unless the URL sets them, and timestamps read back in UTC.
func Config(rawURL string) (*pgx.ConnConfig, error) {
	cfg, err := pgx.ParseConfig(rawURL)
	if err != nil {
		return nil, ErrBadURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, ErrBadURL
	}
	q := u.Query()
	if !q.Has("connect_timeout") {
		cfg.ConnectTimeout = 5 * time.Second
	}
	if !q.Has("target_session_attrs") {
		cfg.ValidateConnect = pgconn.ValidateConnectTargetSessionAttrsReadWrite
	}
	for k, v := range map[string]string{"lock_timeout": "5s", "idle_in_transaction_session_timeout": "30s"} {
		if _, set := cfg.RuntimeParams[k]; !set {
			cfg.RuntimeParams[k] = v
		}
	}
	return cfg, nil
}

// Describe names the server and database of a URL for logs: host and database only.
func Describe(rawURL string) string {
	cfg, err := pgx.ParseConfig(rawURL)
	if err != nil {
		return "(unparsable database URL)"
	}
	return cfg.Host + "/" + cfg.Database
}

// NewConnector opens connections for one pool. A readOnly pool (Store.rdb) runs its
// transactions READ ONLY at REPEATABLE READ, a snapshot as a SQLite read transaction is,
// and never takes the writer lock.
func NewConnector(rawURL string, readOnly bool) (driver.Connector, error) {
	cfg, err := Config(rawURL)
	if err != nil {
		return nil, err
	}
	if readOnly {
		cfg.RuntimeParams["default_transaction_read_only"] = "on"
	}
	writer, _ := LockKeys(cfg.RuntimeParams["search_path"])
	base := stdlib.GetConnector(*cfg, stdlib.OptionAfterConnect(func(_ context.Context, c *pgx.Conn) error {
		c.TypeMap().RegisterType(&pgtype.Type{Name: "timestamptz", OID: pgtype.TimestamptzOID, Codec: &pgtype.TimestamptzCodec{ScanLocation: time.UTC}})
		return nil
	}))
	return &connector{base: base, readOnly: readOnly, lockKey: writer}, nil
}

// LockKeys returns the writer lock key and the migration lock key for a schema: the
// fixed production keys for the default schema, keys derived from the name otherwise.
func LockKeys(schema string) (writer, migration int64) {
	if schema == "" {
		return writerLockKey, writerLockKey + 1
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(schema))
	k := int64(h.Sum64() &^ 1)
	return k, k + 1
}

type connector struct {
	base     driver.Connector
	readOnly bool
	lockKey  int64
}

func (c *connector) Connect(ctx context.Context) (driver.Conn, error) {
	inner, err := c.base.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &conn{inner: inner.(*stdlib.Conn), readOnly: c.readOnly, lockKey: c.lockKey}, nil
}

func (c *connector) Driver() driver.Driver { return Driver{} }

type conn struct {
	inner    *stdlib.Conn
	readOnly bool
	lockKey  int64
	inTx     bool
}

func (c *conn) lock(ctx context.Context) error {
	_, err := c.inner.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", []driver.NamedValue{{Ordinal: 1, Value: c.lockKey}})
	return err
}

func (c *conn) Prepare(query string) (driver.Stmt, error) {
	return &stmt{c: c, query: query}, nil
}

func (c *conn) PrepareContext(_ context.Context, query string) (driver.Stmt, error) {
	return &stmt{c: c, query: query}, nil
}

func (c *conn) Close() error { return c.inner.Close() }

func (c *conn) Begin() (driver.Tx, error) { return c.BeginTx(context.Background(), driver.TxOptions{}) }

func (c *conn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if c.readOnly {
		opts.ReadOnly = true
		if sql.IsolationLevel(opts.Isolation) == sql.LevelDefault {
			opts.Isolation = driver.IsolationLevel(sql.LevelRepeatableRead)
		}
	}
	tx, err := c.inner.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	if !opts.ReadOnly {
		if err := c.lock(ctx); err != nil {
			_ = tx.Rollback()
			return nil, err
		}
	}
	c.inTx = true
	return &txn{tx: tx, c: c}, nil
}

type txn struct {
	tx driver.Tx
	c  *conn
}

func (t *txn) Commit() error {
	t.c.inTx = false
	return t.tx.Commit()
}

func (t *txn) Rollback() error {
	t.c.inTx = false
	return t.tx.Rollback()
}

// autoWrap reports whether a statement must run in its own locked transaction: a write
// outside a transaction on a read-write pool.
func (c *conn) autoWrap(query string) bool {
	return !c.inTx && !c.readOnly && !IsRead(query)
}

func (c *conn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	query = Translate(query)
	if !c.autoWrap(query) {
		return c.inner.ExecContext(ctx, query, args)
	}
	tx, err := c.BeginTx(ctx, driver.TxOptions{})
	if err != nil {
		return nil, err
	}
	res, err := c.inner.ExecContext(ctx, query, args)
	if err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return res, tx.Commit()
}

func (c *conn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	query = Translate(query)
	if !c.autoWrap(query) {
		return c.inner.QueryContext(ctx, query, args)
	}
	tx, err := c.BeginTx(ctx, driver.TxOptions{})
	if err != nil {
		return nil, err
	}
	r, err := c.inner.QueryContext(ctx, query, args)
	if err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return &wrappedRows{Rows: r, tx: tx}, nil
}

// wrappedRows ends the transaction of an auto-wrapped write that returns rows (UPDATE ...
// RETURNING): commit when the rows run out, or at Close if the caller stopped early with
// no error; roll back on any error. A failed commit is reported by Next, so rows.Err and
// QueryRow's Scan see it.
type wrappedRows struct {
	driver.Rows
	tx   driver.Tx
	done bool
}

func (r *wrappedRows) Next(dest []driver.Value) error {
	err := r.Rows.Next(dest)
	switch {
	case err == nil || r.done:
	case err == io.EOF:
		r.done = true
		if cerr := r.tx.Commit(); cerr != nil {
			return cerr
		}
	default:
		r.done = true
		_ = r.tx.Rollback()
	}
	return err
}

func (r *wrappedRows) Close() error {
	err := r.Rows.Close()
	if !r.done {
		r.done = true
		if err != nil {
			_ = r.tx.Rollback()
			return err
		}
		return r.tx.Commit()
	}
	return err
}

// Ping fails on a server that cannot take writes, so readiness fails while the database
// is a read-only standby and the pool reconnects to the new primary afterwards.
func (c *conn) Ping(ctx context.Context) error {
	if err := c.inner.Ping(ctx); err != nil {
		return err
	}
	if c.readOnly {
		return nil
	}
	var ro string
	if err := c.inner.Conn().QueryRow(ctx, "SHOW transaction_read_only").Scan(&ro); err != nil {
		return driver.ErrBadConn
	}
	if ro == "on" {
		return driver.ErrBadConn
	}
	return nil
}

func (c *conn) ResetSession(ctx context.Context) error { return c.inner.ResetSession(ctx) }

func (c *conn) IsValid() bool { return !c.inner.Conn().IsClosed() }

// CheckNamedValue sends Go bools (and driver.Valuers that yield one) as 0/1: the store's
// booleans are INTEGER columns on both backends.
func (c *conn) CheckNamedValue(nv *driver.NamedValue) error {
	if v, ok := nv.Value.(driver.Valuer); ok {
		val, err := v.Value()
		if err != nil {
			return err
		}
		nv.Value = val
	}
	switch v := nv.Value.(type) {
	case bool:
		nv.Value = boolInt(v)
	case *bool:
		if v == nil {
			nv.Value = nil
		} else {
			nv.Value = boolInt(*v)
		}
	}
	return nil
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

type stmt struct {
	c     *conn
	query string
}

func (s *stmt) Close() error  { return nil }
func (s *stmt) NumInput() int { return -1 }

func (s *stmt) Exec(args []driver.Value) (driver.Result, error) {
	return s.ExecContext(context.Background(), named(args))
}

func (s *stmt) Query(args []driver.Value) (driver.Rows, error) {
	return s.QueryContext(context.Background(), named(args))
}

func (s *stmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	return s.c.ExecContext(ctx, s.query, args)
}

func (s *stmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	return s.c.QueryContext(ctx, s.query, args)
}

func named(args []driver.Value) []driver.NamedValue {
	out := make([]driver.NamedValue, len(args))
	for i, v := range args {
		out[i] = driver.NamedValue{Ordinal: i + 1, Value: v}
	}
	return out
}
