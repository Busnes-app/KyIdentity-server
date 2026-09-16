package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Access requests. A user asks for an app an administrator marked requestable, with a
// reason and an optional duration; a global administrator or an owner of that app
// approves or denies. An approval is an ordinary direct assignment with the requested
// expiry, written through the same path a manual grant takes, so there is no second
// way to hold access. The approver's authority and the app's policy are re-read inside
// the deciding transaction, never trusted from the form.

var (
	ErrAppNotRequestable = errors.New("app is not open to requests")
	ErrAlreadyHasAccess  = errors.New("user already has access to this app")
	ErrDuplicateRequest  = errors.New("a request for this app is already pending")
	ErrTooManyRequests   = errors.New("too many pending requests")
	ErrRequestNotPending = errors.New("request is not pending")
	ErrSelfApproval      = errors.New("a request cannot be decided by its requester")
	ErrCannotDecide      = errors.New("not allowed to decide requests for this app")
)

const (
	maxPendingRequests = 5
	MaxRequestDuration = 90 * 24 * time.Hour
	requestTTL         = 14 * 24 * time.Hour
	maxReasonLength    = 500
)

type AccessRequest struct {
	ID              string     `json:"id"`
	AppID           string     `json:"appId"`
	AppName         string     `json:"appName"`
	UserID          string     `json:"userId"`
	Username        string     `json:"username"`
	Reason          string     `json:"reason"`
	DurationSeconds int        `json:"durationSeconds"`
	Status          string     `json:"status"`
	CreatedAt       time.Time  `json:"createdAt"`
	ExpiresAt       time.Time  `json:"expiresAt"`
	DecidedAt       *time.Time `json:"decidedAt,omitempty"`
	DecidedBy       string     `json:"decidedBy,omitempty"`
	DecisionNote    string     `json:"decisionNote,omitempty"`
}

// RequestableApp is an app the user may ask for: requestable, enabled, assigned-only,
// and not already reachable by them.
type RequestableApp struct {
	AppID   string `json:"appId"`
	Name    string `json:"name"`
	Pending bool   `json:"pending"`
}

func (s *Store) migrateAccessRequests() error {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('app_registry') WHERE name='requestable'`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := s.db.Exec(`ALTER TABLE app_registry ADD COLUMN requestable BOOLEAN NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS access_requests (
 id TEXT PRIMARY KEY,
 app_id TEXT NOT NULL REFERENCES app_registry(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 reason TEXT NOT NULL, duration_seconds INTEGER NOT NULL DEFAULT 0,
 status TEXT NOT NULL CHECK(status IN ('pending','approved','denied','cancelled','expired')),
 created_at DATETIME NOT NULL, expires_at INTEGER NOT NULL,
 decided_at DATETIME, decided_by TEXT NOT NULL DEFAULT '', decision_note TEXT NOT NULL DEFAULT '');
 CREATE UNIQUE INDEX IF NOT EXISTS access_requests_pending ON access_requests(app_id,user_id) WHERE status='pending';
 CREATE INDEX IF NOT EXISTS access_requests_user ON access_requests(user_id,created_at)`)
	return err
}

const appDisplayName = `COALESCE(NULLIF(l.name,''),NULLIF(c.client_name,''),NULLIF(s.name,''),a.id)`

// SetAppRequestable opens or closes an app to requests.
func (s *Store) SetAppRequestable(id string, requestable bool, revision int, audit *AuditEvent) error {
	return s.auditedTx(audit, func(tx *sql.Tx) error {
		before, err := lockAppRecord(tx, id, revision)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE app_registry SET requestable=?,revision=revision+1 WHERE id=?`, requestable, id); err != nil {
			return err
		}
		return appRegistryAudit(audit, map[string]any{"app": before.ID, "requestable": requestable})
	})
}

// RequestableApps lists what the user may ask for. Apps not marked requestable are
// never named here, whatever the user already knows.
func (s *Store) RequestableApps(userID string) ([]RequestableApp, error) {
	rows, err := s.db.Query(`SELECT a.id,`+appDisplayName+`,
 EXISTS(SELECT 1 FROM access_requests r WHERE r.app_id=a.id AND r.user_id=? AND r.status='pending')`+appRecordFrom+`
 WHERE a.requestable AND a.enabled AND a.access_mode='assigned_only'
 AND NOT EXISTS(SELECT 1 FROM effective_app_access e WHERE e.app_id=a.id AND e.user_id=?) ORDER BY 2 COLLATE NOCASE, a.id`, userID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RequestableApp{}
	for rows.Next() {
		var r RequestableApp
		if err := rows.Scan(&r.AppID, &r.Name, &r.Pending); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CreateAccessRequest files a request. Duplicate pending requests and more than a
// handful of open ones per user are refused; the row expires unanswered after two weeks.
func (s *Store) CreateAccessRequest(userID, appID, reason string, duration time.Duration, audit *AuditEvent) (*AccessRequest, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > maxReasonLength || duration < 0 || duration > MaxRequestDuration {
		return nil, ErrAppLinkConflict
	}
	now := time.Now().UTC()
	req := &AccessRequest{ID: uuid.NewString(), AppID: appID, UserID: userID, Reason: reason, DurationSeconds: int(duration / time.Second), Status: "pending", CreatedAt: now, ExpiresAt: now.Add(requestTTL).Truncate(time.Second)}
	err := s.auditedTx(audit, func(tx *sql.Tx) error {
		var requestable bool
		err := tx.QueryRow(`SELECT a.requestable AND a.enabled AND a.access_mode='assigned_only' FROM app_registry a WHERE a.id=?`, appID).Scan(&requestable)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && !requestable) {
			return ErrAppNotRequestable
		}
		if err != nil {
			return err
		}
		var has bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM effective_app_access e WHERE e.app_id=? AND e.user_id=?)`, appID, userID).Scan(&has); err != nil {
			return err
		}
		if has {
			return ErrAlreadyHasAccess
		}
		var pending int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM access_requests WHERE user_id=? AND status='pending'`, userID).Scan(&pending); err != nil {
			return err
		}
		if pending >= maxPendingRequests {
			return ErrTooManyRequests
		}
		if _, err := tx.Exec(`INSERT INTO access_requests(id,app_id,user_id,reason,duration_seconds,status,created_at,expires_at) VALUES(?,?,?,?,?,'pending',?,?)`,
			req.ID, appID, userID, reason, req.DurationSeconds, now, req.ExpiresAt.Unix()); err != nil {
			if isUniqueViolation(err) {
				return ErrDuplicateRequest
			}
			return err
		}
		if err := tx.QueryRow(`SELECT `+appDisplayName+appRecordFrom+` WHERE a.id=?`, appID).Scan(&req.AppName); err != nil {
			return err
		}
		return appRegistryAudit(audit, map[string]any{"requestId": req.ID, "app": appID, "durationSeconds": req.DurationSeconds})
	})
	if err != nil {
		return nil, err
	}
	return req, nil
}

// CancelAccessRequest withdraws the user's own pending request.
func (s *Store) CancelAccessRequest(id, userID string, audit *AuditEvent) error {
	return s.auditedTx(audit, func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE access_requests SET status='cancelled', decided_at=? WHERE id=? AND user_id=? AND status='pending'`, time.Now().UTC(), id, userID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrRequestNotPending
		}
		return appRegistryAudit(audit, map[string]any{"requestId": id})
	})
}

// AccessRequestFilter selects requests: the user's own, or the inbox of an actor, which
// is every app for a global administrator and the owned apps for a delegate.
type AccessRequestFilter struct {
	UserID, ActorID, Status string
	Limit, Offset           int
}

const accessRequestSelect = `SELECT r.id,r.app_id,` + appDisplayName + `,r.user_id,u.username,r.reason,r.duration_seconds,r.status,r.created_at,r.expires_at,r.decided_at,r.decided_by,r.decision_note
 FROM access_requests r JOIN users u ON u.id=r.user_id JOIN app_registry a ON a.id=r.app_id
 LEFT JOIN oauth_clients c ON c.id=a.client_id LEFT JOIN applications l ON l.id=a.launcher_id LEFT JOIN paired_systems s ON s.id=a.system_id`

func scanAccessRequest(row interface{ Scan(...any) error }) (*AccessRequest, error) {
	r := &AccessRequest{}
	var expires int64
	var decided sql.NullTime
	err := row.Scan(&r.ID, &r.AppID, &r.AppName, &r.UserID, &r.Username, &r.Reason, &r.DurationSeconds, &r.Status, &r.CreatedAt, &expires, &decided, &r.DecidedBy, &r.DecisionNote)
	if err != nil {
		return nil, err
	}
	r.ExpiresAt = time.Unix(expires, 0).UTC()
	if decided.Valid {
		at := decided.Time
		r.DecidedAt = &at
	}
	return r, nil
}

func (s *Store) ListAccessRequests(f AccessRequestFilter) ([]AccessRequest, int, error) {
	where, args := ` WHERE 1=1`, []any{}
	if f.UserID != "" {
		where, args = where+` AND r.user_id=?`, append(args, f.UserID)
	}
	if f.ActorID != "" {
		where = where + ` AND (EXISTS(SELECT 1 FROM users x WHERE x.id=? AND ` + activeAdminSQL + `) OR r.app_id IN (SELECT d.app_id FROM admin_delegations d WHERE d.user_id=? AND d.kind='app_owner'))`
		args = append(args, f.ActorID, f.ActorID)
	}
	if f.Status != "" {
		where, args = where+` AND r.status=?`, append(args, f.Status)
	}
	if f.Status == "pending" {
		where = where + ` AND r.expires_at>unixepoch()`
	}
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM access_requests r`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(accessRequestSelect+where+` ORDER BY r.created_at DESC, r.id LIMIT ? OFFSET ?`, append(args, f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []AccessRequest{}
	for rows.Next() {
		r, err := scanAccessRequest(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *r)
	}
	return out, total, rows.Err()
}

// DecideAccessRequest approves or denies a pending request as actorID. Authority (global
// administrator or owner of the app), the app's policy and the request's state are all
// read under the write lock, so a stale form, a withdrawn delegation or a second
// decision cannot grant anything. An approval is a direct assignment with the requested
// expiry, written through the same path as a manual grant.
func (s *Store) DecideAccessRequest(id, actorID string, approve bool, note string, audit *AuditEvent) (*AccessRequest, error) {
	note = strings.TrimSpace(note)
	if len(note) > maxReasonLength {
		return nil, ErrAppLinkConflict
	}
	now := time.Now().UTC()
	var out *AccessRequest
	err := s.auditedTx(audit, func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE access_requests SET status=status WHERE id=? AND status='pending'`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrRequestNotPending
		}
		req, err := scanAccessRequest(tx.QueryRow(accessRequestSelect+` WHERE r.id=?`, id))
		if err != nil {
			return err
		}
		if !req.ExpiresAt.After(now) {
			if _, err := tx.Exec(`UPDATE access_requests SET status='expired', decided_at=? WHERE id=?`, now, id); err != nil {
				return err
			}
			return ErrRequestNotPending
		}
		if req.UserID == actorID {
			return ErrSelfApproval
		}
		var may bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM users WHERE id=? AND `+activeAdminSQL+`)
 OR EXISTS(SELECT 1 FROM admin_delegations d JOIN users x ON x.id=d.user_id WHERE d.user_id=? AND d.kind='app_owner' AND d.app_id=? AND x.status='active' AND (x.ends_at IS NULL OR x.ends_at>unixepoch()))`, actorID, actorID, req.AppID).Scan(&may); err != nil {
			return err
		}
		if !may {
			return ErrCannotDecide
		}
		status := "denied"
		if approve {
			var open bool
			if err := tx.QueryRow(`SELECT requestable AND enabled AND access_mode='assigned_only' FROM app_registry WHERE id=?`, req.AppID).Scan(&open); err != nil {
				return err
			}
			if !open {
				return ErrAppNotRequestable
			}
			var expiresAt *time.Time
			if req.DurationSeconds > 0 {
				at := now.Add(time.Duration(req.DurationSeconds) * time.Second).Truncate(time.Second)
				expiresAt = &at
			}
			if _, err := applyAppAssignmentTx(tx, req.AppID, "users", req.UserID, true, expiresAt); err != nil {
				return err
			}
			status = "approved"
		}
		if _, err := tx.Exec(`UPDATE access_requests SET status=?, decided_at=?, decided_by=?, decision_note=? WHERE id=?`, status, now, actorID, note, id); err != nil {
			return err
		}
		req.Status, req.DecidedAt, req.DecidedBy, req.DecisionNote = status, &now, actorID, note
		out = req
		return appRegistryAudit(audit, map[string]any{"requestId": id, "app": req.AppID, "userId": req.UserID, "status": status, "durationSeconds": req.DurationSeconds})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// expireAccessRequestsTx closes pending requests nobody answered in time.
func expireAccessRequestsTx(tx *sql.Tx, now time.Time) error {
	_, err := tx.Exec(`UPDATE access_requests SET status='expired', decided_at=? WHERE status='pending' AND expires_at<=?`, now, now.Unix())
	return err
}
