package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

var ErrEnrollmentPolicy = errors.New("invalid or conflicting MFA enrollment policy")
var ErrEmergencyAdministrator = errors.New("sign in with a compliant administrator factor within five minutes before enabling this policy")
var ErrLastCompliantFactor = errors.New("enroll another permitted factor before removing the last compliant factor")

type EnrollmentPolicy struct {
	Scope          string   `json:"scope"`
	Required       bool     `json:"required"`
	AllowedMethods []string `json:"allowedMethods"`
	GraceSeconds   int64    `json:"graceSeconds"`
	Revision       int      `json:"revision"`
}

func factorBit(method string) int {
	switch method {
	case "totp":
		return 1
	case "push":
		return 2
	case "webauthn":
		return 4
	}
	return 0
}
func factorNames(mask int) []string {
	names := []string{}
	for _, m := range []string{"totp", "push", "webauthn"} {
		if mask&factorBit(m) != 0 {
			names = append(names, m)
		}
	}
	return names
}
func (p EnrollmentPolicy) mask() int {
	mask := 0
	for _, m := range p.AllowedMethods {
		b := factorBit(m)
		if b == 0 || mask&b != 0 {
			return 0
		}
		mask |= b
	}
	return mask
}
func (p EnrollmentPolicy) Valid() bool {
	return (p.Scope == "organization" || p.Scope == "administrators" || (strings.HasPrefix(p.Scope, "group:") && len(p.Scope) > 6 && len(p.Scope) <= 512)) && p.mask() > 0 && p.GraceSeconds >= 0 && p.GraceSeconds <= 90*86400 && p.Revision > 0
}

type EnrollmentStatus struct {
	Required       bool     `json:"required"`
	AllowedMethods []string `json:"allowedMethods"`
	Deadline       int64    `json:"deadline"`
	Enrolled       bool     `json:"enrolled"`
	Restricted     bool     `json:"restricted"`
}

func enrollmentStatus(row interface{ Scan(...any) error }) (EnrollmentStatus, error) {
	var s EnrollmentStatus
	var mask int
	err := row.Scan(&s.Required, &mask, &s.Deadline, &s.Enrolled, &s.Restricted)
	s.AllowedMethods = factorNames(mask)
	return s, err
}

const enrollmentStatusSQL = `SELECT r.required,r.allowed_mask,r.due_at,EXISTS(SELECT 1 FROM enrolled_factors f WHERE f.user_id=r.user_id AND (f.bit&r.allowed_mask)<>0),NOT COALESCE((SELECT allowed FROM mfa_session_access WHERE id=? AND user_id=r.user_id),0) FROM enrollment_requirements r WHERE r.user_id=?`

func (s *Store) SessionEnrollmentStatus(userID, sessionID string) (EnrollmentStatus, error) {
	return enrollmentStatus(s.db.QueryRow(enrollmentStatusSQL, sessionID, userID))
}
func (s *Store) ListEnrollmentPolicies() ([]EnrollmentPolicy, error) {
	rows, err := s.db.Query(`SELECT scope,required,allowed_mask,grace_seconds,revision FROM enrollment_policies WHERE group_id IS NULL ORDER BY scope`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	policies := []EnrollmentPolicy{}
	for rows.Next() {
		var p EnrollmentPolicy
		var mask int
		if err := rows.Scan(&p.Scope, &p.Required, &mask, &p.GraceSeconds, &p.Revision); err != nil {
			return nil, err
		}
		p.AllowedMethods = factorNames(mask)
		policies = append(policies, p)
	}
	return policies, rows.Err()
}

// All edits invalidate outstanding OAuth grants. Preview uses this same temporary
// transaction and rolls it back, including tentative deadline changes.
func applyEnrollmentPolicyTx(tx *sql.Tx, p EnrollmentPolicy) error {
	if !p.Valid() {
		return ErrEnrollmentPolicy
	}
	res, err := tx.Exec(`UPDATE enrollment_policies SET required=?,allowed_mask=?,grace_seconds=?,revision=revision+1 WHERE scope=? AND revision=?`, p.Required, p.mask(), p.GraceSeconds, p.Scope, p.Revision)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrAppLinkConflict
	}
	var compatible bool
	if err = tx.QueryRow(`SELECT NOT EXISTS(SELECT 1 FROM enrollment_requirements WHERE required AND allowed_mask=0)`).Scan(&compatible); err != nil {
		return err
	}
	if !compatible {
		return ErrEnrollmentPolicy
	}
	// ponytail: policy edits scan applicable users; scope this query if the directory grows large.
	_, err = tx.Exec(`INSERT INTO enrollment_deadlines SELECT p.user_id,p.scope,unixepoch()+p.grace_seconds FROM applicable_enrollment_policies p WHERE true ON CONFLICT(user_id,scope) DO UPDATE SET due_at=MIN(enrollment_deadlines.due_at,excluded.due_at)`)
	return err
}

type EnrollmentPreview struct {
	Affected           int  `json:"affected"`
	MissingFactor      int  `json:"missingFactor"`
	RestrictedSessions int  `json:"restrictedSessions"`
	CanActivate        bool `json:"canActivate"`
}

func previewEnrollmentTx(tx *sql.Tx, sessionID, scope string) (EnrollmentPreview, error) {
	var p EnrollmentPreview
	err := tx.QueryRow(`SELECT (SELECT COUNT(*) FROM enrollment_requirements r JOIN users u ON u.id=r.user_id WHERE r.required AND u.status='active' AND (? NOT LIKE 'group:%' OR EXISTS(SELECT 1 FROM group_memberships m WHERE m.user_id=r.user_id AND 'group:'||m.group_id=?))),
 (SELECT COUNT(*) FROM enrollment_requirements r JOIN users u ON u.id=r.user_id WHERE r.required AND u.status='active' AND NOT EXISTS(SELECT 1 FROM enrolled_factors f WHERE f.user_id=r.user_id AND (f.bit&r.allowed_mask)<>0) AND (? NOT LIKE 'group:%' OR EXISTS(SELECT 1 FROM group_memberships m WHERE m.user_id=r.user_id AND 'group:'||m.group_id=?))),
 (SELECT COUNT(*) FROM mfa_session_access a JOIN sessions s ON s.id=a.id WHERE NOT a.allowed AND s.expires_at>? AND (? NOT LIKE 'group:%' OR EXISTS(SELECT 1 FROM group_memberships m WHERE m.user_id=a.user_id AND 'group:'||m.group_id=?)))`, scope, scope, scope, scope, time.Now().UTC(), scope, scope).Scan(&p.Affected, &p.MissingFactor, &p.RestrictedSessions)
	if err != nil {
		return p, err
	}
	// The activating administrator is the tested local recovery path. Step-up alone
	// cannot fabricate login evidence; they must have actually signed in with MFA.
	var primary, factor *time.Time
	var method string
	var required bool
	var mask int
	var enrolled bool
	err = tx.QueryRow(`SELECT s.primary_authenticated_at,s.factor_authenticated_at,s.factor_method,r.required,r.allowed_mask,
 EXISTS(SELECT 1 FROM enrolled_factors f WHERE f.user_id=s.user_id AND f.bit=CASE s.factor_method WHEN 'totp' THEN 1 WHEN 'push' THEN 2 WHEN 'webauthn' THEN 4 ELSE 0 END)
 FROM sessions s JOIN users u ON u.id=s.user_id JOIN enrollment_requirements r ON r.user_id=s.user_id WHERE s.id=? AND u.role='admin' AND u.status='active' AND NOT s.enrollment_only AND s.expires_at>?`, sessionID, time.Now().UTC()).Scan(&primary, &factor, &method, &required, &mask, &enrolled)
	if errors.Is(err, sql.ErrNoRows) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	now := time.Now().UTC()
	p.CanActivate = !required || (enrolled && primary != nil && factor != nil && !primary.After(now) && !factor.After(now) && primary.After(now.Add(-5*time.Minute)) && factor.After(now.Add(-5*time.Minute)) && factorBit(method)&mask != 0)
	return p, nil
}
func (s *Store) PreviewEnrollmentPolicy(p EnrollmentPolicy, sessionID string) (EnrollmentPreview, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return EnrollmentPreview{}, err
	}
	defer tx.Rollback()
	if err = applyEnrollmentPolicyTx(tx, p); err != nil {
		return EnrollmentPreview{}, err
	}
	return previewEnrollmentTx(tx, sessionID, p.Scope)
}
func (s *Store) SetEnrollmentPolicy(p EnrollmentPolicy, sessionID string, audit *AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = applyEnrollmentPolicyTx(tx, p); err != nil {
		return err
	}
	preview, err := previewEnrollmentTx(tx, sessionID, p.Scope)
	if err != nil {
		return err
	}
	if !preview.CanActivate {
		return ErrEmergencyAdministrator
	}
	if _, err = tx.Exec(`DELETE FROM authorization_codes; DELETE FROM authorization_interactions; UPDATE issued_tokens SET revoked_at=? WHERE revoked_at IS NULL`, time.Now().UTC()); err != nil {
		return err
	}
	details := map[string]any{"policy": p, "impact": preview}
	if strings.HasPrefix(p.Scope, "group:") {
		var name string
		if err = tx.QueryRow(`SELECT g.name FROM directory_groups g JOIN enrollment_policies p ON p.group_id=g.id WHERE p.scope=?`, p.Scope).Scan(&name); err != nil {
			return err
		}
		details["groupName"] = name
	}
	if err = appRegistryAudit(audit, details); err != nil {
		return err
	}
	if err = recordAuditTx(tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func compliantEnrollmentTx(tx *sql.Tx, userID string) (bool, error) {
	var yes bool
	err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM enrollment_requirements r JOIN enrolled_factors f ON f.user_id=r.user_id WHERE r.user_id=? AND r.required AND (r.allowed_mask&f.bit)<>0)`, userID).Scan(&yes)
	return yes, err
}
func preserveCompliantEnrollmentTx(tx *sql.Tx, userID string, wasCompliant bool) error {
	if !wasCompliant {
		return nil
	}
	ok, err := compliantEnrollmentTx(tx, userID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrLastCompliantFactor
	}
	return nil
}

// changeEnrollmentDevice runs one device write with its audit row, returning
// sql.ErrNoRows when it matched no device.
func (s *Store) changeEnrollmentDevice(userID string, audit *AuditEvent, query string, args ...any) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`UPDATE users SET id=id WHERE id=?`, userID); err != nil {
		return err
	}
	wasCompliant, err := compliantEnrollmentTx(tx, userID)
	if err != nil {
		return err
	}
	res, err := tx.Exec(query, args...)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return sql.ErrNoRows
	}
	if err = syncPushMethodTx(tx, userID); err != nil {
		return err
	}
	if err = recordAuditTx(tx, audit); err != nil {
		return err
	}
	if err = preserveCompliantEnrollmentTx(tx, userID, wasCompliant); err != nil {
		return err
	}
	return tx.Commit()
}

// syncPushMethodTx makes the mfa_methods push row, which login and step-up offer, follow
// enrolled_factors: present exactly while an approver device with a key remains.
func syncPushMethodTx(tx *sql.Tx, userID string) error {
	if _, err := tx.Exec(`DELETE FROM mfa_methods WHERE user_id=? AND method_type='push' AND NOT EXISTS(SELECT 1 FROM enrolled_factors WHERE user_id=? AND bit=2)`, userID, userID); err != nil {
		return err
	}
	_, err := tx.Exec(`INSERT OR IGNORE INTO mfa_methods(id,user_id,method_type,encrypted_secret,created_at) SELECT ?,?,'push','',? WHERE EXISTS(SELECT 1 FROM enrolled_factors WHERE user_id=? AND bit=2)`, uuid.NewString(), userID, time.Now().UTC(), userID)
	return err
}

const enrollmentSessionViewSQL = ` CREATE VIEW IF NOT EXISTS mfa_session_access AS
 SELECT sess.id,sess.user_id,NOT sess.enrollment_only AND (NOT r.required OR
 (sess.factor_method<>'recovery' AND r.due_at>unixepoch() AND NOT EXISTS(SELECT 1 FROM enrolled_factors f WHERE f.user_id=sess.user_id AND (f.bit&r.allowed_mask)<>0)) OR
 (sess.primary_authenticated_at IS NOT NULL AND sess.factor_authenticated_at IS NOT NULL AND
 ((CASE sess.factor_method WHEN 'totp' THEN 1 WHEN 'push' THEN 2 WHEN 'webauthn' THEN 4 ELSE 0 END)&r.allowed_mask)<>0 AND
 EXISTS(SELECT 1 FROM enrolled_factors f WHERE f.user_id=sess.user_id AND f.bit=CASE sess.factor_method WHEN 'totp' THEN 1 WHEN 'push' THEN 2 WHEN 'webauthn' THEN 4 ELSE 0 END))) allowed
 FROM sessions sess JOIN enrollment_requirements r ON r.user_id=sess.user_id;
`
