package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Staff org selection and the pinned staff passkey (tenancy design, "Roles", build plan
// PR 5). Multi-tenant only: the API calls none of this in a single-tenant install.

// IsStaffOrg reports whether org is the install's staff org.
func (s *Store) IsStaffOrg(org OrgID) (bool, error) {
	var yes bool
	err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM orgs WHERE id=? AND kind='staff')`, org.id).Scan(&yes)
	return yes, err
}

// StaffOrg is the org a staff member selected (X-Ky-Org), checked against orgs: a customer
// org or the staff org that is not deleted. Anything else is ErrNotFound. The caller must
// already have proven the request comes from staff.
func (s *Store) StaffOrg(id string) (OrgID, error) {
	var got string
	err := s.db.QueryRow(`SELECT id FROM orgs WHERE id=? AND kind IN ('`+customerKind+`','staff') AND status<>'deleted'`, id).Scan(&got)
	if errors.Is(err, sql.ErrNoRows) {
		return OrgID{}, ErrNotFound
	}
	return OrgID{got}, err
}

// StaffOrgRow is one org in the staff org finder: no member's name or email.
type StaffOrgRow struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Status     string `json:"status"`
	HomeRegion string `json:"homeRegion"`
	Plan       string `json:"plan"`
	BillingRef string `json:"billingRef"`
	MaxSeats   int64  `json:"maxSeats"`
	SeatsUsed  int64  `json:"seatsUsed"`
}

// FindOrgs is the staff org finder: an empty q is the staff org; otherwise the org whose ID
// or billing_ref is q, or that holds an account whose email is exactly q (case-folded).
// Deleted orgs are left out. The caller audits the orgs returned (a cross-org read).
func (p *PlatformStore) FindOrgs(q string) ([]StaffOrgRow, error) {
	q = strings.TrimSpace(q)
	rows, err := p.s.db.Query(`SELECT o.id,o.name,o.kind,o.status,o.home_region,o.plan,COALESCE(o.billing_ref,''),o.max_seats,
 (SELECT COUNT(*) FROM users u WHERE u.org_id=o.id AND `+seatSQL("u")+`)
 FROM orgs o WHERE o.kind IN ('`+customerKind+`','staff') AND o.status<>'deleted' AND
 (?='' AND o.kind='staff' OR ?<>'' AND (o.id=? OR o.billing_ref=? OR o.id IN (SELECT m.org_id FROM users m WHERE lower(m.email)=?)))
 ORDER BY o.kind DESC,o.name,o.id LIMIT 20`, q, q, q, q, strings.ToLower(q))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []StaffOrgRow{}
	for rows.Next() {
		var o StaffOrgRow
		if err := rows.Scan(&o.ID, &o.Name, &o.Kind, &o.Status, &o.HomeRegion, &o.Plan, &o.BillingRef, &o.MaxSeats, &o.SeatsUsed); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// RecordStaffRead writes a staff read (staff.read) in this org's log, whatever the
// target: the org is the one staff selected.
func (o *OrgStore) RecordStaffRead(e *AuditEvent) error {
	if e.ID == "" {
		e.ID = uuid.NewString()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	_, err := o.s.db.Exec(`INSERT INTO audit_events(org_id,id,actor_id,actor_username,action,target_id,target_type,ip_address,user_agent,outcome,details_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		o.org, e.ID, e.ActorID, e.ActorUsername, e.Action, e.TargetID, e.TargetType, e.IPAddress, e.UserAgent, e.Outcome, e.DetailsJSON, e.CreatedAt)
	return err
}

// StaffPasskeyPolicy is the administrators enrollment policy as multi-tenant mode pins it:
// required, passkey only (allowed_mask 4), grace 0.
var StaffPasskeyPolicy = EnrollmentPolicy{Scope: "administrators", Required: true, AllowedMethods: []string{"webauthn"}}

// ErrPinnedPolicy: a change to the pinned staff passkey policy.
var ErrPinnedPolicy = errors.New("the administrators policy is pinned to passkeys in multi-tenant mode")

// PinStaffPasskey sets the administrators policy to StaffPasskeyPolicy when it differs, on
// every multi-tenant start. Staff without a passkey then get an enrollment-only session
// (grace 0). As any policy change, it ends outstanding OAuth grants; audited as a platform
// row. A platform-wide policy that leaves staff no passkey refuses (ErrEnrollmentPolicy).
func (s *Store) PinStaffPasskey() (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var required bool
	var mask, revision int
	var grace int64
	if err := tx.QueryRow(`SELECT required,allowed_mask,grace_seconds,revision FROM enrollment_policies WHERE scope='administrators'`).Scan(&required, &mask, &grace, &revision); err != nil {
		return false, err
	}
	if required && mask == StaffPasskeyPolicy.mask() && grace == StaffPasskeyPolicy.GraceSeconds {
		return false, nil
	}
	p := StaffPasskeyPolicy
	p.Revision = revision
	if err := applyEnrollmentPolicyTx(tx, p); err != nil {
		return false, err
	}
	now := time.Now().UTC()
	if _, err = tx.Exec(`DELETE FROM authorization_codes; DELETE FROM authorization_interactions; DELETE FROM forward_codes; DELETE FROM forward_sessions; UPDATE issued_tokens SET revoked_at=? WHERE revoked_at IS NULL`, now); err != nil {
		return false, err
	}
	b, _ := json.Marshal(map[string]any{"policy": p, "from": map[string]any{"required": required, "allowedMethods": factorNames(mask), "graceSeconds": grace}})
	if _, err := tx.Exec(`INSERT INTO audit_events(org_id,id,actor_id,actor_username,action,target_id,target_type,ip_address,user_agent,outcome,details_json,created_at) VALUES(NULL,?,'system','system','system.staff_passkey_pinned','administrators','enrollment_policy','','','success',?,?)`,
		uuid.NewString(), string(b), now); err != nil {
		return false, err
	}
	return true, tx.Commit()
}
