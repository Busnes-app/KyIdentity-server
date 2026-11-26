package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/mail"
	"strings"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/google/uuid"
)

// The platform provisioning API's org lifecycle (tenancy design, "Platform provisioning
// API", build plan PR 4). Every write runs in PlatformWrite: its idempotency row, the
// change, the org's audit row and the event to billing commit together.

// PlatformRequestTTL is how long a stored answer replays.
const PlatformRequestTTL = 30 * 24 * time.Hour

// ActivationTTL is the life of an activation link mailed by the platform API.
const PlatformActivationTTL = 7 * 24 * time.Hour

var (
	ErrIdempotencyConflict = errors.New("the idempotency key was used with another request")
	ErrBillingRefConflict  = errors.New("billing_ref belongs to an org created by another request")
	ErrOrgState            = errors.New("the org is not in a state that allows this")
	ErrInvalidHomeRegion   = errors.New("invalid home_region")
	ErrInvalidOrg          = InputError("name 1-200 characters, plan up to 64, billing_ref 1-128, revision at least 1")
	ErrHolderNotMember     = errors.New("the account holder must be a live member of the org")
	ErrEmailInUse          = errors.New("the email or mailbox address is in use")
)

// StaleRevisionError: a lifecycle write whose revision is at or below the org's.
type StaleRevisionError struct{ Current int64 }

func (e *StaleRevisionError) Error() string { return "stale_revision" }

// PlatformCaller is the token behind a call, for the audit row.
type PlatformCaller struct{ TokenID, IP, UserAgent string }

func (c PlatformCaller) audit(action, targetID, targetType string, now time.Time) *AuditEvent {
	return &AuditEvent{ID: uuid.NewString(), ActorID: c.TokenID, ActorUsername: "platform-token", Action: action, TargetID: targetID,
		TargetType: targetType, IPAddress: c.IP, UserAgent: c.UserAgent, Outcome: "success", CreatedAt: now}
}

// PlatformAnswer is a stored response: its status and JSON body.
type PlatformAnswer struct {
	Status int
	Body   json.RawMessage
}

// PlatformWrite runs fn once per (token, key). The same key and request hash gets the
// stored answer, whatever happened since; another hash is ErrIdempotencyConflict. fn's
// answer is stored in its transaction; a refusal (an error) changes and stores nothing.
func (p *PlatformStore) PlatformWrite(tokenID, key, hash string, fn func(tx *sql.Tx, now time.Time) (int, any, error)) (*PlatformAnswer, bool, error) {
	tx, err := p.s.db.Begin()
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	now := rowTime()
	var stored PlatformAnswer
	var storedHash, body string
	err = tx.QueryRow(`SELECT request_hash,status,response_json FROM platform_requests WHERE token_id=? AND idempotency_key=? AND created_at>?`,
		tokenID, key, now.Add(-PlatformRequestTTL)).Scan(&storedHash, &stored.Status, &body)
	switch {
	case err == nil && storedHash == hash:
		stored.Body = json.RawMessage(body)
		return &stored, true, nil
	case err == nil:
		return nil, false, ErrIdempotencyConflict
	case !errors.Is(err, sql.ErrNoRows):
		return nil, false, err
	}
	status, out, err := fn(tx, now)
	if err != nil {
		return nil, false, err
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil, false, err
	}
	// An expired row under the same key gives way to the new answer.
	if _, err := tx.Exec(`DELETE FROM platform_requests WHERE token_id=? AND idempotency_key=?`, tokenID, key); err != nil {
		return nil, false, err
	}
	if _, err := tx.Exec(`INSERT INTO platform_requests(token_id,idempotency_key,request_hash,status,response_json,created_at) VALUES(?,?,?,?,?,?)`,
		tokenID, key, hash, status, string(b), now); err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	return &PlatformAnswer{Status: status, Body: b}, false, nil
}

// RecordPlatformAudit writes a platform API audit row in the org's log when org names a
// live customer org, else as a platform row.
func (p *PlatformStore) RecordPlatformAudit(org string, e *AuditEvent) error {
	_, err := p.s.db.Exec(`INSERT INTO audit_events(org_id,id,actor_id,actor_username,action,target_id,target_type,ip_address,user_agent,outcome,details_json,created_at)
 VALUES((SELECT id FROM orgs WHERE id=? AND kind='`+customerKind+`' AND status<>'deleted'),?,?,?,?,?,?,?,?,?,?,?)`,
		org, e.ID, e.ActorID, e.ActorUsername, e.Action, e.TargetID, e.TargetType, e.IPAddress, e.UserAgent, e.Outcome, e.DetailsJSON, e.CreatedAt)
	return err
}

// DeleteExpiredPlatformRequests drops answers past their replay window.
func (p *PlatformStore) DeleteExpiredPlatformRequests(now time.Time) error {
	_, err := p.s.db.Exec(`DELETE FROM platform_requests WHERE created_at<=?`, now.Add(-PlatformRequestTTL))
	return err
}

// PlatformOrg is GET /platform/v1/orgs/{id}: no user's name or email.
type PlatformOrg struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Status              string `json:"status"`
	StatusReason        string `json:"status_reason"`
	HomeRegion          string `json:"home_region"`
	Plan                string `json:"plan"`
	BillingRef          string `json:"billing_ref"`
	Revision            int64  `json:"revision"`
	MaxSeats            int64  `json:"max_seats"`
	SeatsUsed           int64  `json:"seats_used"`
	PendingInvites      int64  `json:"pending_invites"`
	AccountHolderUserID string `json:"account_holder_user_id,omitempty"`
	HolderActivated     bool   `json:"holder_activated"`
	DeleteAfter         *int64 `json:"delete_after"`
	StorageBytes        int64  `json:"storage_bytes"`
	StoragePerSeatBytes int64  `json:"storage_per_seat_bytes"`
	PoolBytes           int64  `json:"pool_bytes"`
	StorageOverSince    *int64 `json:"storage_over_since"`
}

var platformOrgColumns = `o.id,o.name,o.status,o.status_reason,o.home_region,o.plan,COALESCE(o.billing_ref,''),o.billing_revision,o.max_seats,
 (SELECT COUNT(*) FROM users u WHERE u.org_id=o.id AND ` + seatSQL("u") + `),
 (SELECT COUNT(*) FROM users u WHERE u.org_id=o.id AND u.pending),
 COALESCE(o.account_holder_user_id,''),
 EXISTS(SELECT 1 FROM users u WHERE u.id=o.account_holder_user_id AND NOT u.pending),
 o.delete_after,o.storage_bytes,o.storage_per_seat_bytes,o.storage_over_since`

func scanPlatformOrg(r interface{ Scan(...any) error }) (*PlatformOrg, error) {
	var o PlatformOrg
	var del, over sql.NullInt64
	if err := r.Scan(&o.ID, &o.Name, &o.Status, &o.StatusReason, &o.HomeRegion, &o.Plan, &o.BillingRef, &o.Revision, &o.MaxSeats,
		&o.SeatsUsed, &o.PendingInvites, &o.AccountHolderUserID, &o.HolderActivated, &del, &o.StorageBytes, &o.StoragePerSeatBytes, &over); err != nil {
		return nil, err
	}
	if del.Valid {
		o.DeleteAfter = &del.Int64
	}
	if over.Valid {
		o.StorageOverSince = &over.Int64
	}
	o.PoolBytes = PoolBytes(o.StorageBytes, o.StoragePerSeatBytes, o.MaxSeats)
	return &o, nil
}

func platformOrgTx(q interface {
	QueryRow(string, ...any) *sql.Row
}, id string) (*PlatformOrg, error) {
	o, err := scanPlatformOrg(q.QueryRow(`SELECT `+platformOrgColumns+` FROM orgs o WHERE o.id=? AND o.kind='`+customerKind+`'`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return o, err
}

// PlatformOrg reads one customer org; any other ID is ErrNotFound.
func (p *PlatformStore) PlatformOrg(id string) (*PlatformOrg, error) {
	return platformOrgTx(p.s.db, id)
}

// PlatformOrgs lists customer orgs by ID after cursor, optionally by status or billing_ref.
func (p *PlatformStore) PlatformOrgs(status, billingRef, cursor string, limit int) ([]PlatformOrg, error) {
	rows, err := p.s.db.Query(`SELECT `+platformOrgColumns+` FROM orgs o WHERE o.kind='`+customerKind+`' AND o.id>?
 AND (?='' OR o.status=?) AND (?='' OR o.billing_ref=?) ORDER BY o.id LIMIT ?`, cursor, status, status, billingRef, billingRef, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PlatformOrg{}
	for rows.Next() {
		o, err := scanPlatformOrg(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *o)
	}
	return out, rows.Err()
}

// NewOrg is POST /platform/v1/orgs.
type NewOrg struct {
	Name                 string `json:"name"`
	HomeRegion           string `json:"home_region"`
	Plan                 string `json:"plan"`
	MaxSeats             int64  `json:"max_seats"`
	StorageBytes         int64  `json:"storage_bytes"`
	StoragePerSeatBytes  int64  `json:"storage_per_seat_bytes"`
	HolderEmail          string `json:"holder_email"`
	HolderName           string `json:"holder_name"`
	HolderMailboxAddress string `json:"holder_mailbox_address,omitempty"`
	BillingRef           string `json:"billing_ref"`
	Revision             int64  `json:"revision"`
	// Apps is omitted from the create hash when empty, so a create without it hashes as before.
	Apps map[string]OrgApp `json:"apps,omitempty"`
}

// Invite is an activation link to mail after the transaction commits. Raw is never stored.
type Invite struct{ UserID, Email, Name, Raw string }

func validOrgText(name, plan string) bool {
	return strings.TrimSpace(name) != "" && len(name) <= 200 && len(plan) <= 64
}

// CreateOrg creates a customer org with a pending account holder and its activation
// link, under the caller's idempotency row. A billing_ref that exists answers by the
// org's create hash: the same is 200 with the org, another ErrBillingRefConflict.
func (p *PlatformStore) CreateOrg(tx *sql.Tx, now time.Time, c PlatformCaller, req NewOrg, hash string) (int, *PlatformOrg, *Invite, error) {
	if !validOrgText(req.Name, req.Plan) || req.BillingRef == "" || len(req.BillingRef) > 128 || req.Revision < 1 {
		return 0, nil, nil, ErrInvalidOrg
	}
	var existing, existingHash string
	err := tx.QueryRow(`SELECT id,COALESCE(create_request_hash,'') FROM orgs WHERE billing_ref=?`, req.BillingRef).Scan(&existing, &existingHash)
	switch {
	case err == nil && existingHash == hash:
		o, err := platformOrgTx(tx, existing)
		return 200, o, nil, err
	case err == nil:
		return 0, nil, nil, ErrBillingRefConflict
	case !errors.Is(err, sql.ErrNoRows):
		return 0, nil, nil, err
	}
	if !ValidHomeRegion(req.HomeRegion) {
		return 0, nil, nil, ErrInvalidHomeRegion
	}
	if err := (OrgLimits{req.MaxSeats, req.StorageBytes, req.StoragePerSeatBytes}).valid(); err != nil {
		return 0, nil, nil, err
	}
	email := strings.ToLower(strings.TrimSpace(req.HolderEmail))
	if !validMemberEmail(email) || !validOrgText(req.HolderName, "") {
		return 0, nil, nil, InputError("holder_email must be an address and holder_name 1-200 characters")
	}
	id := uuid.NewString()
	if _, err := tx.Exec(`INSERT INTO orgs(id,name,kind,status,home_region,plan,max_seats,storage_bytes,storage_per_seat_bytes,billing_ref,create_request_hash,billing_revision,revision,created_at,updated_at)
 VALUES(?,?,'`+customerKind+`','active',?,?,?,?,?,?,?,?,`+nextOrgRevisionSQL+`,?,?)`,
		id, strings.TrimSpace(req.Name), req.HomeRegion, req.Plan, req.MaxSeats, req.StorageBytes, req.StoragePerSeatBytes, req.BillingRef, hash, req.Revision, now, now); err != nil {
		return 0, nil, nil, err
	}
	inv, err := addPendingMemberTx(tx, id, email, strings.TrimSpace(req.HolderName), req.HolderMailboxAddress, now)
	if err != nil {
		return 0, nil, nil, err
	}
	if _, err := tx.Exec(`UPDATE orgs SET account_holder_user_id=? WHERE id=?`, inv.UserID, id); err != nil {
		return 0, nil, nil, err
	}
	apps, err := setOrgAppsTx(tx, id, req.Apps)
	if err != nil {
		return 0, nil, nil, err
	}
	if err := queuePlatformEventTx(tx, id, "org.created", "", "", now); err != nil {
		return 0, nil, nil, err
	}
	details := map[string]any{"billing_ref": req.BillingRef, "plan": req.Plan, "max_seats": req.MaxSeats, "home_region": req.HomeRegion, "revision": req.Revision}
	if len(apps) > 0 {
		details["apps"] = apps
	}
	if err := orgAuditTx(tx, id, c.audit("platform.org_created", id, "org", now), details, now); err != nil {
		return 0, nil, nil, err
	}
	o, err := platformOrgTx(tx, id)
	return 201, o, inv, err
}

// validMemberEmail is a bare address (net/mail, no display name), one @, a dotted
// domain; delivery proves the rest.
func validMemberEmail(e string) bool {
	a, err := mail.ParseAddress(e)
	at := strings.IndexByte(e, '@')
	return err == nil && a.Address == e && a.Name == "" && len(e) <= 254 && strings.Count(e, "@") == 1 &&
		strings.Contains(e[at+1:], ".") && !strings.ContainsAny(e, " \t\r\n<>,;\"()[]\\")
}

// addPendingMemberTx creates a pending everyday account (username = email, D5), with its
// mailbox address when given, and its activation link. An email or mailbox address in use
// anywhere is ErrEmailInUse; a full org is ErrSeatLimit.
func addPendingMemberTx(tx *sql.Tx, org, email, name, mailbox string, now time.Time) (*Invite, error) {
	u := &User{ID: uuid.NewString(), Username: email, DisplayName: name, Email: email, Role: "user", Status: "disabled", Pending: true}
	if _, err := tx.Exec(insertUserSQL, org, u.ID, u.Username, u.DisplayName, u.Email, "", u.Role, u.Status, u.Pending, false, now, now); err != nil {
		if isUniqueViolation(err) {
			return nil, ErrEmailInUse
		}
		return nil, staffOrgError(err)
	}
	if mailbox != "" {
		addr, err := NormalizeMailboxAddress(mailbox)
		if err != nil {
			return nil, ErrMailboxDomain
		}
		if _, _, err := setMailboxAddressTx(tx, org, u.ID, addr, false, nil); err != nil {
			if errors.Is(err, ErrMailboxAddressTaken) {
				return nil, ErrEmailInUse
			}
			return nil, err
		}
	}
	if err := reconcileProvisioningTx(tx, now); err != nil {
		return nil, err
	}
	raw, err := issueActivationTx(tx, u.ID, now)
	if err != nil {
		return nil, err
	}
	return &Invite{UserID: u.ID, Email: email, Name: name, Raw: raw}, nil
}

// issueActivationTx ends the user's open activation links and issues a new one, mailed.
func issueActivationTx(tx *sql.Tx, userID string, now time.Time) (string, error) {
	raw, err := crypto.GenerateRandomHex(32)
	if err != nil {
		return "", err
	}
	if err := expireAccountTokensTx(tx, now, `user_id=? AND kind='activation'`, userID); err != nil {
		return "", err
	}
	_, err = tx.Exec(`INSERT INTO account_tokens (id, user_id, kind, token_hash, delivery, expires_at, created_at) VALUES (?,?,'activation',?,'email',?,?)`,
		uuid.NewString(), userID, crypto.HashSHA256(raw), now.Add(PlatformActivationTTL), now)
	return raw, err
}

// lifecycleOrgTx reads a customer org for a lifecycle write and applies the revision rule:
// one at or below billing_revision is StaleRevisionError, else it becomes the new one.
func lifecycleOrgTx(tx *sql.Tx, id string, revision int64) (*PlatformOrg, error) {
	o, err := platformOrgTx(tx, id)
	if err != nil {
		return nil, err
	}
	if revision <= o.Revision {
		return nil, &StaleRevisionError{Current: o.Revision}
	}
	if o.Status == "deleted" {
		return nil, ErrOrgState
	}
	_, err = tx.Exec(`UPDATE orgs SET billing_revision=? WHERE id=?`, revision, id)
	return o, err
}

// OrgPatch is PATCH /platform/v1/orgs/{id}; nil leaves a field as it is.
type OrgPatch struct {
	Revision            int64             `json:"revision"`
	Name                *string           `json:"name"`
	Plan                *string           `json:"plan"`
	MaxSeats            *int64            `json:"max_seats"`
	StorageBytes        *int64            `json:"storage_bytes"`
	StoragePerSeatBytes *int64            `json:"storage_per_seat_bytes"`
	StorageOverPoolAck  bool              `json:"storage_over_pool_ack"`
	AccountHolderUserID *string           `json:"account_holder_user_id"`
	Apps                map[string]OrgApp `json:"apps"`
}

// PatchOrg changes an org's plan, limits, name, account holder or apps.
func (p *PlatformStore) PatchOrg(tx *sql.Tx, now time.Time, c PlatformCaller, id string, req OrgPatch) (*PlatformOrg, error) {
	o, err := lifecycleOrgTx(tx, id, req.Revision)
	if err != nil {
		return nil, err
	}
	details := map[string]any{"revision": req.Revision}
	name, plan := o.Name, o.Plan
	if req.Name != nil {
		name = strings.TrimSpace(*req.Name)
	}
	if req.Plan != nil {
		plan = *req.Plan
	}
	if !validOrgText(name, plan) {
		return nil, ErrInvalidOrg
	}
	if name != o.Name || plan != o.Plan {
		details["plan"] = plan
		if _, err := tx.Exec(`UPDATE orgs SET name=?,plan=?,revision=`+nextOrgRevisionSQL+`,updated_at=? WHERE id=?`, name, plan, now, id); err != nil {
			return nil, err
		}
	}
	if req.MaxSeats != nil || req.StorageBytes != nil || req.StoragePerSeatBytes != nil {
		l := OrgLimits{o.MaxSeats, o.StorageBytes, o.StoragePerSeatBytes}
		for dst, v := range map[*int64]*int64{&l.MaxSeats: req.MaxSeats, &l.StorageBytes: req.StorageBytes, &l.StoragePerSeatBytes: req.StoragePerSeatBytes} {
			if v != nil {
				*dst = *v
			}
		}
		limits, err := setOrgLimitsTx(tx, id, l, req.StorageOverPoolAck, now)
		if err != nil {
			return nil, err
		}
		for k, v := range limits {
			details[k] = v
		}
	}
	if req.AccountHolderUserID != nil && *req.AccountHolderUserID != o.AccountHolderUserID {
		if _, err := tx.Exec(`UPDATE orgs SET account_holder_user_id=?,revision=`+nextOrgRevisionSQL+`,updated_at=? WHERE id=?`, *req.AccountHolderUserID, now, id); err != nil {
			if strings.Contains(err.Error(), msgHolderNotLive) {
				return nil, ErrHolderNotMember
			}
			return nil, erasureError(err)
		}
		details["account_holder_user_id"] = *req.AccountHolderUserID
	}
	if apps, err := setOrgAppsTx(tx, id, req.Apps); err != nil {
		return nil, err
	} else if len(apps) > 0 {
		details["apps"] = apps
	}
	if err := orgAuditTx(tx, id, c.audit("platform.org_updated", id, "org", now), details, now); err != nil {
		return nil, err
	}
	return platformOrgTx(tx, id)
}

// endOrgAccessTx ends every grant of every user of the org, queuing their back-channel
// logouts, and expires their outstanding links (suspension step 2 and 3).
func endOrgAccessTx(tx *sql.Tx, org string, now time.Time) error {
	ids, err := scanStrings(tx.Query(`SELECT id FROM users WHERE org_id=? ORDER BY id`, org))
	if err != nil {
		return err
	}
	for _, uid := range ids {
		if err := revokeUserAccessTx(tx, uid, now); err != nil {
			return err
		}
	}
	return nil
}

// SuspendOrg suspends an active or suspended org (payment or abuse) and ends every grant.
func (p *PlatformStore) SuspendOrg(tx *sql.Tx, now time.Time, c PlatformCaller, id, reason string, revision int64) (*PlatformOrg, error) {
	if reason != "payment" && reason != "abuse" {
		return nil, InputError("reason must be payment or abuse")
	}
	o, err := lifecycleOrgTx(tx, id, revision)
	if err != nil {
		return nil, err
	}
	if o.Status != "active" && o.Status != "suspended" {
		return nil, ErrOrgState
	}
	return p.setOrgStatusTx(tx, now, c, o, "suspended", reason, nil, "org.suspended", revision)
}

// ResumeOrg makes a suspended org, or one scheduled for deletion before delete_after,
// active again. Sessions do not come back; pending members need a new invite.
func (p *PlatformStore) ResumeOrg(tx *sql.Tx, now time.Time, c PlatformCaller, id string, revision int64) (*PlatformOrg, error) {
	o, err := lifecycleOrgTx(tx, id, revision)
	if err != nil {
		return nil, err
	}
	if o.Status != "suspended" && !(o.Status == "deletion_scheduled" && o.DeleteAfter != nil && *o.DeleteAfter > now.Unix()) {
		return nil, ErrOrgState
	}
	return p.setOrgStatusTx(tx, now, c, o, "active", "", nil, "org.resumed", revision)
}

// ScheduleDeletion suspends the org and sets delete_after grace days on. The account
// holder keeps an export-only sign-in until then.
func (p *PlatformStore) ScheduleDeletion(tx *sql.Tx, now time.Time, c PlatformCaller, id string, graceDays int, revision int64) (*PlatformOrg, error) {
	if graceDays < 7 || graceDays > 90 {
		return nil, InputError("grace_days must be 7 to 90")
	}
	o, err := lifecycleOrgTx(tx, id, revision)
	if err != nil {
		return nil, err
	}
	if o.Status != "active" && o.Status != "suspended" {
		return nil, ErrOrgState
	}
	after := now.Add(time.Duration(graceDays) * 24 * time.Hour).Unix()
	return p.setOrgStatusTx(tx, now, c, o, "deletion_scheduled", o.StatusReason, &after, "org.deletion_scheduled", revision)
}

func (p *PlatformStore) setOrgStatusTx(tx *sql.Tx, now time.Time, c PlatformCaller, o *PlatformOrg, status, reason string, deleteAfter *int64, event string, revision int64) (*PlatformOrg, error) {
	if _, err := tx.Exec(`UPDATE orgs SET status=?,status_reason=?,delete_after=?,revision=`+nextOrgRevisionSQL+`,updated_at=? WHERE id=?`,
		status, reason, deleteAfter, now, o.ID); err != nil {
		return nil, erasureError(err)
	}
	if status != "active" {
		if err := endOrgAccessTx(tx, o.ID, now); err != nil {
			return nil, err
		}
	}
	if err := queuePlatformEventTx(tx, o.ID, event, "", "", now); err != nil {
		return nil, err
	}
	action := "platform." + strings.TrimPrefix(event, "org.")
	if err := orgAuditTx(tx, o.ID, c.audit(action, o.ID, "org", now), map[string]any{"from": o.Status, "to": status, "reason": reason, "revision": revision}, now); err != nil {
		return nil, err
	}
	return platformOrgTx(tx, o.ID)
}

// DeleteOrg deletes a deletion_scheduled org whose delete_after has passed: every org row
// in this transaction, the tombstone kept, and the platform audit row with the row counts.
// No revision: the state gate refuses a late call after a resume.
func (p *PlatformStore) DeleteOrg(tx *sql.Tx, now time.Time, c PlatformCaller, id string) (*PlatformOrg, error) {
	o, err := platformOrgTx(tx, id)
	if err != nil {
		return nil, err
	}
	if o.Status != "deletion_scheduled" || o.DeleteAfter == nil || *o.DeleteAfter > now.Unix() {
		return nil, ErrOrgState
	}
	audit := c.audit("platform.org_deleted", id, "org", now)
	setAuditDetails(audit, map[string]any{"org_id": id})
	if err := deleteOrgTx(tx, id, audit, now); err != nil {
		return nil, err
	}
	return platformOrgTx(tx, id)
}
