package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// The platform API's member endpoints (tenancy design, "Member endpoints", build plan
// PR 4): the customer portal invites, re-invites, disables, enables and removes a customer
// org's everyday accounts for its account holder. Each write is audited in the org's log,
// queues org.member_changed and returns a notice for the holder, mailed after commit.

var (
	ErrOrgNotActive = errors.New("the org is not active")
	ErrNotPending   = errors.New("the member is not pending")
	ErrMemberState  = errors.New("the member is not in a state that allows this")
)

// PlatformMember is one row of GET /orgs/{id}/members: no name, session or factor.
type PlatformMember struct {
	UserID        string `json:"user_id"`
	Email         string `json:"email"`
	Status        string `json:"status"` // pending, active or disabled
	AccountHolder bool   `json:"account_holder"`
}

// MemberResult is a member write's answer.
type MemberResult struct {
	UserID string `json:"user_id"`
	Status string `json:"status"`
}

// HolderNotice is a mail to the account holder about a member change; no link.
type HolderNotice struct{ Email, Name, Change, Member string }

func memberStatus(u *User) string {
	switch {
	case u.Pending:
		return "pending"
	case u.Status == "active":
		return "active"
	}
	return "disabled"
}

// customerOrgTx reads a customer org's status; a missing, deleted or other kind is ErrNotFound.
func customerOrgTx(q interface {
	QueryRow(string, ...any) *sql.Row
}, org string) (status, holder string, err error) {
	err = q.QueryRow(`SELECT status,COALESCE(account_holder_user_id,'') FROM orgs WHERE id=? AND kind='`+customerKind+`' AND status<>'deleted'`, org).Scan(&status, &holder)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrNotFound
	}
	return status, holder, err
}

// PlatformMembers lists a customer org's everyday accounts.
func (p *PlatformStore) PlatformMembers(org string) ([]PlatformMember, error) {
	_, holder, err := customerOrgTx(p.s.db, org)
	if err != nil {
		return nil, err
	}
	rows, err := p.s.db.Query(`SELECT `+userColumns+` FROM users WHERE org_id=? AND role='user' ORDER BY email, id`, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PlatformMember{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, PlatformMember{UserID: u.ID, Email: u.Email, Status: memberStatus(u), AccountHolder: u.ID == holder})
	}
	return out, rows.Err()
}

// memberWriteTx is what every member write ends with: the event, the audit row and the
// holder's notice (nil when the holder is the member, or has not activated).
func memberWriteTx(tx *sql.Tx, now time.Time, c PlatformCaller, org, holder string, u *User, change string) (*HolderNotice, error) {
	if err := queuePlatformEventTx(tx, org, "org.member_changed", u.ID, change, now); err != nil {
		return nil, err
	}
	if err := orgAuditTx(tx, org, c.audit("platform.member_"+change, u.ID, "user", now), map[string]any{"user_id": u.ID, "change": change}, now); err != nil {
		return nil, err
	}
	if holder == "" || holder == u.ID {
		return nil, nil
	}
	h, err := scanUser(tx.QueryRow(`SELECT `+userColumns+` FROM users WHERE org_id=? AND id=? AND NOT pending AND status='active'`, org, holder))
	if err != nil || h == nil {
		return nil, err
	}
	return &HolderNotice{Email: h.Email, Name: h.DisplayName, Change: change, Member: u.Email}, nil
}

// AddMember creates a pending member with its activation link. An existing member of this
// org with that email is the same answer (200), its mailbox address set if it has none.
func (p *PlatformStore) AddMember(tx *sql.Tx, now time.Time, c PlatformCaller, org, email, name, mailbox string) (int, *MemberResult, *Invite, *HolderNotice, error) {
	status, holder, err := customerOrgTx(tx, org)
	if err != nil {
		return 0, nil, nil, nil, err
	}
	if status != "active" {
		return 0, nil, nil, nil, ErrOrgNotActive
	}
	email = strings.ToLower(strings.TrimSpace(email))
	name = strings.TrimSpace(name)
	if !validMemberEmail(email) || !validOrgText(name, "") {
		return 0, nil, nil, nil, InputError("email must be an address and name 1-200 characters")
	}
	existing, err := scanUser(tx.QueryRow(`SELECT `+userColumns+` FROM users WHERE email=? OR username=?`, email, email))
	if err != nil {
		return 0, nil, nil, nil, err
	}
	if existing != nil {
		// The same member only by sign-in email: a username left at an old address is not.
		if existing.Org().id != org || existing.Role != "user" || existing.Email != email {
			return 0, nil, nil, nil, ErrEmailInUse
		}
		if mailbox != "" {
			addr, err := NormalizeMailboxAddress(mailbox)
			if err != nil {
				return 0, nil, nil, nil, ErrMailboxDomain
			}
			if _, _, err := setMailboxAddressTx(tx, org, existing.ID, addr, false, nil); err != nil {
				if errors.Is(err, ErrMailboxAddressTaken) {
					return 0, nil, nil, nil, ErrEmailInUse
				}
				return 0, nil, nil, nil, err
			}
		}
		return 200, &MemberResult{existing.ID, memberStatus(existing)}, nil, nil, nil
	}
	inv, err := addPendingMemberTx(tx, org, email, name, mailbox, now)
	if err != nil {
		return 0, nil, nil, nil, err
	}
	u := &User{ID: inv.UserID, Email: email}
	notice, err := memberWriteTx(tx, now, c, org, holder, u, "added")
	if err != nil {
		return 0, nil, nil, nil, err
	}
	return 201, &MemberResult{inv.UserID, "pending"}, inv, notice, nil
}

// memberTx reads one of the org's everyday accounts for a member write.
func memberTx(tx *sql.Tx, org, userID string) (*User, string, string, error) {
	status, holder, err := customerOrgTx(tx, org)
	if err != nil {
		return nil, "", "", err
	}
	u, err := scanUser(tx.QueryRow(`SELECT `+userColumns+` FROM users WHERE org_id=? AND id=? AND role='user'`, org, userID))
	if err == nil && u == nil {
		err = ErrNotFound
	}
	return u, status, holder, err
}

// ResendInvite issues a pending member a new activation link, which ends the old one.
func (p *PlatformStore) ResendInvite(tx *sql.Tx, now time.Time, c PlatformCaller, org, userID string) (*MemberResult, *Invite, *HolderNotice, error) {
	u, status, _, err := memberTx(tx, org, userID)
	if err != nil {
		return nil, nil, nil, err
	}
	if status != "active" {
		return nil, nil, nil, ErrOrgNotActive
	}
	if !u.Pending {
		return nil, nil, nil, ErrNotPending
	}
	raw, err := issueActivationTx(tx, u.ID, now)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := orgAuditTx(tx, org, c.audit("platform.member_invite_resent", u.ID, "user", now), map[string]any{"user_id": u.ID}, now); err != nil {
		return nil, nil, nil, err
	}
	return &MemberResult{u.ID, "pending"}, &Invite{UserID: u.ID, Email: u.Email, Name: u.DisplayName, Raw: raw}, nil, nil
}

// SetMemberEnabled disables an activated member, ending every grant, or enables a
// disabled one, which takes a seat. The account holder cannot be disabled (ErrAccountHolder).
func (p *PlatformStore) SetMemberEnabled(tx *sql.Tx, now time.Time, c PlatformCaller, org, userID string, enable bool) (*MemberResult, *HolderNotice, error) {
	u, status, holder, err := memberTx(tx, org, userID)
	if err != nil {
		return nil, nil, err
	}
	if enable && status != "active" {
		return nil, nil, ErrOrgNotActive
	}
	if u.Pending || u.SourceConnectorID != "" {
		return nil, nil, ErrMemberState
	}
	want, change := "disabled", "disabled"
	if enable {
		want, change = "active", "enabled"
	}
	if u.Status == want {
		return &MemberResult{u.ID, want}, nil, nil
	}
	stored, err := updateUserTx(tx, org, u.ID, nil, func(_ *sql.Tx, row *User) (bool, error) { row.Status = want; return !enable, nil })
	if err != nil {
		return nil, nil, erasureError(err)
	}
	notice, err := memberWriteTx(tx, now, c, org, holder, stored, change)
	if err != nil {
		return nil, nil, err
	}
	return &MemberResult{u.ID, memberStatus(stored)}, notice, nil
}

// RemoveMember deletes a member through the usual deletion, so apps are deprovisioned.
// The account holder cannot be removed (ErrAccountHolder).
func (p *PlatformStore) RemoveMember(tx *sql.Tx, now time.Time, c PlatformCaller, org, userID string) (*MemberResult, *HolderNotice, error) {
	u, _, holder, err := memberTx(tx, org, userID)
	if err != nil {
		return nil, nil, err
	}
	if u.ID == holder {
		return nil, nil, ErrAccountHolder
	}
	if err := deleteUserTx(tx, org, u, now); err != nil {
		return nil, nil, erasureError(err)
	}
	notice, err := memberWriteTx(tx, now, c, org, holder, u, "removed")
	if err != nil {
		return nil, nil, err
	}
	return &MemberResult{u.ID, "removed"}, notice, nil
}

// queueCustomerMemberEventTx queues org.member_changed for a customer org's member; other
// orgs have no billing.
func queueCustomerMemberEventTx(tx *sql.Tx, u *User, change string, now time.Time) error {
	var customer bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM orgs WHERE id=? AND kind='`+customerKind+`')`, u.orgID).Scan(&customer); err != nil || !customer {
		return err
	}
	return queuePlatformEventTx(tx, u.orgID, "org.member_changed", u.ID, change, now)
}
