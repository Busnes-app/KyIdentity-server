package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Delete everything (tenancy design, amendment 2026-11-21). Multi-tenant only: the API
// refuses it in a single-tenant install, and the triggers refuse it for the default org.

// erasureGrace is the export window the other members of a holder's household get. A
// variable only so a test can make it pass.
var erasureGrace = 7 * 24 * time.Hour

var (
	// ErrOrgErased: the account holder asked for Delete everything; nothing takes it back.
	ErrOrgErased = errors.New("store: the account holder deleted this org")
	// ErrAccountHolder: the account holder cannot be deleted, disabled or ended.
	ErrAccountHolder = errors.New("store: the account holder cannot be removed")
	// ErrErasureStepUp: no live step-up grant with a second factor for this operation.
	ErrErasureStepUp = errors.New("store: erasure needs a step-up with a second factor")
	// ErrErasureRefused: the account cannot erase itself (staff, default org, pending, or
	// an org that is not active).
	ErrErasureRefused = errors.New("store: this account cannot be erased")
)

const (
	msgErased       = "the account holder deleted this org; it cannot be undone"
	msgErasureAsk   = "only the holder of an active person or household org asks, immediate exactly when no other member is live"
	msgErasureKept  = "erasure records are never changed or deleted"
	msgErasedReused = "an erased subject is never reused"
)

// otherLiveSQL: a live member of org other than holder (SQL expressions or placeholders).
func otherLiveSQL(org, holder string) string {
	return `EXISTS(SELECT 1 FROM users u WHERE u.org_id=` + org + ` AND u.id<>` + holder + ` AND ` + liveHolder("u") + `)`
}

// holderErasedSQL is the named path holder_erased: the holder asked, with nobody else live.
var holderErasedSQL = `EXISTS(SELECT 1 FROM org_erasures e WHERE e.org_id=OLD.id AND e.immediate AND NOT ` + otherLiveSQL("OLD.id", "e.holder_user_id") + `)`

func erasureTriggers(now string) []tenancyTrigger {
	return []tenancyTrigger{
		// T's status_bad_change and holder_bad_change, each with holder_erased beside its own path.
		{"orgs_account_holder_update", "BEFORE UPDATE OF account_holder_user_id", "orgs", `NEW.account_holder_user_id IS DISTINCT FROM OLD.account_holder_user_id AND CASE WHEN NEW.account_holder_user_id IS NULL
 THEN NOT (NEW.status='deleted' AND (OLD.status='deletion_scheduled' OR OLD.status='active' AND ` + holderErasedSQL + `))
 ELSE NOT EXISTS(SELECT 1 FROM users u WHERE u.id=NEW.account_holder_user_id AND u.org_id=NEW.id AND ` + liveHolder("u") + `) END`, msgHolderNotLive},
		{"orgs_status", "BEFORE UPDATE OF status", "orgs", `NEW.status IS DISTINCT FROM OLD.status AND (OLD.status='deleted' OR NEW.status='deleted'
 AND NOT (OLD.status='deletion_scheduled' AND OLD.delete_after IS NOT NULL AND OLD.delete_after<=` + now + `)
 AND NOT (OLD.status='active' AND ` + holderErasedSQL + `))`, msgDeleted},
		{"orgs_erasure_held", "BEFORE UPDATE", "orgs", `OLD.status='deletion_scheduled' AND EXISTS(SELECT 1 FROM org_erasures e WHERE e.org_id=OLD.id)
 AND ((NEW.status IS DISTINCT FROM OLD.status AND NEW.status<>'deleted') OR NEW.delete_after IS DISTINCT FROM OLD.delete_after)`, msgErased},
		{"org_erasures_holder", "BEFORE INSERT", "org_erasures", `NOT EXISTS(SELECT 1 FROM orgs o WHERE o.id=NEW.org_id AND o.account_holder_user_id=NEW.holder_user_id AND o.status='active' AND o.kind IN ('person','household'))
 OR (NEW.immediate) <> (NOT ` + otherLiveSQL("NEW.org_id", "NEW.holder_user_id") + `)`, msgErasureAsk},
		{"org_erasures_kept_update", "BEFORE UPDATE", "org_erasures", "TRUE", msgErasureKept},
		{"org_erasures_kept_delete", "BEFORE DELETE", "org_erasures", "TRUE", msgErasureKept},
		{"erased_subjects_kept_update", "BEFORE UPDATE", "erased_subjects", "TRUE", msgErasureKept},
		{"erased_subjects_kept_delete", "BEFORE DELETE", "erased_subjects", "TRUE", msgErasureKept},
		{"users_erased_subject", "BEFORE INSERT", "users", `EXISTS(SELECT 1 FROM erased_subjects WHERE subject=NEW.id)`, msgErasedReused},
	}
}

func erasureTablesSQL(ts, num string) string {
	return `CREATE TABLE IF NOT EXISTS org_erasures (org_id TEXT PRIMARY KEY REFERENCES orgs(id), holder_user_id TEXT NOT NULL,
 immediate BOOLEAN NOT NULL, requested_at ` + ts + ` NOT NULL);
CREATE TABLE IF NOT EXISTS erased_subjects (subject TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES orgs(id),
 revision ` + num + ` NOT NULL UNIQUE, erased_at ` + ts + ` NOT NULL);
`
}

func migrateErasure(tx *sql.Tx) error {
	var b strings.Builder
	b.WriteString(erasureTablesSQL("DATETIME", "INTEGER") + "DROP TRIGGER IF EXISTS orgs_account_holder_update;\nDROP TRIGGER IF EXISTS orgs_status;\n")
	for _, t := range erasureTriggers("unixepoch()") {
		b.WriteString(sqliteTriggerSQL(t, t.refusal))
	}
	_, err := tx.Exec(b.String())
	return err
}

func migrateErasurePostgres(tx *sql.Tx) error {
	var b strings.Builder
	b.WriteString(erasureTablesSQL("TIMESTAMPTZ", "BIGINT"))
	for _, n := range []string{"orgs_account_holder_update", "orgs_status"} {
		fmt.Fprintf(&b, "DROP TRIGGER %[1]s ON orgs;\nDROP FUNCTION %[1]s();\n", n)
	}
	for _, t := range erasureTriggers(`extract(epoch from now())`) {
		b.WriteString(pgTriggerSQL(t, t.refusal))
	}
	_, err := tx.Exec(b.String())
	return err
}

// erasureError maps the triggers' refusals to the store's errors.
func erasureError(err error) error {
	switch {
	case err == nil:
		return nil
	case strings.Contains(err.Error(), msgErased), strings.Contains(err.Error(), msgErasureAsk):
		return ErrOrgErased
	case strings.Contains(err.Error(), msgHolder):
		return ErrAccountHolder
	}
	return err
}

// Erasure is what Delete everything did.
type Erasure struct {
	Holder      bool // the account holder's request, for the whole org
	Deleted     bool // the org is deleted now (a holder alone), or the member is
	DeleteAfter time.Time
	// Notify: the other activated members, to be mailed that the org will be deleted.
	Notify []ErasureNotice
}

// ErasureNotice is one member to mail. Never logged.
type ErasureNotice struct{ Email, Name string }

// Erase is the Delete everything button for the signed-in user. It spends their step-up
// grant (hash, for this session and operation) only if it proved a second factor, all in
// the erasure's transaction. The account holder erases the org; any other member only
// themselves. audit is written in the org's log, or as a platform row when the org's rows
// go with it.
func (o *OrgStore) Erase(userID, sessionID, grantHash, operation string, audit *AuditEvent) (*Erasure, error) {
	tx, err := o.s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	res, err := tx.Exec(`UPDATE step_up_tokens SET used_at=? WHERE token_hash=? AND user_id=? AND session_id=? AND operation=? AND used_at IS NULL AND expires_at>?
 AND factor_method IN ('totp','push','webauthn')
 AND EXISTS(SELECT 1 FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=step_up_tokens.session_id AND s.expires_at>? AND u.org_id=? AND u.status='active')`,
		now, grantHash, userID, sessionID, operation, now, now, o.org)
	if err != nil {
		return nil, err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		if err == nil {
			err = ErrErasureStepUp
		}
		return nil, err
	}
	u, err := scanUser(tx.QueryRow(`SELECT `+userColumns+` FROM users WHERE org_id=? AND id=?`, o.org, userID))
	if err != nil {
		return nil, err
	}
	var kind, status, holder string
	err = tx.QueryRow(`SELECT kind,status,COALESCE(account_holder_user_id,'') FROM orgs WHERE id=?`, o.org).Scan(&kind, &status, &holder)
	if err != nil {
		return nil, err
	}
	if u == nil || u.Role != "user" || u.Pending || u.Status != "active" || status != "active" || (kind != "person" && kind != "household") {
		return nil, ErrErasureRefused
	}
	out := &Erasure{Holder: holder == userID}
	if !out.Holder {
		setAuditDetails(audit, map[string]any{"scope": "self"})
		if err := eraseUserTx(tx, o.org, u, audit, now); err != nil {
			return nil, err
		}
		out.Deleted = true
		return out, tx.Commit()
	}
	var others bool
	if err := tx.QueryRow(`SELECT `+otherLiveSQL("?", "?"), o.org, userID).Scan(&others); err != nil {
		return nil, err
	}
	if audit != nil {
		audit.TargetID, audit.TargetType = o.org, "org"
	}
	setAuditDetails(audit, map[string]any{"scope": "org", "orgId": o.org, "immediate": !others})
	if _, err := tx.Exec(`INSERT INTO org_erasures(org_id,holder_user_id,immediate,requested_at) VALUES(?,?,?,?)`, o.org, userID, !others, now); err != nil {
		return nil, erasureError(err)
	}
	if !others {
		if err := deleteOrgTx(tx, o.org, audit, now); err != nil {
			return nil, err
		}
		out.Deleted = true
		return out, tx.Commit()
	}
	rows, err := tx.Query(`SELECT email,display_name FROM users WHERE org_id=? AND id<>? AND status='active' AND NOT pending AND ends_at IS NULL AND email<>''`, o.org, userID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var n ErasureNotice
		if err := rows.Scan(&n.Email, &n.Name); err != nil {
			rows.Close()
			return nil, err
		}
		out.Notify = append(out.Notify, n)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	// The org stops as a suspension does: every grant of every member ends now.
	ids, err := scanStrings(tx.Query(`SELECT id FROM users WHERE org_id=?`, o.org))
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		if err := revokeUserAccessTx(tx, id, now); err != nil {
			return nil, err
		}
	}
	out.DeleteAfter = now.Add(erasureGrace).Truncate(time.Second)
	if _, err := tx.Exec(`UPDATE orgs SET status='deletion_scheduled',status_reason='',delete_after=?,revision=`+nextOrgRevisionSQL+`,updated_at=? WHERE id=?`,
		out.DeleteAfter.Unix(), now, o.org); err != nil {
		return nil, erasureError(err)
	}
	if err := queuePlatformEventTx(tx, o.org, "org.deletion_scheduled", "", now); err != nil {
		return nil, err
	}
	if err := recordAuditTx(tx, audit); err != nil {
		return nil, err
	}
	return out, tx.Commit()
}

func setAuditDetails(audit *AuditEvent, details map[string]any) {
	if audit != nil {
		b, _ := json.Marshal(details)
		audit.DetailsJSON = string(b)
	}
}

// ErasureScope is what the signed-in user's Delete everything would delete.
type ErasureScope struct {
	Holder       bool `json:"holder"`
	OtherMembers int  `json:"otherMembers"`
}

// ErasureScope answers for the button; ErrErasureRefused when it does not apply.
func (o *OrgStore) ErasureScope(userID string) (*ErasureScope, error) {
	u, err := o.GetUserByID(userID)
	if err != nil {
		return nil, err
	}
	var kind, status, holder string
	var others int
	err = o.s.db.QueryRow(`SELECT kind,status,COALESCE(account_holder_user_id,''),
 (SELECT COUNT(*) FROM users u WHERE u.org_id=orgs.id AND u.id<>? AND `+liveHolder("u")+`) FROM orgs WHERE id=?`, userID, o.org).Scan(&kind, &status, &holder, &others)
	if err != nil {
		return nil, err
	}
	if u == nil || u.Role != "user" || u.Pending || u.Status != "active" || status != "active" || (kind != "person" && kind != "household") {
		return nil, ErrErasureRefused
	}
	if holder != userID {
		return &ErasureScope{}, nil
	}
	return &ErasureScope{Holder: true, OtherMembers: others}, nil
}

// eraseUserTx deletes one member and tells every app to delete their data: user.erased
// to every enabled suite webhook, held or not (as deletion's fan-out), and user.deleted to
// generic SCIM and AD, which only disable. Every payload is the bare inactive user.
func eraseUserTx(tx *sql.Tx, org string, u *User, audit *AuditEvent, now time.Time) error {
	if err := offboardErasedTx(tx, org, u.ID, now); err != nil {
		return err
	}
	// Audit rows and alerts that name them go too: as actor or target, or by ID, username
	// or email anywhere in an audit row's details or an alert's text (a group change
	// records its members' usernames). The display name is not matched: a common name would
	// take other people's rows.
	for _, name := range slices.Compact(slices.Sorted(slices.Values([]string{u.ID, u.Username, u.Email}))) {
		if name == "" {
			continue
		}
		like := "%" + likePrefix(name)
		if _, err := tx.Exec(`DELETE FROM audit_events WHERE org_id=? AND (actor_id=? OR target_id=? OR details_json LIKE ? ESCAPE '\')`, org, name, name, like); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM alerts WHERE org_id=? AND (key=? OR title LIKE ? ESCAPE '\' OR summary LIKE ? ESCAPE '\')`, org, name, like, like); err != nil {
			return err
		}
	}
	// The audit row is written while the user still names the org.
	if err := recordAuditTx(tx, audit); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM users WHERE org_id=? AND id=?`, org, u.ID); err != nil {
		return erasureError(err)
	}
	if err := queuePlatformEventTx(tx, org, "org.member_changed", u.ID, now); err != nil {
		return err
	}
	return reconcileProvisioningTx(tx, now)
}

// offboardErasedTx ends a user's access, queuing the back-channel logouts owed, and tells
// every connector, then tombstones the subject. The provisioning and logout rows stay, as
// for any deleted user, so delivery and its evidence outlive the account.
func offboardErasedTx(tx *sql.Tx, org, userID string, now time.Time) error {
	if err := revokeUserAccessTx(tx, userID, now); err != nil {
		return err
	}
	rows, err := tx.Query(`SELECT id,system_type FROM paired_systems WHERE status<>'disabled' ORDER BY id`)
	if err != nil {
		return err
	}
	type system struct{ id, kind string }
	var systems []system
	for rows.Next() {
		var s system
		if err := rows.Scan(&s.id, &s.kind); err != nil {
			rows.Close()
			return err
		}
		systems = append(systems, s)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, s := range systems {
		d := desiredState{systemID: s.id, resourceID: userID, kind: "user", payload: scimInactivePayload(userID), deleted: true,
			erased: s.kind != "scim" && s.kind != "active_directory"}
		if err := queueDesiredStateTx(tx, d, now); err != nil {
			return err
		}
	}
	if err := tombstoneTx(tx, org, userID, now); err != nil {
		return err
	}
	// Delivered profiles hold the name and email. An attempt in flight keeps its payload:
	// held evidence is never rewritten.
	_, err = tx.Exec(`DELETE FROM account_sync_events WHERE org_id=? AND user_id=? AND status='delivered'`, org, userID)
	return err
}

// tombstoneTx lists a subject as erased, once.
func tombstoneTx(tx *sql.Tx, org, subject string, now time.Time) error {
	_, err := tx.Exec(`INSERT INTO erased_subjects(subject,org_id,revision,erased_at)
 SELECT ?,?,(SELECT COALESCE(MAX(revision),0)+1 FROM erased_subjects),? WHERE NOT EXISTS(SELECT 1 FROM erased_subjects WHERE subject=?)`, subject, org, now, subject)
	return err
}

// orgRowTables are the org-owned tables in the order deleteOrgTx empties them; derived
// rows cascade. orgKeptTables outlive the users, as they do any deleted user: queued
// removals and back-channel logouts, held delivery evidence and remote mappings, with
// opaque IDs and bare payloads only. TestDeleteOrgEmptiesEveryOrgTable holds both lists to
// the classification.
var (
	orgRowTables = []string{"group_memberships", "suite_groups", "directory_groups", "scim_connectors",
		"alerts", "audit_events", "org_apps", "users"}
	orgKeptTables = []string{"sync_delivery_attempts", "account_sync_events", "sync_resource_state", "scim_user_links", "logout_deliveries"}
)

// deleteOrgTx deletes every org row, leaving the orgs tombstone, and records it as a
// platform audit row (the org's own log goes with it). The org must be deletable: the
// orgs triggers refuse otherwise.
func deleteOrgTx(tx *sql.Tx, org string, audit *AuditEvent, now time.Time) error {
	ids, err := scanStrings(tx.Query(`SELECT id FROM users WHERE org_id=?`, org))
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := offboardErasedTx(tx, org, id, now); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`UPDATE orgs SET status='deleted',name='',account_holder_user_id=NULL,revision=`+nextOrgRevisionSQL+`,updated_at=? WHERE id=?`, now, org); err != nil {
		return erasureError(err)
	}
	counts := map[string]int64{}
	for _, t := range orgRowTables {
		res, err := tx.Exec(`DELETE FROM `+t+` WHERE org_id=?`, org)
		if err != nil {
			return err
		}
		if counts[t], err = res.RowsAffected(); err != nil {
			return err
		}
	}
	if err := reconcileProvisioningTx(tx, now); err != nil {
		return err
	}
	if err := queuePlatformEventTx(tx, org, "org.deleted", "", now); err != nil {
		return err
	}
	if audit == nil {
		return nil
	}
	details := map[string]any{}
	if audit.DetailsJSON != "" {
		if err := json.Unmarshal([]byte(audit.DetailsJSON), &details); err != nil {
			return err
		}
	}
	details["rows"] = counts
	b, err := json.Marshal(details)
	if err != nil {
		return err
	}
	// The users are gone, so the row has no org: a platform row naming the org by ID.
	audit.DetailsJSON = string(b)
	return recordAuditTx(tx, audit)
}

// queuePlatformEventTx queues an event to billing (tenancy design, "Events back to
// billing"). The body holds IDs and counts only.
func queuePlatformEventTx(tx *sql.Tx, org, typ, userID string, now time.Time) error {
	var billingRef, status string
	var revision, seats int64
	if err := tx.QueryRow(`SELECT COALESCE(billing_ref,''),status,revision,
 (SELECT COUNT(*) FROM users u WHERE u.org_id=orgs.id AND u.role='user' AND (u.status='active' OR u.pending))
 FROM orgs WHERE id=?`, org).Scan(&billingRef, &status, &revision, &seats); err != nil {
		return err
	}
	id := uuid.NewString()
	body := map[string]any{"event_id": id, "type": typ, "org_id": org, "billing_ref": billingRef, "revision": revision,
		"status": status, "seats_used": seats, "at": now.Unix()}
	if userID != "" {
		body["user_id"], body["change"] = userID, "removed"
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO platform_events(id,org_id,type,payload_json,status,next_attempt_at,created_at) VALUES(?,?,?,?,'queued',?,?)`, id, org, typ, string(payload), now, now)
	return err
}

// FinishDueErasures deletes the orgs whose holder asked and whose export window has
// passed. Each org is its own transaction; one that fails is retried on the next pass.
func (p *PlatformStore) FinishDueErasures() (int, error) {
	orgs, err := scanStrings(p.s.db.Query(`SELECT o.id FROM orgs o JOIN org_erasures e ON e.org_id=o.id
 WHERE o.status='deletion_scheduled' AND o.delete_after<unixepoch() ORDER BY o.id`))
	if err != nil {
		return 0, err
	}
	done := 0
	var errs []error
	for _, org := range orgs {
		err := p.s.auditedTx(nil, func(tx *sql.Tx) error {
			var holder string
			if err := tx.QueryRow(`SELECT e.holder_user_id FROM orgs o JOIN org_erasures e ON e.org_id=o.id WHERE o.id=? AND o.status='deletion_scheduled'`, org).Scan(&holder); err != nil {
				return err
			}
			details, _ := json.Marshal(map[string]any{"orgId": org})
			return deleteOrgTx(tx, org, &AuditEvent{ID: uuid.NewString(), ActorID: holder, Action: "org.erased", TargetID: org, TargetType: "org",
				Outcome: "success", DetailsJSON: string(details), CreatedAt: time.Now().UTC()}, time.Now().UTC())
		})
		switch {
		case errors.Is(err, sql.ErrNoRows): // another pass finished it first
		case err != nil:
			errs = append(errs, fmt.Errorf("org %s: %w", org, err))
		default:
			done++
		}
	}
	return done, errors.Join(errs...)
}

// ErasedSubject is one erased account, as GET /api/suite/erased lists it.
type ErasedSubject struct {
	Sub      string `json:"sub"`
	OrgID    string `json:"org_id"`
	Revision int64  `json:"revision"`
}

// SuiteErased lists the erased subjects of the orgs the client's app is told about, after
// revision since, at most limit.
func (p *PlatformStore) SuiteErased(clientID string, since int64, limit int) ([]ErasedSubject, error) {
	out := []ErasedSubject{}
	app, err := p.s.suiteAppID(clientID)
	if err != nil || app == "" {
		return out, err
	}
	rows, err := p.s.rdb.Query(`SELECT e.subject,e.org_id,e.revision FROM erased_subjects e JOIN orgs o ON o.id=e.org_id
 WHERE `+suiteOrgVisibleSQL+` AND e.revision>? ORDER BY e.revision LIMIT ?`, app, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var e ErasedSubject
		if err := rows.Scan(&e.Sub, &e.OrgID, &e.Revision); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
