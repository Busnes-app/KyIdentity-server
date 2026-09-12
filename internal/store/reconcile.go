package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

var ErrReconcileBusy = errors.New("a reconciliation job is already queued or running for this connector")

const reconcileAttempts = 3

// A reconciliation job lists what the target holds and compares it with desired state.
// One job per connector at a time; an interrupted run is re-claimed because repair only
// queues idempotent desired-state work, so a second pass has no duplicate effect.
func (s *Store) migrateReconcile() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, c := range []struct{ probe, ddl string }{
		{`SELECT COUNT(*) FROM pragma_table_info('paired_systems') WHERE name='reconcile_hours'`, `ALTER TABLE paired_systems ADD COLUMN reconcile_hours INTEGER NOT NULL DEFAULT 0`},
		{`SELECT COUNT(*) FROM pragma_table_info('sync_resource_state') WHERE name='observed'`, `ALTER TABLE sync_resource_state ADD COLUMN observed TEXT NOT NULL DEFAULT '';
 ALTER TABLE sync_resource_state ADD COLUMN observed_at DATETIME`},
		{`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='sync_reconcile_jobs'`, `CREATE TABLE sync_reconcile_jobs (
 id TEXT PRIMARY KEY,
 system_id TEXT NOT NULL REFERENCES paired_systems(id) ON DELETE CASCADE,
 kind TEXT NOT NULL CHECK (kind IN ('preview','repair')),
 status TEXT NOT NULL CHECK (status IN ('queued','running','done','failed')),
 requested_by TEXT NOT NULL DEFAULT '', claim_token TEXT NOT NULL DEFAULT '',
 attempts INTEGER NOT NULL DEFAULT 0, created_at DATETIME NOT NULL,
 lease_until DATETIME, started_at DATETIME, finished_at DATETIME,
 result_json TEXT NOT NULL DEFAULT '', error TEXT NOT NULL DEFAULT '');
 CREATE INDEX sync_reconcile_jobs_system ON sync_reconcile_jobs(system_id,created_at)`},
	} {
		var n int
		if err = tx.QueryRow(c.probe).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			if _, err = tx.Exec(c.ddl); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

type ReconcileJob struct {
	ID          string          `json:"id"`
	SystemID    string          `json:"systemId"`
	Kind        string          `json:"kind"`
	Status      string          `json:"status"`
	RequestedBy string          `json:"requestedBy"`
	ClaimToken  string          `json:"-"`
	Attempts    int             `json:"attempts"`
	CreatedAt   time.Time       `json:"createdAt"`
	LeaseUntil  *time.Time      `json:"-"`
	StartedAt   *time.Time      `json:"startedAt,omitempty"`
	FinishedAt  *time.Time      `json:"finishedAt,omitempty"`
	Result      json.RawMessage `json:"result,omitempty"`
	Error       string          `json:"error,omitempty"`
}

const reconcileJobColumns = `id,system_id,kind,status,requested_by,claim_token,attempts,created_at,lease_until,started_at,finished_at,result_json,error`

func scanReconcileJob(row interface{ Scan(...any) error }) (*ReconcileJob, error) {
	j := &ReconcileJob{}
	var result string
	var lease, started, finished sql.NullTime
	err := row.Scan(&j.ID, &j.SystemID, &j.Kind, &j.Status, &j.RequestedBy, &j.ClaimToken, &j.Attempts, &j.CreatedAt, &lease, &started, &finished, &result, &j.Error)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	for src, dst := range map[*sql.NullTime]**time.Time{&lease: &j.LeaseUntil, &started: &j.StartedAt, &finished: &j.FinishedAt} {
		if src.Valid {
			t := src.Time
			*dst = &t
		}
	}
	if result != "" {
		j.Result = json.RawMessage(result)
	}
	return j, nil
}

func (s *Store) CreateReconcileJob(systemID, kind, requestedBy string, audit *AuditEvent) (*ReconcileJob, error) {
	if kind != "preview" && kind != "repair" {
		return nil, errors.New("kind must be preview or repair")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var exists, busy bool
	if err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM paired_systems WHERE id=? AND status<>'disabled'),
 EXISTS(SELECT 1 FROM sync_reconcile_jobs WHERE system_id=? AND status IN ('queued','running'))`, systemID, systemID).Scan(&exists, &busy); err != nil {
		return nil, err
	}
	if !exists {
		return nil, sql.ErrNoRows
	}
	if busy {
		return nil, ErrReconcileBusy
	}
	job := &ReconcileJob{ID: uuid.NewString(), SystemID: systemID, Kind: kind, Status: "queued", RequestedBy: requestedBy, CreatedAt: time.Now().UTC()}
	if _, err = tx.Exec(`INSERT INTO sync_reconcile_jobs(id,system_id,kind,status,requested_by,created_at) VALUES(?,?,?,?,?,?)`, job.ID, job.SystemID, job.Kind, job.Status, job.RequestedBy, job.CreatedAt); err != nil {
		return nil, err
	}
	// Keep a bounded history per connector.
	if _, err = tx.Exec(`DELETE FROM sync_reconcile_jobs WHERE system_id=? AND status IN ('done','failed') AND id NOT IN (SELECT id FROM sync_reconcile_jobs WHERE system_id=? ORDER BY created_at DESC LIMIT 20)`, systemID, systemID); err != nil {
		return nil, err
	}
	if err = recordAuditTx(tx, audit); err != nil {
		return nil, err
	}
	return job, tx.Commit()
}

// ScheduleReconcileJobs queues a repair for every connector whose interval has elapsed.
func (s *Store) ScheduleReconcileJobs(now time.Time) error {
	rows, err := s.db.Query(`SELECT s.id,s.reconcile_hours,(SELECT created_at FROM sync_reconcile_jobs j WHERE j.system_id=s.id ORDER BY created_at DESC LIMIT 1)
 FROM paired_systems s WHERE s.reconcile_hours>0 AND s.system_type='scim' AND s.status<>'disabled'
 AND NOT EXISTS(SELECT 1 FROM sync_reconcile_jobs j WHERE j.system_id=s.id AND j.status IN ('queued','running'))`)
	if err != nil {
		return err
	}
	var due []string
	for rows.Next() {
		var id string
		var hours int
		var last sql.NullTime
		if err := rows.Scan(&id, &hours, &last); err != nil {
			rows.Close()
			return err
		}
		if !last.Valid || !last.Time.Add(time.Duration(hours)*time.Hour).After(now) {
			due = append(due, id)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range due {
		audit := &AuditEvent{ID: uuid.NewString(), ActorUsername: "schedule", Action: "admin.reconcile_requested", TargetID: id, TargetType: "system", Outcome: "success", DetailsJSON: `{"kind":"repair","requestedBy":"schedule"}`}
		if _, err := s.CreateReconcileJob(id, "repair", "schedule", audit); err != nil && !errors.Is(err, ErrReconcileBusy) {
			return err
		}
	}
	return nil
}

// ClaimReconcileJob takes the oldest queued job, or a running one whose lease expired.
// A job interrupted repeatedly is failed rather than retried forever.
func (s *Store) ClaimReconcileJob(lease time.Duration) (*ReconcileJob, error) {
	now := time.Now().UTC()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`UPDATE sync_reconcile_jobs SET status='failed',error='interrupted repeatedly',finished_at=?,lease_until=NULL,claim_token=''
 WHERE status='running' AND lease_until<=? AND attempts>=?`, now, now, reconcileAttempts); err != nil {
		return nil, err
	}
	token := uuid.NewString()
	job, err := scanReconcileJob(tx.QueryRow(`UPDATE sync_reconcile_jobs SET status='running',claim_token=?,lease_until=?,started_at=COALESCE(started_at,?),attempts=attempts+1
 WHERE id=(SELECT id FROM sync_reconcile_jobs WHERE (status='queued' OR (status='running' AND lease_until<=?)) AND attempts<? ORDER BY created_at LIMIT 1)
 RETURNING `+reconcileJobColumns, token, now.Add(lease), now, now, reconcileAttempts))
	if err != nil {
		return nil, err
	}
	return job, tx.Commit()
}

// FinishReconcileJob records the outcome and, for a repair, an audit event carrying the
// counts of what it queued, in one transaction. Only local counts and fixed reasons are
// written; remote text never reaches the audit log.
func (s *Store) FinishReconcileJob(job *ReconcileJob, report *DriftReport, runErr error) error {
	status, message := "done", ""
	if runErr != nil {
		status, message = "failed", runErr.Error()
	}
	body := ""
	if report != nil {
		b, err := json.Marshal(report)
		if err != nil {
			return err
		}
		body = string(b)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := tx.Exec(`UPDATE sync_reconcile_jobs SET status=?,result_json=?,error=?,finished_at=?,lease_until=NULL,claim_token='' WHERE id=? AND claim_token=?`,
		status, body, message, time.Now().UTC(), job.ID, job.ClaimToken)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n != 1 {
		return errors.New("reconciliation job changed")
	}
	if job.Kind == "repair" {
		details := map[string]any{"jobId": job.ID, "requestedBy": job.RequestedBy, "status": status}
		outcome := "success"
		switch {
		case runErr != nil:
			outcome, details["reason"] = "failure", "job failed"
		case report == nil || !report.Supported:
			details["reason"] = "verification unsupported"
		case !report.Complete:
			details["reason"] = "listing incomplete"
		}
		if report != nil {
			for k, v := range map[string]int{"listedUsers": report.ListedUsers, "unrelated": report.Unrelated, "missing": report.MissingCount, "stale": report.StaleCount, "orphaned": report.OrphanedCount, "groupsRequeued": report.GroupsRequeued, "groupsOrphaned": report.GroupsOrphaned, "mappingConflicts": report.MappingConflicts} {
				details[k] = v
			}
			details["repaired"] = report.Repaired
		}
		b, err := json.Marshal(details)
		if err != nil {
			return err
		}
		if err = recordAuditTx(tx, &AuditEvent{ID: uuid.NewString(), ActorUsername: job.RequestedBy, Action: "admin.reconcile_completed", TargetID: job.SystemID, TargetType: "system", Outcome: outcome, DetailsJSON: string(b)}); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ListReconcileJobs(systemID string, limit int) ([]ReconcileJob, error) {
	rows, err := s.db.Query(`SELECT `+reconcileJobColumns+` FROM sync_reconcile_jobs WHERE system_id=? ORDER BY created_at DESC LIMIT ?`, systemID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	jobs := []ReconcileJob{}
	for rows.Next() {
		j, err := scanReconcileJob(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, *j)
	}
	return jobs, rows.Err()
}

// RemoteAccount is what a listing observed at the target for one user resource.
type RemoteAccount struct {
	ID, ExternalID, UserName, DisplayName, Email string
	Active                                       bool
}

// Bounded trims every target-supplied text field to RemoteTextLimit runes. IDs are
// never trimmed: a truncated identifier would be stored and later resolved as a
// different resource, so the listing rejects overlong ones instead.
func (a RemoteAccount) Bounded() RemoteAccount {
	a.UserName, a.DisplayName, a.Email = boundRemoteText(a.UserName), boundRemoteText(a.DisplayName), boundRemoteText(a.Email)
	return a
}

type RemoteGroup struct {
	ID, ExternalID, DisplayName string
}

func (g RemoteGroup) Bounded() RemoteGroup {
	g.DisplayName = boundRemoteText(g.DisplayName)
	return g
}

// RemoteListing is one complete or partial read of the target. Complete is false when a
// page failed or totals disagreed; nothing destructive is inferred from such a run.
type RemoteListing struct {
	Supported    bool
	Complete     bool
	Users        []RemoteAccount
	Groups       []RemoteGroup
	GroupsListed bool
}

type DriftEntry struct {
	ID       string `json:"id"`
	Username string `json:"username,omitempty"`
	Reason   string `json:"reason"`
}

type DriftReport struct {
	Supported      bool         `json:"supported"`
	Complete       bool         `json:"complete"`
	Repaired       bool         `json:"repaired"`
	ListedUsers    int          `json:"listedUsers"`
	Unrelated      int          `json:"unrelated"`
	MissingCount   int          `json:"missingCount"`
	StaleCount     int          `json:"staleCount"`
	OrphanedCount  int          `json:"orphanedCount"`
	Missing        []DriftEntry `json:"missing"`
	Stale          []DriftEntry `json:"stale"`
	Orphaned       []DriftEntry `json:"orphaned"`
	GroupsRequeued int          `json:"groupsRequeued"`
	GroupsOrphaned int          `json:"groupsOrphaned"`
	// MappingConflicts counts managed resources whose target ID disagrees with the stored
	// mapping; they are observed but never re-linked or written through.
	MappingConflicts int `json:"mappingConflicts"`
	// ListingError explains an incomplete run without remote text or credentials.
	ListingError string `json:"listingError,omitempty"`
}

const driftSample = 100

// RemoteTextLimit bounds any target-supplied text kept in memory or in a report.
const RemoteTextLimit = 128

func boundRemoteText(s string) string {
	if utf8.RuneCountInString(s) <= RemoteTextLimit {
		return s
	}
	runes := []rune(s)
	return string(runes[:RemoteTextLimit])
}

func appendDrift(list *[]DriftEntry, count *int, e DriftEntry) {
	*count++
	if len(*list) < driftSample {
		*list = append(*list, e)
	}
}

// ReconcileDrift compares a listing with desired state, records what was observed, and
// when repair is set queues the desired state for every managed account that differs.
// Only accounts this connector manages (externalId naming a local user, a state row or a
// remote link) are compared; anything else at the target is left alone. Deactivation and
// absence are only ever inferred from a complete listing.
func (s *Store) ReconcileDrift(systemID string, listing RemoteListing, repair bool) (*DriftReport, error) {
	report := &DriftReport{Supported: listing.Supported, Complete: listing.Supported && listing.Complete, Missing: []DriftEntry{}, Stale: []DriftEntry{}, Orphaned: []DriftEntry{}}
	now := time.Now().UTC()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var exists bool
	if err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM paired_systems WHERE id=?)`, systemID).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, sql.ErrNoRows
	}
	if !listing.Supported {
		if _, err = tx.Exec(`UPDATE sync_resource_state SET observed='unsupported',observed_at=? WHERE system_id=?`, now, systemID); err != nil {
			return nil, err
		}
		return report, tx.Commit()
	}
	desired := map[string]*User{}
	rows, err := tx.Query(`SELECT `+userColumns+` FROM users WHERE id IN (SELECT e.user_id FROM effective_app_access e JOIN app_registry a ON a.id=e.app_id WHERE a.system_id=?)`, systemID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		desired[u.ID] = u
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	wantedGroups := map[string]bool{}
	var groups []desiredGroup
	if listing.GroupsListed {
		if groups, err = desiredGroupsTx(tx, systemID); err != nil {
			return nil, err
		}
		for _, g := range groups {
			wantedGroups[g.groupID] = true
		}
	}
	// A resource is managed only through a relationship this connector already has:
	// effective access, a held desired-state row, or a stored mapping. A target cannot
	// name an arbitrary local user and thereby become its holder.
	managed := func(kind, id string) (bool, error) {
		if (kind == "user" && desired[id] != nil) || (kind == "group" && wantedGroups[id]) {
			return true, nil
		}
		var known bool
		err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM sync_resource_state WHERE system_id=? AND resource_id=? AND kind=?)
 OR EXISTS(SELECT 1 FROM scim_user_links WHERE system_id=? AND local_id=? AND kind=?)`, systemID, id, kind, systemID, id, kind).Scan(&known)
		return known, err
	}
	// Mappings are only written by repair. A target ID that disagrees with a stored
	// mapping is observed and counted; nothing is written through it.
	link := func(kind, localID, remoteID string) (bool, error) {
		if remoteID == "" || remoteID == "." || remoteID == ".." {
			return false, errors.New("invalid remote ID in listing")
		}
		var stored string
		err := tx.QueryRow(`SELECT remote_id FROM scim_user_links WHERE system_id=? AND local_id=? AND kind=?`, systemID, localID, kind).Scan(&stored)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return false, err
		}
		if stored != "" && stored != remoteID {
			return false, nil
		}
		r, err := tx.Exec(`INSERT INTO scim_user_links(system_id,local_id,kind,remote_id) VALUES(?,?,?,?)
 ON CONFLICT(system_id,local_id) DO UPDATE SET remote_id=excluded.remote_id WHERE kind=excluded.kind AND remote_id=''`, systemID, localID, kind, remoteID)
		if err != nil {
			return false, err
		}
		n, _ := r.RowsAffected()
		return n == 1 || stored == remoteID, nil
	}
	observe := func(kind, id, state string) error {
		_, err := tx.Exec(`UPDATE sync_resource_state SET observed=?,observed_at=? WHERE system_id=? AND resource_id=? AND kind=?`, state, now, systemID, id, kind)
		return err
	}
	// A managed account with no desired-state row (pre-upgrade delivery, or a resource
	// found only at the target) is recorded as held so a disable can be queued for it.
	hold := func(kind, id string) error {
		_, err := tx.Exec(`INSERT INTO sync_resource_state(system_id,resource_id,kind,active,provisioned,revision) VALUES(?,?,?,1,1,0) ON CONFLICT(system_id,resource_id) DO UPDATE SET provisioned=1`, systemID, id, kind)
		return err
	}
	seen := map[string]bool{}
	listedIDs := map[string]bool{}
	report.ListedUsers = len(listing.Users)
	for _, remote := range listing.Users {
		listedIDs[remote.ID] = true
		known := false
		if remote.ExternalID != "" {
			if known, err = managed("user", remote.ExternalID); err != nil {
				return nil, err
			}
		}
		if !known {
			report.Unrelated++
			continue
		}
		seen[remote.ExternalID] = true
		state := "present_inactive"
		if remote.Active {
			state = "present_active"
		}
		linked := true
		if repair {
			if linked, err = link("user", remote.ExternalID, remote.ID); err != nil {
				return nil, err
			}
			if !linked {
				report.MappingConflicts++
			}
		}
		u, wanted := desired[remote.ExternalID]
		switch {
		case !linked:
			// Written through a disputed mapping, a repair could reach the wrong account.
		case wanted && (!remote.Active || remote.UserName != u.Username || remote.DisplayName != u.DisplayName || remote.Email != u.Email):
			appendDrift(&report.Stale, &report.StaleCount, DriftEntry{ID: u.ID, Username: u.Username, Reason: "attributes differ"})
			if repair {
				payload, err := scimUserPayload(u, true)
				if err != nil {
					return nil, err
				}
				if err = queueDesiredStateTx(tx, desiredState{systemID: systemID, resourceID: u.ID, kind: "user", active: true, payload: payload, force: true}, now); err != nil {
					return nil, err
				}
			}
		case !wanted && remote.Active && listing.Complete:
			// The report names the local account where one exists; only a deleted
			// user's entry falls back to bounded remote text.
			local, err := scanUser(tx.QueryRow(`SELECT `+userColumns+` FROM users WHERE id=?`, remote.ExternalID))
			if err != nil {
				return nil, err
			}
			entry := DriftEntry{ID: remote.ExternalID, Username: boundRemoteText(remote.UserName), Reason: "active without access"}
			if local != nil {
				entry.Username = local.Username
			}
			appendDrift(&report.Orphaned, &report.OrphanedCount, entry)
			if repair {
				if err = hold("user", remote.ExternalID); err != nil {
					return nil, err
				}
				payload := scimInactivePayload(remote.ExternalID)
				if local != nil {
					if payload, err = scimUserPayload(local, false); err != nil {
						return nil, err
					}
				}
				if err = queueDesiredStateTx(tx, desiredState{systemID: systemID, resourceID: remote.ExternalID, kind: "user", active: false, payload: payload}, now); err != nil {
					return nil, err
				}
			}
		}
		if err = observe("user", remote.ExternalID, state); err != nil {
			return nil, err
		}
	}
	if listing.Complete {
		for id, u := range desired {
			if seen[id] {
				continue
			}
			appendDrift(&report.Missing, &report.MissingCount, DriftEntry{ID: id, Username: u.Username, Reason: "absent at target"})
			if repair {
				// A mapping to an ID the complete listing did not contain is dead; clearing it
				// lets delivery look the account up by externalId and create it again.
				var remoteID string
				if err := tx.QueryRow(`SELECT remote_id FROM scim_user_links WHERE system_id=? AND local_id=? AND kind='user'`, systemID, id).Scan(&remoteID); err != nil && !errors.Is(err, sql.ErrNoRows) {
					return nil, err
				}
				if remoteID != "" && !listedIDs[remoteID] {
					if _, err := tx.Exec(`DELETE FROM scim_user_links WHERE system_id=? AND local_id=? AND kind='user'`, systemID, id); err != nil {
						return nil, err
					}
				}
				payload, err := scimUserPayload(u, true)
				if err != nil {
					return nil, err
				}
				if err = queueDesiredStateTx(tx, desiredState{systemID: systemID, resourceID: id, kind: "user", active: true, payload: payload, force: true}, now); err != nil {
					return nil, err
				}
			}
		}
		// Every held account the listing did not show is absent.
		if _, err = tx.Exec(`UPDATE sync_resource_state SET observed='absent',observed_at=? WHERE system_id=? AND kind='user' AND (observed_at IS NULL OR observed_at<?)`, now, systemID, now); err != nil {
			return nil, err
		}
	}
	if listing.GroupsListed && listing.Complete {
		for _, g := range groups {
			if repair {
				hash, err := groupMembersHashTx(tx, g)
				if err != nil {
					return nil, err
				}
				if err = queueDesiredStateTx(tx, desiredState{systemID: systemID, resourceID: g.groupID, kind: "group", active: true, payload: scimGroupPayload(g.groupID), members: hash, force: true}, now); err != nil {
					return nil, err
				}
			}
			report.GroupsRequeued++
		}
		for _, remote := range listing.Groups {
			if remote.ExternalID == "" || wantedGroups[remote.ExternalID] {
				continue
			}
			known, err := managed("group", remote.ExternalID)
			if err != nil {
				return nil, err
			}
			if !known {
				continue
			}
			report.GroupsOrphaned++
			if repair {
				linked, err := link("group", remote.ExternalID, remote.ID)
				if err != nil {
					return nil, err
				}
				if !linked {
					report.MappingConflicts++
					continue
				}
				if err = hold("group", remote.ExternalID); err != nil {
					return nil, err
				}
				if err = queueDesiredStateTx(tx, desiredState{systemID: systemID, resourceID: remote.ExternalID, kind: "group", active: false, payload: scimGroupPayload(remote.ExternalID)}, now); err != nil {
					return nil, err
				}
			}
		}
	}
	report.Repaired = repair && listing.Complete
	return report, tx.Commit()
}

type ProvisioningEvent struct {
	Type        string     `json:"type"`
	Status      string     `json:"status"`
	Error       string     `json:"error,omitempty"`
	Attempts    int        `json:"attempts"`
	NextAttempt *time.Time `json:"nextAttemptAt,omitempty"`
	UpdatedAt   time.Time  `json:"updatedAt"`
}

// ProvisioningRow separates what the directory wants (Desired), what was last queued
// (Recorded), what the receiver acknowledged (Acknowledged) and what a listing saw (Observed).
type ProvisioningRow struct {
	UserID       string             `json:"userId"`
	Username     string             `json:"username"`
	DisplayName  string             `json:"displayName"`
	Desired      bool               `json:"desired"`
	Recorded     bool               `json:"recorded"`
	Acknowledged bool               `json:"acknowledged"`
	Observed     string             `json:"observed"`
	ObservedAt   *time.Time         `json:"observedAt,omitempty"`
	Revision     int                `json:"revision"`
	Blocked      bool               `json:"blocked"`
	LastEvent    *ProvisioningEvent `json:"lastEvent,omitempty"`
}

func (s *Store) ListProvisioningState(systemID, query string, limit, offset int) ([]ProvisioningRow, int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	var exists bool
	if err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM paired_systems WHERE id=?)`, systemID).Scan(&exists); err != nil {
		return nil, 0, err
	}
	if !exists {
		return nil, 0, sql.ErrNoRows
	}
	from := ` FROM users u LEFT JOIN sync_resource_state st ON st.system_id=? AND st.resource_id=u.id AND st.kind='user'
 LEFT JOIN account_sync_events ev ON ev.id=(SELECT id FROM account_sync_events x WHERE x.system_id=? AND x.user_id=u.id ORDER BY x.rowid DESC LIMIT 1)
 WHERE (st.resource_id IS NOT NULL OR EXISTS(SELECT 1 FROM effective_app_access e JOIN app_registry a ON a.id=e.app_id WHERE a.system_id=? AND e.user_id=u.id))
 AND (instr(lower(u.username),lower(?))>0 OR instr(lower(u.display_name),lower(?))>0)`
	var total int
	if err = tx.QueryRow(`SELECT COUNT(*)`+from, systemID, systemID, systemID, query, query).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := tx.Query(`SELECT u.id,u.username,u.display_name,
 EXISTS(SELECT 1 FROM effective_app_access e JOIN app_registry a ON a.id=e.app_id WHERE a.system_id=? AND e.user_id=u.id),
 COALESCE(st.active,0),COALESCE(st.provisioned,0),COALESCE(st.observed,''),st.observed_at,COALESCE(st.revision,0),
 EXISTS(SELECT 1 FROM sync_delivery_attempts d WHERE d.system_id=? AND d.user_id=u.id),
 ev.event_type,ev.status,ev.last_error,ev.attempts,ev.next_attempt_at,ev.updated_at`+from+
		` ORDER BY u.username COLLATE NOCASE,u.id LIMIT ? OFFSET ?`, systemID, systemID, systemID, systemID, systemID, query, query, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	result := []ProvisioningRow{}
	for rows.Next() {
		var r ProvisioningRow
		var observedAt sql.NullTime
		var evType, evStatus, evError sql.NullString
		var evAttempts sql.NullInt64
		var evNext, evUpdated sql.NullTime
		if err = rows.Scan(&r.UserID, &r.Username, &r.DisplayName, &r.Desired, &r.Recorded, &r.Acknowledged, &r.Observed, &observedAt, &r.Revision, &r.Blocked,
			&evType, &evStatus, &evError, &evAttempts, &evNext, &evUpdated); err != nil {
			return nil, 0, err
		}
		if observedAt.Valid {
			t := observedAt.Time
			r.ObservedAt = &t
		}
		if evType.Valid {
			r.LastEvent = &ProvisioningEvent{Type: evType.String, Status: evStatus.String, Error: evError.String, Attempts: int(evAttempts.Int64), UpdatedAt: evUpdated.Time}
			if evNext.Valid {
				t := evNext.Time
				r.LastEvent.NextAttempt = &t
			}
		}
		result = append(result, r)
	}
	return result, total, rows.Err()
}

// RetryProvisioning re-queues one user's current desired state, superseding exhausted work.
func (s *Store) RetryProvisioning(systemID, userID string, audit *AuditEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	u, err := scanUser(tx.QueryRow(`SELECT `+userColumns+` FROM users WHERE id=?`, userID))
	if err != nil {
		return err
	}
	var desired, exists, held bool
	if err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM effective_app_access e JOIN app_registry a ON a.id=e.app_id WHERE a.system_id=? AND e.user_id=?),
 EXISTS(SELECT 1 FROM paired_systems WHERE id=? AND status<>'disabled'),
 EXISTS(SELECT 1 FROM sync_resource_state WHERE system_id=? AND resource_id=? AND kind='user')`, systemID, userID, systemID, systemID, userID).Scan(&desired, &exists, &held); err != nil {
		return err
	}
	// Nothing to send for a user the connector neither wants nor holds.
	if !exists || (!desired && !held) {
		return sql.ErrNoRows
	}
	now := time.Now().UTC()
	payload := scimInactivePayload(userID)
	if u != nil {
		if payload, err = scimUserPayload(u, desired); err != nil {
			return err
		}
	}
	if err = queueDesiredStateTx(tx, desiredState{systemID: systemID, resourceID: userID, kind: "user", active: desired, payload: payload, force: desired}, now); err != nil {
		return err
	}
	if err = recordAuditTx(tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}
