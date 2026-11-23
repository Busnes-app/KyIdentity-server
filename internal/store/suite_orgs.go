package store

import (
	"database/sql"
	"encoding/json"
	"errors"
)

// nextOrgRevisionSQL is the revision every org write takes (tenancy build plan PR 4 and 6):
// one past the highest of any org, so revisions order every org change on the install and
// GET /api/suite/orgs?since= finds each one. Writes are serialised (one SQLite writer, one
// Postgres advisory lock), so two never take the same value.
const nextOrgRevisionSQL = `(SELECT COALESCE(MAX(revision),0)+1 FROM orgs)`

// suiteOrgVisibleSQL: the orgs a suite app (app_registry row ?) is told about: every org
// with all apps, every org with an org_apps row for the app, enabled or not, so the app
// learns it was turned off, and every deleted org, whose org_apps rows went with it, so
// the app learns to drop its data. Never the single-tenant default org, which a
// multi-tenant install does not have. Needs orgs o.
const suiteOrgVisibleSQL = `(o.kind<>'default' AND (o.all_apps OR o.status='deleted' OR EXISTS(SELECT 1 FROM org_apps x WHERE x.org_id=o.id AND x.app_id=?)))`

// SuiteOrg is one org as GET /api/suite/orgs lists it to an app. Enabled and Quotas are
// that app's only.
type SuiteOrg struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	Revision int64  `json:"revision"`
	// HomeRegion is where every multi-region app keeps the org (tenancy design, "Home region").
	HomeRegion string          `json:"home_region"`
	Enabled    bool            `json:"enabled"`
	Quotas     json.RawMessage `json:"quotas"`
	// Storage is a customer org's pool (Org storage pool); absent for the staff org.
	Storage *SuiteStorage `json:"storage,omitempty"`
}

// SuiteStorage is the org's pool and when its usage passed it (unix seconds, null while
// within it).
type SuiteStorage struct {
	PoolBytes int64  `json:"pool_bytes"`
	OverSince *int64 `json:"over_since"`
}

// suiteAppID is the app_registry row of an OAuth client, "" when it has none.
func (s *Store) suiteAppID(clientID string) (string, error) {
	var id string
	err := s.rdb.QueryRow(`SELECT id FROM app_registry WHERE client_id=?`, clientID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}

// SuiteOrgs lists the orgs the client's app is told about, ordered by (revision, id) after
// the cursor (afterRevision, afterID), or with afterID "" after revision afterRevision (since). At most limit rows.
func (p *PlatformStore) SuiteOrgs(clientID string, afterRevision int64, afterID string, limit int) ([]SuiteOrg, error) {
	app, err := p.s.suiteAppID(clientID)
	if err != nil || app == "" {
		return []SuiteOrg{}, err
	}
	rows, err := p.s.rdb.Query(`SELECT o.id,o.status,o.revision,o.home_region,
 (o.status<>'deleted' AND (o.all_apps OR COALESCE(oa.enabled,FALSE))),COALESCE(oa.quotas_json,'{}'),
 o.kind,o.storage_bytes,o.storage_per_seat_bytes,o.max_seats,o.storage_over_since
 FROM orgs o LEFT JOIN org_apps oa ON oa.org_id=o.id AND oa.app_id=?
 WHERE `+suiteOrgVisibleSQL+` AND (o.revision>? OR ?<>'' AND o.revision=? AND o.id>?)
 ORDER BY o.revision,o.id LIMIT ?`, app, app, afterRevision, afterID, afterRevision, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SuiteOrg{}
	for rows.Next() {
		var o SuiteOrg
		var quotas, kind string
		var storage, perSeat, seats int64
		var over sql.NullInt64
		if err := rows.Scan(&o.ID, &o.Status, &o.Revision, &o.HomeRegion, &o.Enabled, &quotas, &kind, &storage, &perSeat, &seats, &over); err != nil {
			return nil, err
		}
		o.Quotas = json.RawMessage(quotas)
		if kind == customerKind {
			o.Storage = &SuiteStorage{PoolBytes: PoolBytes(storage, perSeat, seats)}
			if over.Valid {
				o.Storage.OverSince = &over.Int64
			}
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// SuiteOrg is the org named by a suite call's org_id, when the client's app is told about
// it (as SuiteOrgs). The org comes from the orgs row, never from the caller.
func (s *Store) SuiteOrg(clientID, orgID string) (OrgID, bool, error) {
	app, err := s.suiteAppID(clientID)
	if err != nil || app == "" {
		return OrgID{}, false, err
	}
	var id string
	err = s.rdb.QueryRow(`SELECT o.id FROM orgs o WHERE o.id=? AND `+suiteOrgVisibleSQL, orgID, app).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return OrgID{}, false, nil
	}
	return OrgID{id}, err == nil, err
}
