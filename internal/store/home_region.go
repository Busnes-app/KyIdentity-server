package store

import (
	"database/sql"
	"encoding/json"
	"regexp"
)

// Home region (tenancy design, "Home region"). Each org lives in one region of every
// multi-region app; orgs.home_region names it, set at provisioning and never changed.
// client_region_origins gives each regioned app its URL per region.

// HomeRegionLocal is the region of the default and staff orgs, and of every org created
// before home regions: what a single-region app assumes.
const HomeRegionLocal = "local"

// MaxClientRegions bounds one client's region map.
const MaxClientRegions = 32

var homeRegionPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)

// ValidHomeRegion reports whether s is a home region slug. homeRegionCheck* say the same
// in SQL (TestHomeRegion holds them together).
func ValidHomeRegion(s string) bool { return homeRegionPattern.MatchString(s) }

// SQLite has no regular expressions: GLOB for the first character and the alphabet.
const (
	homeRegionCheckSQLite   = `CHECK (length(home_region) BETWEEN 2 AND 32 AND home_region GLOB '[a-z]*' AND home_region NOT GLOB '*[^a-z0-9-]*')`
	homeRegionCheckPostgres = `CHECK (home_region ~ '^[a-z][a-z0-9-]{1,31}$')`
	msgHomeRegionChanged    = "home_region cannot change"
)

var homeRegionTrigger = tenancyTrigger{"orgs_home_region_immutable", "BEFORE UPDATE OF home_region", "orgs", "", msgHomeRegionChanged}

const homeRegionChanged = `NEW.home_region IS DISTINCT FROM OLD.home_region`

const clientRegionOriginsSQL = `CREATE TABLE IF NOT EXISTS client_region_origins (
 client_id TEXT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
 region TEXT NOT NULL, origin TEXT NOT NULL, PRIMARY KEY(client_id, region));`

func migrateHomeRegion(tx *sql.Tx) error {
	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM pragma_table_info('orgs') WHERE name='home_region'`).Scan(&n); err != nil {
		return err
	}
	stmts := clientRegionOriginsSQL + "\n" + sqliteTriggerSQL(homeRegionTrigger, homeRegionChanged)
	if n == 0 {
		// A column default cannot be dropped on SQLite, which is single-tenant only (D2).
		stmts = `ALTER TABLE orgs ADD COLUMN home_region TEXT NOT NULL DEFAULT '` + HomeRegionLocal + `' ` + homeRegionCheckSQLite + ";\n" + stmts
	}
	_, err := tx.Exec(stmts)
	return err
}

// migrateHomeRegionPostgres backfills local, then drops the default so every org insert
// names its region.
func migrateHomeRegionPostgres(tx *sql.Tx) error {
	_, err := tx.Exec(`ALTER TABLE orgs ADD COLUMN home_region TEXT NOT NULL DEFAULT '` + HomeRegionLocal + `' ` + homeRegionCheckPostgres + `;
ALTER TABLE orgs ALTER COLUMN home_region DROP DEFAULT;
` + clientRegionOriginsSQL + "\n" + pgTriggerSQL(homeRegionTrigger, homeRegionChanged))
	return err
}

// HomeRegion is the org's home region.
func (o *OrgStore) HomeRegion() (string, error) {
	var region string
	err := o.s.rdb.QueryRow(`SELECT home_region FROM orgs WHERE id=?`, o.org).Scan(&region)
	return region, err
}

// ClientRegionOrigins is the client's region map, {region: origin}; empty for an app with
// one URL.
func (s *Store) ClientRegionOrigins(clientID string) (map[string]string, error) {
	rows, err := s.rdb.Query(`SELECT region,origin FROM client_region_origins WHERE client_id=?`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var region, origin string
		if err := rows.Scan(&region, &origin); err != nil {
			return nil, err
		}
		out[region] = origin
	}
	return out, rows.Err()
}

// OrgRegionOrigins maps every regioned client to its origin for the org's home region,
// "" when it has none there (the app does not serve the org). Unregioned clients are absent.
func (s *Store) OrgRegionOrigins(org OrgID) (map[string]string, error) {
	rows, err := s.rdb.Query(`SELECT r.client_id, COALESCE(MAX(CASE WHEN r.region=o.home_region THEN r.origin END),'')
 FROM client_region_origins r JOIN orgs o ON o.id=? GROUP BY r.client_id`, org.id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var client, origin string
		if err := rows.Scan(&client, &origin); err != nil {
			return nil, err
		}
		out[client] = origin
	}
	return out, rows.Err()
}

// SetClientRegionOrigins replaces the client's region map with its audit row. The caller
// checks each origin against the client's redirect origins; the audit details name the
// client and the new map.
func (s *Store) SetClientRegionOrigins(clientID string, regions map[string]string, audit *AuditEvent) error {
	if len(regions) > MaxClientRegions {
		return InputError("At most 32 regions")
	}
	for region := range regions {
		if !ValidHomeRegion(region) {
			return InputError("Region must match ^[a-z][a-z0-9-]{1,31}$")
		}
	}
	details, err := json.Marshal(map[string]any{"clientId": clientID, "regions": regions})
	if err != nil {
		return err
	}
	audit.DetailsJSON = string(details)
	return s.auditedTx(audit, func(tx *sql.Tx) error {
		var exists bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM oauth_clients WHERE id=?)`, clientID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		if _, err := tx.Exec(`DELETE FROM client_region_origins WHERE client_id=?`, clientID); err != nil {
			return err
		}
		for region, origin := range regions {
			if _, err := tx.Exec(`INSERT INTO client_region_origins(client_id,region,origin) VALUES(?,?,?)`, clientID, region, origin); err != nil {
				return err
			}
		}
		return nil
	})
}
