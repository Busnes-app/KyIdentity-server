package store

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Suite groups (docs/superpowers/specs/2026-11-15-suite-groups-design.md): a directory
// group whose shared resources every suite app creates. The suite_groups row outlives
// the group as a tombstone, so its ID and slug are never reused.

const suiteGroupsSQL = `CREATE TABLE IF NOT EXISTS suite_groups (
 group_id TEXT PRIMARY KEY, slug TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
 enabled BOOLEAN NOT NULL, deleted_at %[1]s, created_at %[1]s NOT NULL, updated_at %[1]s NOT NULL);
CREATE TABLE IF NOT EXISTS suite_group_apps (
 group_id TEXT NOT NULL REFERENCES suite_groups(group_id) ON DELETE CASCADE,
 client_id TEXT NOT NULL, enabled BOOLEAN NOT NULL, PRIMARY KEY(group_id,client_id))`

func migrateSuiteGroups(tx *sql.Tx) error {
	_, err := tx.Exec(fmt.Sprintf(suiteGroupsSQL, "INTEGER"))
	return err
}

func migrateSuiteGroupsPostgres(tx *sql.Tx) error {
	_, err := tx.Exec(fmt.Sprintf(suiteGroupsSQL, "BIGINT"))
	return err
}

// SuiteGroupApps are the client IDs that create suite group resources, with their
// default when a group is turned on. KyPost's distribution list is opt-in.
var SuiteGroupApps = []struct {
	ID      string
	Default bool
}{{"kycalendar", true}, {"kydrive", true}, {"kymessage", true}, {"kypost", false}}

// ponytail: a bound that keeps one /api/suite/groups answer small; page it to lift.
const MaxSuiteGroups = 200

var ErrTooManySuiteGroups = InputError(fmt.Sprintf("at most %d groups can create shared resources", MaxSuiteGroups))

type SuiteGroupApp struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
}

// SuiteGroupSettings is a group's suite state for administrators.
type SuiteGroupSettings struct {
	Enabled bool            `json:"enabled"`
	Slug    string          `json:"slug,omitempty"`
	Apps    []SuiteGroupApp `json:"apps"`
}

// SuiteGroup is one entry of /api/suite/groups for a calling app.
type SuiteGroup struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Slug    string   `json:"slug"`
	State   string   `json:"state"`
	Members []string `json:"members"`
}

func suiteGroupDefault(clientID string) (bool, bool) {
	for _, a := range SuiteGroupApps {
		if a.ID == clientID {
			return a.Default, true
		}
	}
	return false, false
}

func suiteGroupAppsTx(tx *sql.Tx, groupID string) ([]SuiteGroupApp, error) {
	rows, err := tx.Query(`SELECT client_id,enabled FROM suite_group_apps WHERE group_id=?`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	set := map[string]bool{}
	for rows.Next() {
		var id string
		var on bool
		if err := rows.Scan(&id, &on); err != nil {
			return nil, err
		}
		set[id] = on
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := []SuiteGroupApp{}
	for _, a := range SuiteGroupApps {
		on, ok := set[a.ID]
		if !ok {
			on = a.Default
		}
		out = append(out, SuiteGroupApp{ID: a.ID, Enabled: on})
	}
	return out, nil
}

// GetSuiteGroup returns a live group's suite settings.
func (o *OrgStore) GetSuiteGroup(groupID string) (SuiteGroupSettings, error) {
	tx, err := o.s.rdb.Begin()
	if err != nil {
		return SuiteGroupSettings{}, err
	}
	defer tx.Rollback()
	var settings SuiteGroupSettings
	var slug sql.NullString
	var enabled sql.NullBool
	err = tx.QueryRow(`SELECT s.slug,s.enabled FROM directory_groups g LEFT JOIN suite_groups s ON s.group_id=g.id WHERE g.org_id=? AND g.id=?`, o.org, groupID).Scan(&slug, &enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return settings, ErrGroupTargetMissing
	}
	if err != nil {
		return settings, err
	}
	settings.Enabled, settings.Slug = enabled.Bool, slug.String
	if settings.Apps, err = suiteGroupAppsTx(tx, groupID); err != nil {
		return settings, err
	}
	return settings, tx.Commit()
}

// SetSuiteGroup turns a live group's shared resources on or off and records per-app
// choices (apps not named keep theirs), committing audit with the change.
func (o *OrgStore) SetSuiteGroup(groupID string, enabled bool, apps map[string]bool, audit *AuditEvent) (SuiteGroupSettings, error) {
	for id := range apps {
		if _, ok := suiteGroupDefault(id); !ok {
			return SuiteGroupSettings{}, InputError("unknown suite group app " + id)
		}
	}
	tx, err := o.s.db.Begin()
	if err != nil {
		return SuiteGroupSettings{}, err
	}
	defer tx.Rollback()
	var name string
	if err = tx.QueryRow(`SELECT name FROM directory_groups WHERE org_id=? AND id=?`, o.org, groupID).Scan(&name); errors.Is(err, sql.ErrNoRows) {
		return SuiteGroupSettings{}, ErrGroupTargetMissing
	} else if err != nil {
		return SuiteGroupSettings{}, err
	}
	now := time.Now().Unix()
	var slug string
	var was bool
	err = tx.QueryRow(`SELECT slug,enabled FROM suite_groups WHERE org_id=? AND group_id=?`, o.org, groupID).Scan(&slug, &was)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if !enabled && len(apps) == 0 {
			// Off and never on: nothing to remember.
			settings := SuiteGroupSettings{}
			settings.Apps, err = suiteGroupAppsTx(tx, groupID)
			return settings, err
		}
		if slug, err = uniqueSuiteSlugTx(tx, name); err != nil {
			return SuiteGroupSettings{}, err
		}
		if _, err = tx.Exec(`INSERT INTO suite_groups(org_id,group_id,slug,name,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`, o.org, groupID, slug, name, enabled, now, now); err != nil {
			return SuiteGroupSettings{}, err
		}
	case err != nil:
		return SuiteGroupSettings{}, err
	default:
		if _, err = tx.Exec(`UPDATE suite_groups SET enabled=?,name=?,updated_at=? WHERE org_id=? AND group_id=?`, enabled, name, now, o.org, groupID); err != nil {
			return SuiteGroupSettings{}, err
		}
	}
	if enabled && !was {
		var n int
		if err = tx.QueryRow(`SELECT COUNT(*) FROM suite_groups WHERE org_id=? AND enabled`, o.org).Scan(&n); err != nil {
			return SuiteGroupSettings{}, err
		}
		if n > MaxSuiteGroups {
			return SuiteGroupSettings{}, ErrTooManySuiteGroups
		}
	}
	for id, on := range apps {
		if _, err = tx.Exec(`INSERT INTO suite_group_apps(group_id,client_id,enabled) VALUES(?,?,?) ON CONFLICT(group_id,client_id) DO UPDATE SET enabled=excluded.enabled`, groupID, id, on); err != nil {
			return SuiteGroupSettings{}, err
		}
	}
	settings := SuiteGroupSettings{Enabled: enabled, Slug: slug}
	if settings.Apps, err = suiteGroupAppsTx(tx, groupID); err != nil {
		return settings, err
	}
	if err = recordAuditInOrgTx(tx, o.org, audit); err != nil {
		return settings, err
	}
	return settings, tx.Commit()
}

// suiteSlug is name in lowercase ASCII letters and digits with single hyphens.
func suiteSlug(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(name) {
		if b.Len() >= 40 {
			break
		}
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			if dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			dash = false
			b.WriteRune(r)
		} else {
			dash = true
		}
	}
	if b.Len() == 0 {
		return "group"
	}
	return b.String()
}

// uniqueSuiteSlugTx picks a slug no row, tombstones included, has ever held.
func uniqueSuiteSlugTx(tx *sql.Tx, name string) (string, error) {
	base := suiteSlug(name)
	for n := 1; ; n++ {
		slug := base
		if n > 1 {
			slug = fmt.Sprintf("%s-%d", base, n)
		}
		var taken bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM suite_groups WHERE slug=?)`, slug).Scan(&taken); err != nil {
			return "", err
		}
		if !taken {
			return slug, nil
		}
	}
}

// tombstoneSuiteGroupTx archives a group's suite row as the group is deleted.
func tombstoneSuiteGroupTx(tx *sql.Tx, org, groupID, name string) error {
	now := time.Now().Unix()
	_, err := tx.Exec(`UPDATE suite_groups SET enabled=FALSE,name=?,deleted_at=?,updated_at=? WHERE org_id=? AND group_id=?`, name, now, now, org, groupID)
	return err
}

// SuiteGroupsFor lists every suite group of the org for the calling client: active with its
// members when on for that client, else archived. Clients outside SuiteGroupApps get none.
// Members are active everyday accounts with live membership and access to the client.
func (o *OrgStore) SuiteGroupsFor(clientID string) ([]SuiteGroup, error) {
	def, ok := suiteGroupDefault(clientID)
	if !ok {
		return []SuiteGroup{}, nil
	}
	tx, err := o.s.rdb.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT s.group_id,COALESCE(g.name,s.name),s.slug,
 (s.enabled AND s.deleted_at IS NULL AND g.id IS NOT NULL AND COALESCE(a.enabled,?))
 FROM suite_groups s LEFT JOIN directory_groups g ON g.id=s.group_id
 LEFT JOIN suite_group_apps a ON a.group_id=s.group_id AND a.client_id=?
 WHERE s.org_id=? ORDER BY s.group_id`, def, clientID, o.org)
	if err != nil {
		return nil, err
	}
	out := []SuiteGroup{}
	for rows.Next() {
		var g SuiteGroup
		var active bool
		if err = rows.Scan(&g.ID, &g.Name, &g.Slug, &active); err != nil {
			rows.Close()
			return nil, err
		}
		g.State, g.Members = "archived", []string{}
		if active {
			g.State = "active"
		}
		out = append(out, g)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].State != "active" {
			continue
		}
		members, err := scanStrings(tx.Query(`SELECT m.user_id FROM live_group_memberships m JOIN users u ON u.id=m.user_id
 WHERE m.group_id=? AND u.org_id=? AND u.role='user' AND NOT u.pending
 AND EXISTS(SELECT 1 FROM effective_app_access e JOIN app_registry r ON r.id=e.app_id JOIN oauth_clients c ON c.id=r.client_id WHERE e.user_id=u.id AND c.id=? AND c.enabled)`, out[i].ID, o.org, clientID))
		if err != nil {
			return nil, err
		}
		sort.Strings(members)
		if members != nil {
			out[i].Members = members
		}
	}
	return out, tx.Commit()
}
