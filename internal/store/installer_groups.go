package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

func configureInstallerGroups(tx *sql.Tx, p InstallerSetup, everydayID string, inspect bool, report *InstallerReport,
	ownership func(string, string, string, string) (bool, error), remember func(string, string, string, string) error,
	audit func(string, string, string) error, now time.Time) (map[string]string, error) {
	ids := map[string]string{}
	for _, g := range p.Groups {
		members := 0
		if g.IncludeEveryday {
			members = 1
		}
		var id, name, description, source, external string
		err := tx.QueryRow(`SELECT id,name,description,COALESCE(source_connector_id,''),COALESCE(external_id,'') FROM directory_groups WHERE name=? COLLATE NOCASE`, g.Name).Scan(&id, &name, &description, &source, &external)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		contract, _ := json.Marshal(g)
		reused, err := ownership("group", g.Name, id, string(contract))
		if err != nil {
			return nil, err
		}
		if reused {
			if name != g.Name || description != g.Description || source != "" || external != "" {
				return nil, errors.New("owned group configuration drift")
			}
			var count, matching int
			if err := tx.QueryRow(`SELECT count(*),COALESCE(sum(user_id=? AND expires_at IS NULL),0) FROM group_memberships WHERE group_id=?`, everydayID, id).Scan(&count, &matching); err != nil {
				return nil, err
			}
			if count != members || matching != members {
				return nil, errors.New("owned group membership drift")
			}
			report.Reused = append(report.Reused, InstallerObject{"group", g.Name, id})
		} else {
			if inspect {
				return nil, errors.New("group is not configured")
			}
			id = uuid.NewString()
			if _, err := tx.Exec(`INSERT INTO directory_groups(id,name,description,created_at,updated_at) VALUES(?,?,?,?,?)`, id, g.Name, g.Description, now, now); err != nil {
				return nil, groupWriteError(err)
			}
			// Reuse native policy and role hooks; new groups start with no MFA requirement.
			if g.IncludeEveryday {
				if _, _, err := applyGroupMembershipTx(tx, id, everydayID, true, nil, ""); err != nil {
					return nil, err
				}
				if err := audit("group_membership", g.Name, everydayID); err != nil {
					return nil, err
				}
			}
			if err := remember("group", g.Name, id, string(contract)); err != nil {
				return nil, err
			}
			report.Created = append(report.Created, InstallerObject{"group", g.Name, id})
		}
		ids[g.Name] = id
	}
	return ids, nil
}

func configureInstallerAppGroups(tx *sql.Tx, c InstallerClient, appID string, groups map[string]string, reused bool, audit func(string, string, string) error) error {
	if reused {
		var count int
		if err := tx.QueryRow(`SELECT count(*) FROM app_group_assignments WHERE app_id=?`, appID).Scan(&count); err != nil {
			return err
		}
		if count != len(c.Groups) {
			return errors.New("owned app group assignment drift")
		}
	}
	for _, name := range c.Groups {
		id := groups[name]
		if reused {
			var present bool
			if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM app_group_assignments WHERE app_id=? AND group_id=?)`, appID, id).Scan(&present); err != nil {
				return err
			}
			if !present {
				return errors.New("owned app group assignment drift")
			}
		} else {
			if _, err := applyAppAssignmentTx(tx, appID, "groups", id, true, nil); err != nil {
				return err
			}
			if err := audit("group_assignment", c.ID+"/"+name, id); err != nil {
				return err
			}
		}
	}
	return nil
}
