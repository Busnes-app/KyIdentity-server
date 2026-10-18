package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

// InstallerUser contains validated local setup values, never a plaintext password.
type InstallerUser struct{ Username, Email, Role, PasswordHash string }
type InstallerClient struct {
	ID, Name, SecretHash            string
	RedirectURIs, PostLogoutURIs    []string
	AdministratorRole, EverydayRole string
	SCIM                            *InstallerSCIM
	SuiteWebhook                    *InstallerSuiteWebhook
	Groups                          []string
}
type InstallerSCIM struct {
	URL, Token string
	Groups     bool
}
type InstallerSuiteWebhook struct{ URL, SigningSecret string }
type InstallerGroup struct {
	Name, Description string
	IncludeEveryday   bool
}
type InstallerSetup struct {
	ID              string
	Extends         string // parent setup ID of an amendment; accounts and groups stay the parent's
	Admin, Everyday InstallerUser
	Clients         []InstallerClient
	Groups          []InstallerGroup
	EncryptionKey   []byte
}
type InstallerObject struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	ID   string `json:"id"`
}
type InstallerReport struct {
	Schema  string            `json:"schema"`
	Created []InstallerObject `json:"created"`
	Reused  []InstallerObject `json:"reused"`
}

// OpenInstallerStore opens an already initialized database without running migrations.
// Check mode uses SQLite's read-only connection, preventing side effects even on errors.
func OpenInstallerStore(path string, inspect bool) (*Store, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: absolute}
	q := u.Query()
	q.Set("mode", "rw")
	q.Set("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(ON)")
	q.Set("_txlock", "immediate")
	if inspect {
		q.Set("mode", "ro")
		q.Set("_txlock", "deferred")
	}
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	return &Store{db: db, rdb: db}, nil
}

// InstallerSetupExists reports native receipt ownership without creating resources.
// Preparation must not mint replacement credentials for an already applied setup.
func (s *Store) InstallerSetupExists(id string) (bool, error) {
	var found bool
	err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM installer_setup_resources WHERE setup_id=?)`, id).Scan(&found)
	return found, err
}

// RecordInstallerPreparation binds completed target credentials to native ownership.
// This survives loss of the filesystem markers, without configuring any account.
// Inspection is read-only; creation and its audit commit together.
func (s *Store) RecordInstallerPreparation(id, contract string, inspect bool) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var owner, objectID, retained string
	err = tx.QueryRow(`SELECT setup_id,object_id,contract FROM installer_setup_resources WHERE kind='preparation' AND name=?`, id).Scan(&owner, &objectID, &retained)
	if err == nil {
		if owner != id || objectID != id || retained != contract {
			return errors.New("native preparation ownership or credential receipt changed")
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if inspect {
		return errors.New("native preparation receipt is missing")
	}
	if _, err := tx.Exec(`INSERT INTO installer_setup_resources(kind,name,setup_id,object_id,contract) VALUES('preparation',?,?,?,?)`, id, id, id, contract); err != nil {
		return err
	}
	details, _ := json.Marshal(map[string]string{"setupId": id, "receiptDigest": contract})
	if err := recordAuditTx(tx, &AuditEvent{ID: uuid.NewString(), ActorUsername: "kyquickstart", Action: "installer.credentials_prepared", TargetID: id, TargetType: "preparation", IPAddress: "container-local", Outcome: "success", DetailsJSON: string(details), CreatedAt: time.Now().UTC()}); err != nil {
		return err
	}
	return tx.Commit()
}

// InstallerSetupAdministrator returns the administrator account setupID owns, found by
// the ID its ownership row recorded rather than by a username that may since name another
// account. It refuses unless that account still has the owned username and is an active
// administrator. Both reads share one snapshot.
func (s *Store) InstallerSetupAdministrator(setupID string) (*User, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT name,object_id,contract FROM installer_setup_resources WHERE kind='user' AND setup_id=?`, setupID)
	if err != nil {
		return nil, err
	}
	var name, id string
	for rows.Next() {
		var n, o, contract string
		var f []string
		if err := rows.Scan(&n, &o, &contract); err != nil {
			rows.Close()
			return nil, err
		}
		if json.Unmarshal([]byte(contract), &f) != nil || len(f) != 3 {
			rows.Close()
			return nil, errors.New("setup account ownership is malformed")
		}
		if f[2] == "admin" {
			if id != "" {
				rows.Close()
				return nil, errors.New("setup owns more than one administrator")
			}
			name, id = n, o
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if id == "" {
		return nil, errors.New("setup owns no administrator")
	}
	u, err := scanUser(tx.QueryRow(`SELECT `+userColumns+` FROM users WHERE id=?`, id))
	if err != nil {
		return nil, err
	}
	if u == nil || !strings.EqualFold(u.Username, name) || u.Role != "admin" || u.Status != "active" {
		return nil, errors.New("setup administrator no longer matches its ownership")
	}
	return u, nil
}

// installerParentTx binds an amendment to its parent's owned accounts and the groups its
// clients name, from native ownership only. The caller's inspection then proves them current.
func installerParentTx(tx *sql.Tx, p *InstallerSetup) error {
	if p.Extends == "" || p.Extends == p.ID || p.Admin != (InstallerUser{}) || p.Everyday != (InstallerUser{}) || len(p.Groups) > 0 || len(p.Clients) == 0 {
		return errors.New("an amendment adds clients only and must extend another setup")
	}
	rows, err := tx.Query(`SELECT contract FROM installer_setup_resources WHERE kind='user' AND setup_id=?`, p.Extends)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var contract string
		var f []string
		if err := rows.Scan(&contract); err != nil {
			return err
		}
		if json.Unmarshal([]byte(contract), &f) != nil || len(f) != 3 {
			return errors.New("parent setup account ownership is malformed")
		}
		u := InstallerUser{Username: f[0], Email: f[1], Role: f[2]}
		switch {
		case u.Role == "admin" && p.Admin.Username == "":
			p.Admin = u
		case u.Role == "user" && p.Everyday.Username == "":
			p.Everyday = u
		default:
			return errors.New("parent setup account ownership is malformed")
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if p.Admin.Username == "" || p.Everyday.Username == "" {
		return errors.New("parent setup has no owned administrator and everyday accounts")
	}
	seen := map[string]bool{}
	for _, c := range p.Clients {
		for _, name := range c.Groups {
			if seen[name] {
				continue
			}
			seen[name] = true
			var contract string
			var g InstallerGroup
			err := tx.QueryRow(`SELECT contract FROM installer_setup_resources WHERE kind='group' AND name=? AND setup_id=?`, name, p.Extends).Scan(&contract)
			if errors.Is(err, sql.ErrNoRows) || err == nil && (json.Unmarshal([]byte(contract), &g) != nil || g.Name != name) {
				return fmt.Errorf("group %s is not owned by the parent setup", name)
			}
			if err != nil {
				return err
			}
			p.Groups = append(p.Groups, g)
		}
	}
	return nil
}

// ApplyInstallerSetup commits the complete bundle and one audit row per creation together.
// Existing foreign objects are never adopted. Managed drift fails instead of overwriting it.
func (s *Store) ApplyInstallerSetup(p InstallerSetup, inspect bool) (*InstallerReport, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	report := &InstallerReport{Schema: "kyidentity.setup/1", Created: []InstallerObject{}, Reused: []InstallerObject{}}
	now := time.Now().UTC()
	// An amendment inspects the parent's accounts and groups and never creates or changes them.
	amendment := p.Extends != ""
	accountOwner := p.ID
	if amendment {
		if err := installerParentTx(tx, &p); err != nil {
			return nil, err
		}
		accountOwner = p.Extends
	}
	audit := func(kind, name, id string) error {
		fields := map[string]string{"setupId": p.ID, "name": name}
		if amendment {
			fields["extends"] = p.Extends
		}
		action := "installer." + kind + "_created"
		if kind == "connector" {
			action = "admin.system_created"
			var fieldsType string
			if err := tx.QueryRow(`SELECT system_type FROM paired_systems WHERE id=?`, id).Scan(&fieldsType); err != nil {
				return err
			}
			fields["systemType"] = fieldsType
		}
		if kind == "user" {
			// Use the existing event shape so administrator creation raises its alert.
			var role string
			if err := tx.QueryRow(`SELECT role FROM users WHERE id=?`, id).Scan(&role); err != nil {
				return err
			}
			fields["username"], fields["role"] = name, role
			action = "admin.user_created"
		}
		details, _ := json.Marshal(fields)
		return recordAuditTx(tx, &AuditEvent{ID: uuid.NewString(), ActorUsername: "kyquickstart", Action: action, TargetID: id, TargetType: kind, IPAddress: "container-local", Outcome: "success", DetailsJSON: string(details), CreatedAt: now})
	}
	ownership := func(kind, name, id, contract string) (bool, error) {
		var owner, storedID, storedContract string
		err := tx.QueryRow(`SELECT setup_id,object_id,contract FROM installer_setup_resources WHERE kind=? AND name=?`, kind, name).Scan(&owner, &storedID, &storedContract)
		if errors.Is(err, sql.ErrNoRows) {
			if id != "" {
				return false, fmt.Errorf("%s %s already exists without this installer's ownership", kind, name)
			}
			return false, nil
		}
		if err != nil {
			return false, err
		}
		want := p.ID
		if kind == "user" || kind == "group" {
			want = accountOwner
		}
		if owner != want || storedID != id || storedContract != contract {
			return false, fmt.Errorf("%s %s has conflicting ownership or setup configuration", kind, name)
		}
		return true, nil
	}
	remember := func(kind, name, id, contract string) error {
		if _, err := tx.Exec(`INSERT INTO installer_setup_resources(kind,name,setup_id,object_id,contract) VALUES(?,?,?,?,?)`, kind, name, p.ID, id, contract); err != nil {
			return err
		}
		return audit(kind, name, id)
	}
	for _, u := range []InstallerUser{p.Admin, p.Everyday} {
		var id, email, role, status, source string
		var pending bool
		err := tx.QueryRow(`SELECT id,email,role,status,pending,COALESCE(source_connector_id,'') FROM users WHERE username=? COLLATE NOCASE`, u.Username).Scan(&id, &email, &role, &status, &pending, &source)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		contractBytes, _ := json.Marshal([]string{u.Username, u.Email, u.Role})
		contract := string(contractBytes)
		reused, err := ownership("user", u.Username, id, contract)
		if err != nil {
			return nil, err
		}
		if reused {
			if email != u.Email || role != u.Role || status != "active" || pending || source != "" {
				return nil, fmt.Errorf("user %s no longer matches installer account requirements", u.Username)
			}
			var invalid bool
			if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM users WHERE id=? AND ends_at IS NOT NULL) OR EXISTS(SELECT 1 FROM admin_delegations WHERE user_id=?)`, id, id).Scan(&invalid); err != nil {
				return nil, err
			}
			if invalid {
				return nil, fmt.Errorf("user %s has conflicting account lifecycle or delegated privileges", u.Username)
			}
			report.Reused = append(report.Reused, InstallerObject{"user", u.Username, id})
			continue
		}
		if inspect || amendment {
			return nil, fmt.Errorf("user %s is not configured", u.Username)
		}
		id = uuid.NewString()
		if _, err := tx.Exec(`INSERT INTO users(id,username,display_name,email,password_hash,role,status,pending,created_at,updated_at) VALUES(?,?,?,?,?,?,'active',0,?,?)`, id, u.Username, u.Username, u.Email, u.PasswordHash, u.Role, now, now); err != nil {
			return nil, errors.New("installer account creation conflicts with an existing account")
		}
		if err := remember("user", u.Username, id, contract); err != nil {
			return nil, err
		}
		report.Created = append(report.Created, InstallerObject{"user", u.Username, id})
	}
	var everydayID, adminID string
	if err := tx.QueryRow(`SELECT id FROM users WHERE username=? COLLATE NOCASE`, p.Everyday.Username).Scan(&everydayID); err != nil {
		return nil, err
	}
	if err := tx.QueryRow(`SELECT id FROM users WHERE username=? COLLATE NOCASE`, p.Admin.Username).Scan(&adminID); err != nil {
		return nil, err
	}
	groupIDs, err := configureInstallerGroups(tx, p, everydayID, inspect || amendment, report, ownership, remember, audit, now)
	if err != nil {
		return nil, err
	}
	configureRoles := func(c InstallerClient, appID string) error {
		mappings := []struct{ name, principal string }{}
		if c.AdministratorRole != "" {
			mappings = append(mappings, struct{ name, principal string }{c.AdministratorRole, adminID})
		}
		if c.EverydayRole != "" {
			mappings = append(mappings, struct{ name, principal string }{c.EverydayRole, everydayID})
		}
		for _, mapping := range mappings {
			var id, name, description string
			err := tx.QueryRow(`SELECT id,name,description FROM app_roles WHERE app_id=? AND lower(name)=lower(?)`, appID, mapping.name).Scan(&id, &name, &description)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			key := c.ID + "/" + mapping.name
			contract, _ := json.Marshal([]string{appID, mapping.name, mapping.principal})
			reused, err := ownership("role", key, id, string(contract))
			if err != nil {
				return err
			}
			if !reused {
				if inspect {
					return errors.New("app role is not configured")
				}
				id = uuid.NewString()
				if _, err := tx.Exec(`INSERT INTO app_roles(id,app_id,name,description,created_at) VALUES(?,?,?,'',?)`, id, appID, mapping.name, now); err != nil {
					return err
				}
				app, err := scanAppRecord(tx.QueryRow(appRecordSelect+appRecordFrom+` WHERE a.id=?`, appID))
				if err != nil {
					return err
				}
				if err := appRoleShapeChangeTx(tx, app, 1, now); err != nil {
					return err
				}
				if _, err := tx.Exec(`INSERT INTO app_role_user_assignments(role_id,user_id) VALUES(?,?)`, id, mapping.principal); err != nil {
					return err
				}
				if err := roleChangeTx(tx, app, []string{mapping.principal}, now); err != nil {
					return err
				}
				if err := audit("role_assignment", key, mapping.principal); err != nil {
					return err
				}
				if err := remember("role", key, id, string(contract)); err != nil {
					return err
				}
				report.Created = append(report.Created, InstallerObject{"role", key, id})
			} else {
				var valid bool
				if err := tx.QueryRow(`SELECT (SELECT count(*) FROM app_role_user_assignments WHERE role_id=?)=1 AND EXISTS(SELECT 1 FROM app_role_user_assignments WHERE role_id=? AND user_id=?) AND NOT EXISTS(SELECT 1 FROM app_role_group_assignments WHERE role_id=?)`, id, id, mapping.principal, id).Scan(&valid); err != nil {
					return err
				}
				if name != mapping.name || description != "" || !valid {
					return errors.New("owned app role or assignment drift")
				}
				report.Reused = append(report.Reused, InstallerObject{"role", key, id})
			}
		}
		var count int
		if err := tx.QueryRow(`SELECT count(*) FROM app_roles WHERE app_id=?`, appID).Scan(&count); err != nil {
			return err
		}
		if count != len(mappings) {
			return errors.New("app has undeclared roles")
		}
		return nil
	}
	for _, c := range p.Clients {
		redirects, _ := json.Marshal(c.RedirectURIs)
		logout, _ := json.Marshal(c.PostLogoutURIs)
		contractFields := []string{c.Name, string(redirects), string(logout)}
		if c.AdministratorRole != "" || c.EverydayRole != "" {
			contractFields = append(contractFields, c.AdministratorRole, c.EverydayRole)
		}
		if len(c.Groups) > 0 {
			groupJSON, _ := json.Marshal(c.Groups)
			contractFields = append(contractFields, "groups", string(groupJSON))
		}
		if amendment {
			contractFields = append(contractFields, "extends", p.Extends)
		}
		contractBytes, _ := json.Marshal(contractFields)
		contract := string(contractBytes)
		var id, name, kind, hash, existingRedirects, existingLogout, scopes string
		var enabled bool
		err := tx.QueryRow(`SELECT id,client_name,client_type,client_secret_hash,redirect_uris_json,post_logout_redirect_uris_json,allowed_scopes_json,enabled FROM oauth_clients WHERE id=?`, c.ID).Scan(&id, &name, &kind, &hash, &existingRedirects, &existingLogout, &scopes, &enabled)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		reused, err := ownership("client", c.ID, id, contract)
		if err != nil {
			return nil, err
		}
		if reused {
			if name != c.Name || kind != "confidential" || hash != c.SecretHash || existingRedirects != string(redirects) || existingLogout != string(logout) || scopes != `["openid","profile","email"]` || !enabled {
				return nil, fmt.Errorf("client %s differs from its installer configuration", c.ID)
			}
			var policy, everydayAccess bool
			if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM app_registry a WHERE a.client_id=? AND a.access_mode='assigned_only' AND a.enabled AND NOT a.legacy_role_claim AND a.groups_claim=?), EXISTS(SELECT 1 FROM app_user_assignments x JOIN app_registry a ON a.id=x.app_id WHERE a.client_id=? AND x.user_id=? AND x.expires_at IS NULL)`, c.ID, len(c.Groups) > 0, c.ID, everydayID).Scan(&policy, &everydayAccess); err != nil {
				return nil, err
			}
			if !policy || everydayAccess != (c.AdministratorRole == "" || c.EverydayRole != "") {
				return nil, fmt.Errorf("client %s access assignments differ from installer configuration", c.ID)
			}
			var adminAccess bool
			if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM effective_app_access e JOIN app_registry a ON a.id=e.app_id WHERE a.client_id=? AND e.user_id=?)`, c.ID, adminID).Scan(&adminAccess); err != nil {
				return nil, err
			}
			if adminAccess != (c.AdministratorRole != "") {
				return nil, fmt.Errorf("client %s administrator access differs from its declared role", c.ID)
			}
			if c.AdministratorRole != "" {
				var direct bool
				if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM app_user_assignments x JOIN app_registry a ON a.id=x.app_id WHERE a.client_id=? AND x.user_id=? AND x.expires_at IS NULL)`, c.ID, adminID).Scan(&direct); err != nil {
					return nil, err
				}
				if !direct {
					return nil, errors.New("owned administrator assignment drift")
				}
			}
			if c.AdministratorRole != "" && c.EverydayRole == "" {
				var unexpected bool
				if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM effective_app_access e JOIN app_registry a ON a.id=e.app_id WHERE a.client_id=? AND e.user_id=?)`, c.ID, everydayID).Scan(&unexpected); err != nil {
					return nil, err
				}
				if unexpected {
					return nil, errors.New("everyday identity has management-only application access")
				}
			}
			var appID string
			if err := tx.QueryRow(`SELECT id FROM app_registry WHERE client_id=?`, c.ID).Scan(&appID); err != nil {
				return nil, err
			}
			if err := configureRoles(c, appID); err != nil {
				return nil, err
			}
			if err := configureInstallerAppGroups(tx, c, appID, groupIDs, true, audit); err != nil {
				return nil, err
			}
			if err := configureInstallerConnector(tx, p, c, appID, inspect, report, ownership, remember, audit, now); err != nil {
				return nil, err
			}
			report.Reused = append(report.Reused, InstallerObject{"client", c.ID, id})
			continue
		}
		if inspect {
			return nil, fmt.Errorf("client %s is not configured", c.ID)
		}
		if _, err := tx.Exec(`INSERT INTO oauth_clients(id,client_name,client_type,client_secret_hash,redirect_uris_json,allowed_scopes_json,launch_url,enabled,created_at,post_logout_redirect_uris_json) VALUES(?,?,'confidential',?,?,?,NULL,1,?,?)`, c.ID, c.Name, c.SecretHash, string(redirects), `["openid","profile","email"]`, now, string(logout)); err != nil {
			return nil, err
		}
		var appID string
		if err := tx.QueryRow(`SELECT id FROM app_registry WHERE client_id=? AND access_mode='assigned_only' AND NOT legacy_role_claim`, c.ID).Scan(&appID); err != nil {
			return nil, errors.New("new installer client did not default to assigned-only app-role access")
		}
		principals := []string{}
		if _, err := tx.Exec(`UPDATE app_registry SET groups_claim=? WHERE id=?`, len(c.Groups) > 0, appID); err != nil {
			return nil, err
		}
		if c.AdministratorRole == "" || c.EverydayRole != "" {
			principals = append(principals, everydayID)
		}
		if c.AdministratorRole != "" {
			principals = append(principals, adminID)
		}
		for _, principal := range principals {
			if _, err := applyAppAssignmentTx(tx, appID, "users", principal, true, nil); err != nil {
				return nil, err
			}
			if err := audit("assignment", c.ID, principal); err != nil {
				return nil, err
			}
		}
		if err := configureRoles(c, appID); err != nil {
			return nil, err
		}
		if err := configureInstallerAppGroups(tx, c, appID, groupIDs, false, audit); err != nil {
			return nil, err
		}
		if err := remember("client", c.ID, c.ID, contract); err != nil {
			return nil, err
		}
		if err := configureInstallerConnector(tx, p, c, appID, inspect, report, ownership, remember, audit, now); err != nil {
			return nil, err
		}
		report.Created = append(report.Created, InstallerObject{"client", c.ID, c.ID})
	}
	if inspect {
		return report, nil
	}
	if err := reconcileAccessTx(tx); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return report, nil
}
