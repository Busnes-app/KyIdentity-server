package store

import (
	"strings"
	"testing"
)

// installerState is a cheap fingerprint of what a refused rerun must leave untouched.
func installerState(t *testing.T, s *Store) [4]int {
	t.Helper()
	return [4]int{auditCount(t, s), count(t, s, `SELECT COUNT(*) FROM installer_setup_resources`), count(t, s, `SELECT COUNT(*) FROM users`), count(t, s, `SELECT COUNT(*) FROM app_user_assignments`)}
}

// Guards that managed drift is refused, never repaired: after a successful setup, each
// out-of-band change to an owned account, client, assignment or role makes both the
// rerun and --check fail with a precise reason, writing nothing.
func TestInstallerSetupRefusesManagedDrift(t *testing.T) {
	for name, tc := range map[string]struct {
		configure func(*InstallerSetup)
		drift     string
		reason    string
	}{
		"admin email":           {nil, `UPDATE users SET email='moved@example.test' WHERE username='owner-admin'`, "no longer matches installer account requirements"},
		"admin end date":        {nil, `UPDATE users SET ends_at=unixepoch()+3600 WHERE username='owner-admin'`, "conflicting account lifecycle"},
		"client secret":         {nil, `UPDATE oauth_clients SET client_secret_hash='other' WHERE id='kydrive'`, "client kydrive differs from its installer configuration"},
		"client disabled":       {nil, `UPDATE oauth_clients SET enabled=0 WHERE id='kydrive'`, "client kydrive differs"},
		"client scopes":         {nil, `UPDATE oauth_clients SET allowed_scopes_json='["openid"]' WHERE id='kydrive'`, "client kydrive differs"},
		"everyday unassigned":   {nil, `DELETE FROM app_user_assignments WHERE user_id=(SELECT id FROM users WHERE username='owner')`, "access assignments differ"},
		"open to everyone":      {nil, `UPDATE app_registry SET access_mode='all_active_users' WHERE client_id='kydrive'`, "access assignments differ"},
		"admin gained access":   {nil, `INSERT INTO app_user_assignments(app_id,user_id) SELECT a.id,u.id FROM app_registry a, users u WHERE a.client_id='kydrive' AND u.username='owner-admin'`, "administrator access differs from its declared role"},
		"admin assignment lost": {roles("owner:admin", "editor"), `DELETE FROM app_user_assignments WHERE user_id=(SELECT id FROM users WHERE username='owner-admin')`, "administrator access differs"},
		"admin access via group": {roles("owner:admin", "editor"), `INSERT INTO directory_groups(id,name,description,created_at,updated_at) VALUES('side','Side','',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP);
 INSERT INTO group_memberships(group_id,user_id) SELECT 'side',id FROM users WHERE username='owner-admin';
 INSERT INTO app_group_assignments(app_id,group_id) SELECT id,'side' FROM app_registry WHERE client_id='kydrive';
 DELETE FROM app_user_assignments WHERE user_id=(SELECT id FROM users WHERE username='owner-admin')`, "owned administrator assignment drift"},
		"everyday in management-only": {roles("owner:admin", ""), `INSERT INTO directory_groups(id,name,description,created_at,updated_at) VALUES('side','Side','',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP);
 INSERT INTO group_memberships(group_id,user_id) SELECT 'side',id FROM users WHERE username='owner';
 INSERT INTO app_group_assignments(app_id,group_id) SELECT id,'side' FROM app_registry WHERE client_id='kydrive'`, "everyday identity has management-only application access"},
		"undeclared role": {roles("owner:admin", "editor"), `INSERT INTO app_roles(id,app_id,name,description,created_at) SELECT 'extra',id,'extra','',CURRENT_TIMESTAMP FROM app_registry WHERE client_id='kydrive'`, "app has undeclared roles"},
		"role renamed":    {roles("owner:admin", "editor"), `UPDATE app_roles SET description='changed' WHERE name='editor'`, "owned app role or assignment drift"},
		"role reassigned": {roles("owner:admin", "editor"), `INSERT INTO app_role_user_assignments(role_id,user_id) SELECT r.id,u.id FROM app_roles r, users u WHERE r.name='editor' AND u.username='owner-admin'`, "owned app role or assignment drift"},
	} {
		t.Run(name, func(t *testing.T) {
			s, close := setupTestStore(t)
			defer close()
			p := installerFixture()
			if tc.configure != nil {
				tc.configure(&p)
			}
			if _, err := s.ApplyInstallerSetup(p, false); err != nil {
				t.Fatal(err)
			}
			if _, err := s.ApplyInstallerSetup(p, true); err != nil {
				t.Fatal("clean check failed", err)
			}
			mustExec(t, s, tc.drift)
			before := installerState(t, s)
			for _, inspect := range []bool{false, true} {
				if _, err := s.ApplyInstallerSetup(p, inspect); err == nil || !strings.Contains(err.Error(), tc.reason) {
					t.Fatalf("inspect=%v: got %v, want %q", inspect, err, tc.reason)
				}
			}
			if installerState(t, s) != before {
				t.Fatal("refused rerun changed the database")
			}
		})
	}
}

func roles(admin, everyday string) func(*InstallerSetup) {
	return func(p *InstallerSetup) { p.Clients[0].AdministratorRole, p.Clients[0].EverydayRole = admin, everyday }
}

// Guards --check on a database the setup never touched: it reports the first missing
// account and writes nothing; a foreign account holding the owned username is refused
// rather than adopted.
func TestInstallerSetupCheckAndForeignAccount(t *testing.T) {
	s, close := setupTestStore(t)
	defer close()
	p := installerFixture()
	if _, err := s.ApplyInstallerSetup(p, true); err == nil || !strings.Contains(err.Error(), "user owner-admin is not configured") {
		t.Fatal("check of a fresh database", err)
	}
	if installerState(t, s) != [4]int{0, 0, 0, 0} {
		t.Fatal("check wrote to the database")
	}
	createTestUserNamed(t, s, "Owner-Admin")
	if _, err := s.ApplyInstallerSetup(p, false); err == nil || !strings.Contains(err.Error(), "already exists without this installer's ownership") {
		t.Fatal("foreign account adopted", err)
	}
	if count(t, s, `SELECT COUNT(*) FROM installer_setup_resources`) != 0 || count(t, s, `SELECT COUNT(*) FROM oauth_clients`) != 0 {
		t.Fatal("refused setup left ownership or clients")
	}
}

// Guards a client added to a setup after its accounts: --check names the client as not
// configured, while the apply creates it.
func TestInstallerSetupCheckNamesMissingClient(t *testing.T) {
	s, close := setupTestStore(t)
	defer close()
	p := installerFixture()
	if _, err := s.ApplyInstallerSetup(p, false); err != nil {
		t.Fatal(err)
	}
	p.Clients = append(p.Clients, InstallerClient{ID: "kynotes", Name: "KyNotes", SecretHash: "notes-hash", RedirectURIs: []string{"https://notes.example.test/callback"}, PostLogoutURIs: []string{}})
	if _, err := s.ApplyInstallerSetup(p, true); err == nil || !strings.Contains(err.Error(), "client kynotes is not configured") {
		t.Fatal("check missed new client", err)
	}
	if count(t, s, `SELECT COUNT(*) FROM oauth_clients WHERE id='kynotes'`) != 0 {
		t.Fatal("check created the client")
	}
	if _, err := s.ApplyInstallerSetup(p, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyInstallerSetup(p, true); err != nil {
		t.Fatal("check after apply", err)
	}
}

// Guards the credential export's ownership lookup against tampered ownership rows: a
// malformed contract, a second owned administrator or no owned administrator all refuse
// rather than guessing an account.
func TestInstallerSetupAdministratorRefusesTamperedOwnership(t *testing.T) {
	for name, tamper := range map[string]struct{ q, reason string }{
		"malformed":   {`UPDATE installer_setup_resources SET contract='not json' WHERE kind='user' AND name='owner-admin'`, "malformed"},
		"two admins":  {`UPDATE installer_setup_resources SET contract='["owner","owner@example.test","admin"]' WHERE kind='user' AND name='owner'`, "more than one administrator"},
		"no admin":    {`DELETE FROM installer_setup_resources WHERE kind='user' AND name='owner-admin'`, "owns no administrator"},
		"short tuple": {`UPDATE installer_setup_resources SET contract='["owner-admin","admin"]' WHERE kind='user' AND name='owner-admin'`, "malformed"},
	} {
		t.Run(name, func(t *testing.T) {
			s, close := setupTestStore(t)
			defer close()
			p := installerFixture()
			if _, err := s.ApplyInstallerSetup(p, false); err != nil {
				t.Fatal(err)
			}
			mustExec(t, s, tamper.q)
			if u, err := s.InstallerSetupAdministrator(p.ID); err == nil || u != nil || !strings.Contains(err.Error(), tamper.reason) {
				t.Fatalf("got %+v, %v; want %q", u, err, tamper.reason)
			}
			// An amendment reads the same rows and refuses them too.
			if _, err := s.ApplyInstallerSetup(amendmentFixture(p.ID), false); err == nil {
				t.Fatal("amendment accepted tampered parent ownership")
			}
		})
	}
}
