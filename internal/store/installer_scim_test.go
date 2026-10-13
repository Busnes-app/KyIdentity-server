package store

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
)

func installerSCIMFixture() InstallerSetup {
	p := installerFixture()
	p.EncryptionKey = bytes.Repeat([]byte{7}, 32)
	p.Clients[0].AdministratorRole = "admin"
	p.Clients[0].EverydayRole = "editor"
	p.Clients[0].SCIM = &InstallerSCIM{URL: "https://bridge.example.test/scim/v2/bookstack", Token: strings.Repeat("s", 48)}
	return p
}

func TestInstallerSCIMExtendsOwnedClientAndPreservesRoles(t *testing.T) {
	s, close := setupTestStore(t)
	defer close()
	p := installerSCIMFixture()
	scim := p.Clients[0].SCIM
	p.Clients[0].SCIM = nil
	if _, err := s.ApplyInstallerSetup(p, false); err != nil {
		t.Fatal(err)
	}
	var appID string
	if err := s.db.QueryRow(`SELECT id FROM app_registry WHERE client_id='kydrive'`).Scan(&appID); err != nil {
		t.Fatal(err)
	}
	p.Clients[0].SCIM = scim
	if _, err := s.ApplyInstallerSetup(p, true); err == nil {
		t.Fatal("inspection created missing connector")
	}
	report, err := s.ApplyInstallerSetup(p, false)
	if err != nil || len(report.Created) != 1 || report.Created[0].Kind != "connector" {
		t.Fatalf("extend %+v error %v", report, err)
	}
	id := report.Created[0].ID
	var actualApp, encrypted string
	if err := s.db.QueryRow(`SELECT a.id,s.hmac_secret_encrypted FROM app_registry a JOIN paired_systems s ON s.id=a.system_id WHERE a.client_id='kydrive'`).Scan(&actualApp, &encrypted); err != nil {
		t.Fatal(err)
	}
	plain, err := crypto.DecryptAESGCM(p.EncryptionKey, encrypted)
	if err != nil || string(plain) != scim.Token || actualApp != appID || strings.Contains(encrypted, scim.Token) {
		t.Fatal("wrong native app or protected credential", err)
	}
	for _, inspect := range []bool{true, false} {
		r, err := s.ApplyInstallerSetup(p, inspect)
		if err != nil || len(r.Created) != 0 || len(r.Reused) != 6 {
			t.Fatalf("resume %+v error %v", r, err)
		}
		raw, _ := json.Marshal(r)
		if bytes.Contains(raw, []byte(scim.Token)) || bytes.Contains(raw, []byte(encrypted)) {
			t.Fatal("receipt leaked credential")
		}
	}
	var queues, roles, apps int
	for query, target := range map[string]*int{`SELECT count(*) FROM sync_resource_state WHERE system_id=? AND active`: &queues, `SELECT count(*) FROM app_roles WHERE app_id=?`: &roles, `SELECT count(*) FROM app_registry`: &apps} {
		args := []any{}
		if strings.Contains(query, "system_id") {
			args = append(args, id)
		} else if strings.Contains(query, "app_id") {
			args = append(args, appID)
		}
		if err := s.db.QueryRow(query, args...).Scan(target); err != nil {
			t.Fatal(err)
		}
	}
	if queues != 2 || roles != 2 || apps != 1 {
		t.Fatalf("desired state/roles/app identity %d/%d/%d", queues, roles, apps)
	}
	if err := s.EvaluateAlerts(time.Now()); err != nil {
		t.Fatal(err)
	}
	var alerts int
	if err := s.db.QueryRow(`SELECT count(*) FROM alerts WHERE rule='connector_credentials' AND key=?`, id).Scan(&alerts); err != nil || alerts != 1 {
		t.Fatalf("connector credential alert %d error %v", alerts, err)
	}
}

func TestInstallerSCIMRefusesDriftAndRollsBackAuditFailure(t *testing.T) {
	for _, cause := range []string{"audit", "token", "hold", "endpoint", "groups", "foreign"} {
		t.Run(cause, func(t *testing.T) {
			s, close := setupTestStore(t)
			defer close()
			p := installerSCIMFixture()
			if cause == "audit" {
				if _, err := s.db.Exec(`CREATE TRIGGER refuse_scim_audit BEFORE INSERT ON audit_events WHEN NEW.action='admin.system_created' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := s.ApplyInstallerSetup(p, false); err != nil {
					t.Fatal(err)
				}
				query := ""
				switch cause {
				case "token":
					p.Clients[0].SCIM.Token = strings.Repeat("z", 48)
				case "hold":
					query = `UPDATE paired_systems SET provisioning_hold=1`
				case "endpoint":
					query = `UPDATE paired_systems SET callback_url='https://foreign.test/scim/v2'`
				case "groups":
					query = `UPDATE paired_systems SET groups_enabled=1`
				case "foreign":
					query = `DELETE FROM installer_setup_resources WHERE kind='connector'`
				}
				if query != "" {
					if _, err := s.db.Exec(query); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := s.ApplyInstallerSetup(p, false); err == nil {
				t.Fatal("accepted unsafe connector state")
			}
			if cause == "audit" {
				for _, table := range []string{"users", "oauth_clients", "paired_systems", "app_registry", "app_roles", "installer_setup_resources", "sync_resource_state"} {
					var count int
					if err := s.db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); err != nil || count != 0 {
						t.Fatalf("partial %s %d error %v", table, count, err)
					}
				}
			}
		})
	}
}
