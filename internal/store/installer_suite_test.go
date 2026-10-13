package store

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
)

func installerSuiteFixture() InstallerSetup {
	p := installerSCIMFixture()
	p.Clients[0].SCIM = nil
	p.Clients[0].SuiteWebhook = &InstallerSuiteWebhook{URL: "https://notes.example.test/api/v1/sync/events", SigningSecret: strings.Repeat("w", 64)}
	return p
}

func TestInstallerSuiteConnectorExtensionAndReadonlyResume(t *testing.T) {
	s, close := setupTestStore(t)
	defer close()
	p := installerSuiteFixture()
	connector := p.Clients[0].SuiteWebhook
	p.Clients[0].SuiteWebhook = nil
	if _, err := s.ApplyInstallerSetup(p, false); err != nil {
		t.Fatal(err)
	}
	var appID string
	if err := s.db.QueryRow(`SELECT id FROM app_registry WHERE client_id='kydrive'`).Scan(&appID); err != nil {
		t.Fatal(err)
	}
	p.Clients[0].SuiteWebhook = connector
	if _, err := s.ApplyInstallerSetup(p, true); err == nil {
		t.Fatal("check created a missing suite connector")
	}
	r, err := s.ApplyInstallerSetup(p, false)
	if err != nil || len(r.Created) != 1 || r.Created[0].Kind != "connector" {
		t.Fatal("suite extension failed", err)
	}
	id := r.Created[0].ID
	var kind, bound, encrypted, auditKind string
	if err := s.db.QueryRow(`SELECT s.system_type,a.id,s.hmac_secret_encrypted FROM paired_systems s JOIN app_registry a ON a.system_id=s.id WHERE s.id=?`, id).Scan(&kind, &bound, &encrypted); err != nil {
		t.Fatal(err)
	}
	plain, err := crypto.DecryptAESGCM(p.EncryptionKey, encrypted)
	if err != nil || kind != "suite_webhook" || bound != appID || string(plain) != connector.SigningSecret || strings.Contains(encrypted, connector.SigningSecret) {
		t.Fatal("suite identity/credential mismatch", err)
	}
	if err := s.db.QueryRow(`SELECT json_extract(details_json,'$.systemType') FROM audit_events WHERE action='admin.system_created' AND target_id=?`, id).Scan(&auditKind); err != nil || auditKind != "suite_webhook" {
		t.Fatal("incorrect native connector audit", err, auditKind)
	}
	var before, after int
	if err := s.db.QueryRow(`SELECT count(*) FROM audit_events`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	for _, inspect := range []bool{true, false} {
		r, err := s.ApplyInstallerSetup(p, inspect)
		if err != nil || len(r.Created) != 0 || len(r.Reused) != 6 {
			t.Fatal("suite check/resume failed", err)
		}
		body, _ := json.Marshal(r)
		if strings.Contains(string(body), connector.SigningSecret) || strings.Contains(string(body), encrypted) {
			t.Fatal("credential in receipt")
		}
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM audit_events`).Scan(&after); err != nil || after != before {
		t.Fatal("check/resume mutated audit", err)
	}
	p.Clients[0].SuiteWebhook = nil // Omission preserves an existing connector.
	if _, err := s.ApplyInstallerSetup(p, false); err != nil {
		t.Fatal(err)
	}
	var retained int
	if err := s.db.QueryRow(`SELECT count(*) FROM paired_systems WHERE id=?`, id).Scan(&retained); err != nil || retained != 1 {
		t.Fatal("omission deleted native connector", err)
	}
}

func TestInstallerSuiteConnectorRefusesDriftAndRollsBack(t *testing.T) {
	for _, cause := range []string{"audit", "secret", "protocol", "hold", "endpoint", "groups", "foreign", "intent", "key"} {
		t.Run(cause, func(t *testing.T) {
			s, close := setupTestStore(t)
			defer close()
			p := installerSuiteFixture()
			if cause == "audit" {
				if _, err := s.db.Exec(`CREATE TRIGGER refuse_suite_audit BEFORE INSERT ON audit_events WHEN NEW.action='admin.system_created' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := s.ApplyInstallerSetup(p, false); err != nil {
					t.Fatal(err)
				}
				query := ""
				switch cause {
				case "secret":
					p.Clients[0].SuiteWebhook.SigningSecret = strings.Repeat("z", 64)
				case "protocol":
					query = `UPDATE paired_systems SET system_type='scim'`
				case "hold":
					query = `UPDATE paired_systems SET provisioning_hold=1`
				case "endpoint":
					query = `UPDATE paired_systems SET callback_url='https://foreign.test/sync/events'`
				case "groups":
					query = `UPDATE paired_systems SET groups_enabled=1`
				case "foreign":
					query = `DELETE FROM installer_setup_resources WHERE kind='connector'`
				case "intent":
					p.Clients[0].SCIM = &InstallerSCIM{URL: p.Clients[0].SuiteWebhook.URL, Token: p.Clients[0].SuiteWebhook.SigningSecret}
					p.Clients[0].SuiteWebhook = nil
				case "key":
					p.EncryptionKey[0] ^= 1
				}
				if query != "" {
					if _, err := s.db.Exec(query); err != nil {
						t.Fatal(err)
					}
				}
			}
			for _, inspect := range []bool{true, false} {
				if _, err := s.ApplyInstallerSetup(p, inspect); err == nil {
					t.Fatal("unsafe suite connector accepted", cause)
				}
			}
			if cause == "audit" {
				for _, table := range []string{"users", "oauth_clients", "paired_systems", "app_registry", "app_roles", "installer_setup_resources", "sync_resource_state"} {
					var count int
					if err := s.db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); err != nil || count != 0 {
						t.Fatal("partial setup after audit failure", table, err, count)
					}
				}
			}
		})
	}
}
