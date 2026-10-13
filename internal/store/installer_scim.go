package store

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/google/uuid"
)

// Setup attaches only its newly created, unassigned connector to its owned app.
// General administrator linking retains its stricter independent policy checks.
func configureInstallerConnector(tx *sql.Tx, p InstallerSetup, c InstallerClient, appID string, inspect bool, report *InstallerReport,
	ownership func(string, string, string, string) (bool, error), remember func(string, string, string, string) error,
	audit func(string, string, string) error, now time.Time) error {
	if c.SCIM == nil && c.SuiteWebhook == nil {
		return nil
	}
	if c.SCIM != nil && c.SuiteWebhook != nil {
		return errors.New("one connector protocol is allowed per client")
	}
	var kind, endpoint, credential string
	var deliveryGroups bool
	var contractFields []string
	if c.SCIM != nil {
		kind, endpoint, credential, deliveryGroups = "scim", c.SCIM.URL, c.SCIM.Token, c.SCIM.Groups
		// Preserve existing SCIM ownership receipts byte for byte.
		contractFields = []string{appID, endpoint, crypto.HashSHA256(credential)}
		if deliveryGroups {
			contractFields = append(contractFields, "groups")
		}
	} else {
		kind, endpoint, credential = "suite_webhook", c.SuiteWebhook.URL, c.SuiteWebhook.SigningSecret
		contractFields = []string{appID, endpoint, crypto.HashSHA256(credential), kind}
	}
	contractBytes, _ := json.Marshal(contractFields)
	contract := string(contractBytes)
	var id string
	if err := tx.QueryRow(`SELECT COALESCE(system_id,'') FROM app_registry WHERE id=?`, appID).Scan(&id); err != nil {
		return err
	}
	reused, err := ownership("connector", c.ID, id, contract)
	if err != nil {
		return err
	}
	if reused {
		var name, actualKind, actualEndpoint, encrypted, status, description, icon string
		var groups, hold bool
		var reconcile int
		if err := tx.QueryRow(`SELECT name,system_type,callback_url,hmac_secret_encrypted,status,description,icon_url,groups_enabled,provisioning_hold,reconcile_hours FROM paired_systems WHERE id=?`, id).
			Scan(&name, &actualKind, &actualEndpoint, &encrypted, &status, &description, &icon, &groups, &hold, &reconcile); err != nil {
			return err
		}
		token, err := crypto.DecryptAESGCM(p.EncryptionKey, encrypted)
		if err != nil || subtle.ConstantTimeCompare(token, []byte(credential)) != 1 || name != c.Name || actualKind != kind || actualEndpoint != endpoint ||
			(status != "active" && status != "failing") || description != "" || icon != "" || groups != deliveryGroups || hold || reconcile != 0 {
			return errors.New("owned connector configuration, credential or recovery hold differs")
		}
		report.Reused = append(report.Reused, InstallerObject{"connector", c.ID, id})
		return nil
	}
	if inspect {
		return errors.New("connector is not configured")
	}
	encrypted, err := crypto.EncryptAESGCM(p.EncryptionKey, []byte(credential))
	if err != nil {
		return errors.New("cannot protect connector credential with existing product key")
	}
	id = uuid.NewString()
	if _, err := tx.Exec(`INSERT INTO paired_systems(id,name,system_type,callback_url,hmac_secret_encrypted,status,created_at,groups_enabled) VALUES(?,?,?,?,?,'active',?,?)`, id, c.Name, kind, endpoint, encrypted, now, deliveryGroups); err != nil {
		return err
	}
	// Its insertion trigger minted a separate empty app. It belongs to this transaction;
	// retaining the owned OAuth app's stable ID also retains its roles and assignments.
	var separate string
	if err := tx.QueryRow(`SELECT id FROM app_registry WHERE system_id=? AND client_id IS NULL AND launcher_id IS NULL`, id).Scan(&separate); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM app_registry WHERE id=?`, separate); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE app_registry SET system_id=?,revision=revision+1 WHERE id=? AND system_id IS NULL`, id, appID); err != nil {
		return err
	}
	if err := audit("connector_link", c.ID, appID); err != nil {
		return err
	}
	if err := remember("connector", c.ID, id, contract); err != nil {
		return err
	}
	report.Created = append(report.Created, InstallerObject{"connector", c.ID, id})
	return nil
}
