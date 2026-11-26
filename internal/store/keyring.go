package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

const keyringSchema = `
CREATE TABLE IF NOT EXISTS keyrings (
 org_id TEXT NOT NULL REFERENCES orgs(id), user_id TEXT NOT NULL, version TEXT NOT NULL,
 PRIMARY KEY (org_id, user_id),
 FOREIGN KEY (org_id, user_id) REFERENCES users(org_id, id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS keyring_wrappers (
 org_id TEXT NOT NULL REFERENCES orgs(id), user_id TEXT NOT NULL, id TEXT NOT NULL,
 kind TEXT NOT NULL CHECK (kind IN ('device','recovery','prf')),
 sealed TEXT NOT NULL CHECK (length(sealed)=80),
 device_hash TEXT NOT NULL, credential_id TEXT NOT NULL,
 CHECK ((kind='device' AND length(device_hash)=64 AND credential_id='')
     OR (kind='recovery' AND device_hash='' AND credential_id='')
     OR (kind='prf' AND device_hash='' AND length(credential_id) BETWEEN 2 AND 1024)),
 PRIMARY KEY (org_id, user_id, id),
 FOREIGN KEY (org_id, user_id) REFERENCES keyrings(org_id, user_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS keyring_one_recovery ON keyring_wrappers(org_id,user_id) WHERE kind='recovery';
CREATE UNIQUE INDEX IF NOT EXISTS keyring_prf_credential ON keyring_wrappers(org_id,user_id,credential_id) WHERE kind='prf';
CREATE TABLE IF NOT EXISTS keyring_app_keys (
 org_id TEXT NOT NULL REFERENCES orgs(id), user_id TEXT NOT NULL, client_id TEXT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
 key_version BIGINT NOT NULL CHECK (key_version BETWEEN 1 AND 2147483647),
 sealed TEXT NOT NULL CHECK (length(sealed) IN (0,80)),
 PRIMARY KEY (org_id, user_id, client_id),
 FOREIGN KEY (org_id, user_id) REFERENCES keyrings(org_id, user_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS keyring_app_client ON keyring_app_keys(client_id);
CREATE TABLE IF NOT EXISTS keyring_transfers (
 org_id TEXT NOT NULL REFERENCES orgs(id), user_id TEXT NOT NULL, id TEXT NOT NULL,
 request_session TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
 expires_at BIGINT NOT NULL,
 recipient_key TEXT NOT NULL CHECK (length(recipient_key)=87),
 request_mac TEXT NOT NULL CHECK (length(request_mac)=43),
 approved_device TEXT, sender_key TEXT NOT NULL DEFAULT '', sealed TEXT NOT NULL DEFAULT '',
 CHECK ((approved_device IS NULL AND sender_key='' AND sealed='')
     OR (approved_device IS NOT NULL AND length(sender_key)=87 AND length(sealed)=80)),
 PRIMARY KEY (org_id, user_id, id), UNIQUE (org_id, user_id, request_session),
 FOREIGN KEY (org_id, user_id) REFERENCES keyrings(org_id, user_id) ON DELETE CASCADE,
 FOREIGN KEY (org_id, user_id, approved_device) REFERENCES keyring_wrappers(org_id, user_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS keyring_transfer_expiry ON keyring_transfers(expires_at);
CREATE INDEX IF NOT EXISTS keyring_transfer_session ON keyring_transfers(request_session);
`

func keyringSchemaWithTriggers(triggerSQL func(tenancyTrigger, string) string) string {
	var ddl strings.Builder
	ddl.WriteString(keyringSchema)
	refusals := tenancyRefusals("unixepoch()")
	for _, table := range []string{"keyrings", "keyring_wrappers", "keyring_app_keys", "keyring_transfers"} {
		ddl.WriteString(triggerSQL(tenancyTrigger{table + "_org_exists", "BEFORE INSERT", table, "org_missing", msgOrgMissing}, refusals["org_missing"]))
		ddl.WriteString(triggerSQL(tenancyTrigger{table + "_org_immutable", "BEFORE UPDATE OF org_id", table, "org_changed", msgOrgChanged}, refusals["org_changed"]))
	}
	return ddl.String()
}

func migrateKeyring(tx *sql.Tx) error {
	_, err := tx.Exec(keyringSchemaWithTriggers(sqliteTriggerSQL))
	return err
}

func migrateKeyringPostgres(tx *sql.Tx) error {
	replace := strings.NewReplacer("CREATE FUNCTION ", "CREATE OR REPLACE FUNCTION ", "CREATE TRIGGER ", "CREATE OR REPLACE TRIGGER ")
	_, err := tx.Exec(keyringSchemaWithTriggers(func(trigger tenancyTrigger, refusal string) string {
		return replace.Replace(pgTriggerSQL(trigger, refusal))
	}))
	return err
}

var (
	ErrKeyringDenied   = errors.New("keyring access denied")
	ErrKeyringConflict = errors.New("keyring state changed or limit reached")
	ErrKeyringStepUp   = errors.New("keyring change requires step-up")
)

const (
	maxKeyringWrappers  = 16 // devices and PRF credentials together
	maxKeyringTransfers = 4
	maxKeyringAppKeys   = 128
	keyringTransferTTL  = 5 * time.Minute
)

type KeyringWrapperInfo struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	CredentialID string `json:"credential_id,omitempty"`
}

type KeyringWrapper struct {
	KeyringWrapperInfo
	Sealed     string `json:"sealed"`
	DeviceHash string `json:"-"`
}

type KeyringStatus struct {
	Version  string               `json:"keyring_version"`
	Wrappers []KeyringWrapperInfo `json:"wrappers"`
}

type KeyringAppKey struct {
	Version int    `json:"key_version"`
	Sealed  string `json:"sealed"` // empty at a revoked version
}

type KeyringTransferRequest struct {
	RecipientKey string `json:"recipient_key"`
	RequestMAC   string `json:"request_mac"`
}

type KeyringTransferResponse struct {
	SenderKey string `json:"sender_key"`
	Sealed    string `json:"sealed"`
}

// KeyringSession names an authenticated account session. Store operations recheck it
// under the database's existing transaction writer lock, including enrollment changes.
type KeyringSession struct {
	UserID    string
	SessionID string
}

type KeyringGrant struct {
	Hash      string
	Operation string
}

const keyringPrincipalSQL = ` FROM users u JOIN orgs o ON o.id=u.org_id
 JOIN sessions s ON s.user_id=u.id JOIN mfa_session_access m ON m.id=s.id AND m.allowed
 WHERE u.org_id=? AND u.id=? AND u.role='user' AND u.status='active' AND NOT u.pending
 AND NOT u.password_change_required AND (u.ends_at IS NULL OR u.ends_at>unixepoch())
 AND o.status='active' AND o.kind IN ('default','customer') AND NOT s.export_only AND s.expires_at>?`

func (o *OrgStore) keyringTx(p KeyringSession, grant *KeyringGrant, audit *AuditEvent, run func(*sql.Tx, time.Time) error) error {
	return o.s.auditedTx(audit, func(tx *sql.Tx) error {
		now := time.Now().UTC()
		var allowed bool
		limits := o.s.SessionLimits()
		err := tx.QueryRow(`SELECT EXISTS(SELECT 1`+keyringPrincipalSQL+`
 AND s.id=? AND s.workstation_client_id IS NULL AND s.last_active_at>? AND s.created_at>?)`,
			o.org, p.UserID, now, p.SessionID, now.Add(-limits.IdleTTL()), now.Add(-limits.AbsoluteTTL())).Scan(&allowed)
		if err != nil {
			return err
		}
		if !allowed {
			return ErrKeyringDenied
		}
		if grant != nil {
			res, err := tx.Exec(`UPDATE step_up_tokens SET used_at=? WHERE token_hash=? AND user_id=? AND session_id=?
 AND operation=? AND used_at IS NULL AND expires_at>?`, now, grant.Hash, p.UserID, p.SessionID, grant.Operation, now)
			if err := keyringAffected(res, err, ErrKeyringStepUp); err != nil {
				return err
			}
		}
		return run(tx, now)
	})
}

func keyringAffected(res sql.Result, err, missing error) error {
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n != 1 {
		return missing
	}
	return nil
}

func (o *OrgStore) KeyringStatus(p KeyringSession) (KeyringStatus, error) {
	out := KeyringStatus{Wrappers: []KeyringWrapperInfo{}}
	err := o.keyringTx(p, nil, nil, func(tx *sql.Tx, _ time.Time) error {
		err := tx.QueryRow(`SELECT version FROM keyrings WHERE org_id=? AND user_id=?`, o.org, p.UserID).Scan(&out.Version)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		rows, err := tx.Query(`SELECT id,kind,credential_id FROM keyring_wrappers WHERE org_id=? AND user_id=? ORDER BY kind,id`, o.org, p.UserID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var w KeyringWrapperInfo
			if err := rows.Scan(&w.ID, &w.Kind, &w.CredentialID); err != nil {
				return err
			}
			out.Wrappers = append(out.Wrappers, w)
		}
		return rows.Err()
	})
	return out, err
}

func (o *OrgStore) keyringVersionTx(tx *sql.Tx, user, version string) error {
	var exists bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM keyrings WHERE org_id=? AND user_id=? AND version=?)`, o.org, user, version).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrKeyringConflict
	}
	return nil
}

func (o *OrgStore) insertKeyringWrapper(tx *sql.Tx, user string, w KeyringWrapper) error {
	res, err := tx.Exec(`INSERT INTO keyring_wrappers(org_id,user_id,id,kind,sealed,device_hash,credential_id)
 VALUES(?,?,?,?,?,?,?) ON CONFLICT DO NOTHING`, o.org, user, w.ID, w.Kind, w.Sealed, w.DeviceHash, w.CredentialID)
	return keyringAffected(res, err, ErrKeyringConflict)
}

func (o *OrgStore) InitializeKeyring(p KeyringSession, version string, device, recovery KeyringWrapper, grant KeyringGrant, audit *AuditEvent) error {
	return o.keyringTx(p, &grant, audit, func(tx *sql.Tx, _ time.Time) error {
		res, err := tx.Exec(`INSERT INTO keyrings(org_id,user_id,version) VALUES(?,?,?) ON CONFLICT DO NOTHING`, o.org, p.UserID, version)
		if err := keyringAffected(res, err, ErrKeyringConflict); err != nil {
			return err
		}
		if err := o.insertKeyringWrapper(tx, p.UserID, device); err != nil {
			return err
		}
		return o.insertKeyringWrapper(tx, p.UserID, recovery)
	})
}

func (o *OrgStore) KeyringWrapper(p KeyringSession, id, deviceHash string) (KeyringWrapper, error) {
	var w KeyringWrapper
	err := o.keyringTx(p, nil, nil, func(tx *sql.Tx, _ time.Time) error {
		return tx.QueryRow(`SELECT id,kind,credential_id,sealed FROM keyring_wrappers WHERE org_id=? AND user_id=? AND id=?
 AND (kind<>'device' OR device_hash=?)`, o.org, p.UserID, id, deviceHash).Scan(&w.ID, &w.Kind, &w.CredentialID, &w.Sealed)
	})
	return w, err
}

func (o *OrgStore) AddKeyringWrapper(p KeyringSession, version string, w KeyringWrapper, grant KeyringGrant, audit *AuditEvent) error {
	return o.keyringTx(p, &grant, audit, func(tx *sql.Tx, _ time.Time) error {
		if err := o.keyringVersionTx(tx, p.UserID, version); err != nil {
			return err
		}
		var count int
		if err := tx.QueryRow(`SELECT count(*) FROM keyring_wrappers WHERE org_id=? AND user_id=? AND kind<>'recovery'`, o.org, p.UserID).Scan(&count); err != nil {
			return err
		}
		if count >= maxKeyringWrappers {
			return ErrKeyringConflict
		}
		return o.insertKeyringWrapper(tx, p.UserID, w)
	})
}

func (o *OrgStore) RevokeKeyringWrapper(p KeyringSession, id string, grant KeyringGrant, audit *AuditEvent) error {
	return o.keyringTx(p, &grant, audit, func(tx *sql.Tx, _ time.Time) error {
		res, err := tx.Exec(`DELETE FROM keyring_wrappers WHERE org_id=? AND user_id=? AND id=? AND kind<>'recovery'`, o.org, p.UserID, id)
		return keyringAffected(res, err, sql.ErrNoRows)
	})
}

func (o *OrgStore) RotateKeyringRecovery(p KeyringSession, version, previous string, w KeyringWrapper, grant KeyringGrant, audit *AuditEvent) error {
	return o.keyringTx(p, &grant, audit, func(tx *sql.Tx, _ time.Time) error {
		if err := o.keyringVersionTx(tx, p.UserID, version); err != nil {
			return err
		}
		res, err := tx.Exec(`DELETE FROM keyring_wrappers WHERE org_id=? AND user_id=? AND id=? AND kind='recovery'`, o.org, p.UserID, previous)
		if err := keyringAffected(res, err, ErrKeyringConflict); err != nil {
			return err
		}
		return o.insertKeyringWrapper(tx, p.UserID, w)
	})
}

const keyringAppAccessSQL = `EXISTS(SELECT 1 FROM effective_app_access e JOIN app_registry a ON a.id=e.app_id
 JOIN oauth_clients c ON c.id=a.client_id WHERE e.user_id=? AND c.id=? AND c.enabled)`

func keyringAppKeyTx(tx *sql.Tx, org, user, client string) (KeyringAppKey, error) {
	var out KeyringAppKey
	err := tx.QueryRow(`SELECT key_version,sealed FROM keyring_app_keys WHERE org_id=? AND user_id=? AND client_id=?`, org, user, client).Scan(&out.Version, &out.Sealed)
	return out, err
}

func (o *OrgStore) KeyringAppKey(p KeyringSession, client string) (KeyringAppKey, error) {
	var out KeyringAppKey
	err := o.keyringTx(p, nil, nil, func(tx *sql.Tx, _ time.Time) error {
		if err := keyringCheckApp(tx, p.UserID, client); err != nil {
			return err
		}
		var err error
		out, err = keyringAppKeyTx(tx, o.org, p.UserID, client)
		return err
	})
	return out, err
}

func keyringCheckApp(tx *sql.Tx, user, client string) error {
	var allowed bool
	if err := tx.QueryRow(`SELECT `+keyringAppAccessSQL, user, client).Scan(&allowed); err != nil {
		return err
	}
	if !allowed {
		return ErrKeyringDenied
	}
	return nil
}

// KeyringAppKeyForToken accepts the subject, client and jti of a verified access
// token. The issued-token binding and live grant are checked in the ciphertext read.
func (o *OrgStore) KeyringAppKeyForToken(user, client, jti string) (KeyringAppKey, error) {
	var out KeyringAppKey
	err := o.s.inTx(func(tx *sql.Tx) error {
		now := time.Now().UTC()
		var allowed bool
		err := tx.QueryRow(`SELECT EXISTS(SELECT 1`+keyringPrincipalSQL+`
 AND EXISTS(SELECT 1 FROM issued_tokens t WHERE t.user_id=u.id AND t.client_id=? AND t.session_id=s.id AND t.jti=? AND t.revoked_at IS NULL AND t.expires_at>?))
 AND `+keyringAppAccessSQL, o.org, user, now, client, jti, now, user, client).Scan(&allowed)
		if err != nil {
			return err
		}
		if !allowed {
			return ErrKeyringDenied
		}
		out, err = keyringAppKeyTx(tx, o.org, user, client)
		return err
	})
	return out, err
}

// PutKeyringAppKey advances one app's version, even for revocation (empty sealed).
// A revoked row keeps its version so an older writer cannot recreate it.
func (o *OrgStore) PutKeyringAppKey(p KeyringSession, ring, client string, key KeyringAppKey, grant KeyringGrant, audit *AuditEvent) error {
	return o.keyringTx(p, &grant, audit, func(tx *sql.Tx, _ time.Time) error {
		if err := o.keyringVersionTx(tx, p.UserID, ring); err != nil {
			return err
		}
		if err := keyringCheckApp(tx, p.UserID, client); err != nil {
			return err
		}
		if key.Version == 1 && key.Sealed != "" {
			var count int
			if err := tx.QueryRow(`SELECT count(*) FROM keyring_app_keys WHERE org_id=? AND user_id=?`, o.org, p.UserID).Scan(&count); err != nil {
				return err
			}
			if count >= maxKeyringAppKeys {
				return ErrKeyringConflict
			}
			res, err := tx.Exec(`INSERT INTO keyring_app_keys(org_id,user_id,client_id,key_version,sealed) VALUES(?,?,?,?,?) ON CONFLICT DO NOTHING`,
				o.org, p.UserID, client, key.Version, key.Sealed)
			return keyringAffected(res, err, ErrKeyringConflict)
		}
		res, err := tx.Exec(`UPDATE keyring_app_keys SET key_version=?,sealed=? WHERE org_id=? AND user_id=? AND client_id=? AND key_version=?
 AND (sealed<>'' OR ?<>'')`, key.Version, key.Sealed, o.org, p.UserID, client, key.Version-1, key.Sealed)
		return keyringAffected(res, err, ErrKeyringConflict)
	})
}
